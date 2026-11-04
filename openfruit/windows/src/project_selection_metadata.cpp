#include "project_selection_metadata.hpp"
#include "build_workspace.hpp"
#include "content_hash.hpp"
#include <algorithm>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
constexpr std::uint64_t kMetadataLimit = 16 * 1024 * 1024;
fs::path Absolute(const fs::path& path) {
    return path.is_absolute() ? path : fs::absolute(path);
}
bool Contains(const fs::path& parent, const fs::path& child) {
    const auto relative = child.lexically_relative(parent);
    return relative.empty() ? parent == child : !relative.is_absolute() && *relative.begin() != L"..";
}
fs::path MetadataRoot(const fs::path& logical) {
    auto owner = logical;
    for (auto current = logical; !current.empty(); current = current.parent_path()) {
        if (current.extension() == L".xcodeproj" || current.extension() == L".xcworkspace") {
            owner = current; break;
        }
        if (current.parent_path() == current) break;
    }
    while (!owner.empty() && !fs::exists(owner)) {
        const auto parent = owner.parent_path();
        if (parent == owner) break;
        owner = parent;
    }
    return FindBuildSourceRoot(owner);
}
std::optional<std::string> ReadFrom(const fs::path& root, const fs::path& logical,
    std::vector<ProjectMetadataAdmission>* admissions) {
    const auto resolved = TryResolveGitSourcePath(root, logical);
    if (!resolved) {
        if (admissions) {
            const auto previous = std::find_if(admissions->begin(), admissions->end(),
                [&](const auto& item) { return item.logical_path == logical; });
            if (previous != admissions->end() && previous->present)
                throw std::runtime_error("OPENFRUIT selection: admitted metadata disappeared: " + logical.string());
            if (previous == admissions->end()) admissions->push_back({logical, {}, false});
        }
        return std::nullopt;
    }
    std::error_code error;
    if (!fs::is_regular_file(*resolved, error) || error)
        throw std::runtime_error("OPENFRUIT selection: metadata is not an accessible file: " + logical.string());
    const auto length = fs::file_size(*resolved, error);
    if (error || length > kMetadataLimit)
        throw std::runtime_error("OPENFRUIT selection: metadata exceeds the read limit: " + logical.string());
    std::ifstream input(*resolved, std::ios::binary);
    if (!input) throw std::runtime_error("OPENFRUIT selection: cannot read metadata: " + logical.string());
    std::string bytes(static_cast<std::size_t>(length), '\0');
    input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (static_cast<std::size_t>(input.gcount()) != bytes.size() || input.peek() != std::char_traits<char>::eof())
        throw std::runtime_error("OPENFRUIT selection: metadata changed while reading: " + logical.string());
    const auto digest = Sha256(bytes);
    if (!digest) throw std::runtime_error("OPENFRUIT selection: cannot hash admitted metadata.");
    if (admissions) {
        const auto found = std::find_if(admissions->begin(), admissions->end(),
            [&](const auto& item) { return item.logical_path == logical; });
        if (found != admissions->end()) {
            if (!found->present || found->sha256 != *digest)
                throw std::runtime_error("OPENFRUIT selection: admitted metadata changed: " + logical.string());
        } else admissions->push_back({logical, *digest});
    }
    return bytes;
}
void Unique(std::vector<fs::path>& paths, const fs::path& value) {
    const auto normalized = value.lexically_normal();
    if (std::find(paths.begin(), paths.end(), normalized) == paths.end()) paths.push_back(normalized);
}
struct Scope {
    std::vector<fs::path> containers, projects;
};
Scope Discover(const fs::path& input, std::vector<ProjectMetadataAdmission>& admissions) {
    Scope scope;
    const auto admit = [&](const fs::path& owner) {
        Unique(scope.containers, owner);
        if (owner.extension() == L".xcodeproj") { Unique(scope.projects, owner); return; }
        if (owner.extension() != L".xcworkspace") return;
        const auto file = owner / "contents.xcworkspacedata";
        const auto xml = ProjectSelectionMetadata::Read(file, &admissions);
        if (!xml) throw std::runtime_error("OPENFRUIT selection: workspace metadata is absent: " + file.string());
        std::string error;
        const auto contents = XcodeWorkspace::Parse(owner, *xml, &error);
        if (!contents) throw std::runtime_error(error);
        for (const auto& project : contents->projects) {
            // Xcode lists a missing referenced project (for example Pods.xcodeproj
            // before `pod install`) as absent; it contributes no schemes.
            std::error_code missing;
            if (!fs::exists(Absolute(project), missing)) continue;
            const auto canonical = ProjectSelectionMetadata::CanonicalInput(project);
            Unique(scope.projects, canonical); Unique(scope.containers, canonical);
        }
    };
    if (input.filename() == L"project.pbxproj") admit(input.parent_path());
    else if (input.extension() == L".xcodeproj" || input.extension() == L".xcworkspace") admit(input);
    else {
        const auto root = FindBuildSourceRoot(input);
        const auto resolved = TryResolveGitSourcePath(root, input);
        if (!resolved || !fs::is_directory(*resolved))
            throw std::runtime_error("OPENFRUIT selection: input is not a project, workspace or directory.");
        for (const auto& entry : fs::directory_iterator(*resolved)) {
            const auto extension = entry.path().extension();
            if (extension == L".xcodeproj" || extension == L".xcworkspace") admit(ProjectSelectionMetadata::CanonicalInput(input / entry.path().filename()));
            if (scope.containers.size() > 512)
                throw std::runtime_error("OPENFRUIT selection: too many project containers in the requested scope.");
        }
    }
    std::sort(scope.projects.begin(), scope.projects.end());
    std::sort(scope.containers.begin(), scope.containers.end());
    return scope;
}
fs::path SchemeOwner(const fs::path& file) {
    const auto schemes = file.parent_path(), shared = schemes.parent_path(), owner = shared.parent_path();
    if (schemes.filename() != L"xcschemes" || shared.filename() != L"xcshareddata" ||
        (owner.extension() != L".xcodeproj" && owner.extension() != L".xcworkspace"))
        throw std::runtime_error("OPENFRUIT selection: explicit scheme must identify a shared project/workspace scheme.");
    return owner;
}
fs::path FindScheme(const ProjectInspectionRequest& request, const fs::path& input,
    Scope& scope, std::vector<ProjectMetadataAdmission>& admissions) {
    const auto selector = fs::u8path(*request.scheme);
    if (selector.empty()) throw std::runtime_error("OPENFRUIT selection: scheme selector is empty.");
    const auto base = input.extension() == L".xcodeproj" || input.extension() == L".xcworkspace" ||
        input.filename() == L"project.pbxproj" ? input.parent_path() : input;
    if (selector.is_absolute() || selector.has_parent_path()) {
        const auto file = selector.is_absolute() ? selector : base / selector;
        const auto owner = ProjectSelectionMetadata::CanonicalInput(SchemeOwner(file));
        if (std::find(scope.containers.begin(), scope.containers.end(), owner.lexically_normal()) == scope.containers.end())
            throw std::runtime_error("OPENFRUIT selection: explicit scheme is outside the requested container scope.");
        return owner / "xcshareddata/xcschemes" / file.filename();
    }
    const auto name = selector.extension() == L".xcscheme" ? selector : fs::path(selector.wstring() + L".xcscheme");
    std::vector<fs::path> matches;
    std::set<fs::path> canonical_matches;
    for (const auto& owner : scope.containers) {
        const auto candidate = owner / "xcshareddata/xcschemes" / name;
        if (ProjectSelectionMetadata::Read(candidate, &admissions)) {
            const auto resolved = TryResolveGitSourcePath(MetadataRoot(candidate), candidate);
            if (!resolved) throw std::runtime_error("OPENFRUIT selection: scheme disappeared during admission.");
            if (canonical_matches.insert(fs::canonical(*resolved)).second) Unique(matches, candidate);
        }
    }
    if (matches.size() != 1)
        throw std::runtime_error(matches.empty() ? "OPENFRUIT selection: shared scheme was not found." :
            "OPENFRUIT selection: shared scheme name is ambiguous; provide its explicit path.");
    return matches.front();
}
struct Candidate {
    fs::path project;
    XcodeTarget target;
};
bool Same(const Candidate& candidate, const XcodeTargetDependency& reference) {
    return candidate.project == reference.project_path.lexically_normal() && candidate.target.id == reference.target_id;
}
fs::path Remap(const fs::path& original, const GitSourceView& view) {
    const SourceViewMapping* chosen = nullptr;
    std::size_t chosen_length = 0;
    for (const auto& mapping : view.mappings) {
        if (!Contains(mapping.original, original)) continue;
        const auto length = mapping.original.native().size();
        if (!chosen || length > chosen_length) { chosen = &mapping; chosen_length = length; }
    }
    if (!chosen) throw std::runtime_error("OPENFRUIT selection: metadata is outside admitted source mappings: " + original.string());
    const auto relative = original.lexically_relative(chosen->original);
    return relative.empty() || relative == L"." ? chosen->projected : chosen->projected / relative;
}
} // namespace

fs::path ProjectSelectionMetadata::CanonicalInput(const fs::path& logical) {
    const auto absolute = Absolute(logical);
    if (absolute.filename() == L"project.pbxproj")
        return fs::canonical(absolute.parent_path()) / absolute.filename();
    return fs::canonical(absolute);
}

std::optional<std::string> ProjectSelectionMetadata::Read(const fs::path& logical,
    std::vector<ProjectMetadataAdmission>* admissions) {
    const auto absolute = Absolute(logical);
    return ReadFrom(MetadataRoot(absolute), absolute, admissions);
}
std::optional<XcodeProject> ProjectSelectionMetadata::LoadProject(const fs::path& logical_project,
    const fs::path& products, std::vector<ProjectMetadataAdmission>* admissions, const fs::path& metadata_root) {
    const auto path = Absolute(logical_project);
    const auto bundle = path.filename() == L"project.pbxproj" ? path.parent_path() : path;
    const auto root = metadata_root.empty() ? FindBuildSourceRoot(bundle) : metadata_root;
    const auto bytes = ReadFrom(root, bundle / "project.pbxproj", admissions);
    if (!bytes) return std::nullopt;
    auto known_roots = std::make_shared<std::vector<fs::path>>(std::vector<fs::path>{root.lexically_normal()});
    XcodeMetadataReader reader = [known_roots, admissions](const fs::path& file) {
        const auto absolute = Absolute(file);
        for (auto current = absolute; !current.empty(); current = current.parent_path()) {
            if (current.extension() == L".xcodeproj" || current.extension() == L".xcworkspace") {
                Unique(*known_roots, MetadataRoot(absolute));
                break;
            }
            if (current.parent_path() == current) break;
        }
        fs::path file_root;
        for (const auto& candidate : *known_roots)
            if (Contains(candidate, absolute) &&
                (file_root.empty() || candidate.native().size() < file_root.native().size()))
                file_root = candidate;
        if (file_root.empty()) {
            file_root = MetadataRoot(absolute);
            Unique(*known_roots, file_root);
        }
        return ReadFrom(file_root, absolute, admissions);
    };
    return XcodeProject::LoadMetadata(bundle, *bytes, products, std::move(reader));
}

std::optional<ResolvedProjectSelection> ProjectSelectionMetadata::Resolve(
    const ProjectInspectionRequest& request, std::string* error) {
    if (error) error->clear();
    try {
        if (request.path.empty()) throw std::runtime_error("OPENFRUIT selection: project path is empty.");
        ResolvedProjectSelection result;
        result.input_path = CanonicalInput(request.path);
        result.action = request.action;
        result.explicit_selection = request.action != ProjectBuildAction::LegacyProductBuild || request.scheme || request.target;
        Unique(result.source_roots, FindBuildSourceRoot(result.input_path));
        auto scope = Discover(result.input_path, result.admissions);
        for (const auto& container : scope.containers) Unique(result.source_roots, FindBuildSourceRoot(container));
        std::map<fs::path, XcodeProject> projects;
        const auto load = [&](const fs::path& bundle) -> const XcodeProject& {
            const auto path = bundle.lexically_normal();
            if (const auto found = projects.find(path); found != projects.end()) return found->second;
            auto project = LoadProject(path, {}, &result.admissions);
            if (!project) throw std::runtime_error("OPENFRUIT selection: cannot parse project: " + path.string());
            Unique(result.source_roots, FindBuildSourceRoot(path));
            return projects.emplace(path, std::move(*project)).first->second;
        };
        std::vector<Candidate> eligible;
        if (request.scheme) {
            const auto file = FindScheme(request, result.input_path, scope, result.admissions);
            const auto bytes = Read(file, &result.admissions);
            if (!bytes) throw std::runtime_error("OPENFRUIT selection: selected scheme metadata is absent.");
            std::string scheme_error;
            result.scheme = XcodeScheme::Parse(file, SchemeOwner(file), *bytes, request.action, &scheme_error);
            if (!result.scheme) throw std::runtime_error(scheme_error);
            Unique(result.source_roots, FindBuildSourceRoot(result.scheme->owner_container));
            if (!result.scheme->build_implicit_dependencies.has_value())
                throw std::runtime_error("OPENFRUIT selection: scheme does not declare its implicit-dependency policy.");
            for (auto& entry : result.scheme->build_entries) entry.project_path = CanonicalInput(entry.project_path);
            if (result.scheme->runnable) result.scheme->runnable->project_path = CanonicalInput(result.scheme->runnable->project_path);
            for (const auto& entry : result.scheme->build_entries) {
                const auto& project = load(entry.project_path);
                const auto target = project.FindTarget(entry.target_id);
                if (!target || target->id != entry.target_id)
                    throw std::runtime_error("OPENFRUIT selection: scheme target UUID is missing: " + entry.target_id);
                if (std::none_of(eligible.begin(), eligible.end(), [&](const auto& candidate) { return Same(candidate, entry); }))
                    eligible.push_back({project.ProjectBundle(), *target});
            }
        } else {
            for (const auto& bundle : scope.projects) {
                const auto& project = load(bundle);
                if (!request.target && request.action == ProjectBuildAction::LegacyProductBuild) {
                    if (const auto target = project.MainApplicationTarget()) eligible.push_back({bundle, *target});
                } else for (const auto& target : project.Targets()) eligible.push_back({bundle, target});
            }
        }
        if (eligible.empty()) throw std::runtime_error("OPENFRUIT selection: no target is enabled for the requested purpose.");
        std::optional<Candidate> selected;
        if (request.target) {
            if (request.target->uuid.empty()) throw std::runtime_error("OPENFRUIT selection: selected target UUID is empty.");
            fs::path owner = request.target->project;
            if (!owner.empty() && !owner.is_absolute()) {
                const auto base = result.input_path.extension() == L".xcodeproj" || result.input_path.extension() == L".xcworkspace" ?
                    result.input_path.parent_path() : result.input_path;
                owner = base / owner;
            }
            if (!owner.empty()) owner = CanonicalInput(owner);
            for (const auto& candidate : eligible) {
                if (candidate.target.id != request.target->uuid || (!owner.empty() && candidate.project != owner)) continue;
                if (selected) throw std::runtime_error("OPENFRUIT selection: target UUID needs a unique project owner.");
                selected = candidate;
            }
            if (!selected) throw std::runtime_error("OPENFRUIT selection: requested target is absent or disabled for this purpose.");
        } else if (result.scheme && result.scheme->runnable &&
            (request.action == ProjectBuildAction::Running || request.action == ProjectBuildAction::Profiling)) {
            for (const auto& candidate : eligible)
                if (Same(candidate, *result.scheme->runnable)) selected = candidate;
        }
        if (!selected) {
            for (const auto& candidate : eligible) {
                if (candidate.target.product_type != "com.apple.product-type.application") continue;
                if (selected) throw std::runtime_error("OPENFRUIT selection: multiple application roots require an explicit target UUID.");
                selected = candidate;
            }
            if (!selected && eligible.size() == 1) selected = eligible.front();
        }
        if (!selected) throw std::runtime_error("OPENFRUIT selection: multiple eligible roots require an explicit target UUID.");
        result.project_bundle = selected->project;
        result.target_id = selected->target.id;
        auto requested_configuration = request.configuration;
        if (!requested_configuration && result.scheme && !result.scheme->configuration.empty())
            requested_configuration = result.scheme->configuration;
        if (request.action == ProjectBuildAction::LegacyProductBuild && !request.scheme && !request.target) {
            result.configuration = requested_configuration.value_or("Debug");
        } else {
            std::string configuration_error;
            const auto configuration = load(result.project_bundle).ResolveConfigurationName(
                selected->target, requested_configuration, &configuration_error);
            if (!configuration) throw std::runtime_error(configuration_error);
            result.configuration = *configuration;
            if (result.scheme) for (const auto& candidate : eligible) {
                if (!load(candidate.project).ResolveConfigurationName(candidate.target, result.configuration, &configuration_error))
                    throw std::runtime_error(configuration_error);
            }
        }
        // Evaluate the actual selected settings through the same parser and
        // admitted reader. This also freezes required and optional xcconfig
        // inputs before any projection or execution can consume them.
        XcodeDependencyOptions settings_options;
        settings_options.include_scheme = false;
        settings_options.strict_build_settings = result.explicit_selection;
        if (result.scheme) settings_options.infer_linked_products = *result.scheme->build_implicit_dependencies;
        std::set<std::pair<fs::path, std::string>> frozen_targets;
        const auto freeze_settings = [&](const auto& self, const Candidate& candidate) -> void {
            const auto key = std::make_pair(candidate.project.lexically_normal(), candidate.target.id);
            if (!frozen_targets.insert(key).second) return;
            const auto resolved = load(candidate.project).ResolveTarget(
                candidate.target, result.configuration, settings_options);
            if (!resolved)
                throw std::runtime_error("OPENFRUIT selection: selected target settings could not be resolved.");
            for (const auto& dep : resolved->target_dependencies) {
                if (dep.scheme_entry || !dep.resolution_error.empty()) continue;
                const auto dep_bundle = dep.is_subproject && !dep.project_path.empty() ?
                    CanonicalInput(dep.project_path) : candidate.project;
                const auto& dep_project = load(dep_bundle);
                const auto dep_target = !dep.target_id.empty() ?
                    dep_project.FindTarget(dep.target_id) : dep_project.FindTarget(dep.target_name);
                if (dep_target) self(self, Candidate{dep_project.ProjectBundle(), *dep_target});
            }
        };
        freeze_settings(freeze_settings, *selected);
        if (result.scheme) for (const auto& candidate : eligible) {
            if (candidate.project != selected->project || candidate.target.id != selected->target.id)
                freeze_settings(freeze_settings, candidate);
        }
        for (const auto& admission : result.admissions) {
            if (std::none_of(result.source_roots.begin(), result.source_roots.end(),
                    [&](const auto& root) { return Contains(root, admission.logical_path); }))
                Unique(result.source_roots, MetadataRoot(admission.logical_path));
        }
        return result;
    } catch (const std::exception& failure) {
        if (error) *error = failure.what();
        return std::nullopt;
    }
}

ResolvedProjectSelection ProjectSelectionMetadata::Project(
    const ResolvedProjectSelection& original, const GitSourceView& view) {
    auto result = original;
    result.input_path = Remap(original.input_path, view);
    result.project_bundle = Remap(original.project_bundle, view);
    for (auto& root : result.source_roots) root = Remap(root, view);
    for (auto& admission : result.admissions) {
        admission.logical_path = Remap(admission.logical_path, view);
        fs::path metadata_root;
        for (const auto& root : result.source_roots)
            if (Contains(root, admission.logical_path) &&
                (metadata_root.empty() || root.native().size() < metadata_root.native().size())) metadata_root = root;
        if (metadata_root.empty())
            throw std::runtime_error("OPENFRUIT selection: projected metadata lacks an admitted source root.");
        const auto resolved = TryResolveGitSourcePath(metadata_root, admission.logical_path);
        if (!admission.present) {
            if (resolved) throw std::runtime_error("OPENFRUIT selection: previously absent metadata appeared: " + admission.logical_path.string());
            continue;
        }
        const auto digest = resolved ? Sha256File(*resolved) : std::nullopt;
        if (!digest || *digest != admission.sha256)
            throw std::runtime_error("OPENFRUIT selection: projected metadata does not match the admitted original: " + admission.logical_path.string());
    }
    if (result.scheme) {
        auto& scheme = *result.scheme;
        scheme.scheme_file = Remap(scheme.scheme_file, view);
        scheme.owner_container = Remap(scheme.owner_container, view);
        for (auto& entry : scheme.build_entries) entry.project_path = Remap(entry.project_path, view);
        if (scheme.runnable) scheme.runnable->project_path = Remap(scheme.runnable->project_path, view);
    }
    return result;
}
} // namespace OpenFruit
