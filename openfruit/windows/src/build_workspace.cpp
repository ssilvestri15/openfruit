#include "build_workspace.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"
#include <algorithm>
#include <fstream>
#include <set>
#include <stdexcept>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
bool Contains(const fs::path& parent, const fs::path& child) {
    const auto relative = child.lexically_relative(parent);
    return !relative.empty() && !relative.is_absolute() &&
        *relative.begin() != L"..";
}
}
fs::path FindBuildSourceRoot(const fs::path& target) {
    auto source = fs::absolute(target).lexically_normal();
    if (fs::is_regular_file(source)) source = source.parent_path();
    else if (source.extension() == L".xcodeproj" || source.extension() == L".xcworkspace")
        source = source.parent_path();
    for (auto parent = source; !parent.empty(); parent = parent.parent_path()) {
        if (fs::exists(parent / ".git")) { source = parent; break; }
        if (parent.parent_path() == parent) break;
    }
    return fs::canonical(source);
}

fs::path StableBuildWorkspacePath(const fs::path& parent, const fs::path& target,
    const std::string& configuration) {
    auto identity = JsonValue::ObjectValue();
    identity.Set("schema", JsonValue::String("openfruit.build-workspace.v1"));
    identity.Set("target", JsonValue::String(Win32Process::ToNarrow(fs::canonical(target).wstring())));
    identity.Set("configuration", JsonValue::String(configuration));
    const auto hash = Sha256(identity.Serialize());
    if (!hash) throw std::runtime_error("OPENFRUIT workspace: cannot hash identity.");
    // Keep SwiftPM/Clang consumer paths compact; the ownership marker checks
    // the full identity and fails closed on a digest-prefix collision.
    return fs::absolute(parent).lexically_normal() / ("r1-" + hash->substr(0, 16));
}

static BuildWorkspace PrepareWorkspace(const fs::path& target, const fs::path& workspace,
    const std::string& configuration, const ProcessRunOptions& control, bool reuse,
    const ResolvedProjectSelection* selection) {
    BuildWorkspace result;
    result.original_target = fs::canonical(fs::absolute(target));
    result.original_root = FindBuildSourceRoot(target);
    const auto relative = result.original_target.lexically_relative(result.original_root);
    if (relative.empty() || relative.is_absolute() ||
        (relative.begin() != relative.end() && *relative.begin() == L".."))
        throw std::runtime_error("OPENFRUIT workspace: target is outside the source root.");
    // As with xcodebuild -workspace, a workspace names its buildables only
    // through a scheme.
    if (!selection && relative.extension() == L".xcworkspace")
        throw std::runtime_error("OPENFRUIT workspace: building an .xcworkspace requires --scheme.");
    result.root = fs::absolute(workspace).lexically_normal();
    if (!reuse && fs::exists(result.root))
        throw std::runtime_error("OPENFRUIT workspace: destination already exists.");
    if (reuse) {
        result.lease = ArtifactLease::Acquire(result.root, control);
        // A workspace is reusable only by the exact original target/configuration.
        // Write ownership before the first mutation so interrupted sync can resume.
        auto identity = JsonValue::ObjectValue();
        identity.Set("schema", JsonValue::String("openfruit.build-workspace.v1"));
        identity.Set("target", JsonValue::String(Win32Process::ToNarrow(result.original_target.wstring())));
        identity.Set("source", JsonValue::String(Win32Process::ToNarrow(result.original_root.wstring())));
        identity.Set("configuration", JsonValue::String(configuration));
        const auto marker = result.root / "workspace-owner.json";
        if (fs::exists(result.root)) {
            if (!fs::is_directory(result.root) || fs::is_symlink(fs::symlink_status(result.root)))
                throw std::runtime_error("OPENFRUIT workspace: unsafe workspace root.");
            std::ifstream input(marker, std::ios::binary);
            const std::string text((std::istreambuf_iterator<char>(input)), {});
            const auto recorded = JsonValue::Parse(text);
            if (!recorded || !recorded->IsObject() ||
                recorded->GetString("schema") != identity.GetString("schema") ||
                recorded->GetString("target") != identity.GetString("target") ||
                recorded->GetString("source") != identity.GetString("source") ||
                recorded->GetString("configuration") != configuration)
                throw std::runtime_error("OPENFRUIT workspace: reusable ownership mismatch.");
        } else {
            fs::create_directories(result.root);
            if (!AtomicFile::Publish(marker, identity.Serialize(true)))
                throw std::runtime_error("OPENFRUIT workspace: cannot publish ownership.");
        }
    }
    const auto project_sources = [&](const fs::path& source, const fs::path& destination) {
        if (!reuse) return CreateGitSourceView(source, destination, control);
        const auto digest = Sha256(Win32Process::ToNarrow(destination.lexically_relative(result.root).wstring()));
        if (!digest) throw std::runtime_error("OPENFRUIT workspace: cannot hash receipt identity.");
        auto synced = SynchronizeGitSourceView(source, destination,
            result.root / "receipts" / (*digest + ".json"), control);
        result.sync_stats.files_copied += synced.stats.files_copied;
        result.sync_stats.files_reused += synced.stats.files_reused;
        result.sync_stats.bytes_copied += synced.stats.bytes_copied;
        result.sync_stats.entries_removed += synced.stats.entries_removed;
        return std::move(synced.view);
    };
    auto products = result.root / "build" / "Products";
    if (selection && selection->explicit_selection) {
        auto identity = JsonValue::ObjectValue();
        identity.Set("schema", JsonValue::String("openfruit.selected-products.v1"));
        identity.Set("project", JsonValue::String(Win32Process::ToNarrow(selection->project_bundle.wstring())));
        identity.Set("target_uuid", JsonValue::String(selection->target_id));
        identity.Set("configuration", JsonValue::String(configuration));
        identity.Set("purpose", JsonValue::Number(std::to_string(static_cast<int>(selection->action))));
        if (selection->scheme) {
            identity.Set("scheme", JsonValue::String(Win32Process::ToNarrow(selection->scheme->scheme_file.wstring())));
            identity.Set("implicit", JsonValue::Boolean(*selection->scheme->build_implicit_dependencies));
            auto entries = JsonValue::ArrayValue();
            for (const auto& entry : selection->scheme->build_entries) {
                auto item = JsonValue::ObjectValue();
                item.Set("project", JsonValue::String(Win32Process::ToNarrow(entry.project_path.wstring())));
                item.Set("target_uuid", JsonValue::String(entry.target_id));
                entries.ArrayItems().push_back(std::move(item));
            }
            identity.Set("build_entries", std::move(entries));
        }
        const auto digest = Sha256(identity.Serialize());
        if (!digest) throw std::runtime_error("OPENFRUIT workspace: cannot hash selected product context.");
        products /= "p1-" + digest->substr(0, 16);
    }
    const auto inspect = [&] {
        if (!selection) {
            result.target = result.sources.root / relative;
            return UniversalProject::Inspect(result.target.wstring(), configuration, products);
        }
        const auto frozen = ProjectSelectionMetadata::Project(*selection, result.sources);
        result.target = frozen.project_bundle;
        fs::path metadata_root;
        for (const auto& root : frozen.source_roots)
            if (Contains(root, frozen.project_bundle) &&
                (metadata_root.empty() || root.native().size() < metadata_root.native().size())) metadata_root = root;
        const auto project = ProjectSelectionMetadata::LoadProject(frozen.project_bundle, products, nullptr, metadata_root);
        if (!project) throw std::runtime_error("OPENFRUIT workspace: cannot read the selected projected project.");
        const auto selected = project->FindTarget(frozen.target_id);
        if (!selected || selected->id != frozen.target_id)
            throw std::runtime_error("OPENFRUIT workspace: selected UUID changed during projection.");
        std::string error;
        const auto config = project->ResolveConfigurationName(*selected, frozen.configuration, &error);
        if (!config || *config != frozen.configuration)
            throw std::runtime_error(error.empty() ? "OPENFRUIT workspace: selected configuration changed during projection." : error);
        return UniversalProject::InspectSelected(*project, *selected, frozen.configuration, frozen.action, frozen.scheme);
    };
    std::vector<fs::path> roots{result.original_root};
    if (selection) for (const auto& root : selection->source_roots)
        if (std::find(roots.begin(), roots.end(), root) == roots.end()) roots.push_back(root);
    const auto combined_sources = [&]() {
        auto anchor = result.original_root;
        for (const auto& root : roots) {
            while (!Contains(anchor, root)) {
                const auto parent = anchor.parent_path();
                if (parent == anchor || parent.empty())
                    throw std::runtime_error("OPENFRUIT workspace: declared source roots span incompatible volumes.");
                anchor = parent;
            }
        }
        std::vector<fs::path> independent;
        for (const auto& root : roots) {
            if (std::any_of(roots.begin(), roots.end(), [&](const auto& other) {
                    return other != root && Contains(other, root);
                })) continue;
            independent.push_back(root);
        }
        const auto layout = result.root / "local-sources";
        GitSourceView combined;
        combined.root = layout / result.original_root.lexically_relative(anchor);
        for (const auto& root : independent) {
            const auto destination = layout / root.lexically_relative(anchor);
            GitSourceView view;
            if (root == result.original_root && !reuse && !result.sources.root.empty() &&
                !fs::exists(destination) && destination != result.sources.root &&
                std::all_of(result.sources.mappings.begin(), result.sources.mappings.end(),
                    [&](const auto& mapping) { return Contains(root, mapping.original); })) {
                fs::create_directories(destination.parent_path());
                fs::rename(result.sources.root, destination);
                view = std::move(result.sources);
                for (auto& mapping : view.mappings)
                    mapping.projected = destination / mapping.projected.lexically_relative(view.root);
                view.root = destination;
            } else if (!reuse && fs::exists(destination)) {
                for (const auto& mapping : result.sources.mappings)
                    if (Contains(root, mapping.original) && Contains(destination, mapping.projected))
                        view.mappings.push_back(mapping);
                if (view.mappings.empty())
                    throw std::runtime_error("OPENFRUIT workspace: existing source destination lacks admitted ownership.");
                view.root = destination;
            } else view = project_sources(root, destination);
            combined.mappings.insert(combined.mappings.end(), view.mappings.begin(), view.mappings.end());
        }
        return combined;
    };
    if (std::any_of(roots.begin(), roots.end(), [&](const auto& root) { return !Contains(result.original_root, root); }))
        result.sources = combined_sources();
    else result.sources = project_sources(result.original_root, result.root / "sources" / result.original_root.filename());
    result.project = inspect();
    if (!result.project.is_valid)
        throw std::runtime_error("OPENFRUIT workspace: projected project discovery failed.");
    if (result.project.pbxproj_path.empty()) return result;

    // Discover references through the Git-aware view, including project.pbxproj
    // stored as a mode-120000 placeholder. Keep upstream metadata unchanged.
    fs::path metadata_root;
    std::vector<fs::path> projected_roots;
    if (selection) {
        const auto frozen = ProjectSelectionMetadata::Project(*selection, result.sources);
        projected_roots = frozen.source_roots;
        for (const auto& admitted : frozen.source_roots)
            if (Contains(admitted, frozen.project_bundle) &&
                (metadata_root.empty() || admitted.native().size() < metadata_root.native().size())) metadata_root = admitted;
    }
    const auto project = selection ? ProjectSelectionMetadata::LoadProject(
        result.project.pbxproj_path, result.project.build_products_root, nullptr, metadata_root) :
        XcodeProject::Load(result.project.pbxproj_path, result.project.build_products_root);
    const auto roots_before_packages = roots;
    if (project) {
        const auto selected = project->FindTarget(result.project.target_id);
        XcodeDependencyOptions options;
        if (selection) {
            options.include_scheme = false;
            options.strict_build_settings = true;
            if (selection->scheme) options.infer_linked_products = *selection->scheme->build_implicit_dependencies;
        }
        const auto add_local_packages = [&](const fs::path& original_project_root,
                                            const std::vector<XcodePackageReference>& references) {
            for (const auto& reference : references) {
                if (!reference.is_local) continue;
                const fs::path declared(reference.relative_path);
                // Absolute/transitive package mapping belongs to the package
                // graph layer; this service preserves relative Xcode layout.
                if (declared.is_absolute() || declared.has_root_name()) continue;
                auto original_package = (original_project_root / declared).lexically_normal();
                if (original_package.filename().empty()) original_package = original_package.parent_path();
                if (!fs::is_directory(original_package) ||
                    !fs::is_regular_file(original_package / "Package.swift"))
                    throw std::runtime_error("OPENFRUIT workspace: declared local package is missing: " +
                        original_package.string());
                // Keep the declared lexical layout. Resolving a directory
                // junction here would silently change ../ semantics.
                if (fs::canonical(original_package) != original_package)
                    throw std::runtime_error("OPENFRUIT workspace: local package directory alias requires source mapping: " +
                        original_package.string());
                if (std::none_of(roots.begin(), roots.end(), [&](const fs::path& root) {
                        return Contains(root, original_package);
                    })) roots.push_back(original_package);
            }
        };
        std::set<std::pair<fs::path, std::string>> visited_targets;
        const auto collect_closure = [&](const auto& self, const XcodeProject& current_project,
                                         const XcodeTarget& current_target,
                                         const fs::path& original_current_root,
                                         bool root_target) -> void {
            const auto key = std::make_pair(original_current_root.lexically_normal(), current_target.id);
            if (!visited_targets.insert(key).second) return;
            auto current_options = options;
            if (!root_target) current_options.include_scheme = false;
            const auto resolved = current_project.ResolveTarget(current_target, configuration, current_options);
            if (!resolved) return;
            add_local_packages(original_current_root, resolved->package_references);
            for (const auto& dep : resolved->target_dependencies) {
                if (dep.is_subproject && !dep.project_path.empty()) {
                    const auto sub_rel = dep.project_path.lexically_relative(current_project.SourceRoot());
                    if (sub_rel.is_absolute() || sub_rel.has_root_name()) continue;
                    const auto original_sub_bundle = (original_current_root / sub_rel).lexically_normal();
                    if (!fs::is_directory(original_sub_bundle) ||
                        !fs::is_regular_file(original_sub_bundle / "project.pbxproj")) continue;
                    const auto sub_source_root = FindBuildSourceRoot(original_sub_bundle);
                    if (std::none_of(roots.begin(), roots.end(), [&](const fs::path& root) {
                            return Contains(root, sub_source_root);
                        })) roots.push_back(sub_source_root);
                    const bool projected_sub_exists = fs::is_regular_file(dep.project_path / "project.pbxproj");
                    fs::path sub_metadata_root;
                    if (projected_sub_exists) {
                        for (const auto& admitted : projected_roots)
                            if (Contains(admitted, dep.project_path) &&
                                (sub_metadata_root.empty() || admitted.native().size() < sub_metadata_root.native().size()))
                                sub_metadata_root = admitted;
                        if (sub_metadata_root.empty() && Contains(result.sources.root, dep.project_path))
                            sub_metadata_root = result.sources.root;
                    }
                    const auto sub_project = projected_sub_exists ?
                        (selection ? ProjectSelectionMetadata::LoadProject(
                            dep.project_path, result.project.build_products_root, nullptr, sub_metadata_root) :
                            XcodeProject::Load(dep.project_path / "project.pbxproj", result.project.build_products_root)) :
                        ProjectSelectionMetadata::LoadProject(original_sub_bundle, result.project.build_products_root);
                    if (!sub_project) continue;
                    const auto sub_target = !dep.target_id.empty() ?
                        sub_project->FindTarget(dep.target_id) : sub_project->FindTarget(dep.target_name);
                    if (sub_target)
                        self(self, *sub_project, *sub_target, original_sub_bundle.parent_path(), false);
                } else if (!dep.is_subproject && dep.resolution_error.empty()) {
                    const auto dep_target = !dep.target_id.empty() ?
                        current_project.FindTarget(dep.target_id) : current_project.FindTarget(dep.target_name);
                    if (dep_target)
                        self(self, current_project, *dep_target, original_current_root, false);
                }
            }
        };
        if (selected && selected->id == result.project.target_id) {
            const auto project_relative = project->SourceRoot().lexically_relative(result.sources.root);
            if (!selection && !Contains(result.sources.root, project->SourceRoot()))
                throw std::runtime_error("OPENFRUIT workspace: project source root escaped source view.");
            const auto original_project_root = selection ? selection->project_bundle.parent_path() :
                result.original_root / project_relative;
            collect_closure(collect_closure, *project, *selected, original_project_root, true);
        }
    }
    if (roots == roots_before_packages) return result;

    result.sources = combined_sources();
    result.project = inspect();
    if (!result.project.is_valid)
        throw std::runtime_error("OPENFRUIT workspace: local-package project discovery failed.");
    return result;
}

BuildWorkspace PrepareBuildWorkspace(const fs::path& target, const fs::path& workspace,
    const std::string& configuration, const ProcessRunOptions& control, bool reuse) {
    return PrepareWorkspace(target, workspace, configuration, control, reuse, nullptr);
}
BuildWorkspace PrepareBuildWorkspace(const ProjectInspectionRequest& request,
    const ResolvedProjectSelection& selection, const fs::path& workspace,
    const ProcessRunOptions& control, bool reuse) {
    if (ProjectSelectionMetadata::CanonicalInput(request.path) != selection.input_path)
        throw std::runtime_error("OPENFRUIT workspace: selection belongs to a different input request.");
    return PrepareWorkspace(selection.input_path, workspace, selection.configuration, control, reuse, &selection);
}
} // namespace OpenFruit
