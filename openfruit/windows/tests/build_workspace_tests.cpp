#include "build_workspace.hpp"
#include "git_symlinks.hpp"
#include "project_inspection.hpp"
#include "operation_events.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
std::string Read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    Require(static_cast<bool>(in), "cannot read fixture");
    return {(std::istreambuf_iterator<char>(in)), {}};
}
std::string Git(const fs::path& path, std::vector<std::wstring> args) {
    args.insert(args.begin(), {L"git.exe", L"-C", path.wstring()});
    const auto result = Win32Process::Run(L"git.exe", args);
    Require(result.success, "Git fixture command failed");
    return result.std_out;
}
void Link(const fs::path& root, const fs::path& path, const std::string& target) {
    std::ofstream(root / path, std::ios::binary) << target;
    auto hash = Git(root, {L"hash-object", L"-w", (root / path).wstring()});
    while (!hash.empty() && (hash.back() == '\n' || hash.back() == '\r')) hash.pop_back();
    Git(root, {L"update-index", L"--add", L"--cacheinfo", L"120000",
              Win32Process::ToWide(hash), path.wstring()});
}
void TestExplicitSelection(const fs::path& fixture, const fs::path& root) {
    const auto source = root / "explicit-selection";
    fs::create_directories(root);
    fs::copy(fixture, source, fs::copy_options::recursive);
    Git(source, {L"init", L"--quiet"});
    Git(source, {L"config", L"core.symlinks", L"false"});
    const auto bundle = source / "Probe.xcodeproj";
    const auto pbx = bundle / "project.pbxproj";
    const auto scheme = bundle / "xcshareddata/xcschemes/Extension.xcscheme";
    fs::create_directories(scheme.parent_path());
    const std::string xml = R"(<Scheme version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="NO"><BuildActionEntries>
<BuildActionEntry buildForRunning="YES" buildForTesting="NO" buildForProfiling="NO" buildForAnalyzing="NO" buildForArchiving="NO"><BuildableReference BlueprintIdentifier="A00000000000000000000004" ReferencedContainer="container:Probe.xcodeproj"/></BuildActionEntry>
<BuildActionEntry buildForRunning="YES" buildForTesting="YES" buildForProfiling="YES" buildForAnalyzing="YES" buildForArchiving="YES"><BuildableReference BlueprintIdentifier="A0000000000000000000000C" ReferencedContainer="container:Probe.xcodeproj"/></BuildActionEntry>
</BuildActionEntries></BuildAction>
<LaunchAction buildConfiguration="Debug"><BuildableProductRunnable><BuildableReference BlueprintIdentifier="A0000000000000000000000C" ReferencedContainer="container:Probe.xcodeproj"/></BuildableProductRunnable></LaunchAction></Scheme>)";
    std::ofstream(scheme, std::ios::binary) << xml;
    // Optional includes are part of the selected metadata contract, including
    // their absence. A newly appearing include must invalidate the frozen plan.
    { std::ofstream config(source / "Config/Extension.xcconfig", std::ios::app);
      config << "\n#include? \"Optional.xcconfig\"\n"; }
    Git(source, {L"add", L"."});
    fs::rename(pbx, bundle / "real.pbxproj");
    Link(source, "Probe.xcodeproj/project.pbxproj", "real.pbxproj");
    fs::rename(scheme, scheme.parent_path() / "Real.xcscheme");
    Link(source, "Probe.xcodeproj/xcshareddata/xcschemes/Extension.xcscheme", "Real.xcscheme");
    const auto before = Git(source, {L"status", L"--porcelain", L"-z"});
    ProjectInspectionRequest request;
    request.path = bundle;
    request.scheme = "Extension";
    std::string error;
    const auto selection = ProjectSelectionMetadata::Resolve(request, &error);
    Require(selection.has_value(), error.c_str());
    Require(selection->target_id == "A0000000000000000000000C" && selection->configuration == "Debug",
        "Scheme runnable/configuration did not select the extension UUID");
    Require(std::any_of(selection->admissions.begin(), selection->admissions.end(), [](const auto& item) {
        return item.logical_path.filename() == "Optional.xcconfig" && !item.present;
    }), "Optional xcconfig absence was not admitted");
    const auto inspected = ProjectInspection::Inspect(request);
    Require(inspected.success && inspected.project.selection_frozen &&
        inspected.project.target_id == selection->target_id && inspected.project.configuration == L"Debug" &&
        inspected.project.target_dependencies.size() == 1,
        "Readonly selected inspection lost runnable/co-build/configuration identity");
    Require(Read(pbx) == "real.pbxproj" && Read(scheme) == "Real.xcscheme" &&
        before == Git(source, {L"status", L"--porcelain", L"-z"}),
        "Readonly selection changed Git placeholders or source state");
    const auto workspace_path = StableBuildWorkspacePath(root / "selected-workspaces", request.path, selection->configuration);
    fs::path products_a, sources_a;
    fs::file_time_type source_time;
    {
        const auto workspace = PrepareBuildWorkspace(request, *selection, workspace_path, {}, true);
        products_a = workspace.project.build_products_root;
        sources_a = workspace.sources.root;
        source_time = fs::last_write_time(sources_a / "Owned.swift");
        Require(workspace.project.target_id == selection->target_id &&
            workspace.project.selected_scheme_sha256 == selection->scheme->content_sha256 &&
            products_a.filename().string().rfind("p1-", 0) == 0 && products_a.filename() != "Debug",
            "Frozen selected product/schema metadata did not reach the projected consumer");
    }
    const auto upper_source = root / "EXPLICIT-SELECTION";
    std::error_code spelling_error;
    if (fs::canonical(upper_source, spelling_error) == fs::canonical(source) && !spelling_error) {
        auto alias_request = request;
        alias_request.path = upper_source / "Probe.xcodeproj";
        alias_request.scheme = Win32Process::ToNarrow((upper_source /
            "Probe.xcodeproj/xcshareddata/xcschemes/Extension.xcscheme").wstring());
        alias_request.target = ProjectTargetSelection{upper_source / "Probe.xcodeproj", "A0000000000000000000000C"};
        const auto alias_selection = ProjectSelectionMetadata::Resolve(alias_request, &error);
        Require(alias_selection && alias_selection->input_path == fs::canonical(bundle) &&
            alias_selection->scheme->owner_container == fs::canonical(bundle),
            "Uppercase root/qualified owner/explicit scheme did not preserve canonical container ownership");
        const auto alias_inspection = ProjectInspection::Inspect(alias_request);
        Require(alias_inspection.success && alias_inspection.project.target_id == selection->target_id,
            "Readonly explicit scheme inspection rejected physically identical root spelling");
        const auto alias_workspace = PrepareBuildWorkspace(alias_request, *alias_selection, workspace_path, {}, true);
        Require(alias_workspace.sources.root == sources_a && alias_workspace.sync_stats.files_copied == 0 &&
            alias_workspace.project.target_id == selection->target_id &&
            alias_workspace.project.build_products_root == products_a &&
            fs::last_write_time(sources_a / "Owned.swift") == source_time,
            "Uppercase root pipeline failed admission remapping or duplicated the stable workspace");
        Require(Read(pbx) == "real.pbxproj" && Read(scheme) == "Real.xcscheme" &&
            before == Git(source, {L"status", L"--porcelain", L"-z"}),
            "Root spelling alias pipeline modified original metadata or Git state");
    } else std::cerr << "SKIP uppercase root pipeline: fixture root is case-sensitive\n";
    request.scheme.reset();
    request.target = ProjectTargetSelection{bundle, "A00000000000000000000004"};
    request.configuration = "debug";
    const auto app = ProjectSelectionMetadata::Resolve(request, &error);
    Require(app && app->configuration == "Debug", "Selected configuration was not canonicalized");
    {
        const auto workspace = PrepareBuildWorkspace(request, *app, workspace_path, {}, true);
        Require(workspace.sources.root == sources_a && workspace.sync_stats.files_copied == 0 &&
            fs::last_write_time(sources_a / "Owned.swift") == source_time &&
            workspace.project.build_products_root != products_a,
            "Changing selected UUID duplicated/replaced source view or reused another target's products");
    }
    request.target->uuid = "OwnedExtension";
    Require(!ProjectSelectionMetadata::Resolve(request, &error), "A target label was accepted as an exact UUID");
    request.target->uuid = "A00000000000000000000004";
    request.configuration = "Missing";
    Require(!ProjectSelectionMetadata::Resolve(request, &error), "Missing selected configuration silently used Debug settings");
    request.configuration = "Debug";
    { std::ofstream config(source / "Config/Shared.xcconfig", std::ios::app); config << "\nCHANGED = YES\n"; }
    bool refused = false;
    try { (void)PrepareBuildWorkspace(request, *app, workspace_path, {}, true); }
    catch (const std::exception&) { refused = true; }
    Require(refused, "Changed admitted xcconfig bytes were consumed through a frozen selection");
    // Restore only this owned test input; now isolate optional-absence drift.
    auto shared = Read(fixture / "Config/Shared.xcconfig");
    std::ofstream(source / "Config/Shared.xcconfig", std::ios::binary | std::ios::trunc) << shared;
    std::ofstream(source / "Config/Optional.xcconfig") << "CHANGED = YES\n";
    request.scheme = "Extension"; request.target.reset();
    refused = false;
    try { (void)PrepareBuildWorkspace(request, *selection, workspace_path, {}, true); }
    catch (const std::exception&) { refused = true; }
    Require(refused, "A newly appearing optional xcconfig changed a frozen selection silently");
    fs::remove(source / "Config/Optional.xcconfig");
    request.scheme.reset(); request.target = ProjectTargetSelection{bundle, "A00000000000000000000004"};
    { std::ofstream changed(bundle / "real.pbxproj", std::ios::app); changed << "\n// changed metadata\n"; }
    refused = false;
    try { (void)PrepareBuildWorkspace(request, *app, workspace_path, {}, true); }
    catch (const std::exception&) { refused = true; }
    Require(refused, "Changed admitted PBX digest was accepted by the projected consumer");
}

struct CancelDuringCreation final : EventSink {
    std::weak_ptr<OperationContext> context;
    fs::path source;
    bool observed = false;
    bool pristine_during = false;
    void Emit(OperationEvent event) noexcept override {
        if (event.kind != "process.started" || observed) return;
        observed = true;
        try {
            pristine_during = fs::is_regular_file(source / "Owned.swift") &&
                Read(source / "Owned.swift") == "Real.swift" &&
                fs::is_regular_file(source / "Config/Debug.entitlements") &&
                Read(source / "Config/Debug.entitlements") == "Real.entitlements";
        } catch (...) { pristine_during = false; }
        if (const auto operation = context.lock()) operation->RequestCancellation();
    }
};
}
int main(int argc, char** argv) {
    fs::path root;
    try {
        Require(argc == 2, "fixture root required");
        root = fs::temp_directory_path() / ("OPENFRUIT-build-workspace-" + NewOperationId());
        TestExplicitSelection(fs::path(Win32Process::ToWide(argv[1])), root);
        const auto source = root / "original", output = root / "workspace";
        fs::create_directories(root);
        fs::copy(fs::path(Win32Process::ToWide(argv[1])), source, fs::copy_options::recursive);
        Git(source, {L"init", L"--quiet"});
        Git(source, {L"config", L"core.symlinks", L"false"});
        const auto original_source = Read(source / "Owned.swift");
        fs::rename(source / "Owned.swift", source / "Real.swift");
        fs::rename(source / "Config" / "Debug.entitlements", source / "Config" / "Real.entitlements");
        Git(source, {L"add", L"."});
        Link(source, "Owned.swift", "Real.swift");
        Link(source, "Config/Debug.entitlements", "Real.entitlements");
        Git(source, {L"-c", L"user.name=OPENFRUIT fixture", L"-c", L"user.email=fixture@example.invalid",
            L"commit", L"--quiet", L"-m", L"owned workspace input"});
        const auto before = Git(source, {L"status", L"--porcelain", L"-z"});
        Require(before.empty(), "upstream must begin pristine");
        const auto original_project = UniversalProject::Inspect((source / "Probe.xcodeproj").wstring(), "Debug");
        Require(original_project.is_valid, "original project metadata not discoverable");
        // Same entrypoint and configuration passed by main. No source/include
        // paths, settings or entitlement paths are injected into the consumer.
        const auto workspace = PrepareBuildWorkspace(source / "Probe.xcodeproj", output, "Debug");
        Require(workspace.original_root == source, "containing Git root not derived");
        Require(workspace.project.bundle_id == original_project.bundle_id &&
            workspace.project.target_id == original_project.target_id, "project identity changed");
        const auto setting = [](const DiscoveredProject& project, const std::wstring& key) {
            for (const auto& item : project.build_settings)
                if (item.first == key) return fs::path(item.second).lexically_normal();
            return fs::path{};
        };
        const auto managed_products = output / "build" / "Products";
        Require(workspace.project.build_products_root == managed_products &&
            setting(workspace.project, L"BUILD_DIR") == managed_products,
            "workspace product seed did not precede build-setting expansion");
        Require(setting(workspace.project, L"BUILT_PRODUCTS_DIR") == managed_products / "Debug",
            "workspace derived product location escaped the invocation");
        // A markerless project is inspected relative to its source directory,
        // rather than accidentally acquiring C:/build/Products.
        const auto standalone = root / "standalone";
        fs::copy(fs::path(Win32Process::ToWide(argv[1])), standalone, fs::copy_options::recursive);
        const auto standalone_project = UniversalProject::Inspect(
            (standalone / "Probe.xcodeproj").wstring(), "Debug");
        Require(standalone_project.is_valid && setting(standalone_project, L"BUILD_DIR") ==
            standalone / "build" / "Products", "markerless inspection uses a drive-root build directory");
        // Explicit project metadata overrides invocation defaults; no resolved
        // compiler flags or output paths are injected into the consumer.
        const auto pbx = standalone / "Probe.xcodeproj" / "project.pbxproj";
        auto metadata = Read(pbx);
        const auto empty_settings = metadata.find("buildSettings = {};");
        Require(empty_settings != std::string::npos, "project configuration fixture missing");
        metadata.replace(empty_settings, std::string("buildSettings = {};").size(),
            "buildSettings = { BUILD_DIR = \"$(SRCROOT)/Declared Products\"; };");
        std::ofstream(pbx, std::ios::binary | std::ios::trunc) << metadata;
        const auto overridden = UniversalProject::Inspect(
            (standalone / "Probe.xcodeproj").wstring(), "Debug", root / "override-seed");
        Require(overridden.is_valid && setting(overridden, L"BUILD_DIR") == standalone / "Declared Products" &&
            setting(overridden, L"BUILT_PRODUCTS_DIR") == standalone / "Declared Products" / "Debug",
            "project build-directory override does not reach derived settings");
        std::ofstream(standalone / "Config" / "Shared.xcconfig", std::ios::binary | std::ios::app)
            << "\nBUILD_DIR = $(SRCROOT)/Target Products\n";
        const auto target_override = UniversalProject::Inspect(
            (standalone / "Probe.xcodeproj").wstring(), "Debug", root / "override-seed");
        Require(target_override.is_valid && setting(target_override, L"BUILD_DIR") ==
            standalone / "Target Products" && setting(target_override, L"BUILT_PRODUCTS_DIR") ==
            standalone / "Target Products" / "Debug",
            "target xcconfig build-directory override does not supersede project/default values");
        const auto shell_source = root / "shell-original";
        fs::copy(fs::path(Win32Process::ToWide(argv[1])).parent_path() / "xcode-shell-phase",
            shell_source, fs::copy_options::recursive);
        const auto shell_workspace = PrepareBuildWorkspace(
            shell_source / "ShellPhaseProbe.xcodeproj", root / "shell-workspace", "Release");
        const auto shell_products = shell_workspace.root / "build" / "Products";
        bool derived_flag = false;
        const std::wstring modulemap_prefix = L"-fmodule-map-file=";
        for (const auto& flag : shell_workspace.project.c_flags)
            if (flag.rfind(modulemap_prefix, 0) == 0 &&
                fs::path(flag.substr(modulemap_prefix.size())).lexically_normal() ==
                    shell_products / "Release" / "ShellPhaseProducer" / "Generated.modulemap")
                derived_flag = true;
        Require(derived_flag, "shell consumer flag expanded before managed product context");
        const auto shell_graph = XcodeProject::Load(shell_workspace.target, shell_workspace.project.build_products_root);
        Require(shell_graph.has_value(), "shell graph missing");
        const auto producer = shell_graph->FindTarget("ShellPhaseProducer");
        Require(producer.has_value(), "shell producer missing");
        const auto resolved_producer = shell_graph->ResolveTarget(*producer, "Release");
        Require(resolved_producer && resolved_producer->shell_script_phases.size() == 1 &&
            resolved_producer->shell_script_phases.front().output_paths.size() == 2 &&
            fs::path(resolved_producer->shell_script_phases.front().output_paths.front()).lexically_normal() ==
                shell_products / "Release" / "ShellPhaseProducer" / "Generated.h",
            "shell producer output and consumer flag disagree on managed product root");
        const auto spec = UniversalProject::ToAppBuildSpec(workspace.project);
        Require(!spec.additional_sources.empty(), "project source phase not discovered");
        bool has_alias = false;
        for (const auto& file : spec.additional_sources)
            if (fs::path(file).filename() == L"Owned.swift") {
                Require(fs::path(file).parent_path() == workspace.sources.root, "consumer points at original source");
                Require(Read(file) == original_source, "source consumer receives placeholder text");
                has_alias = true;
            }
        Require(has_alias, "project source alias missing");
        const auto packaging = UniversalProject::ToPackagingSpec(workspace.project);
        Require(fs::path(packaging.code_sign_entitlements_path) ==
                workspace.sources.root / "Config" / "Debug.entitlements", "packaging path not derived from view");
        Require(Read(packaging.code_sign_entitlements_path) == Read(source / "Config" / "Real.entitlements"),
                "packaging consumer receives entitlement placeholder text");
        Require(Read(source / "Owned.swift") == "Real.swift", "source placeholder was materialized");
        Require(Read(source / "Config" / "Debug.entitlements") == "Real.entitlements", "entitlement placeholder changed");
        Require(before == Git(source, {L"status", L"--porcelain", L"-z"}), "workspace changed upstream status");
        Require(!fs::exists(source / "build"), "upstream intermediates created");
        const auto reusable_path = StableBuildWorkspacePath(root / "reusable", source / "Probe.xcodeproj", "Debug");
        Require(reusable_path == StableBuildWorkspacePath(root / "reusable", source / "Probe.xcodeproj", "Debug") &&
            reusable_path != StableBuildWorkspacePath(root / "reusable", source / "Probe.xcodeproj", "Release"),
            "workspace identity is unstable or ignores configuration");
        fs::file_time_type unchanged_time;
        {
            const auto first = PrepareBuildWorkspace(source / "Probe.xcodeproj", reusable_path, "Debug", {}, true);
            Require(first.sync_stats.files_copied > 0 && !ArtifactLease::TryAcquire(reusable_path),
                "first reusable workspace was not copied or consumer lease released early");
            unchanged_time = fs::last_write_time(first.sources.root / "Owned.swift");
        }
        {
            const auto warm = PrepareBuildWorkspace(source / "Probe.xcodeproj", reusable_path, "Debug", {}, true);
            Require(warm.sync_stats.files_copied == 0 && warm.sync_stats.files_reused > 0 &&
                fs::last_write_time(warm.sources.root / "Owned.swift") == unchanged_time,
                "warm workspace recopies unchanged source inputs");
        }
        std::ofstream(source / "additional.txt", std::ios::binary) << "one new input\n";
        {
            const auto delta = PrepareBuildWorkspace(source / "Probe.xcodeproj", reusable_path, "Debug", {}, true);
            std::cout << "workspace delta: copied=" << delta.sync_stats.files_copied << ", reused=" <<
                delta.sync_stats.files_reused << ", preserved=" <<
                (fs::last_write_time(delta.sources.root / "Owned.swift") == unchanged_time) << '\n';
            Require(delta.sync_stats.files_copied == 1 && Read(delta.sources.root / "additional.txt") == "one new input\n" &&
                fs::last_write_time(delta.sources.root / "Owned.swift") == unchanged_time,
                "one changed input invalidated unrelated workspace sources");
        }
        fs::remove(source / "additional.txt");
        bool owner_rejected = false;
        try { PrepareBuildWorkspace(source / "Probe.xcodeproj", reusable_path, "Release", {}, true); }
        catch (const std::exception&) { owner_rejected = true; }
        Require(owner_rejected && before == Git(source, {L"status", L"--porcelain", L"-z"}),
            "incompatible workspace accepted or sync changed upstream sources");
        // Local package paths must reach the real project consumer through the
        // source-view service; no dependency is manually copied to its output.
        for (const bool git_package : {false, true}) {
            const auto local_case = root / (git_package ? "local-git" : "local-plain");
            const auto app = local_case / "app", package = local_case / "Dependency";
            fs::create_directories(local_case);
            fs::copy(fs::path(Win32Process::ToWide(argv[1])), app, fs::copy_options::recursive);
            fs::create_directories(package / "Sources");
            std::ofstream(package / "Package.swift") << "// owned package manifest\n";
            std::ofstream(package / "Sources/Value.swift") << "public let value = 17\n";
            std::ofstream(local_case / "unrelated-secret") << "must stay outside view";
            if (git_package) {
                Git(package, {L"init", L"--quiet"});
                Git(package, {L"add", L"."});
                Link(package, "Sources/Alias.swift", "Value.swift");
            }
            const auto project_file = app / "Probe.xcodeproj/project.pbxproj";
            auto bytes = Read(project_file);
            const auto project_isa = bytes.find("isa = PBXProject;");
            Require(project_isa != std::string::npos, "local project fixture missing");
            bytes.insert(project_isa, "packageReferences = (B00000000000000000000001, B00000000000000000000002,);\n");
            const auto target_isa = bytes.find("isa = PBXNativeTarget;");
            Require(target_isa != std::string::npos, "local target fixture missing");
            bytes.insert(target_isa, "packageProductDependencies = (B00000000000000000000003, B00000000000000000000004,);\n");
            const auto objects = bytes.find("objects = {");
            bytes.insert(objects + std::string("objects = {").size(),
                "\nB00000000000000000000001 = { isa = XCLocalSwiftPackageReference; relativePath = \"../Dependency\"; };\n"
                "B00000000000000000000002 = { isa = XCLocalSwiftPackageReference; relativePath = \"../Dependency/.\"; };\n"
                "B00000000000000000000003 = { isa = XCSwiftPackageProductDependency; package = B00000000000000000000001; productName = Dependency; };\n"
                "B00000000000000000000004 = { isa = XCSwiftPackageProductDependency; package = B00000000000000000000002; productName = Dependency; };\n");
            std::ofstream(project_file, std::ios::binary | std::ios::trunc) << bytes;
            const auto projected = PrepareBuildWorkspace(app / "Probe.xcodeproj", local_case / "output", "Debug");
            Require(Read(projected.project.pbxproj_path) == bytes && Read(project_file) == bytes,
                "local projection changed project metadata");
            const auto graph = XcodeProject::Load(projected.project.pbxproj_path);
            const auto target = graph ? graph->FindTarget(projected.project.target_id) : std::optional<XcodeTarget>{};
            const auto resolved = target ? graph->ResolveTarget(*target, "Debug") : std::optional<XcodeResolvedTarget>{};
            Require(resolved && !resolved->package_references.empty(), "consumer lost local package references");
            const auto dependency = (graph->SourceRoot() / resolved->package_references.front().relative_path).lexically_normal();
            Require(Read(dependency / "Sources/Value.swift") == Read(package / "Sources/Value.swift"),
                "declared sibling package did not reach projected consumer");
            Require(dependency != package && !fs::exists(dependency.parent_path() / "unrelated-secret"),
                "projection read original dependency or copied undeclared parent contents");
            if (git_package) Require(Read(dependency / "Sources/Alias.swift") == Read(package / "Sources/Value.swift"),
                "external Git placeholder not materialized independently");
            fs::path stable_local_root;
            {
                const auto first = PrepareBuildWorkspace(app / "Probe.xcodeproj", local_case / "reuse", "Debug", {}, true);
                stable_local_root = first.sources.root;
            }
            {
                const auto warm = PrepareBuildWorkspace(app / "Probe.xcodeproj", local_case / "reuse", "Debug", {}, true);
                Require(warm.sources.root == stable_local_root && warm.sync_stats.files_copied == 0,
                    "relative local package layout moved or recopied during warm reuse");
                Require(Read(warm.sources.root.parent_path() / "Dependency/Sources/Value.swift") ==
                    Read(package / "Sources/Value.swift"), "warm local dependency content changed");
            }
            // Once inside a shared checkout, the same declared dependency needs
            // no additional source view and keeps the original simple layout.
            Git(local_case, {L"init", L"--quiet"});
            const auto contained = PrepareBuildWorkspace(app / "Probe.xcodeproj", root /
                (git_package ? "contained-git" : "contained-plain"), "Debug");
            Require(contained.sources.root == contained.root / "sources" / local_case.filename(),
                "contained local dependency unnecessarily changed source layout");
            Require(fs::is_regular_file(contained.sources.root / "Dependency/Package.swift"),
                "contained package missing");
            fs::rename(package / "Package.swift", package / "Missing.swift");
            bool missing = false;
            try { PrepareBuildWorkspace(app / "Probe.xcodeproj", root /
                    (git_package ? "missing-git" : "missing-plain"), "Debug"); }
            catch (const std::exception& e) { missing = std::string(e.what()).find("declared local package is missing") != std::string::npos; }
            Require(missing, "missing declared local package was not diagnosed by producer");
        }
        {
            const auto transitive_case = root / "transitive-local";
            const auto app = transitive_case / "app", package = transitive_case / "TransitivePkg";
            fs::create_directories(transitive_case);
            fs::copy(fs::path(Win32Process::ToWide(argv[1])), app, fs::copy_options::recursive);
            fs::create_directories(package / "Sources");
            std::ofstream(package / "Package.swift") << "// transitive owned package manifest\n";
            std::ofstream(package / "Sources/TransitiveValue.swift") << "public let transitiveValue = 42\n";
            const auto project_file = app / "Probe.xcodeproj/project.pbxproj";
            auto bytes = Read(project_file);
            const auto project_isa = bytes.find("isa = PBXProject;");
            Require(project_isa != std::string::npos, "transitive project fixture missing");
            bytes.insert(project_isa, "packageReferences = (C00000000000000000000001,);\n");
            const auto root_target_name = bytes.find("name = Probe;");
            Require(root_target_name != std::string::npos, "root target fixture missing");
            bytes.insert(root_target_name, "dependencies = (C00000000000000000000003,);\n");
            const auto child_target_name = bytes.find("name = OwnedExtension;");
            Require(child_target_name != std::string::npos, "child target fixture missing");
            bytes.insert(child_target_name, "packageProductDependencies = (C00000000000000000000002,);\n");
            const auto objects = bytes.find("objects = {");
            bytes.insert(objects + std::string("objects = {").size(),
                "\nC00000000000000000000001 = { isa = XCLocalSwiftPackageReference; relativePath = \"../TransitivePkg\"; };\n"
                "C00000000000000000000002 = { isa = XCSwiftPackageProductDependency; package = C00000000000000000000001; productName = TransitivePkg; };\n"
                "C00000000000000000000003 = { isa = PBXTargetDependency; target = A0000000000000000000000C; };\n");
            std::ofstream(project_file, std::ios::binary | std::ios::trunc) << bytes;
            const auto projected = PrepareBuildWorkspace(app / "Probe.xcodeproj", transitive_case / "output", "Debug");
            const auto projected_pkg = (projected.sources.root.parent_path() / "TransitivePkg").lexically_normal();
            Require(Read(projected_pkg / "Sources/TransitiveValue.swift") ==
                Read(package / "Sources/TransitiveValue.swift"),
                "transitive local package declared on child target did not reach projected workspace");
            ProjectInspectionRequest req;
            req.path = app / "Probe.xcodeproj";
            req.target = ProjectTargetSelection{app / "Probe.xcodeproj", "A00000000000000000000004"};
            req.configuration = "Debug";
            std::string sel_error;
            const auto sel = ProjectSelectionMetadata::Resolve(req, &sel_error);
            Require(sel.has_value(), sel_error.c_str());
            fs::path stable_transitive_root;
            {
                const auto first = PrepareBuildWorkspace(req, *sel, transitive_case / "selected-reuse", {}, true);
                stable_transitive_root = first.sources.root;
                Require(Read(first.sources.root.parent_path() / "TransitivePkg/Sources/TransitiveValue.swift") ==
                    Read(package / "Sources/TransitiveValue.swift"),
                    "selected transitive local package was not projected");
            }
            {
                const auto warm = PrepareBuildWorkspace(req, *sel, transitive_case / "selected-reuse", {}, true);
                Require(warm.sources.root == stable_transitive_root && warm.sync_stats.files_copied == 0,
                    "selected transitive local package recopied during warm reuse");
            }
        }
        std::ofstream(source / "ordinary.h") << "Real.swift";
        Git(source, {L"add", L"ordinary.h"});
        Require(ResolveGitSymlinkPlaceholderTarget(source / "ordinary.h") == source / "ordinary.h",
                "legacy consumer guessed a link from ordinary short contents");
        Require(ResolveGitSymlinkPlaceholderTarget(source / "Owned.swift") == source / "Real.swift",
                "legacy consumer did not derive link from Git metadata");
        fs::rename(source / "Probe.xcodeproj" / "project.pbxproj", source / "Probe.xcodeproj" / "real.pbxproj");
        Git(source, {L"add", L"Probe.xcodeproj/real.pbxproj"});
        Link(source, "Probe.xcodeproj/project.pbxproj", "real.pbxproj");
        const auto aliased_project = PrepareBuildWorkspace(source / "Probe.xcodeproj", root / "project-alias", "Debug");
        Require(aliased_project.project.is_valid &&
            aliased_project.project.bundle_id == original_project.bundle_id,
            "initial discovery cannot consume a projected project-file alias");
        auto operation = std::make_shared<OperationContext>();
        operation->RequestCancellation();
        bool cancelled = false;
        { OperationBinding binding(operation);
          try { PrepareBuildWorkspace(source / "Probe.xcodeproj", root / "cancelled", "Debug"); }
          catch (const std::exception& e) { cancelled = std::string(e.what()).find("cancelled") != std::string::npos; }
        }
        Require(cancelled, "root operation cancellation did not reach workspace creation");
        Require(!fs::exists(root / "cancelled" / "sources" / "original"), "cancelled sources published");
        const auto status_before_cancel = Git(source, {L"status", L"--porcelain", L"-z"});
        auto running = std::make_shared<OperationContext>();
        auto observer = std::make_shared<CancelDuringCreation>();
        observer->context = running; observer->source = source;
        running->sink = observer;
        cancelled = false;
        { OperationBinding binding(running);
          try { PrepareBuildWorkspace(source / "Probe.xcodeproj", root / "mid-cancelled", "Debug"); }
          catch (const std::exception& e) { cancelled = std::string(e.what()).find("cancelled") != std::string::npos; }
        }
        Require(observer->observed && observer->pristine_during && cancelled,
                "cancellation during real Git index process did not preserve upstream");
        Require(!fs::exists(root / "mid-cancelled" / "sources" / "original"), "mid-cancelled view published");
        Require(status_before_cancel == Git(source, {L"status", L"--porcelain", L"-z"}),
                "mid-operation cancellation changed upstream status");
        fs::remove_all(root); // Freshly reserved owned fixture only.
        std::cout << "PASS: main workspace service derives project/consumer paths without modifying upstream\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << "\nEvidence: " << root.string() << '\n';
        return 1;
    }
}
