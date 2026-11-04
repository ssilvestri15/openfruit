#include "application_service.hpp"
#include "darwin_provider_acquisition.hpp"
#include "app_builder.hpp"
#include "build_workspace.hpp"
#include "cache_compression_manager.hpp"
#include "device_session.hpp"
#include "environment_manager.hpp"
#include "git_symlinks.hpp"
#include "packager_signer.hpp"
#include "package_engine.hpp"
#include "cocoapods_installer.hpp"
#include "project_selection_metadata.hpp"
#include "sdk_auto_selection.hpp"
#include "sdk_manager.hpp"
#include "sdk_usage.hpp"
#include "system_info.hpp"
#include "tool_paths.hpp"
#include "universal_project.hpp"
#include "win32_process.hpp"

#include <windows.h>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
bool HasUnresolvedBuildSetting(const std::wstring& value) {
    return value.find(L"$(") != std::wstring::npos || value.find(L"${") != std::wstring::npos;
}
template <typename T>
void AddUnique(std::vector<T>& values, const T& value) {
    if (std::find(values.begin(), values.end(), value) == values.end()) values.push_back(value);
}
std::wstring ConfigurationFor(const BuildRequest& request) {
    if (!request.project.configuration) return request.configuration;
    auto value = *request.project.configuration;
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return Win32Process::ToWide(lower == "debug" || lower == "release" ? lower : value);
}
int ExecuteBuild(const BuildRequest& request, const BuildContext& context, BuildResult& result) {
    Config config = context.configuration;
    const Secrets& secrets = context.credentials;
    const std::wstring repo_root = context.repository_root.wstring();
    auto journal = context.journal;
    std::unique_ptr<OperationBinding> journal_binding;
    const auto& abs_target = request.project.path;
    const auto target_path = Win32Process::ToNarrow(abs_target.wstring());
    auto selection_request = request.project;
    const std::string command = request.mode == BuildProductMode::UnsignedPackage ? "package" : "build";
    unsigned int jobs = request.jobs ? request.jobs :
        (config.default_jobs ? config.default_jobs : SystemInfo::GetOptimalThreadCount());
    std::wstring configuration = ConfigurationFor(request);
    const bool deploy = request.deploy;
    const auto& udid = request.device_udid;
    const bool sdk_override_explicit = request.sdk_path.has_value() || request.sdk_version.has_value();
    const bool cache_override_explicit = request.cache_path.has_value();
    const bool p12_override_explicit = request.p12_path.has_value();
    const bool provisioning_override_explicit = request.provisioning_profile_path.has_value();
    auto override_sdk = request.sdk_path.value_or(config.sdk_path);
    auto override_sdk_version = request.sdk_version.value_or(config.ios_sdk_version);
    const auto override_cache = request.cache_path.value_or(L"");
    const auto override_bundle_id = request.bundle_id.value_or(L"");
    const auto override_display_name = request.display_name.value_or(L"");
    auto override_p12 = request.p12_path.value_or(secrets.signing_p12_path);
    auto override_prov = request.provisioning_profile_path.value_or(secrets.signing_profile_path);
    const bool match_profile_bundle_id = request.match_profile_bundle_id;
    const bool pack_cache = request.pack_cache;
    if (request.sdk_version && !request.sdk_path) {
        auto found = config.ios_sdk_paths.find(override_sdk_version);
        auto slot = override_sdk_version;
        const auto dot = slot.find(L'.');
        if (found == config.ios_sdk_paths.end() && dot != std::wstring::npos) {
            slot.resize(dot);
            found = config.ios_sdk_paths.find(slot);
        }
        override_sdk = found != config.ios_sdk_paths.end() ? found->second :
            (ToolPaths::LocalHome() / "sdk" / "ios" / slot / "iPhoneOS.sdk").wstring();
    }
    if (command == "package" && (deploy || p12_override_explicit || provisioning_override_explicit)) {
        std::cerr << "OPENFRUIT: package produces an unsigned IPA; signing/deploy options require build or sign.\n";
        return 2;
    }
    // The current CLI applies this snapshot before dispatch. Direct application
    // callers need the same preparation before Git/workspace discovery too.
    // Its legacy process-global semantics are why this first service slice must
    // be hosted by the serialized operation queue.
    config.ApplyEnvironment();
    const auto project_stem = abs_target.stem().string();
    const auto user_state_dir = config.user_state_root.empty() ? ToolPaths::UserStateRoot() : fs::path(config.user_state_root);
    if (CacheCompressionManager::HasColdArchive(user_state_dir, project_stem) &&
        !CacheCompressionManager::IsProjectCacheActive(user_state_dir, project_stem)) {
        std::cout << "OPENFRUIT: Restoring cold cache archive for '" << project_stem << "' before build...\n";
        CacheCompressionManager::UnpackProjectCache(user_state_dir, project_stem);
    }
    // Project metadata must precede SDK acquisition. SDKROOT chooses the
    // platform; the deployment target is a lower compatibility bound, not
    // a requested Base SDK version.
    const auto original_root = FindBuildSourceRoot(abs_target);
    if (!InitializeMissingGitSubmodules(original_root)) return 1;
    // `pod install` precedes an Xcode build: a locked Podfile without a current
    // sandbox is installed into an owned view, which the build then reads.
    const auto pods_view = PrepareCocoaPodsView(abs_target, original_root, ToolPaths::UserStateRoot() / "w");
    const auto build_target = pods_view ? pods_view->target : abs_target;
    if (pods_view) selection_request.path = build_target;
    const auto workspace = [&]() {
        if (selection_request.scheme || selection_request.target) {
            std::string error;
            const auto selected = ProjectSelectionMetadata::Resolve(selection_request, &error);
            if (!selected) throw std::runtime_error("Project selection: " + error);
            return PrepareBuildWorkspace(selection_request, *selected,
                StableBuildWorkspacePath(ToolPaths::UserStateRoot() / "w", build_target,
                    selected->configuration), {}, true);
        }
        return PrepareBuildWorkspace(build_target,
            StableBuildWorkspacePath(ToolPaths::UserStateRoot() / "w", build_target,
                Win32Process::ToNarrow(configuration)),
            Win32Process::ToNarrow(configuration), {}, true);
    }();
    if (const auto operation = CurrentOperationContext()) {
        auto metadata = JsonValue::ObjectValue();
        metadata.Set("original_root", JsonValue::String(Win32Process::ToNarrow(workspace.original_root.wstring())));
        metadata.Set("source_view", JsonValue::String(Win32Process::ToNarrow(workspace.sources.root.wstring())));
        metadata.Set("workspace", JsonValue::String(Win32Process::ToNarrow(workspace.root.wstring())));
        metadata.Set("source_files_copied", JsonValue::Number(std::to_string(workspace.sync_stats.files_copied)));
        metadata.Set("source_files_reused", JsonValue::Number(std::to_string(workspace.sync_stats.files_reused)));
        metadata.Set("source_bytes_copied", JsonValue::Number(std::to_string(workspace.sync_stats.bytes_copied)));
        operation->Emit("build.workspace", std::move(metadata));
    }
    result.workspace = workspace.root;
    DiscoveredProject project = workspace.project;
    if (!project.is_valid) {
        std::cerr << "OPENFRUIT Error: no valid project in target directory: " << target_path << "\n";
        return 1;
    }
    if (project.selection_frozen) configuration = project.configuration;
    const bool aggregate_root = project.target_kind == XcodeTargetKind::Aggregate;
    const bool application_root = !aggregate_root && project.product_type == "com.apple.product-type.application";
    const bool supported_native_product = application_root ||
        project.product_type == "com.apple.product-type.framework" ||
        project.product_type == "com.apple.product-type.library.static" ||
        project.product_type == "com.apple.product-type.bundle" ||
        project.product_type.find("extension") != std::string::npos;
    if (!aggregate_root && !supported_native_product) {
        std::cerr << "OPENFRUIT: unsupported selected product type: " << project.product_type << '\n';
        return 2;
    }
    if (!application_root && (command == "package" || deploy || p12_override_explicit || provisioning_override_explicit)) {
        std::cerr << "OPENFRUIT: packaging, signing and deployment require an application root target.\n";
        return 2;
    }
    const std::wstring persisted_toolchain_path = config.toolchain_path;
    bool toolchain_auto_selected = false;
    if (!sdk_override_explicit) {
        const auto sdk_choice = SDKAutoSelection::Resolve(config, project.sdk_root,
            project.minimum_os_version, config.bootstrap_auto_install);
        if (!sdk_choice.succeeded) {
            std::cerr << "OPENFRUIT Fatal: " << sdk_choice.message << "\n";
            return 1;
        }
        override_sdk = sdk_choice.path;
        override_sdk_version = sdk_choice.version;
        if (sdk_choice.swift_compiler_version.empty()) {
            std::cerr << "OPENFRUIT Fatal: Apple's Xcode support metadata does not identify the Swift compiler for the selected iPhoneOS SDK.\n";
            return 1;
        }
        const fs::path matching_swift = EnvironmentManager::SelectSwiftToolchain(
            config, sdk_choice.swift_compiler_version,
            sdk_choice.compiler_metadata_from_sdk ? sdk_choice.path : std::wstring{},
            project.minimum_os_version);
        if (matching_swift.empty()) {
            std::cerr << "OPENFRUIT Fatal: no compatible validated Windows Swift "
                      << Win32Process::ToNarrow(sdk_choice.swift_compiler_version)
                      << " toolchain is installed for Xcode "
                      << Win32Process::ToNarrow(sdk_choice.xcode_version) << ".\n";
            return 1;
        }
        config.toolchain_path = matching_swift.wstring();
        SetEnvironmentVariableW(L"OPENFRUIT_SWIFT_BIN", config.toolchain_path.c_str());
        toolchain_auto_selected = true;
        std::cout << "OpenFruit: selected iPhoneOS Base SDK "
                  << Win32Process::ToNarrow(sdk_choice.version) << " for deployment target "
                  << Win32Process::ToNarrow(project.minimum_os_version) << ".\n";
        std::cout << "OpenFruit: selected Swift "
                  << Win32Process::ToNarrow(sdk_choice.swift_compiler_version)
                  << " toolchain for Xcode "
                  << Win32Process::ToNarrow(sdk_choice.xcode_version) << ".\n";
    }

    // Apply CLI-only dependency hints to a bootstrap view of the config.
    // CheckAndBootstrap may import/register managed dependencies, while the
    // user's persisted config remains authoritative for non-CLI values.
    if (!journal) {
        journal = EventJournal::Create(ToolPaths::UserStateRoot() / "diagnostics" / "build-events");
        auto binding_context = std::make_shared<OperationContext>(*journal->Context());
        if (const auto parent = CurrentOperationContext()) {
            binding_context->control = parent->control;
            binding_context->span_id = parent->span_id;
            if (!parent->build_id.empty()) binding_context->build_id = parent->build_id;
            if (parent->sink) binding_context->sink = std::make_shared<CompositeEventSink>(
                std::vector<std::shared_ptr<EventSink>>{journal->Context()->sink, parent->sink});
        }
        journal_binding = std::make_unique<OperationBinding>(binding_context);
    }
    if (journal) {
        std::cout << "OPENFRUIT structured events: " << journal->Directory().string() << '\n';
    }
    // Original SDK macros (for example SwiftUI's) run through the managed
    // provider of the selected SDK; acquire it on first use of that SDK.
    if (!override_sdk.empty() && config.bootstrap_auto_install) {
        const auto provider = EnsureDarwinMacroProvider(fs::path(override_sdk), ToolPaths::LocalHome(), std::cout);
        if (!provider.succeeded)
            std::cerr << "OPENFRUIT warning: the original Darwin macro provider is unavailable; original SDK macros "
                         "cannot expand: " << provider.message << "\n";
    }
    // Asset catalogs need the native asset compiler; a clean installation
    // builds it once from source in the same host environment as packages.
    if (config.bootstrap_auto_install) {
        const fs::path host_swift = config.toolchain_path.empty()
            ? ToolPaths::SwiftBin(fs::path(repo_root)) : fs::path(config.toolchain_path);
        const auto host_environment = PackageEngine::HostEnvironment(host_swift);
        if (!EnvironmentManager::EnsureAssetCompiler(fs::path(repo_root), &host_environment))
            std::cerr << "OPENFRUIT warning: the native asset catalog compiler is unavailable.\n";
    }
    auto operation_metadata = JsonValue::ObjectValue();
    operation_metadata.Set("project", JsonValue::String(Win32Process::ToNarrow(abs_target.wstring())));
    operation_metadata.Set("configuration", JsonValue::String(Win32Process::ToNarrow(configuration)));
    operation_metadata.Set("target_id", JsonValue::String(project.target_id));
    operation_metadata.Set("project_metadata", JsonValue::String(Win32Process::ToNarrow(project.pbxproj_path)));
    operation_metadata.Set("selection_frozen", JsonValue::Boolean(project.selection_frozen));
    operation_metadata.Set("scheme_sha256", JsonValue::String(project.selected_scheme_sha256));
    operation_metadata.Set("jobs", JsonValue::Number(std::to_string(jobs)));
    OperationSpan build_operation("build", std::move(operation_metadata));
    std::vector<std::string> planned_stages = {"environment", "project", "sdk", "dependencies", "targets", "compile"};
    if (application_root) planned_stages.push_back("package");
    if (deploy) planned_stages.push_back("deploy");
    StageProgress progress(std::move(planned_stages));
    progress.Started("environment");
    Config bootstrap_config = config;
    const std::wstring persisted_sdk_path = config.sdk_path;
    const std::wstring persisted_sdk_version = config.ios_sdk_version;
    const auto persisted_ios_sdk_paths = config.ios_sdk_paths;
    const std::wstring persisted_cache = config.cache_root;
    const std::wstring persisted_p12 = config.signing_p12_path;
    const std::wstring persisted_profile = config.signing_profile_path;
    if (sdk_override_explicit) bootstrap_config.sdk_path = override_sdk;
    if (cache_override_explicit) {
        bootstrap_config.cache_root = override_cache;
        SetEnvironmentVariableW(L"OPENFRUIT_CACHE_ROOT", override_cache.c_str());
    }
    if (p12_override_explicit) bootstrap_config.signing_p12_path = override_p12;
    if (provisioning_override_explicit) bootstrap_config.signing_profile_path = override_prov;

    const BootstrapResult bootstrap = EnvironmentManager::CheckAndBootstrap(
        fs::path(repo_root), bootstrap_config, config.bootstrap_auto_install, true);
    if (!bootstrap.build_ready) {
        std::cerr << "OPENFRUIT Fatal: build environment is incomplete. Run 'OPENFRUIT bootstrap' or configure the missing paths in ~/.OPENFRUIT/config.toml.\n";
        return 1;
    }
    progress.Completed("environment");

    // Adopt paths discovered/imported by bootstrap, but keep explicit CLI
    // overrides ephemeral for this invocation. CheckAndBootstrap persists its
    // managed discoveries, so restore CLI-owned fields and save once more.
    if (sdk_override_explicit) {
        bootstrap_config.sdk_path = persisted_sdk_path;
        bootstrap_config.ios_sdk_version = persisted_sdk_version;
        bootstrap_config.ios_sdk_paths = persisted_ios_sdk_paths;
    }
    if (cache_override_explicit) bootstrap_config.cache_root = persisted_cache;
    if (p12_override_explicit) bootstrap_config.signing_p12_path = persisted_p12;
    if (provisioning_override_explicit) bootstrap_config.signing_profile_path = persisted_profile;
    const std::wstring invocation_toolchain_path = bootstrap_config.toolchain_path;
    if (toolchain_auto_selected) bootstrap_config.toolchain_path = persisted_toolchain_path;
    if (sdk_override_explicit || cache_override_explicit ||
        p12_override_explicit || provisioning_override_explicit ||
        toolchain_auto_selected) {
        bootstrap_config.Save();
    }

    config = bootstrap_config;
    if (toolchain_auto_selected) config.toolchain_path = invocation_toolchain_path;

    // If bootstrap imported an existing SDK into the managed OPENFRUIT home,
    // preserve the previous SDK path for this invocation so PackageEngine
    // can derive the exact pre-v27 content-addressed SwiftPM key and reuse
    // that expensive scratch directory non-destructively.
    if (!sdk_override_explicit &&
        !persisted_sdk_path.empty() &&
        !config.sdk_path.empty() &&
        fs::path(persisted_sdk_path).lexically_normal() != fs::path(config.sdk_path).lexically_normal()) {
        SetEnvironmentVariableW(L"OPENFRUIT_LEGACY_SDK_PATH", persisted_sdk_path.c_str());
    }

    if (!sdk_override_explicit) override_sdk = config.sdk_path;
    if (!p12_override_explicit && !config.signing_p12_path.empty()) override_p12 = config.signing_p12_path;
    if (!provisioning_override_explicit && !config.signing_profile_path.empty()) override_prov = config.signing_profile_path;
    config.ApplyEnvironment();
    if (cache_override_explicit) {
        SetEnvironmentVariableW(L"OPENFRUIT_CACHE_ROOT", override_cache.c_str());
    }

    std::cout << "OpenFruit: Analyzing target: " << target_path << "\n";
    std::cout << "OpenFruit: Parallel execution: " << jobs << " hardware threads.\n";

    // Auto-discover any iOS project or directory
    progress.Started("project");
    if (!override_bundle_id.empty()) {
        project.bundle_id = override_bundle_id;
    } else if (application_root && (project.bundle_id.empty() ||
               HasUnresolvedBuildSetting(project.bundle_id))) {
        if (config.default_bundle_id.empty() ||
            HasUnresolvedBuildSetting(config.default_bundle_id)) {
            std::cerr
                << "OPENFRUIT Error: PRODUCT_BUNDLE_IDENTIFIER is missing or "
                   "contains unresolved build settings. Configure "
                   "build.default_bundle_id or pass --bundle-id.\n";
            return 1;
        }

        std::cout
            << "OpenFruit: unresolved project bundle identifier; using "
               "configured build.default_bundle_id.\n";
        project.bundle_id = config.default_bundle_id;
    }

    std::cout << "Target Project: " << Win32Process::ToNarrow(project.project_name) << "\n"
              << "  Source Files:       " << project.swift_sources.size() << " Swift files\n"
              << "  Bundle Identifier:  " << Win32Process::ToNarrow(project.bundle_id) << "\n"
              << "  Deployment Target:  iOS " << Win32Process::ToNarrow(project.minimum_os_version) << "\n";

    // 1. Discover or use specified SDK
    progress.Completed("project");
    progress.Started("sdk");
    const fs::path selected_sdk = override_sdk.empty()
        ? ToolPaths::IosSdk(fs::path(repo_root)) : fs::path(override_sdk);
    SDKUsage sdk_usage(selected_sdk);
    if (!sdk_usage.Held()) {
        std::cerr << "OPENFRUIT Fatal: unable to hold the selected SDK directory (Windows error "
                  << sdk_usage.NativeError() << ").\n";
        return 1;
    }
    std::string sdk_inspection_error;
    const SDKInfo sdk_info = SDKManager::InspectSelectedSDK(
        selected_sdk, project.minimum_os_version, &sdk_inspection_error);

    if (!sdk_info.is_valid) {
        std::cerr << "OPENFRUIT Fatal: " << sdk_inspection_error
                  << " Use 'OPENFRUIT sdk download' or '--sdk-path'.\n";
        return 1;
    }
    std::string linker_validation_error;
    if (!EnvironmentManager::EnsureCompatibleLlvm(config, fs::path(sdk_info.sdk_path),
            sdk_info.deployment_version, L"arm64", true, linker_validation_error)) {
        std::cerr << "OPENFRUIT Fatal: " << linker_validation_error << "\n";
        return 1;
    }
    // Persist only the managed linker discovery, preserving invocation-only
    // SDK and compiler choices restored above.
    bootstrap_config.llvm_path = config.llvm_path;
    if (!bootstrap_config.Save()) {
        std::cerr << "OPENFRUIT: validated LLVM selection is active for this invocation; configuration persistence failed.\n";
    }
    progress.Completed("sdk");
    auto dimensions = JsonValue::ObjectValue();
    dimensions.Set("target", JsonValue::String(Win32Process::ToNarrow(sdk_info.target_triple)));
    dimensions.Set("sdk", JsonValue::String(Win32Process::ToNarrow(sdk_info.sdk_path)));
    dimensions.Set("deployment_target", JsonValue::String(Win32Process::ToNarrow(sdk_info.deployment_version)));
    dimensions.Set("swift_toolchain", JsonValue::String(Win32Process::ToNarrow(config.toolchain_path)));
    dimensions.Set("configuration", JsonValue::String(Win32Process::ToNarrow(configuration)));
    build_operation.Context()->Emit("build.dimensions", std::move(dimensions));
    progress.Started("dependencies");

    // All paths/settings came from independent sources. Products,
    // dependency manifests and intermediates use the separate workspace
    // root; the original checkout is never materialized or restored.
    const std::wstring build_repo_root = workspace.root.wstring();

    // 2. Build Dependencies if present
    std::string xcframework_error;
    if (!UniversalProject::ResolveXcframeworkSlices(
            project, sdk_info.target_triple, xcframework_error)) {
        std::cerr << "OPENFRUIT v4: XCFramework selection failed: "
                  << xcframework_error << "\n";
        return 1;
    }

    // Validate every reachable Xcode target before compiling any packages.
    if (!project.target_dependencies.empty()) {
        OperationSpan target_preflight("build.target_graph.validate");
        const bool valid = AppBuilder::ValidateTargetDependencies(project, sdk_info, configuration);
        target_preflight.Complete(JsonValue::ObjectValue(), valid);
        if (!valid) return 1;
    }

    PackageBuildResult pkg_res;
    if (!project.project_dir.empty()) {
        fs::path proj_p(project.project_dir);
        bool has_pbx = fs::exists(proj_p / "project.pbxproj") || !project.pbxproj_path.empty();
        bool has_pkg = fs::exists(proj_p / "Package.swift") || !project.package_swift_path.empty();

        if (has_pbx) {
            std::cout << "OPENFRUIT v4: Resolving Xcode package graph natively...\n";
            const XcodeDependencyOptions options{!project.selection_frozen,
                project.build_implicit_dependencies.value_or(true), project.selection_frozen};
            pkg_res = PackageEngine::BuildXcodePackages(build_repo_root,
                project.pbxproj_path.empty() ? project.project_dir : project.pbxproj_path, sdk_info, configuration,
                jobs, &workspace.sources, project.target_id, &options);
        } else if (has_pkg) {
            std::cout << "OPENFRUIT v4: Resolving SwiftPM package graph natively...\n";
            pkg_res = PackageEngine::BuildSwiftPMPackage(build_repo_root, project.project_dir, sdk_info, configuration, jobs);
        }

        if (!pkg_res.success) {
            std::cerr
                << "OPENFRUIT v4: dependency graph failed; application compilation will not start.\n";
            return 1;
        }
    } else {
        pkg_res.success = true;
    }

    // Generated source guards keep this view pinned through every consumer
    // and restore their outputs before releasing the source workspace lease.
    if (workspace.lease) pkg_res.artifact_leases.push_back(workspace.lease);

    // 2b. Build Xcode target dependencies (subprojects, frameworks, static libraries)
    progress.Completed("dependencies");
    progress.Started("targets");
    if (!project.target_dependencies.empty()) {
        std::cout << "\nOPENFRUIT v4: Building Xcode target dependencies ("
                  << project.target_dependencies.size() << ")...\n" << std::flush;
        if (!AppBuilder::BuildTargetDependencies(build_repo_root, project, sdk_info, configuration, jobs, pkg_res)) {
            std::cerr << "OPENFRUIT v4: Failed to build Xcode target dependencies.\n";
            return 1;
        }
    }

    // 3. Compile & Link Target
    progress.Completed("targets");
    progress.Started("compile");
    std::cout << "\nOPENFRUIT v4: Building application target...\n";
    AppBuildSpec spec = UniversalProject::ToAppBuildSpec(project, jobs);
    spec.preview_agent = request.preview;
    if (project.selection_frozen)
        spec.intermediates_namespace = (project.build_products_root / "Intermediates").wstring();
    spec.jobs = jobs;
    spec.configuration = configuration;

    const fs::path products_root =
        (project.build_products_root.empty() ? workspace.root / "build" / "Products" : project.build_products_root)
            / Win32Process::ToNarrow(configuration);
    spec.products_dir = products_root.wstring();
    AddUnique(spec.embedded_framework_dirs, products_root.wstring());
    AddUnique(spec.swift_include_paths, products_root.wstring());

    AppBuildResult build_res = AppBuilder::Build(build_repo_root, spec, sdk_info, pkg_res);
    result.product_path = build_res.product_path;
    if (!build_res.success) {
        std::cerr << "OpenFruit: Build failed.\n";
        return 1;
    }

    // 4. Package & Sign
    progress.Completed("compile");
    if (!application_root) {
        auto artifacts = JsonValue::ObjectValue();
        artifacts.Set("target_id", JsonValue::String(project.target_id));
        artifacts.Set("product_kind", JsonValue::String(aggregate_root ? "aggregate" : project.product_type));
        artifacts.Set("product_path", JsonValue::String(Win32Process::ToNarrow(build_res.product_path)));
        build_operation.Complete(std::move(artifacts), true);
        progress.Finished(true);
        if (journal) journal->Flush();
        if (aggregate_root) std::cout << "OPENFRUIT: aggregate build completed.\n";
        else std::cout << "OPENFRUIT: Target product: " << Win32Process::ToNarrow(build_res.product_path) << '\n';
        return 0;
    }
    progress.Started("package");
    PackagingSpec pack_spec = UniversalProject::ToPackagingSpec(project);
    if (!override_bundle_id.empty()) {
        pack_spec.bundle_id = override_bundle_id;
    }
    pack_spec.match_profile_bundle_id = match_profile_bundle_id;
    if (!override_display_name.empty()) {
        pack_spec.display_name = override_display_name;
    }
    pack_spec.p12_path = override_p12;
    pack_spec.provisioning_profile_path = override_prov;
    if (secrets.signing_password.rfind(L"DPAPI:", 0) == 0) {
        pack_spec.dpapi_password_path = secrets.signing_password.substr(6);
    } else if (!config.signing_password_dpapi_path.empty()) {
        pack_spec.dpapi_password_path = config.signing_password_dpapi_path;
    }

    PackagerSigner::ApplyDependencyProducts(pack_spec, pkg_res);

    PackagingResult pack_res = command == "package"
        ? PackagerSigner::PackageUnsigned(build_repo_root, build_res, pack_spec)
        : PackagerSigner::PackageAndSign(build_repo_root, build_res, pack_spec);
    result.unsigned_ipa = pack_res.unsigned_ipa_path;
    result.signed_ipa = pack_res.signed_ipa_path;
    if (!pack_res.success) {
        std::cerr << "OpenFruit: Packaging or signing failed.\n";
        return 1;
    }

    // 5. Deploy if requested
    progress.Completed("package");
    if (deploy) {
        progress.Started("deploy");
        std::cout << "OpenFruit: Deploying to iOS device...\n";
        // Native usbmux/lockdown install (installation_proxy over AFC), the
        // same path as `openfruit device install`.
        DeviceTarget target;
        target.mode = DeviceTransportMode::Usb;
        target.udid = Win32Process::ToNarrow(udid);
        DeviceSession session(target);
        std::string deploy_error;
        const auto context = CurrentOperationContext();
        int reported = -1;
        const bool deployed = session.Connect(deploy_error) && session.DeployIpa(
            Win32Process::ToNarrow(pack_res.signed_ipa_path),
            [&](int percent, const std::string& status) {
                if (percent == reported) return;
                reported = percent;
                std::cout << "OpenFruit: Installing [" << percent << "%] " << status << '\n';
                if (context) {
                    auto data = JsonValue::ObjectValue();
                    data.Set("basis", JsonValue::String("percent"));
                    data.Set("completed", JsonValue::Number(std::to_string(percent)));
                    data.Set("planned", JsonValue::Number("100"));
                    data.Set("status", JsonValue::String(status));
                    context->Emit("deploy.progress", std::move(data));
                }
            },
            deploy_error);
        if (!deployed) {
            std::cerr << "OpenFruit: Device deployment failed: " << deploy_error << "\n";
            return 1;
        }
        std::cout << "OpenFruit: Application successfully installed on device!\n";
        progress.Completed("deploy");
    }

    auto artifacts = JsonValue::ObjectValue();
    artifacts.Set("signed_ipa", JsonValue::String(Win32Process::ToNarrow(pack_res.signed_ipa_path)));
    artifacts.Set("unsigned_ipa", JsonValue::String(Win32Process::ToNarrow(pack_res.unsigned_ipa_path)));
    artifacts.Set("bundle_id", JsonValue::String(Win32Process::ToNarrow(pack_res.bundle_id)));
    artifacts.Set("deployed", JsonValue::Boolean(deploy));
    build_operation.Complete(std::move(artifacts), true);
    progress.Finished(true);
    if (journal) {
        journal->Flush();
        if (journal->HasErrors()) std::cerr << "OpenFruit: structured event journal is incomplete; inspect logging status.\n";
    }

    std::cout << "\n=========================================================\n"
              << "  BUILD SUCCESSFUL\n"
              << (command == "package" ? "  Unsigned IPA: " : "  Signed IPA: ")
              << Win32Process::ToNarrow(command == "package" ? pack_res.unsigned_ipa_path : pack_res.signed_ipa_path) << "\n"
              << "=========================================================\n";
    if (pack_cache) {
        std::cout << "OPENFRUIT: Packing cache archive for '" << project_stem << "' (--pack-cache)...\n";
        CacheCompressionManager::PackProjectCache(user_state_dir, project_stem);
    }
    return 0;

}
const char* OutcomeName(BuildOutcome outcome) {
    switch (outcome) {
    case BuildOutcome::Succeeded: return "succeeded";
    case BuildOutcome::Cancelled: return "cancelled";
    case BuildOutcome::TimedOut: return "timed_out";
    case BuildOutcome::InvalidRequest: return "invalid_request";
    default: return "failed";
    }
}
} // namespace

JsonValue BuildResult::ToJson() const {
    auto value = JsonValue::ObjectValue();
    value.Set("schema", JsonValue::String("openfruit.build-result.v1"));
    value.Set("state", JsonValue::String(OutcomeName(outcome)));
    value.Set("exit_code", JsonValue::Number(std::to_string(exit_code)));
    value.Set("diagnostic_code", JsonValue::String(diagnostic_code));
    if (!workspace.empty()) value.Set("workspace", JsonValue::String(Win32Process::ToNarrow(workspace.wstring())));
    if (!product_path.empty()) value.Set("product_path", JsonValue::String(Win32Process::ToNarrow(product_path.wstring())));
    if (!unsigned_ipa.empty()) value.Set("unsigned_ipa", JsonValue::String(Win32Process::ToNarrow(unsigned_ipa.wstring())));
    if (!signed_ipa.empty()) value.Set("signed_ipa", JsonValue::String(Win32Process::ToNarrow(signed_ipa.wstring())));
    return value;
}

BuildResult ApplicationService::Build(const BuildRequest& request, const BuildContext& context) {
    BuildResult result;
    auto operation = context.operation ? context.operation :
        context.journal ? context.journal->Context() : CurrentOperationContext();
    if (!operation) operation = std::make_shared<OperationContext>();
    OperationBinding binding(operation);
    if (operation->CancellationRequested()) {
        result.outcome = BuildOutcome::Cancelled;
        result.exit_code = 130;
        result.diagnostic_code = "operation.cancelled";
        return result;
    }
    if (operation->DeadlineExceeded()) {
        result.outcome = BuildOutcome::TimedOut;
        result.exit_code = 124;
        result.diagnostic_code = "operation.deadline_exceeded";
        return result;
    }
    if ((request.mode != BuildProductMode::BuildAndSign && request.mode != BuildProductMode::UnsignedPackage) ||
        request.project.path.empty() || !request.project.path.is_absolute() ||
        ConfigurationFor(request).empty() ||
        (request.sdk_path && (request.sdk_path->empty() || !fs::path(*request.sdk_path).is_absolute())) ||
        (request.cache_path && (request.cache_path->empty() || !fs::path(*request.cache_path).is_absolute())) ||
        (!request.project.scheme && request.project.action != ProjectBuildAction::Running &&
            request.project.action != ProjectBuildAction::LegacyProductBuild) ||
        (request.mode == BuildProductMode::UnsignedPackage &&
            (request.deploy || request.p12_path.has_value() || request.provisioning_profile_path.has_value()))) {
        result.outcome = BuildOutcome::InvalidRequest;
        result.exit_code = 2;
        result.diagnostic_code = "build.invalid_request";
        return result;
    }
    result.exit_code = ExecuteBuild(request, context, result);
    if (operation->CancellationRequested()) {
        result.outcome = BuildOutcome::Cancelled;
        result.exit_code = 130;
        result.diagnostic_code = "operation.cancelled";
    } else if (operation->DeadlineExceeded()) {
        result.outcome = BuildOutcome::TimedOut;
        result.exit_code = 124;
        result.diagnostic_code = "operation.deadline_exceeded";
    } else {
        result.outcome = result.exit_code == 0 ? BuildOutcome::Succeeded :
            result.exit_code == 2 ? BuildOutcome::InvalidRequest : BuildOutcome::Failed;
        result.diagnostic_code = result.exit_code == 0 ? "" :
            result.exit_code == 2 ? "build.invalid_request" : "build.failed";
    }
    return result;
}
} // namespace OpenFruit
