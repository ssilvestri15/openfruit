#include "compiler_proxy.hpp"
#include "package_engine.hpp"
#include "sdk_manager.hpp"
#include "tool_paths.hpp"
#include "artifact_store.hpp"
#include "sdk_target_runtime.hpp"
#include "sdk_auto_selection.hpp"
#include "environment_manager.hpp"
#include "config.hpp"
#include "operation_events.hpp"
#include "build_workspace.hpp"
#include "app_builder.hpp"
#include "sdk_usage.hpp"
#include "json_value.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

namespace {

std::string ReadText(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

} // namespace

int main(int argc, char** argv) {
    if (OpenFruit::CompilerProxy::IsActive()) {
        return OpenFruit::CompilerProxy::Run(argc, argv);
    }

    const bool runtime_lifetime = argc == 4 && std::string(argv[3]) == "--runtime-lifetime";
    const bool target_graph_only = argc == 5 && std::string(argv[3]) == "--target-graph-only";
    if (argc != 3 && !runtime_lifetime && !target_graph_only) {
        std::cerr << "usage: swiftpm_host_sdk_probe "
                     "<OPENFRUIT-repo-root> <package-or-project-path> "
                     "[--runtime-lifetime | --target-graph-only <configuration>]\n";
        return 2;
    }

    const fs::path repo_root =
        fs::absolute(fs::path(argv[1])).lexically_normal();
    const fs::path package =
        fs::absolute(fs::path(argv[2])).lexically_normal();

    // Exercise the production workspace and shared target planner without
    // compiling packages or requiring a working compiler for metadata analysis.
    if (target_graph_only) {
        auto proof = OpenFruit::JsonValue::ObjectValue();
        proof.Set("schema", OpenFruit::JsonValue::String("openfruit.target-graph-probe.v1"));
        proof.Set("configuration", OpenFruit::JsonValue::String(argv[4]));
        bool valid = false;
        try {
            const std::string configuration = argv[4];
            auto config = OpenFruit::Config::Load(L"", false);
            auto workspace = OpenFruit::PrepareBuildWorkspace(package,
                OpenFruit::StableBuildWorkspacePath(
                    OpenFruit::ToolPaths::UserStateRoot() / "w", package, configuration),
                configuration, {}, true);
            proof.Set("workspace", OpenFruit::JsonValue::String(workspace.root.string()));
            proof.Set("target_id", OpenFruit::JsonValue::String(workspace.project.target_id));
            proof.Set("files_copied", OpenFruit::JsonValue::Number(std::to_string(workspace.sync_stats.files_copied)));
            proof.Set("files_reused", OpenFruit::JsonValue::Number(std::to_string(workspace.sync_stats.files_reused)));
            proof.Set("bytes_copied", OpenFruit::JsonValue::Number(std::to_string(workspace.sync_stats.bytes_copied)));
            const auto selected = OpenFruit::SDKAutoSelection::Resolve(config,
                workspace.project.sdk_root, workspace.project.minimum_os_version, false);
            if (!selected.succeeded) throw std::runtime_error(selected.message);
            OpenFruit::SDKUsage sdk_usage(selected.path);
            if (!sdk_usage.Held()) throw std::runtime_error("Cannot hold the selected SDK directory");
            config.ApplyEnvironment();
            const auto sdk = OpenFruit::SDKManager::DiscoverSDK(
                repo_root.wstring(), workspace.project.minimum_os_version);
            if (!sdk.is_valid || fs::canonical(sdk.sdk_path) != fs::canonical(selected.path))
                throw std::runtime_error("SDK discovery did not preserve automatic SDK selection");
            proof.Set("sdk", OpenFruit::JsonValue::String(OpenFruit::Win32Process::ToNarrow(sdk.sdk_path)));
            proof.Set("target_triple", OpenFruit::JsonValue::String(OpenFruit::Win32Process::ToNarrow(sdk.target_triple)));
            std::string selection_error;
            if (!OpenFruit::UniversalProject::ResolveXcframeworkSlices(
                    workspace.project, sdk.target_triple, selection_error))
                throw std::runtime_error(selection_error);
            valid = OpenFruit::AppBuilder::ValidateTargetDependencies(
                workspace.project, sdk, OpenFruit::Win32Process::ToWide(configuration));
        } catch (const std::exception& failure) {
            proof.Set("error", OpenFruit::JsonValue::String(failure.what()));
        }
        proof.Set("valid", OpenFruit::JsonValue::Boolean(valid));
        proof.Set("compilation_requested", OpenFruit::JsonValue::Boolean(false));
        std::cout << "TARGET_GRAPH_PROBE=" << proof.Serialize() << '\n';
        return valid ? 0 : 12;
    }

    if (runtime_lifetime) {
        auto config = OpenFruit::Config::Load();
        const auto selected = OpenFruit::SDKAutoSelection::Resolve(config, L"iphoneos", L"18.0", false);
        if (!selected.succeeded) { std::cerr << selected.message << '\n'; return 3; }
        const auto compiler = OpenFruit::EnvironmentManager::SelectSwiftToolchain(config,
            selected.swift_compiler_version, selected.compiler_metadata_from_sdk ? selected.path : std::wstring{}, L"18.0");
        if (compiler.empty()) { std::cerr << "Compatible original compiler unavailable\n"; return 3; }
        config.toolchain_path = compiler.wstring();
        config.ApplyEnvironment();
    }
    const OpenFruit::SDKInfo sdk = OpenFruit::SDKManager::DiscoverSDK(
        repo_root.wstring(), runtime_lifetime ? L"18.0" : L"18.6");
    if (!sdk.is_valid) {
        std::cerr << "SDK discovery failed\n";
        return 3;
    }

    std::optional<OpenFruit::BuildWorkspace> workspace;
    if (runtime_lifetime && package.extension() == ".xcodeproj") {
        workspace = OpenFruit::PrepareBuildWorkspace(package,
            OpenFruit::StableBuildWorkspacePath(OpenFruit::ToolPaths::UserStateRoot() / "w", package, "release"),
            "release", {}, true);
    }
    OpenFruit::PackageBuildResult result =
        runtime_lifetime && package.extension() == ".xcodeproj"
        ? OpenFruit::PackageEngine::BuildXcodePackages(
            workspace->root.wstring(), workspace->project.project_dir, sdk, L"release", 2, &workspace->sources)
        : OpenFruit::PackageEngine::BuildSwiftPMPackage(
            repo_root.wstring(), package.wstring(), sdk, L"release", 2);
    if (!result.success) {
        std::cerr << (runtime_lifetime ? "runtime lifetime package build failed\n" : "legacy manifest package build failed\n");
        return 5;
    }

    if (runtime_lifetime) {
        auto context = std::make_shared<OpenFruit::OperationContext>();
        context->control = std::make_shared<OpenFruit::OperationControl>(
            std::chrono::steady_clock::now() + std::chrono::seconds(10));
        OpenFruit::OperationBinding binding(context);
        auto runtime = OpenFruit::EnsureIosTargetRuntime(sdk.sdk_path,
            OpenFruit::ToolPaths::LlvmBin(repo_root), OpenFruit::Win32Process::ToNarrow(sdk.deployment_version),
            OpenFruit::ToolPaths::LocalHome());
        if (!runtime.available || !runtime.artifact_lease || runtime.library_directories.size() != 1) return 8;
        const auto publication = runtime.library_directories.front().parent_path();
        runtime = {};
        if (OpenFruit::ArtifactLease::TryAcquire(publication)) {
            std::cerr << "Package result lost the runtime consumer lease after artifact discovery\n"; return 9;
        }
        auto copied = result;
        result = {};
        if (OpenFruit::ArtifactLease::TryAcquire(publication)) return 10;
        copied = {};
        if (!OpenFruit::ArtifactLease::TryAcquire(publication)) return 11;
        std::cout << "PACKAGE_RUNTIME_LIFETIME=pass\nRUNTIME_PUBLICATION=" << publication.string() << '\n';
        return 0;
    }

    fs::path projected_module_map;
    const fs::path projection_root =
        OpenFruit::ToolPaths::CacheRoot() / "host-sdk-projections";
    std::error_code ec;
    for (fs::recursive_directory_iterator it(
             projection_root,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (it->is_regular_file(ec) && !ec &&
            it->path().filename() == "ucrt.modulemap") {
            projected_module_map = it->path();
            break;
        }
        ec.clear();
    }

    if (projected_module_map.empty()) {
        std::cerr << "host SDK projection was not published\n";
        return 6;
    }

    const std::string projected = ReadText(projected_module_map);
    const bool submodule_disabled =
        projected.find("module stdnoreturn {") == std::string::npos &&
        projected.find(
            "module stdnoreturn disabled for the installed UCRT") !=
            std::string::npos;

    std::cout << "PROJECTED_UCRT_MODULEMAP="
              << projected_module_map.string() << "\n";
    std::cout << "STDNORETURN_SUBMODULE_DISABLED="
              << (submodule_disabled ? 1 : 0) << "\n";
    if (!submodule_disabled) {
        std::cerr << "projected host SDK retained the absent UCRT submodule\n";
        return 7;
    }

    std::cout << "LEGACY_MANIFEST_BUILD=pass\n";
    return 0;
}
