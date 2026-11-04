#include "preview_agent.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "preview_agent_source.hpp"

#include <windows.h>

#include <chrono>
#include <iostream>
#include <string_view>

namespace fs = std::filesystem;

namespace OpenFruit {

const std::vector<std::wstring>& PreviewAgentFrameworks() {
    static const std::vector<std::wstring> frameworks = {
        L"UIKit", L"QuartzCore", L"VideoToolbox", L"CoreMedia", L"CoreVideo", L"CoreGraphics", L"CoreFoundation", L"Foundation"
    };
    return frameworks;
}

fs::path EnsurePreviewAgentObject(const fs::path& repo_root, const fs::path& compiler, const SDKInfo& sdk_info) {
    const std::string_view source_text(kPreviewAgentSource);
    const auto source_digest = Sha256(std::string(source_text));
    const auto compiler_digest = Sha256File(compiler);
    if (!source_digest || !compiler_digest) return {};
    auto inputs = JsonValue::ObjectValue();
    inputs.Set("schema", JsonValue::String("openfruit.preview-agent.v1"));
    inputs.Set("source_sha256", JsonValue::String(*source_digest));
    inputs.Set("compiler_sha256", JsonValue::String(*compiler_digest));
    inputs.Set("target", JsonValue::String(Win32Process::ToNarrow(sdk_info.target_triple)));
    inputs.Set("sdk", JsonValue::String(Win32Process::ToNarrow(sdk_info.sdk_path)));
    std::error_code ec;
    const auto settings = fs::path(sdk_info.sdk_path) / "SDKSettings.json";
    if (fs::is_regular_file(settings, ec)) {
        const auto settings_digest = Sha256File(settings);
        if (!settings_digest) return {};
        inputs.Set("sdk_settings_sha256", JsonValue::String(*settings_digest));
    }
    if (!sdk_info.vfs_overlay_path.empty()) {
        const auto overlay_digest = Sha256File(fs::path(sdk_info.vfs_overlay_path));
        if (!overlay_digest) return {};
        inputs.Set("overlay_sha256", JsonValue::String(*overlay_digest));
    }
    const auto identity = Sha256(inputs.Serialize());
    if (!identity) return {};

    const auto directory = ToolPaths::CacheRoot() / "preview-agent" / "v1" / *identity;
    const auto object = directory / "OpenFruitPreviewAgent.o";
    if (fs::is_regular_file(object, ec) && fs::file_size(object, ec) > 0) return object;
    fs::create_directories(directory, ec);
    if (ec) return {};

    const auto staging = directory / ("stage-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
    fs::create_directory(staging, ec);
    if (ec) return {};
    struct Cleanup { fs::path path; ~Cleanup() { std::error_code ignored; fs::remove_all(path, ignored); } } cleanup{staging};
    const auto source = staging / "OpenFruitPreviewAgent.m";
    const auto output = staging / "OpenFruitPreviewAgent.o";
    if (!AtomicFile::Publish(source, std::string(source_text))) return {};

    std::vector<std::wstring> args = {
        compiler.wstring(), L"-target", sdk_info.target_triple, L"-isysroot", sdk_info.sdk_path,
        L"-x", L"objective-c", L"-fobjc-arc", L"-fPIC", L"-O2", L"-fvisibility=hidden",
        L"-Wno-unused-command-line-argument", L"-c", source.wstring(), L"-o", output.wstring()
    };
    if (!sdk_info.vfs_overlay_path.empty()) {
        args.push_back(L"-ivfsoverlay");
        args.push_back(sdk_info.vfs_overlay_path);
    }
    ProcessRunOptions options;
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    const auto build = Win32Process::Run(compiler.wstring(), args, repo_root.wstring(), {}, nullptr, nullptr, options);
    if (!build.success || !fs::is_regular_file(output, ec)) {
        std::cerr << "OPENFRUIT: preview agent compilation failed:\n" << build.std_out << build.std_err << std::endl;
        return {};
    }
    if (!MoveFileExW(output.c_str(), object.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return {};
    std::cout << "OPENFRUIT: preview agent built: " << object.string() << std::endl;
    return object;
}

} // namespace OpenFruit
