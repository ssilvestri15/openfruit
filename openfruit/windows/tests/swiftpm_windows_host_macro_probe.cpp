#include "compiler_proxy.hpp"
#include "package_engine.hpp"
#include "sdk_manager.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

bool IsWindowsHostMacro(const fs::path& executable) {
    const fs::path configuration = executable.parent_path();
    const fs::path host_root = configuration.parent_path();
    const std::string name = host_root.filename().string();
    return name.rfind("x86_64-unknown-windows-msvc", 0) == 0 &&
           executable.extension() == ".exe";
}

std::wstring HostPath(const fs::path& repo_root) {
    const std::wstring toolchain =
        OpenFruit::ToolPaths::SwiftBin(repo_root).wstring();
    const DWORD required = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    if (required == 0) {
        return toolchain;
    }

    std::wstring inherited(required, L'\0');
    const DWORD copied = GetEnvironmentVariableW(
        L"PATH", inherited.data(), required);
    if (copied == 0 || copied >= required) {
        return toolchain;
    }
    inherited.resize(copied);
    return toolchain + L";" + inherited;
}

} // namespace

int main(int argc, char** argv) {
    if (OpenFruit::CompilerProxy::IsActive()) {
        return OpenFruit::CompilerProxy::Run(argc, argv);
    }

    if (argc != 3) {
        std::cerr << "usage: swiftpm_windows_host_macro_probe "
                     "<OPENFRUIT-repo-root> <package-path>\n";
        return 2;
    }

    const fs::path repo_root =
        fs::absolute(fs::path(argv[1])).lexically_normal();
    const fs::path package =
        fs::absolute(fs::path(argv[2])).lexically_normal();

    const OpenFruit::SDKInfo sdk = OpenFruit::SDKManager::DiscoverSDK(
        repo_root.wstring(), L"18.6");
    if (!sdk.is_valid) {
        std::cerr << "SDK discovery failed\n";
        return 3;
    }

    const OpenFruit::PackageBuildResult result =
        OpenFruit::PackageEngine::BuildSwiftPMPackage(
            repo_root.wstring(), package.wstring(), sdk, L"release", 2);
    if (!result.success) {
        std::cerr << "Windows-host macro package build failed\n";
        return 5;
    }

    if (result.macro_plugins.size() != 1) {
        std::cerr << "expected exactly one published macro plugin, got "
                  << result.macro_plugins.size() << "\n";
        return 6;
    }

    const std::wstring publication = result.macro_plugins.front();
    const std::size_t separator = publication.rfind(L'#');
    if (separator == std::wstring::npos || separator == 0 ||
        separator + 1 >= publication.size()) {
        std::cerr << "invalid macro plugin publication\n";
        return 7;
    }

    const fs::path executable(publication.substr(0, separator));
    const std::wstring module = publication.substr(separator + 1);
    if (!fs::is_regular_file(executable) ||
        !IsWindowsHostMacro(executable)) {
        std::cerr << "published macro is not a Windows host executable\n";
        return 8;
    }

    const OpenFruit::ProcessResult launch = OpenFruit::Win32Process::Run(
        executable.wstring(),
        { executable.wstring() },
        executable.parent_path().wstring(),
        { { L"PATH", HostPath(repo_root) } });
    if (!launch.success) {
        std::cerr << "macro executable launch failed\n"
                  << launch.std_err;
        return 9;
    }

    bool consumer_module_found = false;
    for (const std::wstring& directory : result.module_include_dirs) {
        if (fs::is_regular_file(
                fs::path(directory) /
                "WindowsHostMacroConsumer.swiftmodule")) {
            consumer_module_found = true;
            break;
        }
    }
    if (!consumer_module_found) {
        std::cerr << "iOS consumer module was not emitted\n";
        return 10;
    }

    std::wcout << L"WINDOWS_HOST_MACRO_EXECUTABLE="
               << executable.wstring() << L"\n";
    std::wcout << L"WINDOWS_HOST_MACRO_MODULE=" << module << L"\n";
    std::cout << "WINDOWS_HOST_MACRO_BUILD=pass\n";
    std::cout << "WINDOWS_HOST_MACRO_LAUNCH=pass\n";
    std::cout << "SWIFT_PLUGIN_PROTOCOL=pass\n";
    std::cout << "IOS_MACRO_CONSUMER=pass\n";
    return 0;
}
