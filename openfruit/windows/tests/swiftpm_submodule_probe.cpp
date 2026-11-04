#include "compiler_proxy.hpp"
#include "package_engine.hpp"
#include "sdk_manager.hpp"
#include "tool_paths.hpp"

#include <windows.h>

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace {

bool LongPathRegularFile(const fs::path& input) {
    std::wstring value = fs::absolute(input).lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\", 0) != 0) {
        value = L"\\\\?\\" + value;
    }
    const DWORD attributes = GetFileAttributesW(value.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

} // namespace

int main(int argc, char** argv) {
    if (OpenFruit::CompilerProxy::IsActive()) {
        return OpenFruit::CompilerProxy::Run(argc, argv);
    }

    if (argc != 3) {
        std::cerr << "usage: swiftpm_submodule_probe "
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
    std::cout << "PACKAGE_RESULT_SUCCESS=" << (result.success ? 1 : 0) << "\n";

    fs::path payload;
    const auto find_payload = [&](const fs::path& scratch) {
        const fs::path candidate =
            scratch / "checkouts" / "LNPopupController" /
            "LNPopupSettings" / "SettingKeys.h";
        if (LongPathRegularFile(candidate)) {
            payload = candidate;
        }
    };

    if (!result.package_archive_path.empty()) {
        fs::path cursor = fs::path(result.package_archive_path).parent_path();
        for (int depth = 0; depth < 5 && !cursor.empty() && payload.empty();
             ++depth, cursor = cursor.parent_path()) {
            find_payload(cursor);
        }
    }

    /*
     * A failed baseline has no archive from which to derive its scratch.
     * Retain discovery below the configured cache solely for that negative
     * control; successful candidates use PackageBuildResult as authority.
     */
    std::error_code ec;
    const fs::path swiftpm_root = OpenFruit::ToolPaths::CacheRoot() / "swiftpm";
    for (fs::directory_iterator it(
             swiftpm_root,
             fs::directory_options::skip_permission_denied,
             ec);
         payload.empty() && it != fs::directory_iterator();
         it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        find_payload(it->path());
    }

    std::cout << "SUBMODULE_PAYLOAD=" << payload.string() << "\n";
    std::cout << "SUBMODULE_PAYLOAD_LENGTH="
              << payload.string().size() << "\n";
    if (payload.empty()) {
        std::cerr << "SwiftPM Git submodule checkout was not materialized\n";
        return 5;
    }

    std::cout << "SUBMODULE_LONG_PATH_CHECKOUT=pass\n";
    return 0;
}
