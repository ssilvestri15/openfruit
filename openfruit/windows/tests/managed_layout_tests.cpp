#include "tool_paths.hpp"
#include "sdk_manager.hpp"
#include "operation_events.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <optional>
#include <vector>
namespace fs = std::filesystem;
struct Environment {
    std::vector<std::pair<std::wstring, std::optional<std::wstring>>> original;
    void Set(const wchar_t* name, const std::wstring& value = L"") {
        const DWORD count = GetEnvironmentVariableW(name, nullptr, 0);
        std::optional<std::wstring> old;
        if (count) {
            std::wstring buffer(count, L'\0');
            const DWORD written = GetEnvironmentVariableW(name, buffer.data(), count);
            buffer.resize(written); old = std::move(buffer);
        }
        original.emplace_back(name, old);
        SetEnvironmentVariableW(name, value.empty() ? nullptr : value.c_str());
    }
    ~Environment() {
        for (auto it = original.rbegin(); it != original.rend(); ++it)
            SetEnvironmentVariableW(it->first.c_str(), it->second ? it->second->c_str() : nullptr);
    }
};
void File(const fs::path& path, const char* content = "owned path fixture") {
    fs::create_directories(path.parent_path());
    std::ofstream output(path); output << content;
}
void Sdk(const fs::path& path) {
    fs::create_directories(path / "usr" / "lib");
    fs::create_directories(path / "System" / "Library" / "Frameworks");
    File(path / "SDKSettings.json", "{\"Version\":\"26.5\"}");
}
int main() {
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-layout-tests-" + OpenFruit::NewOperationId());
    const auto repo = root / "project", managed = root / "managed";
    Environment env;
    env.Set(L"OPENFRUIT_HOME", managed.wstring());
    for (const auto* name : {L"OPENFRUIT_IOS_SDK", L"OPENFRUIT_SWIFT_BIN", L"OPENFRUIT_LLVM_BIN", L"OPENFRUIT_ZSIGN", L"OPENFRUIT_PYMOBILEDEVICE3", L"OPENFRUIT_DARLING_TOOLS", L"OPENFRUIT_XCODE_PATH", L"OPENFRUIT_CACHE_ROOT", L"PATH"}) env.Set(name);
    Sdk(repo / ".tools" / "apple-sdk" / "iPhoneOS.sdk");
    File(repo / ".tools" / "signing" / "bin" / "zsign.exe");
    File(repo / ".tools" / "device-venv" / "Scripts" / "pymobiledevice3.exe");
    fs::create_directories(repo / ".tools" / "darling");
    fs::create_directories(repo / ".tools" / "apple-downloads" / "extracted" / "Xcode.app");
    if (!OpenFruit::ToolPaths::IosSdk(repo).empty() || OpenFruit::SDKManager::DiscoverSDK(repo.wstring()).is_valid) return 1;
    if (!OpenFruit::ToolPaths::Zsign(repo).empty() || !OpenFruit::ToolPaths::Pymobiledevice3(repo).empty()
        || !OpenFruit::ToolPaths::DarlingRoot(repo).empty() || !OpenFruit::ToolPaths::XcodeRoot(repo).empty()) return 2;
    const auto sdk = managed / "sdk" / "ios" / "26" / "iPhoneOS.sdk";
    Sdk(sdk);
    if (OpenFruit::ToolPaths::IosSdk(repo) != sdk) return 3;
    // Production SDK discovery must retain original declarations and ignore
    // even an already-published legacy header-enrichment overlay.
    const auto header = sdk / "System" / "Library" / "Frameworks" /
        "Photos.framework" / "Headers" / "PHPhotoLibrary.h";
    const std::string original = "// OPENFRUIT-owned immutable SDK fixture\n@interface PHPhotoLibrary @end\n";
    File(header, original.c_str());
    const auto legacy = managed / "cache" / "sdk" /
        std::to_string(std::hash<std::wstring>{}(fs::absolute(sdk).lexically_normal().wstring()));
    File(legacy / "arm64-vfs-overlay.json", "{\"legacy\":\"PHPhotoLibrary.h\"}");
    File(legacy / "vfs-files" / "PHPhotoLibrary.h", "invalid legacy declarations");
    const auto discovered = OpenFruit::SDKManager::DiscoverSDK(repo.wstring(), L"17.0");
    if (!discovered.is_valid || !discovered.vfs_overlay_path.empty() ||
        discovered.sdk_path != sdk.wstring() || discovered.target_triple != L"arm64-apple-ios17.0") return 7;
    std::ifstream header_in(header, std::ios::binary);
    const std::string retained((std::istreambuf_iterator<char>(header_in)), {});
    // File() writes in text mode on Windows; compare the same transport bytes.
    const std::string expected = "// OPENFRUIT-owned immutable SDK fixture\r\n@interface PHPhotoLibrary @end\r\n";
    if (retained != expected) return 8;
    std::wstring overlay = L"stale caller path";
    if (OpenFruit::SDKManager::EnsureVFSOverlay(repo.wstring(), (root / "missing-sdk").wstring(), overlay)
        || !overlay.empty()) return 9;
    const auto zsign = managed / "bin" / "signing" / "zsign.exe";
    File(zsign);
    if (OpenFruit::ToolPaths::Zsign(repo) != zsign) return 4;
    if (OpenFruit::ToolPaths::CacheRoot() != managed / "cache") return 5;
    // Deliberately misleading directory suffixes: the upstream Identifier,
    // rather than a filename or caller-provided preference, selects the variant.
    const auto assertion_slot = managed / "toolchains/swift/6.4.1+NoAsserts";
    const auto release_slot = managed / "toolchains/swift/6.4.1+Asserts";
    for (const auto& slot : {assertion_slot, release_slot}) {
        for (const auto* executable : {"swift.exe", "swiftc.exe", "clang.exe", "llvm-ar.exe", "llvm-readobj.exe"})
            File(slot / "usr/bin" / executable);
        File(slot / "usr/lib/clang/21/include/stdalign.h");
        File(slot / ".openfruit-relocatable-ok");
    }
    File(assertion_slot / "ToolchainInfo.plist",
        "<plist><dict><key>Identifier</key><string>swift-6.4.1-RELEASE.Asserts</string></dict></plist>");
    File(release_slot / "ToolchainInfo.plist",
        "<plist><dict><key>Identifier</key><string>swift-6.4.1-RELEASE.NoAsserts</string></dict></plist>");
    if (OpenFruit::ToolPaths::SwiftBin(repo) != release_slot / "usr/bin" ||
        OpenFruit::ToolPaths::SwiftAssertions(assertion_slot / "usr/bin") != OpenFruit::SwiftToolchainAssertions::Enabled ||
        OpenFruit::ToolPaths::SwiftAssertions(release_slot / "usr/bin") != OpenFruit::SwiftToolchainAssertions::Disabled)
        return 10;
    File(release_slot / "ToolchainInfo.plist", "invalid toolchain metadata");
    if (OpenFruit::ToolPaths::SwiftAssertions(release_slot / "usr/bin") != OpenFruit::SwiftToolchainAssertions::Unspecified)
        return 11;
    env.Set(L"OPENFRUIT_HOME"); env.Set(L"LOCALAPPDATA");
    env.Set(L"OPENFRUIT_USER_STATE"); env.Set(L"USERPROFILE");
    const auto local = OpenFruit::ToolPaths::LocalHome(), user = OpenFruit::ToolPaths::UserStateRoot();
    if (!local.is_absolute() || !user.is_absolute() || local.filename() != "OpenFruit" || user.filename() != ".openfruit") return 6;
    return 0;
}
