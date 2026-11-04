#include "tool_paths.hpp"

#include <windows.h>
#include <shlobj.h>
#include <stdexcept>
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <fstream>
#include <regex>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {
fs::path KnownFolder(REFKNOWNFOLDERID identifier) {
    PWSTR value = nullptr;
    if (FAILED(SHGetKnownFolderPath(identifier, 0, nullptr, &value)))
        throw std::runtime_error("Required Windows user state directory is unavailable");
    fs::path path(value);
    CoTaskMemFree(value);
    return path;
}

std::wstring Env(const wchar_t* name) {
    const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0) {
        return {};
    }
    std::wstring value(required, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), required);
    if (written == 0) {
        return {};
    }
    value.resize(written);
    return value;
}

fs::path FirstExistingDirectory(std::initializer_list<fs::path> values) {
    std::error_code ec;
    for (const auto& value : values) {
        if (!value.empty() && !ToolPaths::IsImportScratchPath(value) && fs::is_directory(value, ec) && !ec) {
            return value;
        }
        ec.clear();
    }
    return {};
}



bool IsUsableIosSdk(const fs::path& sdk) {
    std::error_code ec;
    if (sdk.empty() || !fs::is_directory(sdk, ec) || ec) return false;
    ec.clear();
    const bool has_usr_lib = fs::is_directory(sdk / "usr" / "lib", ec) && !ec;
    ec.clear();
    const bool has_frameworks = fs::is_directory(sdk / "System" / "Library" / "Frameworks", ec) && !ec;
    ec.clear();
    const bool has_settings = fs::is_regular_file(sdk / "SDKSettings.json", ec) || fs::is_regular_file(sdk / "SDKSettings.plist", ec);
    return has_usr_lib && has_frameworks && has_settings;
}

bool HasClangBuiltinHeader(const fs::path& swift_bin, const wchar_t* header) {
    if (swift_bin.empty()) return false;
    const fs::path clang_root = swift_bin.parent_path() / "lib" / "clang";
    std::error_code ec;
    if (!fs::is_directory(clang_root, ec) || ec) return false;
    for (const auto& entry : fs::directory_iterator(clang_root, ec)) {
        if (ec) break;
        if (!entry.is_directory(ec) || ec) { ec.clear(); continue; }
        ec.clear();
        if (fs::is_regular_file(entry.path() / "include" / header, ec) && !ec) return true;
        ec.clear();
    }
    return false;
}

bool IsStructurallyUsableSwiftBin(const fs::path& swift_bin) {
    std::error_code ec;
    if (swift_bin.empty() || !fs::is_directory(swift_bin, ec) || ec) return false;
    for (const auto& exe : {L"swift.exe", L"swiftc.exe", L"clang.exe", L"llvm-ar.exe"}) {
        ec.clear();
        if (!fs::is_regular_file(swift_bin / exe, ec) || ec) return false;
    }
    return HasClangBuiltinHeader(swift_bin, L"stdalign.h");
}


bool IsSourceCrossSwiftBin(const fs::path& swift_bin) {
    std::error_code ec;
    if (swift_bin.empty() || !fs::is_directory(swift_bin, ec) || ec) return false;
    for (const auto& exe : {L"swift.exe", L"swiftc.exe", L"clang.exe", L"llvm-ar.exe", L"llvm-readobj.exe"}) {
        ec.clear();
        if (!fs::is_regular_file(swift_bin / exe, ec) || ec) return false;
    }
    return true;
}
fs::path FirstExistingFile(std::initializer_list<fs::path> values) {
    std::error_code ec;
    for (const auto& value : values) {
        if (!value.empty() && !ToolPaths::IsImportScratchPath(value) && fs::is_regular_file(value, ec) && !ec) {
            return value;
        }
        ec.clear();
    }
    return {};
}

long long VersionRank(const fs::path& value) {
    const std::wstring text = value.filename().wstring();
    long long rank = 0;
    long long component = 0;
    int components = 0;
    bool have_digit = false;
    for (wchar_t c : text) {
        if (c >= L'0' && c <= L'9') {
            component = component * 10 + (c - L'0');
            have_digit = true;
        } else if (c == L'.' && have_digit) {
            rank = rank * 10000 + std::min<long long>(component, 9999);
            component = 0;
            have_digit = false;
            if (++components >= 3) break;
        } else if (have_digit) {
            break;
        }
    }
    if (have_digit && components < 4) {
        rank = rank * 10000 + std::min<long long>(component, 9999);
        ++components;
    }
    while (components++ < 4) rank *= 10000;
    return rank;
}

fs::path BestVersionedDirectory(
    const fs::path& root,
    const fs::path& suffix,
    const fs::path& required_file = {},
    bool prefer_no_asserts = false
) {
    std::error_code ec;
    if (!fs::is_directory(root, ec) || ec) return {};
    fs::path best;
    long long best_rank = -1;
    for (const auto& entry : fs::directory_iterator(root, ec)) {
        if (ec) break;
        if (!entry.is_directory(ec) || ec) { ec.clear(); continue; }
        const fs::path candidate = entry.path() / suffix;
        if (ToolPaths::IsImportScratchPath(candidate)) continue;
        const bool usable = required_file.empty()
            ? fs::is_directory(candidate, ec)
            : fs::is_regular_file(candidate / required_file, ec);
        if (!ec && usable) {
            const long long rank = VersionRank(entry.path());
            if (best.empty() || rank > best_rank || (prefer_no_asserts && rank == best_rank &&
                ToolPaths::SwiftAssertions(candidate) == SwiftToolchainAssertions::Disabled &&
                ToolPaths::SwiftAssertions(best) != SwiftToolchainAssertions::Disabled)) {
                best = candidate;
                best_rank = rank;
            }
        }
        ec.clear();
    }
    return best;
}


bool IsUnderPath(const fs::path& child, const fs::path& parent) {
    if (child.empty() || parent.empty()) return false;
    std::error_code ec1, ec2;
    fs::path c = fs::absolute(child, ec1).lexically_normal();
    fs::path p = fs::absolute(parent, ec2).lexically_normal();
    if (ec1 || ec2) return false;
    auto ci = c.begin();
    auto pi = p.begin();
    for (; pi != p.end(); ++pi, ++ci) {
        if (ci == c.end()) return false;
        std::wstring a = ci->wstring();
        std::wstring b = pi->wstring();
        std::transform(a.begin(), a.end(), a.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
        std::transform(b.begin(), b.end(), b.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
        if (a != b) return false;
    }
    return true;
}

fs::path ReadManagedXcodePointer(const fs::path& local_home) {
    const fs::path root = local_home / "sdk" / "xcode";
    std::vector<fs::path> slots;
    slots.push_back(root / "current");

    std::error_code ec;
    if (fs::is_directory(root, ec) && !ec) {
        std::vector<std::pair<long long, fs::path>> versions;
        for (const auto& entry : fs::directory_iterator(root, ec)) {
            if (ec) break;
            if (!entry.is_directory(ec) || ec || entry.path().filename() == "current") {
                ec.clear();
                continue;
            }
            versions.emplace_back(VersionRank(entry.path()), entry.path());
            ec.clear();
        }
        std::sort(versions.begin(), versions.end(), [](const auto& a, const auto& b) {
            return a.first > b.first;
        });
        for (const auto& [_, path] : versions) slots.push_back(path);
    }

    for (const auto& slot : slots) {
        std::ifstream input(slot / "source.path", std::ios::binary);
        if (!input) continue;
        std::string line;
        std::getline(input, line);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        const fs::path candidate = fs::path(line);
        ec.clear();
        if (!candidate.empty() && fs::is_directory(candidate, ec) && !ec) return candidate;
    }
    return {};
}

} // namespace

fs::path ToolPaths::LocalHome() {
    const std::wstring configured = Env(L"OPENFRUIT_HOME");
    if (!configured.empty()) {
        return fs::path(configured);
    }

    const std::wstring local = Env(L"LOCALAPPDATA");
    if (!local.empty()) {
        return fs::path(local) / "OpenFruit";
    }

    return KnownFolder(FOLDERID_LocalAppData) / "OpenFruit";
}

fs::path ToolPaths::UserStateRoot() {
    const std::wstring configured = Env(L"OPENFRUIT_USER_STATE");
    if (!configured.empty()) {
        return fs::path(configured);
    }

    const std::wstring profile = Env(L"USERPROFILE");
    if (!profile.empty()) {
        return fs::path(profile) / ".openfruit";
    }

    return KnownFolder(FOLDERID_Profile) / ".openfruit";
}

fs::path ToolPaths::FileDigestCache() {
    return CacheRoot() / "file-digests" / "v1.tsv";
}

fs::path ToolPaths::CacheRoot() {
    const std::wstring configured = Env(L"OPENFRUIT_CACHE_ROOT");
    if (!configured.empty()) {
        return fs::path(configured);
    }
    return LocalHome() / "cache";
}

bool ToolPaths::IsPublishedSwiftBin(const fs::path& swift_bin) {
    if (swift_bin.empty()) return false;
    const fs::path root = swift_bin.parent_path().parent_path();
    std::error_code ec;
    if (IsImportScratchPath(root) || !IsStructurallyUsableSwiftBin(swift_bin)) return false;
    return fs::is_regular_file(root / ".openfruit-relocatable-ok", ec) && !ec;
}

SwiftToolchainAssertions ToolPaths::SwiftAssertions(const fs::path& swift_bin) {
    if (swift_bin.empty()) return SwiftToolchainAssertions::Unspecified;
    const auto metadata = swift_bin.parent_path().parent_path() / "ToolchainInfo.plist";
    std::error_code error;
    const auto bytes = fs::file_size(metadata, error);
    if (error || bytes > 65536) return SwiftToolchainAssertions::Unspecified;
    std::ifstream input(metadata, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(input)), {});
    std::smatch identifier;
    if (!input || !std::regex_search(text, identifier,
        std::regex(R"(<key>Identifier</key>\s*<string>([^<]+)</string>)")))
        return SwiftToolchainAssertions::Unspecified;
    const auto value = identifier[1].str();
    if (value.ends_with(".NoAsserts")) return SwiftToolchainAssertions::Disabled;
    if (value.ends_with(".Asserts")) return SwiftToolchainAssertions::Enabled;
    return SwiftToolchainAssertions::Unspecified;
}

bool ToolPaths::IsImportScratchPath(const fs::path& path) {
    const auto reserved = [](const fs::path& candidate) {
        for (const auto& part : candidate) {
            auto name = part.wstring();
            std::transform(name.begin(), name.end(), name.begin(), [](wchar_t ch) { return std::towlower(ch); });
            for (const auto marker : {L".partial-", L".previous-"}) {
                const auto size = std::wcslen(marker);
                if (name.size() <= size + 32) continue;
                if (name.compare(name.size() - size - 32, size, marker) == 0 &&
                    name.substr(name.size() - 32).find_first_not_of(L"0123456789abcdef") == std::wstring::npos) return true;
            }
        }
        return false;
    };
    if (reserved(path)) return true;
    std::error_code ec;
    const auto resolved = fs::weakly_canonical(path, ec);
    return !ec && reserved(resolved);
}

fs::path ToolPaths::FindOnPath(const std::wstring& executable) {
    std::wstring path_value = Env(L"PATH");

    if (path_value.empty()) {
        return {};
    }

    // Also read system (HKLM) and user (HKCU) PATH from registry to catch newly added
    // environment variables that the parent process hasn't refreshed yet.
    auto query_reg_path = [](HKEY root, const wchar_t* subkey) -> std::wstring {
        HKEY key = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &key) == ERROR_SUCCESS) {
            DWORD bytes = 0;
            if (RegQueryValueExW(key, L"Path", nullptr, nullptr, nullptr, &bytes) == ERROR_SUCCESS && bytes > 0) {
                std::wstring buffer(bytes / sizeof(wchar_t), L'\0');
                if (RegQueryValueExW(key, L"Path", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer.data()), &bytes) == ERROR_SUCCESS) {
                    while (!buffer.empty() && buffer.back() == L'\0') buffer.pop_back();
                    RegCloseKey(key);
                    return buffer;
                }
            }
            RegCloseKey(key);
        }
        return {};
    };

    const std::wstring machine_path = query_reg_path(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    const std::wstring user_path = query_reg_path(HKEY_CURRENT_USER, L"Environment");
    if (!machine_path.empty()) path_value += L";" + machine_path;
    if (!user_path.empty()) path_value += L";" + user_path;


    std::wstringstream input(path_value);
    std::wstring entry;
    std::error_code ec;
    while (std::getline(input, entry, L';')) {
        if (entry.size() >= 2 && entry.front() == L'"' && entry.back() == L'"') {
            entry = entry.substr(1, entry.size() - 2);
        }
        if (entry.empty()) {
            continue;
        }
        const fs::path candidate = fs::path(entry) / executable;
        if (!IsImportScratchPath(candidate) && fs::is_regular_file(candidate, ec) && !ec) {
            return candidate;
        }
        ec.clear();
    }
    return {};
}

fs::path ToolPaths::SwiftBin(const fs::path& repo_root) {
    const fs::path local_home = LocalHome();

    // OPENFRUIT_SWIFT_BIN may have been persisted by an older bootstrap.  A
    // managed mirror is only trusted after the relocatability smoke test has
    // explicitly marked it good.  External/user-provided toolchains only need
    // the structural cross-toolchain checks here; SwiftPM pairs them with the
    // matching host runtime separately.
    const std::wstring configured = Env(L"OPENFRUIT_SWIFT_BIN");
    if (!configured.empty() && !IsImportScratchPath(fs::path(configured))) {
        const fs::path candidate(configured);
        if (IsUnderPath(candidate, local_home / "toolchains" / "swift")) {
            if (IsPublishedSwiftBin(candidate)) return candidate;
        } else if (IsSourceCrossSwiftBin(candidate)) {
            return candidate;
        }
    }

    // Managed Swift is opt-in only after validation.  Merely having swiftc.exe
    // in a copied directory is insufficient because the Windows Swift driver
    // derives resource/header locations relative to its installation root.
    fs::path managed = local_home / "toolchains" / "swift" / "current" / "usr" / "bin";
    if (!IsPublishedSwiftBin(managed)) {
        managed.clear();
        const fs::path managed_root = local_home / "toolchains" / "swift";
        std::error_code ec;
        if (fs::is_directory(managed_root, ec) && !ec) {
            std::vector<std::pair<long long, fs::path>> candidates;
            for (const auto& entry : fs::directory_iterator(managed_root, ec)) {
                if (ec) break;
                if (!entry.is_directory(ec) || ec || entry.path().filename() == "current") { ec.clear(); continue; }
                const fs::path candidate = entry.path() / "usr" / "bin";
                if (IsPublishedSwiftBin(candidate)) {
                    candidates.emplace_back(VersionRank(entry.path()), candidate);
                }
                ec.clear();
            }
            if (!candidates.empty()) {
                std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
                    if (a.first != b.first) return a.first > b.first;
                    return SwiftAssertions(a.second) == SwiftToolchainAssertions::Disabled &&
                        SwiftAssertions(b.second) != SwiftToolchainAssertions::Disabled;
                });
                managed = candidates.front().second;
            }
        }
    }

    // Prefer validated managed or complete installed cross toolchains.
    const std::wstring local_app_data = Env(L"LOCALAPPDATA");
    fs::path installed_swift;
    if (!local_app_data.empty()) {
        installed_swift = BestVersionedDirectory(
            fs::path(local_app_data) / "Programs" / "Swift" / "Toolchains",
            fs::path("usr") / "bin",
            "swiftc.exe", true
        );
    }

    const fs::path path_swift = FindOnPath(L"swift.exe");

    if (!managed.empty() && IsPublishedSwiftBin(managed)) return managed;
    for (const auto& candidate : {
            installed_swift,
            path_swift.empty() ? fs::path{} : path_swift.parent_path()}) {
        if (!candidate.empty() && IsSourceCrossSwiftBin(candidate)) return candidate;
    }
    return {};
}

fs::path ToolPaths::LlvmBin(const fs::path& repo_root) {
    const std::wstring configured = Env(L"OPENFRUIT_LLVM_BIN");
    if (!configured.empty() && !IsImportScratchPath(fs::path(configured)) && fs::exists(configured)) {
        return fs::path(configured);
    }

    const std::wstring program_files = Env(L"ProgramFiles");
    const fs::path path_lld = FindOnPath(L"ld64.lld.exe");
    fs::path managed = LocalHome() / "toolchains" / "llvm" / "current" / "bin";
    if (IsImportScratchPath(managed) || !fs::exists(managed / "ld64.lld.exe")) {
        managed = BestVersionedDirectory(LocalHome() / "toolchains" / "llvm", "bin", "ld64.lld.exe");
    }
    return FirstExistingDirectory({
        managed,
        program_files.empty() ? fs::path{} : fs::path(program_files) / "LLVM" / "bin",
        path_lld.empty() ? fs::path{} : path_lld.parent_path()
    });
}


fs::path ToolPaths::Git() {
    const fs::path path_git = FindOnPath(L"git.exe");
    const std::wstring program_files = Env(L"ProgramFiles");
    const std::wstring local_app_data = Env(L"LOCALAPPDATA");
    return FirstExistingFile({
        path_git,
        program_files.empty() ? fs::path{} : fs::path(program_files) / "Git" / "cmd" / "git.exe",
        program_files.empty() ? fs::path{} : fs::path(program_files) / "Git" / "bin" / "git.exe",
        local_app_data.empty() ? fs::path{} : fs::path(local_app_data) / "Programs" / "Git" / "cmd" / "git.exe",
        local_app_data.empty() ? fs::path{} : fs::path(local_app_data) / "Programs" / "Git" / "bin" / "git.exe"
    });
}

fs::path ToolPaths::Zsign(const fs::path& repo_root) {
    const std::wstring configured = Env(L"OPENFRUIT_ZSIGN");
    if (!configured.empty() && fs::exists(configured)) {
        return fs::path(configured);
    }
    return FirstExistingFile({
        LocalHome() / "bin" / "signing" / "zsign.exe",
        FindOnPath(L"zsign.exe")
    });
}

fs::path ToolPaths::Pymobiledevice3(const fs::path& repo_root) {
    const std::wstring configured = Env(L"OPENFRUIT_PYMOBILEDEVICE3");
    if (!configured.empty() && fs::exists(configured)) {
        return fs::path(configured);
    }
    return FirstExistingFile({
        LocalHome() / "toolchains" / "device" / "pymobiledevice3" / "Scripts" / "pymobiledevice3.exe",
        FindOnPath(L"pymobiledevice3.exe")
    });
}

fs::path ToolPaths::Ipsw() {
    const std::wstring configured = Env(L"OPENFRUIT_IPSW");
    if (!configured.empty() && fs::exists(configured)) {
        return fs::path(configured);
    }
    return FirstExistingFile({
        LocalHome() / "bin" / "ipsw.exe",
        FindOnPath(L"ipsw.exe")
    });
}

fs::path ToolPaths::DarlingRoot(const fs::path& repo_root) {
    const std::wstring configured = Env(L"OPENFRUIT_DARLING_TOOLS");
    if (!configured.empty() && fs::exists(configured)) {
        return fs::path(configured);
    }
    return FirstExistingDirectory({
        LocalHome() / "toolchains" / "darling",
    });
}

fs::path ToolPaths::IosSdk(const fs::path& repo_root) {
    return IosSdk(LocalHome(), fs::path(Env(L"OPENFRUIT_IOS_SDK")));
}

fs::path ToolPaths::IosSdk(const fs::path& managed_home, const fs::path& configured_sdk) {
    if (!configured_sdk.empty() && IsUsableIosSdk(configured_sdk)) return configured_sdk;
    if (managed_home.empty()) return {};
    const fs::path managed_root = managed_home / "sdk" / "ios";
    std::error_code ec;
    fs::path managed;
    long long best_rank = -1;
    if (fs::is_directory(managed_root, ec) && !ec) {
        for (const auto& entry : fs::directory_iterator(managed_root, ec)) {
            if (ec) break;
            if (!entry.is_directory(ec) || ec) { ec.clear(); continue; }
            const fs::path candidate = entry.path() / "iPhoneOS.sdk";
            if (IsUsableIosSdk(candidate)) {
                const long long rank = VersionRank(entry.path());
                if (managed.empty() || rank > best_rank) { managed = candidate; best_rank = rank; }
            }
            ec.clear();
        }
    }
    if (!managed.empty()) return managed;

    return {};
}

fs::path ToolPaths::XcodeRoot(const fs::path& repo_root) {
    const std::wstring configured = Env(L"OPENFRUIT_XCODE_PATH");
    if (!configured.empty() && fs::exists(configured)) {
        return fs::path(configured);
    }

    const fs::path managed = ReadManagedXcodePointer(LocalHome());
    return FirstExistingDirectory({
        managed
    });
}

} // namespace OpenFruit
