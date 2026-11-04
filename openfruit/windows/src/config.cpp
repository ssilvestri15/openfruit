#include "config.hpp"
#include "protected_credential_store.hpp"
#include "atomic_file.hpp"
#include "artifact_store.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include <stdexcept>
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "text_util.hpp"

#include <windows.h>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <unordered_map>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

std::wstring ReadEnvironment(const wchar_t* name) {
    const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0) return {};
    std::wstring value(required, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), required);
    if (written == 0) return {};
    value.resize(written);
    return value;
}

std::wstring GetHomeDir() {
    const std::wstring profile = ReadEnvironment(L"USERPROFILE");
    return profile.empty() ? L"." : profile;
}

std::string Unquote(std::string value) {
    value = TrimWhitespace(std::move(value));
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
        std::string decoded;
        decoded.reserve(value.size());
        for (std::size_t i = 0; i < value.size(); ++i) {
            if (value[i] == '\\' && i + 1 < value.size()) {
                const char next = value[++i];
                if (next == '\\' || next == '"') decoded.push_back(next);
                else if (next == 'n') decoded.push_back('\n');
                else { decoded.push_back('\\'); decoded.push_back(next); }
            } else {
                decoded.push_back(value[i]);
            }
        }
        return decoded;
    }
    return value;
}

std::string QuoteToml(const std::wstring& value) {
    const std::string input = Win32Process::ToNarrow(value);
    std::string out = "\"";
    for (char c : input) {
        if (c == '\\' || c == '"') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

std::unordered_map<std::string, std::string> ParseToml(const std::string& text) {
    std::unordered_map<std::string, std::string> values;
    std::istringstream stream(text);
    std::string line;
    std::string section;

    while (std::getline(stream, line)) {
        const std::size_t comment = line.find('#');
        if (comment != std::string::npos) line.resize(comment);
        line = TrimWhitespace(line);
        if (line.empty()) continue;

        if (line.front() == '[' && line.back() == ']') {
            section = TrimWhitespace(line.substr(1, line.size() - 2));
            continue;
        }

        const std::size_t equals = line.find('=');
        if (equals == std::string::npos) continue;
        const std::string key = TrimWhitespace(line.substr(0, equals));
        const std::string value = Unquote(line.substr(equals + 1));
        values[section.empty() ? key : section + "." + key] = value;
    }
    return values;
}

std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::regex reg("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch m;
    if (std::regex_search(json, m, reg) && m.size() > 1) return m[1].str();
    return "";
}

std::wstring NormalizePathEntry(std::wstring_view raw) {
    const auto is_space = [](wchar_t ch) {
        return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
    };
    while (!raw.empty() && is_space(raw.front())) raw.remove_prefix(1);
    while (!raw.empty() && is_space(raw.back())) raw.remove_suffix(1);
    if (raw.size() >= 2 && raw.front() == L'"' && raw.back() == L'"') {
        raw.remove_prefix(1);
        raw.remove_suffix(1);
        while (!raw.empty() && is_space(raw.front())) raw.remove_prefix(1);
        while (!raw.empty() && is_space(raw.back())) raw.remove_suffix(1);
    }
    if (raw.empty()) return {};
    std::wstring cleaned(raw);
    for (wchar_t& ch : cleaned) {
        if (ch == L'/') ch = L'\\';
    }
    while (cleaned.size() > 1 && cleaned.back() == L'\\' &&
           !(cleaned.size() == 3 && cleaned[1] == L':')) {
        cleaned.pop_back();
    }
    std::wstring normalized = fs::path(cleaned).lexically_normal().make_preferred().wstring();
    while (normalized.size() > 1 && normalized.back() == L'\\' &&
           !(normalized.size() == 3 && normalized[1] == L':')) {
        normalized.pop_back();
    }
    for (wchar_t& ch : normalized) {
        ch = static_cast<wchar_t>(std::towlower(static_cast<wint_t>(ch)));
    }
    return normalized;
}

bool PathContainsDirectory(std::wstring_view path_env, std::wstring_view target_dir) {
    const std::wstring target_norm = NormalizePathEntry(target_dir);
    if (target_norm.empty()) return false;
    std::size_t start = 0;
    while (start <= path_env.size()) {
        const std::size_t semi = path_env.find(L';', start);
        const std::wstring_view entry = (semi == std::wstring_view::npos)
            ? path_env.substr(start)
            : path_env.substr(start, semi - start);
        if (!entry.empty() && NormalizePathEntry(entry) == target_norm) {
            return true;
        }
        if (semi == std::wstring_view::npos) break;
        start = semi + 1;
    }
    return false;
}

bool ParseBool(const std::string& value, bool fallback) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (lower == "true" || lower == "1" || lower == "yes" || lower == "on") return true;
    if (lower == "false" || lower == "0" || lower == "no" || lower == "off") return false;
    return fallback;
}

} // namespace

std::wstring Secrets::GetDefaultSecretsPath() {
    return (fs::path(GetHomeDir()) / ".OPENFRUIT" / "credentials" / "secrets.json").wstring();
}

Secrets Secrets::Load(const std::wstring& custom_path) {
    Secrets sec;
    fs::path path = custom_path.empty() ? fs::path(GetDefaultSecretsPath()) : fs::path(custom_path);
    if (!fs::exists(path)) {
        if (!custom_path.empty()) return sec;
        const fs::path legacy_user = fs::path(GetHomeDir()) / ".OPENFRUIT" / "secrets.json";
        if (fs::exists(legacy_user)) path = legacy_user;
        else return sec;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) return sec;
    const std::string json((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();
    const auto parsed = JsonValue::Parse(json);
    // The old writer did not JSON-escape Windows paths. Retain its literal
    // representation while migrating; new records use the strict JSON writer.
    const auto read = [&](const char* key) {
        return Win32Process::ToWide(parsed && parsed->IsObject()
            ? parsed->GetString(key) : ExtractJsonString(json, key));
    };
    sec.apple_id = read("apple_id");
    sec.apple_team_id = read("apple_team_id");
    sec.signing_p12_path = read("signing_p12_path");
    sec.signing_profile_path = read("signing_profile_path");
    sec.signing_password = read("signing_password");
    sec.apple_session_dpapi_path = read("apple_session_dpapi_path");
    sec.apple_cookies_dpapi_path = read("apple_cookies_dpapi_path");
    if (!sec.signing_password.empty() && sec.signing_password.rfind(L"DPAPI:", 0) != 0) {
        if (!sec.Save(path.wstring())) throw std::runtime_error("Unable to protect legacy signing credential; original metadata preserved.");
        return Load(path.wstring());
    }
    return sec;
}
bool Secrets::Save(const std::wstring& custom_path) const {
    const fs::path path = custom_path.empty() ? fs::path(GetDefaultSecretsPath()) : fs::path(custom_path);
    std::wstring password_reference = signing_password;
    if (!password_reference.empty() && password_reference.rfind(L"DPAPI:", 0) != 0) {
        const auto protected_path = fs::absolute(path).parent_path() /
            ("signing-password-" + NewOperationId() + ".dpapi");
        if (!ProtectedCredentialStore::Write(protected_path, password_reference, CredentialPurpose::SigningPassword)) return false;
        password_reference = L"DPAPI:" + protected_path.wstring();
    }
    JsonValue data = JsonValue::ObjectValue();
    data.Set("schema_version", JsonValue::Number("3"));
    data.Set("apple_id", JsonValue::String(Win32Process::ToNarrow(apple_id)));
    data.Set("apple_team_id", JsonValue::String(Win32Process::ToNarrow(apple_team_id)));
    data.Set("signing_p12_path", JsonValue::String(Win32Process::ToNarrow(signing_p12_path)));
    data.Set("signing_profile_path", JsonValue::String(Win32Process::ToNarrow(signing_profile_path)));
    data.Set("signing_password", JsonValue::String(Win32Process::ToNarrow(password_reference)));
    data.Set("apple_session_dpapi_path", JsonValue::String(Win32Process::ToNarrow(apple_session_dpapi_path)));
    data.Set("apple_cookies_dpapi_path", JsonValue::String(Win32Process::ToNarrow(apple_cookies_dpapi_path)));
    return AtomicFile::Publish(path, data.Serialize(true));
}
void Secrets::AutoDiscover(const std::wstring& repo_root, const std::wstring& save_path) {
    // When credentials paths are not explicitly configured by the user,
    // do not guess or silently bind files from directories.
    (void)repo_root;
    (void)save_path;
}

std::wstring Config::GetDefaultConfigPath() {
    return (ToolPaths::UserStateRoot() / "config.toml").wstring();
}

Config Config::Load(const std::wstring& custom_path, bool initialize_missing) {
    Config cfg;
    cfg.OPENFRUIT_home = ToolPaths::LocalHome().wstring();
    cfg.user_state_root = ToolPaths::UserStateRoot().wstring();
    cfg.cache_root = ToolPaths::CacheRoot().wstring();
    cfg.credentials_dir = (fs::path(cfg.user_state_root) / "credentials").wstring();
    cfg.certificates_dir = (fs::path(cfg.user_state_root) / "certificates").wstring();
    cfg.secrets_path = (fs::path(cfg.credentials_dir) / "secrets.json").wstring();

    fs::path path = custom_path.empty() ? fs::path(GetDefaultConfigPath()) : fs::path(custom_path);
    if (fs::exists(path)) {
        std::ifstream f(path, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        const auto values = ParseToml(text);
        const auto get = [&](const char* key) -> std::string {
            const auto it = values.find(key);
            return it == values.end() ? std::string{} : it->second;
        };
        const auto wide = [&](const char* key) -> std::wstring { return Win32Process::ToWide(get(key)); };

        const bool has_home = !get("paths.home").empty();
        const bool has_user_state = !get("paths.user_state").empty();
        const bool has_cache = !get("paths.cache").empty();
        const bool has_credentials_dir = !get("secrets.credentials_dir").empty();
        const bool has_certificates_dir = !get("secrets.certificates_dir").empty();
        const bool has_secrets_file = !get("secrets.file").empty();

        if (has_home) cfg.OPENFRUIT_home = wide("paths.home");
        if (has_user_state) cfg.user_state_root = wide("paths.user_state");
        if (has_cache) cfg.cache_root = wide("paths.cache");
        if (!get("sdk.ios.path").empty()) cfg.sdk_path = wide("sdk.ios.path");
        if (!get("sdk.ios.version").empty()) cfg.ios_sdk_version = wide("sdk.ios.version");
        if (!get("sdk.macos.path").empty()) cfg.macos_sdk_path = wide("sdk.macos.path");
        if (!get("sdk.xcode.path").empty()) cfg.xcode_path = wide("sdk.xcode.path");
        if (!get("toolchains.swift").empty()) cfg.toolchain_path = wide("toolchains.swift");
        if (!get("toolchains.llvm").empty()) cfg.llvm_path = wide("toolchains.llvm");
        if (!get("tools.git").empty()) cfg.git_path = wide("tools.git");
        if (!get("tools.zsign").empty()) cfg.zsign_path = wide("tools.zsign");
        if (!get("tools.pymobiledevice3").empty()) cfg.pymobiledevice3_path = wide("tools.pymobiledevice3");
        if (!get("tools.ipsw").empty()) cfg.ipsw_path = wide("tools.ipsw");
        if (!get("tools.darling").empty()) cfg.darling_tools_path = wide("tools.darling");
        if (has_credentials_dir) cfg.credentials_dir = wide("secrets.credentials_dir");
        else if (has_user_state) cfg.credentials_dir = (fs::path(cfg.user_state_root) / "credentials").wstring();

        if (has_certificates_dir) cfg.certificates_dir = wide("secrets.certificates_dir");
        else if (has_user_state) cfg.certificates_dir = (fs::path(cfg.user_state_root) / "certificates").wstring();

        if (has_secrets_file) cfg.secrets_path = wide("secrets.file");
        else if (has_user_state || has_credentials_dir) cfg.secrets_path = (fs::path(cfg.credentials_dir) / "secrets.json").wstring();

        if (!has_cache && has_user_state) cfg.cache_root = (fs::path(cfg.user_state_root) / "cache").wstring();
        if (!get("signing.p12").empty()) cfg.signing_p12_path = wide("signing.p12");
        if (!get("signing.provisioning_profile").empty()) cfg.signing_profile_path = wide("signing.provisioning_profile");
        if (!get("signing.password_dpapi").empty()) cfg.signing_password_dpapi_path = wide("signing.password_dpapi");
        if (!get("build.default_bundle_id").empty()) cfg.default_bundle_id = wide("build.default_bundle_id");
        if (!get("wsl.distro").empty()) cfg.wsl_distro = wide("wsl.distro");
        if (!get("build.default_jobs").empty()) {
            try { cfg.default_jobs = static_cast<unsigned int>(std::stoul(get("build.default_jobs"))); } catch (...) {}
        }
        if (!get("bootstrap.auto_install").empty()) cfg.bootstrap_auto_install = ParseBool(get("bootstrap.auto_install"), true);

        for (const auto& [key, value] : values) {
            std::smatch match;
            if (std::regex_match(key, match, std::regex(R"(^sdk\.ios\.(.+)\.path$)")) && match.size() > 1) {
                cfg.ios_sdk_paths[Win32Process::ToWide(match[1].str())] = Win32Process::ToWide(value);
            } else if (std::regex_match(key, match, std::regex(R"(^sdk\.macos\.(.+)\.path$)")) && match.size() > 1) {
                cfg.macos_sdk_paths[Win32Process::ToWide(match[1].str())] = Win32Process::ToWide(value);
            }
        }
        if (!cfg.ios_sdk_version.empty()) {
            const auto it = cfg.ios_sdk_paths.find(cfg.ios_sdk_version);
            if (it != cfg.ios_sdk_paths.end() && !it->second.empty()) cfg.sdk_path = it->second;
        }
        return cfg;
    }

    // One-time migration from the v4 JSON config.
    const fs::path legacy = fs::path(GetHomeDir()) / ".OPENFRUIT" / "config.json";
    if (fs::exists(legacy)) {
        std::ifstream f(legacy, std::ios::binary);
        const std::string json((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        cfg.sdk_path = Win32Process::ToWide(ExtractJsonString(json, "sdk_path"));
        cfg.toolchain_path = Win32Process::ToWide(ExtractJsonString(json, "toolchain_path"));
        const std::string bundle = ExtractJsonString(json, "default_bundle_id");
        if (!bundle.empty()) cfg.default_bundle_id = Win32Process::ToWide(bundle);
        const std::string distro = ExtractJsonString(json, "wsl_distro");
        if (!distro.empty()) cfg.wsl_distro = Win32Process::ToWide(distro);
        std::regex jobs_reg("\"default_jobs\"\\s*:\\s*([0-9]+)");
        std::smatch match;
        if (std::regex_search(json, match, jobs_reg) && match.size() > 1) {
            cfg.default_jobs = static_cast<unsigned int>(std::stoul(match[1].str()));
        }
        if (initialize_missing) cfg.Save();
    }
    return cfg;
}

bool Config::Save(const std::wstring& custom_path) const {
    return SaveImpl(custom_path, nullptr);
}

bool Config::SaveIfUnchanged(const std::wstring& custom_path, const std::string& expected_sha256) const {
    if (expected_sha256.size() != 64 || !std::all_of(expected_sha256.begin(), expected_sha256.end(),
        [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); })) return false;
    return SaveImpl(custom_path, &expected_sha256);
}

std::optional<std::string> Config::SerializePublication() const {
    // Serialize the complete snapshot before touching persistent state. A
    // failed write/flush/replacement must leave the previous configuration intact.
    std::ostringstream out;

    out << "# OPENFRUIT user configuration. Paths may point to managed or external toolchains.\n\n"
        << "[paths]\n"
        << "home = " << QuoteToml(OPENFRUIT_home) << "\n"
        << "user_state = " << QuoteToml(user_state_root) << "\n"
        << "cache = " << QuoteToml(cache_root) << "\n\n"
        << "[sdk.ios]\n"
        << "path = " << QuoteToml(sdk_path) << "\n"
        << "version = " << QuoteToml(ios_sdk_version) << "\n\n"
        << "[sdk.macos]\n"
        << "path = " << QuoteToml(macos_sdk_path) << "\n\n"
        << "[sdk.xcode]\n"
        << "path = " << QuoteToml(xcode_path) << "\n\n";

    for (const auto& [version, path_value] : ios_sdk_paths) {
        out << "[sdk.ios." << Win32Process::ToNarrow(version) << "]\n"
            << "path = " << QuoteToml(path_value) << "\n\n";
    }
    for (const auto& [version, path_value] : macos_sdk_paths) {
        out << "[sdk.macos." << Win32Process::ToNarrow(version) << "]\n"
            << "path = " << QuoteToml(path_value) << "\n\n";
    }

    out << "[toolchains]\n"
        << "swift = " << QuoteToml(toolchain_path) << "\n"
        << "llvm = " << QuoteToml(llvm_path) << "\n\n"
        << "[tools]\n"
        << "git = " << QuoteToml(git_path) << "\n"
        << "zsign = " << QuoteToml(zsign_path) << "\n"
        << "pymobiledevice3 = " << QuoteToml(pymobiledevice3_path) << "\n"
        << "ipsw = " << QuoteToml(ipsw_path) << "\n"
        << "darling = " << QuoteToml(darling_tools_path) << "\n\n"
        << "[secrets]\n"
        << "file = " << QuoteToml(secrets_path) << "\n"
        << "credentials_dir = " << QuoteToml(credentials_dir) << "\n"
        << "certificates_dir = " << QuoteToml(certificates_dir) << "\n\n"
        << "[signing]\n"
        << "p12 = " << QuoteToml(signing_p12_path) << "\n"
        << "provisioning_profile = " << QuoteToml(signing_profile_path) << "\n"
        << "password_dpapi = " << QuoteToml(signing_password_dpapi_path) << "\n\n"
        << "[build]\n"
        << "default_bundle_id = " << QuoteToml(default_bundle_id) << "\n"
        << "default_jobs = " << default_jobs << "\n\n"
        << "[wsl]\n"
        << "distro = " << QuoteToml(wsl_distro) << "\n\n"
        << "[bootstrap]\n"
        << "auto_install = " << (bootstrap_auto_install ? "true" : "false") << "\n";
    if (!out) return std::nullopt;
    return out.str();
}

std::optional<std::string> Config::PublicationSha256() const {
    const auto bytes = SerializePublication();
    return bytes ? Sha256(*bytes) : std::nullopt;
}

bool Config::SaveImpl(const std::wstring& custom_path, const std::string* expected_sha256) const {
    const auto bytes = SerializePublication();
    if (!bytes) return false;
    const fs::path path = custom_path.empty() ? fs::path(GetDefaultConfigPath()) : fs::path(custom_path);
    try {
        std::error_code error;
        const auto absolute = fs::absolute(path, error).lexically_normal();
        if (error) return false;
        // Both unconditional and conditional native writers use this same
        // nonblocking lease. No pin or caller-owned lease is held recursively.
        const auto writer = ArtifactLease::TryAcquire(absolute);
        if (!writer) return false;
        if (expected_sha256) {
            auto native_path = absolute.wstring();
            if (native_path.rfind(LR"(\\?\)", 0) != 0)
                native_path = native_path.rfind(LR"(\\)", 0) == 0 ?
                    LR"(\\?\UNC\)" + native_path.substr(2) : LR"(\\?\)" + native_path;
            HANDLE pin = CreateFileW(native_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (pin == INVALID_HANDLE_VALUE) return false;
            struct ReadPin { HANDLE value; ~ReadPin() { CloseHandle(value); } } held{pin};
            BY_HANDLE_FILE_INFORMATION info{};
            if (!GetFileInformationByHandle(pin, &info) || info.nNumberOfLinks != 1 ||
                (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) return false;
            const auto observed = Sha256FileHandle(pin);
            if (!observed || *observed != *expected_sha256) return false;
        } // Close the read/delete pin before replacement, retaining writer lease.
        return AtomicFile::Publish(absolute, *bytes);
    } catch (...) { return false; }
}

void Config::AutoDiscover(const std::wstring& repo_root_value) {
    bool changed = false;
    const fs::path root(repo_root_value);

    if (OPENFRUIT_home.empty()) { OPENFRUIT_home = ToolPaths::LocalHome().wstring(); changed = true; }
    if (user_state_root.empty()) { user_state_root = ToolPaths::UserStateRoot().wstring(); changed = true; }
    if (cache_root.empty()) { cache_root = (fs::path(user_state_root) / "cache").wstring(); changed = true; }
    if (credentials_dir.empty()) { credentials_dir = (fs::path(user_state_root) / "credentials").wstring(); changed = true; }
    if (certificates_dir.empty()) { certificates_dir = (fs::path(user_state_root) / "certificates").wstring(); changed = true; }
    if (secrets_path.empty()) { secrets_path = (fs::path(credentials_dir) / "secrets.json").wstring(); changed = true; }

    if (sdk_path.empty() || !fs::exists(sdk_path)) {
        const fs::path discovered = ToolPaths::IosSdk(root);
        if (!discovered.empty()) { sdk_path = discovered.wstring(); changed = true; }
    }
    if (xcode_path.empty() || !fs::exists(xcode_path)) {
        const fs::path discovered = ToolPaths::XcodeRoot(root);
        if (!discovered.empty()) { xcode_path = discovered.wstring(); changed = true; }
    }
    if (toolchain_path.empty() || !fs::exists(toolchain_path)) {
        const fs::path discovered = ToolPaths::SwiftBin(root);
        if (!discovered.empty()) { toolchain_path = discovered.wstring(); changed = true; }
    }
    if (llvm_path.empty() || !fs::exists(llvm_path)) {
        const fs::path discovered = ToolPaths::LlvmBin(root);
        if (!discovered.empty()) { llvm_path = discovered.wstring(); changed = true; }
    }
    if (git_path.empty() || !fs::exists(git_path)) {
        const fs::path discovered = ToolPaths::Git();
        if (!discovered.empty()) { git_path = discovered.wstring(); changed = true; }
    }
    if (zsign_path.empty() || !fs::exists(zsign_path)) {
        const fs::path discovered = ToolPaths::Zsign(root);
        if (!discovered.empty()) { zsign_path = discovered.wstring(); changed = true; }
    }
    if (pymobiledevice3_path.empty() || !fs::exists(pymobiledevice3_path)) {
        const fs::path discovered = ToolPaths::Pymobiledevice3(root);
        if (!discovered.empty()) { pymobiledevice3_path = discovered.wstring(); changed = true; }
    }
    if (ipsw_path.empty() || !fs::exists(ipsw_path)) {
        const fs::path discovered = ToolPaths::Ipsw();
        if (!discovered.empty()) { ipsw_path = discovered.wstring(); changed = true; }
    }
    if (darling_tools_path.empty() || !fs::exists(darling_tools_path)) {
        const fs::path discovered = ToolPaths::DarlingRoot(root);
        if (!discovered.empty()) { darling_tools_path = discovered.wstring(); changed = true; }
    }

    if (changed) Save();
}

std::map<std::wstring, std::wstring> Config::BuildEnvironmentVariables(
    const std::wstring& current_path_env) const {
    std::map<std::wstring, std::wstring> env;
    const auto set_if_not_empty = [&](const wchar_t* name, const std::wstring& value) {
        if (!value.empty()) env[name] = value;
    };
    set_if_not_empty(L"OPENFRUIT_HOME", OPENFRUIT_home);
    set_if_not_empty(L"OPENFRUIT_USER_STATE", user_state_root);
    set_if_not_empty(L"OPENFRUIT_CACHE_ROOT", cache_root);
    set_if_not_empty(L"OPENFRUIT_IOS_SDK", sdk_path);
    set_if_not_empty(L"OPENFRUIT_XCODE_PATH", xcode_path);
    set_if_not_empty(L"OPENFRUIT_SWIFT_BIN", toolchain_path);
    set_if_not_empty(L"OPENFRUIT_LLVM_BIN", llvm_path);
    set_if_not_empty(L"OPENFRUIT_ZSIGN", zsign_path);
    set_if_not_empty(L"OPENFRUIT_PYMOBILEDEVICE3", pymobiledevice3_path);
    set_if_not_empty(L"OPENFRUIT_IPSW", ipsw_path);
    set_if_not_empty(L"OPENFRUIT_DARLING_TOOLS", darling_tools_path);
    set_if_not_empty(L"OPENFRUIT_WSL_DISTRO", wsl_distro);

    if (!git_path.empty()) {
        const fs::path git(git_path);
        std::error_code ec;
        const std::wstring git_dir = (fs::is_directory(git, ec) && !ec)
            ? git.wstring()
            : git.parent_path().wstring();
        if (!git_dir.empty()) {
            if (current_path_env.empty()) {
                env[L"PATH"] = git_dir;
            } else if (PathContainsDirectory(current_path_env, git_dir)) {
                env[L"PATH"] = current_path_env;
            } else {
                env[L"PATH"] = git_dir + L";" + current_path_env;
            }
        }
    }
    return env;
}

void Config::ApplyEnvironment() const {
    const std::wstring current_path = ReadEnvironment(L"PATH");
    const auto env = BuildEnvironmentVariables(current_path);
    for (const auto& [key, value] : env) {
        _wputenv_s(key.c_str(), value.c_str());
        SetEnvironmentVariableW(key.c_str(), value.c_str());
    }
}

void Config::SetValue(const std::string& key, const std::string& value) {
    const std::wstring wide = Win32Process::ToWide(value);
    if (key == "paths.home" || key == "OPENFRUIT_home") OPENFRUIT_home = wide;
    else if (key == "paths.user_state" || key == "user_state_root") user_state_root = wide;
    else if (key == "paths.cache" || key == "cache_root") cache_root = wide;
    else if (key == "sdk.ios.path" || key == "sdk_path") {
        sdk_path = wide;
        if (!ios_sdk_version.empty()) {
            ios_sdk_paths[ios_sdk_version] = wide;
        }
    }
    else if (key == "sdk.ios.version" || key == "ios_sdk_version") ios_sdk_version = wide;
    else if (key == "sdk.macos.path" || key == "macos_sdk_path") macos_sdk_path = wide;
    else if (key == "sdk.xcode.path" || key == "xcode_path") xcode_path = wide;
    else if (key == "toolchains.swift" || key == "toolchain_path") toolchain_path = wide;
    else if (key == "toolchains.llvm" || key == "llvm_path") llvm_path = wide;
    else if (key == "tools.git" || key == "git_path") git_path = wide;
    else if (key == "tools.zsign" || key == "zsign_path") zsign_path = wide;
    else if (key == "tools.pymobiledevice3" || key == "pymobiledevice3_path") pymobiledevice3_path = wide;
    else if (key == "tools.ipsw" || key == "ipsw_path") ipsw_path = wide;
    else if (key == "tools.darling" || key == "darling_tools_path") darling_tools_path = wide;
    else if (key == "secrets.file" || key == "secrets_path") secrets_path = wide;
    else if (key == "secrets.credentials_dir" || key == "credentials_dir") credentials_dir = wide;
    else if (key == "secrets.certificates_dir" || key == "certificates_dir") certificates_dir = wide;
    else if (key == "signing.p12" || key == "signing_p12" || key == "signing_p12_path") signing_p12_path = wide;
    else if (key == "signing.provisioning_profile" || key == "signing_profile" || key == "signing_profile_path" || key == "signing.profile") signing_profile_path = wide;
    else if (key == "signing.password_dpapi" || key == "signing_password_dpapi" || key == "signing_password_dpapi_path") signing_password_dpapi_path = wide;
    else if (key == "signing.password" || key == "signing_password") {
        // Plaintext password provided by user: encrypt via DPAPI into credentials store and set signing_password_dpapi_path
        const fs::path creds_dir = credentials_dir.empty() ? fs::path(user_state_root) / "credentials" : fs::path(credentials_dir);
        std::error_code ec;
        fs::create_directories(creds_dir, ec);
        const fs::path dpapi_file = creds_dir / "signing.password.dpapi";
        if (ProtectedCredentialStore::Write(dpapi_file, wide, CredentialPurpose::SigningPassword)) {
            signing_password_dpapi_path = dpapi_file.wstring();
        }
    }
    else if (key == "build.default_bundle_id" || key == "default_bundle_id") default_bundle_id = wide;
    else if (key == "wsl.distro" || key == "wsl_distro") wsl_distro = wide;
    else if (key == "build.default_jobs" || key == "default_jobs") default_jobs = static_cast<unsigned int>(std::stoul(value));
    else if (key == "bootstrap.auto_install") bootstrap_auto_install = ParseBool(value, bootstrap_auto_install);
    else {
        std::smatch match;
        if (std::regex_match(key, match, std::regex(R"(^sdk\.ios\.(.+)\.path$)")) && match.size() > 1) {
            ios_sdk_paths[Win32Process::ToWide(match[1].str())] = wide;
        } else if (std::regex_match(key, match, std::regex(R"(^sdk\.macos\.(.+)\.path$)")) && match.size() > 1) {
            macos_sdk_paths[Win32Process::ToWide(match[1].str())] = wide;
        }
    }
}

std::string Config::GetValue(const std::string& key) const {
    if (key == "paths.home" || key == "OPENFRUIT_home") return Win32Process::ToNarrow(OPENFRUIT_home);
    if (key == "paths.user_state" || key == "user_state_root") return Win32Process::ToNarrow(user_state_root);
    if (key == "paths.cache" || key == "cache_root") return Win32Process::ToNarrow(cache_root);
    if (key == "sdk.ios.path" || key == "sdk_path") return Win32Process::ToNarrow(sdk_path);
    if (key == "sdk.ios.version" || key == "ios_sdk_version") return Win32Process::ToNarrow(ios_sdk_version);
    if (key == "sdk.macos.path" || key == "macos_sdk_path") return Win32Process::ToNarrow(macos_sdk_path);
    if (key == "sdk.xcode.path" || key == "xcode_path") return Win32Process::ToNarrow(xcode_path);
    if (key == "toolchains.swift" || key == "toolchain_path") return Win32Process::ToNarrow(toolchain_path);
    if (key == "toolchains.llvm" || key == "llvm_path") return Win32Process::ToNarrow(llvm_path);
    if (key == "tools.git" || key == "git_path") return Win32Process::ToNarrow(git_path);
    if (key == "tools.zsign" || key == "zsign_path") return Win32Process::ToNarrow(zsign_path);
    if (key == "tools.pymobiledevice3" || key == "pymobiledevice3_path") return Win32Process::ToNarrow(pymobiledevice3_path);
    if (key == "tools.ipsw" || key == "ipsw_path") return Win32Process::ToNarrow(ipsw_path);
    if (key == "tools.darling" || key == "darling_tools_path") return Win32Process::ToNarrow(darling_tools_path);
    if (key == "secrets.file" || key == "secrets_path") return Win32Process::ToNarrow(secrets_path);
    if (key == "secrets.credentials_dir" || key == "credentials_dir") return Win32Process::ToNarrow(credentials_dir);
    if (key == "secrets.certificates_dir" || key == "certificates_dir") return Win32Process::ToNarrow(certificates_dir);
    if (key == "signing.p12" || key == "signing_p12" || key == "signing_p12_path") return Win32Process::ToNarrow(signing_p12_path);
    if (key == "signing.provisioning_profile" || key == "signing_profile" || key == "signing_profile_path" || key == "signing.profile") return Win32Process::ToNarrow(signing_profile_path);
    if (key == "signing.password_dpapi" || key == "signing_password_dpapi" || key == "signing_password_dpapi_path") return Win32Process::ToNarrow(signing_password_dpapi_path);
    if (key == "build.default_bundle_id" || key == "default_bundle_id") return Win32Process::ToNarrow(default_bundle_id);
    if (key == "wsl.distro" || key == "wsl_distro") return Win32Process::ToNarrow(wsl_distro);
    if (key == "build.default_jobs" || key == "default_jobs") return std::to_string(default_jobs);
    if (key == "bootstrap.auto_install") return bootstrap_auto_install ? "true" : "false";
    std::smatch match;
    if (std::regex_match(key, match, std::regex(R"(^sdk\.ios\.(.+)\.path$)")) && match.size() > 1) {
        const auto it = ios_sdk_paths.find(Win32Process::ToWide(match[1].str()));
        return it == ios_sdk_paths.end() ? std::string{} : Win32Process::ToNarrow(it->second);
    }
    if (std::regex_match(key, match, std::regex(R"(^sdk\.macos\.(.+)\.path$)")) && match.size() > 1) {
        const auto it = macos_sdk_paths.find(Win32Process::ToWide(match[1].str()));
        return it == macos_sdk_paths.end() ? std::string{} : Win32Process::ToNarrow(it->second);
    }
    return {};
}

} // namespace OpenFruit
