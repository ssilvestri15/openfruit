#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <optional>
#include <unordered_map>

namespace OpenFruit {

struct Secrets {
    std::wstring apple_id;
    std::wstring apple_team_id;
    std::wstring signing_p12_path;
    std::wstring signing_profile_path;
    std::wstring signing_password;
    std::wstring apple_session_dpapi_path;
    std::wstring apple_cookies_dpapi_path;

    static std::wstring GetDefaultSecretsPath();
    static Secrets Load(const std::wstring& custom_path = L"");
    bool Save(const std::wstring& custom_path = L"") const;
    void AutoDiscover(const std::wstring& repo_root, const std::wstring& save_path = L"");
};

struct Config {
    // Managed OPENFRUIT layout.
    std::wstring OPENFRUIT_home;
    std::wstring user_state_root;
    std::wstring cache_root;

    // Apple / SDK paths.
    std::wstring sdk_path;
    std::wstring ios_sdk_version;
    std::unordered_map<std::wstring, std::wstring> ios_sdk_paths;
    std::wstring macos_sdk_path;
    std::unordered_map<std::wstring, std::wstring> macos_sdk_paths;
    std::wstring xcode_path;

    // Toolchains and tools.
    std::wstring toolchain_path; // Swift usr/bin
    std::wstring llvm_path;      // LLVM bin
    std::wstring git_path;
    std::wstring zsign_path;
    std::wstring pymobiledevice3_path;
    std::wstring ipsw_path;
    std::wstring darling_tools_path;

    // User-owned secret/certificate locations. These are paths only; callers
    // should keep actual passwords/tokens in DPAPI-protected stores.
    std::wstring secrets_path;
    std::wstring credentials_dir;
    std::wstring certificates_dir;
    std::wstring signing_p12_path;
    std::wstring signing_profile_path;
    std::wstring signing_password_dpapi_path;

    std::wstring default_bundle_id = L"dev.OPENFRUIT.app";
    unsigned int default_jobs = 0; // 0 = auto-detect
    std::wstring wsl_distro = L"Ubuntu";
    bool bootstrap_auto_install = true;

    static std::wstring GetDefaultConfigPath();
    static Config Load(const std::wstring& custom_path = L"", bool initialize_missing = true);
    bool Save(const std::wstring& custom_path = L"") const;
    // Coordinates native Config writers through the existing artifact lease.
    // The expected digest binds exact existing bytes; missing/unsafe files or
    // concurrent writers fail without replacing configuration. External writers
    // that ignore this lease are outside the cooperative transaction contract.
    bool SaveIfUnchanged(const std::wstring& custom_path, const std::string& expected_sha256) const;
    // Pure digest of the exact bytes produced by the shared publication serializer.
    std::optional<std::string> PublicationSha256() const;
    void AutoDiscover(const std::wstring& repo_root);
    std::map<std::wstring, std::wstring> BuildEnvironmentVariables(
        const std::wstring& current_path_env = L"") const;
    void ApplyEnvironment() const;

    void SetValue(const std::string& key, const std::string& value);
    std::string GetValue(const std::string& key) const;
private:
    std::optional<std::string> SerializePublication() const;
    bool SaveImpl(const std::wstring& custom_path, const std::string* expected_sha256) const;
};

} // namespace OpenFruit
