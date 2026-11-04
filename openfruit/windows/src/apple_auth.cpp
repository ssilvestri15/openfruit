#include "apple_auth.hpp"
#include "win32_process.hpp"
#include "protected_credential_store.hpp"
#include "operation_events.hpp"

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace OpenFruit {

bool AppleAuth::Login(
    Secrets& secrets,
    const std::string& apple_id,
    const std::string& password_or_token,
    const std::wstring& secrets_path
) {
    if (apple_id.empty()) {
        std::cerr
            << "OPENFRUIT Error: Apple ID cannot be empty."
            << std::endl;

        return false;
    }

    Secrets updated = secrets;
    const auto account = Win32Process::ToWide(apple_id);
    if (updated.apple_id != account) {
        updated.apple_session_dpapi_path.clear();
        updated.apple_cookies_dpapi_path.clear();
    }
    updated.apple_id = account;
    if (!password_or_token.empty()) {
        const fs::path metadata = secrets_path.empty()
            ? fs::path(Secrets::GetDefaultSecretsPath()) : fs::path(secrets_path);
        const auto protected_path = fs::absolute(metadata).parent_path() /
            ("apple-session-" + NewOperationId() + ".dpapi");
        if (!ProtectedCredentialStore::Write(protected_path,
                Win32Process::ToWide(password_or_token), CredentialPurpose::AppleSession)) return false;
        updated.apple_session_dpapi_path = protected_path.wstring();
    }
    if (!updated.Save(secrets_path)) return false;
    secrets = std::move(updated);

    std::cout
        << "OPENFRUIT: Apple Developer account configured: "
        << apple_id
        << std::endl;

    return true;
}

} // namespace OpenFruit
