#include "apple_auth.hpp"
#include "operation_events.hpp"
#include "protected_credential_store.hpp"
#include "json_value.hpp"
#include <fstream>
#include <iterator>
#include <windows.h>
#include <filesystem>
#include <iostream>
int main() {
    const auto root = std::filesystem::temp_directory_path() / ("OPENFRUIT-credential-tests-" + OpenFruit::NewOperationId());
    std::filesystem::create_directories(root);
    OpenFruit::Secrets secrets;
    secrets.signing_password = L"DPAPI:" + (root / "signing-password.dpapi").wstring();
    secrets.signing_p12_path = (root / "certificate.p12").wstring();
    const auto expected_password = secrets.signing_password;
    const auto expected_certificate = secrets.signing_p12_path;
    if (!OpenFruit::AppleAuth::Login(secrets, "owned-test@example.invalid", "owned-test-apple-token", (root / "secrets.json").wstring())) return 2;
    if (secrets.signing_password != expected_password || secrets.signing_p12_path != expected_certificate) {
        std::cerr << "Apple account configuration changed signing credentials.\n";
        return 1;
    }
    const auto reloaded = OpenFruit::Secrets::Load((root / "secrets.json").wstring());
    if (reloaded.signing_password != expected_password || reloaded.signing_p12_path != expected_certificate
        || reloaded.apple_session_dpapi_path.empty()) return 3;
    std::wstring decoded;
    using Store = OpenFruit::ProtectedCredentialStore;
    using Purpose = OpenFruit::CredentialPurpose;
    if (!Store::Read(reloaded.apple_session_dpapi_path, decoded, Purpose::AppleSession)
        || decoded != L"owned-test-apple-token") return 4;
    if (Store::Read(reloaded.apple_session_dpapi_path, decoded, Purpose::SigningPassword)) return 5;
    const auto signing = root / "signing.dpapi";
    const std::wstring owned_password = L"owned-signing-password-\u03c0\r\n";
    if (!Store::Write(signing, owned_password, Purpose::SigningPassword)
        || !Store::Read(signing, decoded, Purpose::SigningPassword) || decoded != owned_password) return 6;
    if (Store::Read(signing, decoded, Purpose::AppleSession)) return 7;
    if (!Store::Write(root / "empty.dpapi", L"", Purpose::SigningPassword)
        || !Store::Read(root / "empty.dpapi", decoded, Purpose::SigningPassword) || !decoded.empty()) return 8;
    auto legacy = OpenFruit::JsonValue::ObjectValue();
    legacy.Set("signing_password", OpenFruit::JsonValue::String("owned-legacy-password"));
    legacy.Set("signing_p12_path", OpenFruit::JsonValue::String((root / "legacy.p12").string()));
    const auto legacy_path = root / "legacy.json";
    if (!Store::Publish(legacy_path, legacy.Serialize())) return 9;
    const auto migrated = OpenFruit::Secrets::Load(legacy_path.wstring());
    if (migrated.signing_password.rfind(L"DPAPI:", 0) != 0
        || !Store::Read(migrated.signing_password.substr(6), decoded, Purpose::SigningPassword)
        || decoded != L"owned-legacy-password") return 10;
    std::ifstream migrated_input(legacy_path);
    const std::string metadata((std::istreambuf_iterator<char>(migrated_input)), std::istreambuf_iterator<char>());
    if (metadata.find("owned-legacy-password") != std::string::npos || !OpenFruit::JsonValue::Parse(metadata)) return 11;
    auto unchanged = reloaded;
    const auto invalid_destination = root / "metadata-directory";
    std::filesystem::create_directories(invalid_destination);
    if (OpenFruit::AppleAuth::Login(unchanged, "different-owned-test@example.invalid", "owned-token-two", invalid_destination.wstring())) return 12;
    if (unchanged.apple_id != reloaded.apple_id || unchanged.apple_session_dpapi_path != reloaded.apple_session_dpapi_path) return 13;
    if (!OpenFruit::AppleAuth::Login(unchanged, "different-owned-test@example.invalid", "", (root / "changed-account.json").wstring())
        || !unchanged.apple_session_dpapi_path.empty() || unchanged.signing_password != expected_password) return 14;
    // A requested missing custom store must never silently read another account.
    if (!OpenFruit::Secrets::Load((root / "missing.json").wstring()).apple_id.empty()) return 15;
    const auto locked_legacy = root / "read-only-legacy.json";
    if (!Store::Publish(locked_legacy, legacy.Serialize())
        || !SetFileAttributesW(locked_legacy.c_str(), FILE_ATTRIBUTE_READONLY)) return 16;
    bool migration_failed = false;
    try { OpenFruit::Secrets::Load(locked_legacy.wstring()); }
    catch (const std::exception&) { migration_failed = true; }
    SetFileAttributesW(locked_legacy.c_str(), FILE_ATTRIBUTE_NORMAL);
    std::ifstream unchanged_input(locked_legacy);
    const std::string original_metadata((std::istreambuf_iterator<char>(unchanged_input)), std::istreambuf_iterator<char>());
    if (!migration_failed || original_metadata != legacy.Serialize()) return 17;
    if (!Store::Publish(root / "invalid.dpapi", "invalid ciphertext")
        || Store::Read(root / "invalid.dpapi", decoded, Purpose::SigningPassword)) return 18;
    if (Store::Write(root / "nul.dpapi", std::wstring(L"owned\0test", 10), Purpose::SigningPassword)) return 19;
    return 0;
}
