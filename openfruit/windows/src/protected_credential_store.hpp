#pragma once
#include <filesystem>
#include <string>
namespace OpenFruit {
enum class CredentialPurpose { SigningPassword, AppleSession, AppleCookies };
class ProtectedCredentialStore {
public:
    // SigningPassword retains compatibility with existing SecureString DPAPI hex.
    static bool Write(const std::filesystem::path&, const std::wstring&, CredentialPurpose);
    static bool Read(const std::filesystem::path&, std::wstring&, CredentialPurpose);
    static bool Publish(const std::filesystem::path&, const std::string&);
};
}
