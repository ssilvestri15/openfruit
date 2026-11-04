#include "protected_credential_store.hpp"
#include "atomic_file.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <cctype>
#include <fstream>
#include <iterator>
#include <limits>
#include <vector>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
constexpr wchar_t apple_entropy[] = L"OPENFRUIT.AppleSession.v1";
constexpr wchar_t cookies_entropy[] = L"OPENFRUIT.AppleCookies.v1";
DATA_BLOB Entropy(CredentialPurpose purpose) {
    DATA_BLOB blob{};
    if (purpose == CredentialPurpose::AppleSession) {
        blob.pbData = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(apple_entropy));
        blob.cbData = sizeof(apple_entropy);
    } else if (purpose == CredentialPurpose::AppleCookies) {
        blob.pbData = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(cookies_entropy));
        blob.cbData = sizeof(cookies_entropy);
    }
    return blob;
}
struct LocalBlob {
    DATA_BLOB value{};
    ~LocalBlob() {
        if (value.pbData) {
            SecureZeroMemory(value.pbData, value.cbData);
            LocalFree(value.pbData);
        }
    }
};
int Hex(unsigned char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}
}
bool ProtectedCredentialStore::Publish(const fs::path& destination, const std::string& bytes) {
    return AtomicFile::Publish(destination, bytes);
}
bool ProtectedCredentialStore::Write(const fs::path& path, const std::wstring& secret, CredentialPurpose purpose) {
    if (secret.size() > 128 * 1024 || secret.find(L'\0') != std::wstring::npos) return false;
    DATA_BLOB plain{};
    plain.pbData = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(secret.data()));
    plain.cbData = static_cast<DWORD>(secret.size() * sizeof(wchar_t));
    auto entropy = Entropy(purpose);
    LocalBlob cipher;
    if (!CryptProtectData(&plain, L"OPENFRUIT protected credential", entropy.cbData ? &entropy : nullptr,
        nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &cipher.value)) return false;
    constexpr char hex[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(cipher.value.cbData * 2);
    for (DWORD index = 0; index < cipher.value.cbData; ++index) {
        const BYTE ch = cipher.value.pbData[index];
        encoded.push_back(hex[ch >> 4]); encoded.push_back(hex[ch & 15]);
    }
    return Publish(path, encoded);
}
bool ProtectedCredentialStore::Read(const fs::path& path, std::wstring& secret, CredentialPurpose purpose) {
    secret.clear();
    std::error_code ec;
    if (fs::file_size(path, ec) > 1024 * 1024 || ec) return false;
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    std::string encoded(1024 * 1024 + 1, '\0');
    input.read(encoded.data(), static_cast<std::streamsize>(encoded.size()));
    if (input.gcount() > 1024 * 1024) return false;
    encoded.resize(static_cast<std::size_t>(input.gcount()));
    while (!encoded.empty() && std::isspace(static_cast<unsigned char>(encoded.back()))) encoded.pop_back();
    const auto start = encoded.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return false;
    encoded.erase(0, start);
    if (encoded.size() % 2) return false;
    std::vector<BYTE> bytes;
    bytes.reserve(encoded.size() / 2);
    for (std::size_t index = 0; index < encoded.size(); index += 2) {
        const int high = Hex(encoded[index]), low = Hex(encoded[index + 1]);
        if (high < 0 || low < 0) return false;
        bytes.push_back(static_cast<BYTE>((high << 4) | low));
    }
    DATA_BLOB cipher{static_cast<DWORD>(bytes.size()), bytes.data()};
    auto entropy = Entropy(purpose);
    LocalBlob plain;
    if (!CryptUnprotectData(&cipher, nullptr, entropy.cbData ? &entropy : nullptr,
        nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain.value)) return false;
    if (plain.value.cbData % sizeof(wchar_t)) return false;
    auto count = plain.value.cbData / sizeof(wchar_t);
    const auto* characters = reinterpret_cast<const wchar_t*>(plain.value.pbData);
    while (count && characters[count - 1] == L'\0') --count;
    if (count) secret.assign(characters, count);
    return true;
}
}
