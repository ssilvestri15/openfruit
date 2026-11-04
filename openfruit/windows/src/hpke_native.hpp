#pragma once
#include <memory>
#include <string>
#include <string_view>
namespace OpenFruit {
// Noncopyable secret storage. Never serialize its contents.
class SecretBytes {
public:
    explicit SecretBytes(std::size_t);
    ~SecretBytes();
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    std::string_view View() const noexcept { return bytes_; }
    unsigned char* Data() noexcept;
private:
    std::string bytes_;
};
// RFC 9180 base mode / DHKEM(P256, HKDF-SHA256), HKDF-SHA256,
// AES256-GCM; single-shot recipient, sequence zero. Native CNG handle borrowed.
std::unique_ptr<SecretBytes> HpkeP256Aes256Open(void* recipient_key,
    std::string_view recipient_public, std::string_view encapsulation,
    std::string_view ciphertext, std::string_view info, std::string_view aad,
    std::string& error);
}
