#pragma once
#include "json_value.hpp"
#include "hpke_native.hpp"
#include <memory>
#include <string>
#include <string_view>
namespace OpenFruit {
// Ephemeral Windows CNG key, never persisted or serialized.
class AeaFcsKey {
public:
    ~AeaFcsKey();
    AeaFcsKey(const AeaFcsKey&) = delete;
    AeaFcsKey& operator=(const AeaFcsKey&) = delete;
    static std::unique_ptr<AeaFcsKey> ImportPem(std::string_view, std::string& error);
    std::unique_ptr<SecretBytes> OpenHpke(std::string_view enc, std::string_view ciphertext,
        std::string_view info, std::string_view aad, std::string& error) const;
    JsonValue ToJson() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit AeaFcsKey(std::unique_ptr<Impl>);
};
}
