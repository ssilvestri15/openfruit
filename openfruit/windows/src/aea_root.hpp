#pragma once
#include "hpke_native.hpp"
#include "json_value.hpp"
#include <cstdint>
#include <memory>
#include <functional>
#include <optional>
#include "cancellation.hpp"
#include <chrono>
namespace OpenFruit {
struct AeaDecodeResult {
    bool authenticated=false;
    std::uint64_t decoded_bytes=0,input_bytes=0,clusters=0,segments=0,padding_bytes=0;
    std::string sha256,sha384,error;
    JsonValue ToJson() const;
};
using AeaRead=std::function<std::optional<std::string>(std::uint64_t,std::uint64_t)>;
using AeaSink=std::function<bool(std::string_view)>;
// Authenticated root metadata; Decode verifies the full remaining container.
class AeaRoot {
public:
    ~AeaRoot();
    AeaRoot(const AeaRoot&) = delete;
    AeaRoot& operator=(const AeaRoot&) = delete;
    static std::unique_ptr<AeaRoot> Open(std::uint32_t profile, std::string_view auth_data,
        std::string_view master_key, std::string_view salt, std::string_view encrypted_root,
        std::uint64_t input_bytes, std::string& error);
    AeaDecodeResult Decode(const AeaRead&,const AeaSink&,CancellationToken = {},
        std::chrono::steady_clock::time_point = std::chrono::steady_clock::time_point::max()) const;
    JsonValue ToJson() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit AeaRoot(std::unique_ptr<Impl>);
};
}
