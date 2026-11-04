#pragma once
#include "json_value.hpp"
#include <string>
#include <array>
#include <string_view>
namespace OpenFruit {
// Registration evidence for immutable mounted code, independent of Apple trust.
struct DarwinFileSignature {
    std::uint64_t code_limit=0,end_offset=0,code_pages=0;
    bool cms_present=false,cms_verified=false,ad_hoc=false;
    std::string identifier;
    std::array<std::uint8_t,20> cdhash{};
    JsonValue ToJson() const;
};
// Never mutates the image. Unsupported signature contracts fail explicitly.
int VerifyDarwinFileSignature(std::string_view image,std::uint64_t blob_offset,
    std::uint64_t blob_size,DarwinFileSignature& output,std::string& error);
}
