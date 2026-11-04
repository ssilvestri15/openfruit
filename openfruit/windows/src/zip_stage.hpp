#pragma once
#include "zip_member.hpp"
#include <filesystem>
namespace OpenFruit {
struct ZipStageResult {
    ZipMemberResult stream;
    std::filesystem::path path;
    bool digest_matched = false;
    bool encrypted_input_retained = false;
    std::string error;
    JsonValue ToJson() const;
};
ZipStageResult StageZipMember(const ZipInventoryResult&,const std::string& name,const ZipInventoryRead&,
    const std::filesystem::path& new_directory,const std::string& hash_method,const std::string& digest_hex,
    CancellationToken = {},std::chrono::steady_clock::time_point = std::chrono::steady_clock::time_point::max());
}
