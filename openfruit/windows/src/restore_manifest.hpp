#pragma once
#include "zip_member.hpp"
#include <optional>
namespace OpenFruit {
struct RestoreManifestResult {
    bool metadata_validated = false;
    JsonValue metadata = JsonValue::ObjectValue();
    std::string error;
    JsonValue ToJson() const;
};
RestoreManifestResult ParseRestoreManifests(const ZipInventoryResult&,
    const ZipMemberResult& restore, const ZipMemberResult& build_manifest);
RestoreManifestResult InspectRestoreArchive(const RangeTransferRequest&);
// Stages every variant of a component, or with `variant` only that one, where
// variants are ordered by how many build identities use them (most first).
JsonValue StageRestoreComponents(const RangeTransferRequest&,const std::string& component,
    const std::filesystem::path& new_directory, std::optional<std::size_t> variant = std::nullopt);
}
