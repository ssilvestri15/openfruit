#pragma once

#include "json_value.hpp"
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace OpenFruit {

struct ManifestProjectionRequirement {
    std::string identity;
    std::vector<std::string> required_products;
};

struct ManifestProjectionResult {
    bool success = true;
    bool changed = false;
    std::unordered_map<std::string, std::filesystem::path> local_packages;
};

class ManifestProjection {
public:
    // Shared bounded original-source evaluation. Callers supply an owned,
    // versioned scratch outside the dependency checkout; no global cache.
    static std::optional<JsonValue> EvaluateOriginalManifest(
        const std::filesystem::path& swift,
        const std::filesystem::path& package,
        const std::filesystem::path& scratch,
        const std::vector<std::pair<std::wstring, std::wstring>>& environment
    );

    static ManifestProjectionResult LoadExistingAppleHostOverlays(
        const std::filesystem::path& swift,
        const std::filesystem::path& scratch,
        const std::vector<ManifestProjectionRequirement>& requirements,
        const std::vector<std::pair<std::wstring, std::wstring>>& environment
    );

    static ManifestProjectionResult PrepareAppleHostOverlays(
        const std::filesystem::path& swift,
        const std::filesystem::path& scratch,
        const std::vector<ManifestProjectionRequirement>& requirements,
        const std::vector<std::pair<std::wstring, std::wstring>>& environment,
        const std::unordered_map<std::string, std::filesystem::path>&
            local_package_overrides
    );
};

} // namespace OpenFruit
