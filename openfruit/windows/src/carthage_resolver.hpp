#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace OpenFruit {

struct CarthageResolveResult {
    bool success = false;
    // Verified XCFramework containers retained for cache/provenance tracking.
    std::vector<std::filesystem::path> frameworks;
    // Concrete iOS-device framework slices consumed by compile/link/embed.
    std::vector<std::filesystem::path> device_frameworks;
    std::string error;
};

// Resolves exact-version binary Cartfile entries into the versioned OPENFRUIT
// cache and returns the XCFrameworks referenced by the selected Xcode target.
// The upstream source tree is never modified.
CarthageResolveResult ResolveCarthageBinaryFrameworks(
    const std::filesystem::path& source_root,
    const std::vector<std::filesystem::path>& declared_frameworks
);

} // namespace OpenFruit
