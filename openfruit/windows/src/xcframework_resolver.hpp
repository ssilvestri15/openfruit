#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace OpenFruit {

struct XcframeworkSliceResult {
    bool success = false;
    std::vector<std::filesystem::path> libraries;
    std::string error;
};

// Resolves XCFramework containers to the concrete library selected by Xcode's
// platform, variant, and architecture contract. Non-XCFramework paths pass
// through unchanged.
XcframeworkSliceResult ResolveXcframeworkSlices(
    const std::vector<std::filesystem::path>& artifacts,
    const std::wstring& target_triple
);

} // namespace OpenFruit
