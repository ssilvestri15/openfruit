#pragma once

#include "json_value.hpp"
#include "win32_process.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace OpenFruit {

// Static target ABI eligibility only: this does not prove Swift ABI compatibility,
// archive authenticity, symbol completeness, or execution on an iOS device.
struct IosRuntimeArchiveInspection {
    bool eligible = false;
    std::string error;
    std::vector<std::string> architectures;
    std::vector<std::string> minimum_versions;
    JsonValue evidence = JsonValue::ObjectValue();
};

IosRuntimeArchiveInspection InspectIosRuntimeArchive(
    const std::filesystem::path& archive,
    const std::filesystem::path& llvm_bin,
    const std::string& deployment_target,
    const ProcessRunOptions& options = {});

} // namespace OpenFruit
