#pragma once

#include "sdk_manager.hpp"

#include <filesystem>

namespace OpenFruit {

std::filesystem::path EnsureIosAvailabilityRuntimeObject(
    const std::filesystem::path& repo_root,
    const std::filesystem::path& clang_executable,
    const SDKInfo& sdk_info
);



} // namespace OpenFruit
