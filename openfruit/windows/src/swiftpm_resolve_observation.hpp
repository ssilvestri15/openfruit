#pragma once

#include "win32_process.hpp"
#include <filesystem>
#include <string_view>
#include <utility>
#include <vector>

namespace OpenFruit {
// Diagnostic observations only: no resolver, environment or cache mutation.
// Allowlisted caller/inherited values exclude the later journal injection.
// File fingerprints are separate bounded observations, not an atomic snapshot.
void EmitSwiftPMResolveObservation(
    std::string_view resolve_id,
    const std::filesystem::path& package,
    const std::filesystem::path& scratch,
    const std::vector<std::pair<std::wstring, std::wstring>>& environment,
    const ProcessResult* result = nullptr) noexcept;
}
