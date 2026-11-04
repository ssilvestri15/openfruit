#pragma once
#include "json_value.hpp"
#include <filesystem>
namespace OpenFruit {
// Diagnostic aggregation only: never executes or substitutes guest services.
JsonValue ReportDarwinProgress(const std::filesystem::path& inventory,
    const std::filesystem::path& probe, const std::filesystem::path& command,
    const std::filesystem::path& ledger, const std::filesystem::path& previous = {});
}
