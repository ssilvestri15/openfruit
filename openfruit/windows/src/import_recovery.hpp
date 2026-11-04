#pragma once
#include "win32_process.hpp"
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
namespace OpenFruit {
struct ImportRecoveryOutcome {
    ProcessResult result;
    std::vector<std::wstring> arguments;
};
// The caller owns configuration/environment. Recovery consumes the authoritative
// graph and its operation cache explicitly; it never edits project sources.
std::optional<ImportRecoveryOutcome> RecoverImplicitSwiftImports(
    const std::wstring& swiftc,
    const std::vector<std::wstring>& arguments,
    const ProcessResult& baseline,
    const std::filesystem::path& build_description,
    const std::filesystem::path& recovery_root);
}
