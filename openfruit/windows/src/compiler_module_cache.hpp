#pragma once

#include <filesystem>
#include <string>

namespace OpenFruit {

struct CompilerModuleCacheResult {
    bool success = false;
    std::filesystem::path path;
    std::string key;
    std::string error;
};

// Prepare an identity-scoped Clang module directory, not an artifact cache hit.
// Clang still owns dependency/header/flag validation and compilation locking.
// Existing legacy directories are preserved and never admitted to this scope.
CompilerModuleCacheResult PrepareCompilerModuleCache(
    const std::filesystem::path& cache_root,
    const std::filesystem::path& swiftc,
    const std::filesystem::path& sdk_root,
    const std::wstring& target,
    const std::wstring& configuration,
    const std::wstring& module_name,
    const std::string& sdk_input_policy);

} // namespace OpenFruit
