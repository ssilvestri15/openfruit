#pragma once
#include "darwin_closure.hpp"
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace OpenFruit {
inline constexpr wchar_t kDarwinMacroProviderEnvironment[] = L"OPENFRUIT_DARWIN_MACRO_PROVIDER";
inline constexpr wchar_t kDarwinMacroModulesEnvironment[] = L"OPENFRUIT_DARWIN_MACRO_MODULES";
inline constexpr char kDarwinMacroProviderReceipt[] = "provider.json";

struct DarwinMacroProviderPlugin {
    std::string module, virtual_path, sha256;
    std::filesystem::path file;
};

// Validated view of the existing managed SDK provider receipt, not a registry
// or another loader. Original file leases exclude mutation while this view lives.
struct DarwinMacroProvider {
    std::filesystem::path receipt, managed_root, sdk, parent_cache_report;
    std::string executable;
    std::vector<std::filesystem::path> original_trees, child_cache_reports;
    std::vector<DarwinMacroProviderPlugin> plugins;
    JsonValue provenance;
    std::vector<std::shared_ptr<void>> retained_inputs;

    // Only an admitted original plugin can be translated. No basename lookup,
    // arbitrary Windows filesystem access or macro/module-specific fallback.
    bool TranslateLibraryPath(const std::string& requested, std::string& virtual_path) const;
};

// Binds selected SDKSettings, original files and cache descriptors to the receipt.
// Cache payload hashes/ABI/set completeness remain checked by DyldCacheView::Open.
// False clears output; expected_sdk, when supplied, must identify the same SDK.
bool ReadDarwinMacroProvider(const std::filesystem::path& receipt,
    const std::filesystem::path& managed_root, DarwinMacroProvider& output,
    std::string& error, const std::filesystem::path& expected_sdk = {},
    const DarwinClosureOptions& options = {});

// Locate metadata only beneath the managed home and above the selected SDK.
// Missing receipt is normal (native-only configuration); malformed receipts
// are diagnosed by ReadDarwinMacroProvider rather than silently accepted.
std::filesystem::path FindDarwinMacroProviderReceipt(const std::filesystem::path& managed_root,
    const std::filesystem::path& selected_sdk);
}
