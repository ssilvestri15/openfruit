#pragma once
#include <filesystem>
#include <string>
namespace OpenFruit {
// Explicit local import into the selected SDK's existing managed slot. Does not
// download, change publisher assurances, copy cache payloads or execute guests.
// A failed import may leave verified inputs but never publishes provider.json.
bool ImportDarwinMacroProvider(const std::filesystem::path& specification,
    const std::filesystem::path& managed_root, const std::filesystem::path& selected_sdk,
    std::string& error);
}
