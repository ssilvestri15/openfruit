#pragma once
#include <string>
#include <utility>
#include <vector>

namespace OpenFruit {
// Target settings stay attached to the physical product through assembly.
// No provisioning grants or container settings are substituted for these inputs.
struct SigningProduct {
    std::wstring product_path;
    std::wstring bundle_id;
    std::wstring entitlements_path;
    std::wstring project_file;
    std::string target_id;
    std::wstring configuration;
    std::vector<std::pair<std::wstring, std::wstring>> build_settings;
};
}
