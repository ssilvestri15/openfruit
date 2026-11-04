#pragma once
#include <filesystem>
#include <string>
#include <string_view>
namespace OpenFruit {
struct BundleResourceSeal {
    std::filesystem::path executable_path;
    std::string info_plist;
    std::string code_resources;
};
// Apple's default shallow iOS bundle resource policy. Derives the executable
// from actual Info.plist; reads all included regular files and link targets,
// including nested bundle signatures. Does not follow links or modify files.
bool BuildFlatBundleResourceSeal(const std::filesystem::path& bundle,
    BundleResourceSeal& seal, std::string& error);
// Independent inventory/hash/schema reader. This proves resource integrity,
// not nested CMS/provisioning eligibility or the main executable's signature.
bool VerifyFlatBundleResourceSeal(const std::filesystem::path& bundle,
    std::string_view code_resources, std::string& error);
}
