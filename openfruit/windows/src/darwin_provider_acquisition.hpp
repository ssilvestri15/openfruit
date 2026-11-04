#pragma once
#include <filesystem>
#include <ostream>
#include <string>

namespace OpenFruit {

struct DarwinProviderAcquisitionResult {
    bool succeeded = false;
    bool already_present = false;
    std::string message;
};

// Publishes the managed original macro provider for a managed iPhoneOS SDK
// whose Xcode archive is retained: the original swift-plugin-server and plugin
// trees from that archive, plus the original macOS dyld shared cache and disk
// dyld from the matching public macOS restore image. Every input goes through
// the existing native verified stages (ZIP/AEA/APFS/dyld cache/XIP) and the
// validated import; nothing is synthesized. Completed stages are reused, so an
// interrupted acquisition resumes. Progress is written to `log`.
DarwinProviderAcquisitionResult EnsureDarwinMacroProvider(const std::filesystem::path& selected_sdk,
                                                          const std::filesystem::path& managed_home,
                                                          std::ostream& log);

} // namespace OpenFruit
