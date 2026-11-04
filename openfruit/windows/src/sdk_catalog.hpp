#pragma once
#include <filesystem>
#include <string>
#include <vector>
namespace OpenFruit {
struct SDKRegistration {
    std::wstring version;
    std::filesystem::path path;
};
struct SDKLayoutInspection {
    bool directory = false;
    bool libraries = false;
    bool frameworks = false;
    bool settings = false;
    bool Usable() const noexcept { return directory && libraries && frameworks && settings; }
};
struct SDKCatalogEntry {
    SDKRegistration registration;
    bool selected = false;
    SDKLayoutInspection layout;
};
// Read-only catalog. Layout presence is not SDK identity or compiler validation.
class SDKCatalog {
public:
    // Catalog roots must be absolute. Relative registrations remain visible
    // as incomplete rows and never inspect ambient working-directory state.
    static SDKLayoutInspection Inspect(const std::filesystem::path&);
    static bool HasUsableLayout(const std::filesystem::path&);
    // Repair metadata only when its target is positively absent. Existing
    // incomplete trees and filesystem errors must never authorize replacement.
    static bool RegistrationTargetMissing(const std::filesystem::path&);
    static std::vector<SDKCatalogEntry> List(const std::vector<SDKRegistration>&,
        const std::wstring& selected_version, const std::filesystem::path& fallback_path);
};
}
