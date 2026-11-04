#pragma once

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace OpenFruit {

struct AssetCatalogInputs {
    std::vector<std::filesystem::path> catalogs;
    bool requires_svg = false;
    // A referenced file outside its asset directory is not covered by the
    // catalog's content identity, so such compilations are never reused.
    bool external_references = false;
};

// App icon sets compiled for a target: ASSETCATALOG_COMPILER_APPICON_NAME,
// ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS and
// ASSETCATALOG_COMPILER_ALTERNATE_APPICON_NAMES.
struct AppIconSelection {
    std::wstring primary;
    bool include_all = false;
    std::vector<std::wstring> alternates;

    AppIconSelection() = default;
    AppIconSelection(std::wstring primary_icon) : primary(std::move(primary_icon)) {}
    AppIconSelection(const wchar_t* primary_icon) : primary(primary_icon) {}
    AppIconSelection(std::wstring primary_icon, bool include_all_icons, std::vector<std::wstring> alternate_icons)
        : primary(std::move(primary_icon)), include_all(include_all_icons), alternates(std::move(alternate_icons)) {}

    bool Selects(const std::wstring& name) const;
};

/* Compiles Xcode asset-catalog inputs into the CoreUI archive consumed by
   UIColor(named:), UIImage(named:), and SpringBoard. */
class AssetCatalogCompiler {
public:
    // Discover requirements from selected asset metadata, never from unrelated
    // files in a catalog. Shared with focused contract tests.
    static bool PrepareInputs(const std::vector<std::wstring>& catalogs,
                              const AppIconSelection& app_icons,
                              AssetCatalogInputs& inputs, std::string& error);

    // Like actool's partial Info.plist, the compiler's icon declarations are
    // merged into the bundle's Info.plist when it exists; keys the Info.plist
    // already declares are kept.
    static bool Compile(
        const std::vector<std::wstring>& catalogs,
        const std::filesystem::path& product_bundle,
        const std::wstring& deployment_target,
        const AppIconSelection& app_icons,
        std::string& error
    );

    // Merges partial into info, keeping values info already declares;
    // dictionaries merge key by key. Shared with focused contract tests.
    static bool MergePartialInfoPlist(const std::filesystem::path& info,
                                      const std::filesystem::path& partial,
                                      std::string& error);
};

} // namespace OpenFruit
