#include "asset_catalog_compiler.hpp"
#include "operation_events.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary);
    stream << text;
    Require(static_cast<bool>(stream), "fixture write failed");
}
void Set(const fs::path& path, const std::string& filename) {
    Write(path / "Contents.json", "{\"images\":[{\"filename\":\"" + filename + "\"}]}" );
    Write(path / filename, "controlled test source");
}
}

int main() {
    const auto root = fs::temp_directory_path() / ("of-assets-" + NewOperationId());
    try {
        fs::create_directories(root);
        AssetCatalogInputs result;
        std::string error = "stale error";
        Require(AssetCatalogCompiler::PrepareInputs({}, {}, result, error), "no catalogs should be a valid no-op");
        Require(error.empty() && result.catalogs.empty() && !result.requires_svg, "empty result was not reset");
        Require(AssetCatalogCompiler::Compile({}, root / "missing-bundle", {}, {}, error), "no inputs should not acquire tools or require a bundle");
        Require(!AssetCatalogCompiler::Compile({(root / "Missing.xcassets").wstring()}, root / "missing-bundle", {}, {}, error), "missing bundle accepted");
        Require(error.find("product bundle") != std::string::npos, "missing bundle diagnostic lost");
        Require(!AssetCatalogCompiler::PrepareInputs({(root / "Missing.xcassets").wstring()}, {}, result, error), "declared missing catalog accepted");
        Require(error.find("declared asset catalog") != std::string::npos, "missing catalog diagnostic lost");

        const auto catalog = root / "Images.xcassets";
        Set(catalog / "Group" / "Raster.imageset", "raster.PNG");
        Write(catalog / "Group" / "Raster.imageset" / "unreferenced.svg", "unused");
        Write(catalog / ".ignored.imageset" / "Contents.json", "invalid hidden metadata");
        Write(catalog / "Tone.colorset" / "Contents.json", "{\"colors\":[]}");
        Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error), "nested raster catalog rejected");
        Require(!result.requires_svg, "unreferenced SVG forced provider acquisition");

        Set(catalog / "Group" / "Vector.imageset", "vector.SVG");
        Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error), "nested SVG catalog rejected");
        Require(result.requires_svg && result.catalogs == std::vector<fs::path>{catalog}, "metadata-derived SVG requirement lost");
        fs::remove(catalog / "Group" / "Vector.imageset" / "vector.SVG");
        Require(!AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error), "missing referenced SVG accepted");
        Require(error.find("missing referenced asset") != std::string::npos && !result.requires_svg && result.catalogs.empty(), "failed discovery leaked a partial plan");
        fs::remove_all(catalog / "Group" / "Vector.imageset");

        Set(catalog / "Primary.appiconset", "icon.png");
        Set(catalog / "Alternate.appiconset", "alternate.svg");
        Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, L"Primary", result, error), "selected icon rejected");
        Require(!result.requires_svg, "unselected icon forced SVG provider");
        Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error) && result.requires_svg, "unrestricted icon requirements not discovered");
        Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, AppIconSelection(L"Primary", true, {}), result, error) &&
                result.requires_svg, "INCLUDE_ALL_APPICON_ASSETS did not select the alternate icon");
        Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, AppIconSelection(L"Primary", false, {L"Alternate"}), result, error) &&
                result.requires_svg, "ALTERNATE_APPICON_NAMES did not select the named icon");
        Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, AppIconSelection(L"Primary", false, {L"Other"}), result, error) &&
                !result.requires_svg, "an unnamed alternate icon was selected");
        fs::remove_all(catalog / "Alternate.appiconset");
        Write(catalog / "Group" / "Raster.imageset" / "Contents.json", "invalid");
        Require(!AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error), "malformed metadata accepted");
        Write(catalog / "Group" / "Raster.imageset" / "Contents.json", "\xEF\xBB\xBF{\"images\":[{\"filename\":\"raster.PNG\"}]}");
        Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error), "BOM metadata rejected");
        // Valid metadata and present payloads must not make unsupported asset
        // families appear compilable: validation alone cannot emit a CoreUI
        // data or symbol rendition, and an image downgrade loses semantics.
        for (const auto& family : {std::string("stickerset"), std::string("complicationset")}) {
            const auto asset = catalog / ("Unsupported." + family);
            const auto filename = family == "stickerset" ? "sticker.png" : "complication.png";
            const auto array_key = family == "stickerset" ? "stickers" : "complications";
            Write(asset / "Contents.json", std::string("{\"info\":{\"author\":\"xcode\",\"version\":1},\"") +
                array_key + "\":[{\"idiom\":\"universal\",\"filename\":\"" + filename + "\"}]}");
            Write(asset / filename, family == "stickerset" ? "sticker" : "complication");
            Require(!AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error),
                    "unsupported asset with valid metadata was admitted");
            Require(error.find("unsupported asset type:") != std::string::npos &&
                    error.find("Unsupported." + family) != std::string::npos,
                    "unsupported asset diagnostic lost its family/path");
            Require(result.catalogs.empty() && !result.requires_svg,
                    "unsupported asset leaked a partial plan or acquired a rasterizer");
            Require(fs::is_regular_file(asset / filename), "unsupported asset payload was removed");
            fs::remove_all(asset);
            Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error),
                    "supported catalog did not recover after unsupported asset rejection");
        }

        // Other platforms' layered images have no iOS rendition and are skipped
        // without reading their layers (here an SVG layer that would otherwise
        // require the rasterizer).
        {
            const auto stack = catalog / "AppIconVisionOS.solidimagestack";
            Write(stack / "Contents.json", "{\"layers\":[{\"filename\":\"Front.solidimagestacklayer\"}]}");
            Set(stack / "Front.solidimagestacklayer" / "Content.imageset", "layer.svg");
            Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error) && !result.requires_svg,
                    ("visionOS solid image stack was not skipped for iOS: " + error).c_str());
            fs::remove_all(stack);
        }

        // Symbolset and dataset are admitted when valid
        {
            const auto symbol_asset = catalog / "Custom.symbolset";
            Write(symbol_asset / "Contents.json",
                "{\"info\":{\"author\":\"xcode\",\"version\":1},\"symbols\":[{\"idiom\":\"universal\",\"filename\":\"glyph.svg\"}]}");
            Write(symbol_asset / "glyph.svg",
                "<svg xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M0 0\"/></svg>");
            Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error),
                    ("valid symbolset was rejected: " + error).c_str());
            Require(result.requires_svg, "symbolset svg did not set requires_svg");
            fs::remove_all(symbol_asset);

            const auto data_asset = catalog / "Payload.dataset";
            Write(data_asset / "Contents.json",
                "{\"info\":{\"author\":\"xcode\",\"version\":1},\"data\":[{\"idiom\":\"universal\",\"filename\":\"data.bin\"}]}");
            Write(data_asset / "data.bin", "binary");
            Require(AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error),
                    ("valid dataset was rejected: " + error).c_str());
            fs::remove_all(data_asset);
        }

        const auto metadata = catalog / "Group" / "Raster.imageset" / "Contents.json";
        Write(metadata, std::string(4 * 1024 * 1024 + 1, ' '));
        Require(!AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error), "oversized metadata accepted");
        Require(error.find("4 MiB limit") != std::string::npos, "metadata limit diagnostic lost");
        Write(metadata, "{\"images\":[{\"filename\":\"raster.PNG\"}]}");
        const auto deep_catalog = root / "Deep.xcassets";
        fs::path nested = deep_catalog;
        for (unsigned depth = 0; depth < 65; ++depth) nested /= "n";
        fs::create_directories(nested);
        Require(!AssetCatalogCompiler::PrepareInputs({deep_catalog.wstring()}, {}, result, error), "unbounded namespace recursion accepted");
        Require(error.find("64 levels") != std::string::npos, "namespace limit diagnostic lost");
        fs::remove_all(deep_catalog);
        // Windows may require developer mode/privilege for directory symlinks.
        std::error_code symlink_error;
        fs::create_directory_symlink(catalog, catalog / "Cycle", symlink_error);
        if (!symlink_error) {
            Require(!AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error), "directory symlink cycle accepted");
            Require(error.find("symbolic-link") != std::string::npos, "symlink cycle diagnostic lost");
            fs::remove(catalog / "Cycle");
        }

        auto context = std::make_shared<OperationContext>();
        context->RequestCancellation();
        { OperationBinding binding(context);
          Require(!AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error), "cancelled scan proceeded");
          Require(error.find("cancelled") != std::string::npos, "cancellation diagnostic lost"); }
        context = std::make_shared<OperationContext>();
        context->control = std::make_shared<OperationControl>(std::chrono::steady_clock::now() - std::chrono::seconds(1));
        { OperationBinding binding(context);
          Require(!AssetCatalogCompiler::PrepareInputs({catalog.wstring()}, {}, result, error), "expired scan proceeded");
          Require(error.find("deadline") != std::string::npos, "deadline diagnostic lost"); }

        // actool's partial Info.plist: declared keys win, dictionaries merge.
        const auto info = root / "Bundle.app" / "Info.plist";
        const auto partial = root / "Bundle.app" / "assetcatalog_generated_info.plist";
        const std::string header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">";
        Write(info, header + "<dict><key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict>"
                    "<key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict></dict></plist>");
        Write(partial, header + "<dict><key>CFBundleIcons</key><dict><key>CFBundlePrimaryIcon</key><dict>"
                       "<key>CFBundleIconFiles</key><array><string>Replaced</string></array></dict>"
                       "<key>CFBundleAlternateIcons</key><dict><key>Red</key><dict><key>CFBundleIconName</key><string>Red</string>"
                       "<key>CFBundleIconFiles</key><array><string>Red1024x1024</string></array></dict></dict></dict>"
                       "<key>CFBundleIcons~ipad</key><dict><key>CFBundleAlternateIcons</key><dict/></dict></dict></plist>");
        Require(AssetCatalogCompiler::MergePartialInfoPlist(info, partial, error), error.c_str());
        std::stringstream merged_text;
        { std::ifstream merged_stream(info, std::ios::binary); merged_text << merged_stream.rdbuf(); }
        const auto merged = merged_text.str();
        Require(merged.find("<string>AppIcon60x60</string>") != std::string::npos &&
                merged.find("Replaced") == std::string::npos, "partial Info.plist replaced a declared key");
        Require(merged.find("<key>CFBundleAlternateIcons</key>") != std::string::npos &&
                merged.find("<string>Red1024x1024</string>") != std::string::npos, "alternate icons were not merged");
        Require(merged.find("<key>CFBundleIcons~ipad</key>") != std::string::npos, "missing top-level key was not added");
        Write(partial, header + "<array/></plist>");
        Require(!AssetCatalogCompiler::MergePartialInfoPlist(info, partial, error), "non-dictionary additions accepted");

        fs::remove_all(root);
        std::cout << "asset catalog input contracts PASS\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << '\n';
        std::error_code ignored;
        fs::remove_all(root, ignored);
        return 1;
    }
}
