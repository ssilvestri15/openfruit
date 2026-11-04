#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace OpenFruit {

/* Windows-native implementation of Xcode's string catalog (.xcstrings) build
   rule: each catalog becomes one table per language, written as
   <language>.lproj/<table>.strings plus <table>.stringsdict for plural and
   substitution variations, the files Foundation reads at run time. */
class StringCatalogCompiler {
public:
    /* Compiles `catalogs` into `bundle_dir`, creating it when needed.
       `development_region` receives the catalogs' source language. */
    static bool Compile(
        const std::vector<std::filesystem::path>& catalogs,
        const std::filesystem::path& bundle_dir,
        std::string& development_region,
        std::string& error
    );
};

} // namespace OpenFruit
