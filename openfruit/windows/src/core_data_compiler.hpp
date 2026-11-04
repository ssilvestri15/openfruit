#pragma once

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace OpenFruit {

/* Windows-native implementation of Xcode's Core Data model build rule. */
class CoreDataCompiler {
public:
    static bool Compile(
        const std::vector<std::pair<std::wstring, std::wstring>>& models,
        const std::filesystem::path& product_bundle,
        std::string& error
    );

    /* Scan a bundle directory for .momd directories that still contain
       uncompiled .xcdatamodel sources (as left by CocoaPods resource-copy
       scripts) and compile them in-place. */
    static bool CompileUncompiledInBundle(
        const std::filesystem::path& bundle_dir,
        std::string& error
    );
};

} // namespace OpenFruit
