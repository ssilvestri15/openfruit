#pragma once

#include <filesystem>
#include <string>

namespace OpenFruit {

// Apply Xcode's Interface Builder resource build rule to staged bundles.
class InterfaceBuilderCompiler {
public:
    // target_module is the Swift module of the bundle's own target. Its
    // resources resolve customModuleProvider="target" classes to it; nested
    // bundles belong to other targets and keep their stored customModule.
    static bool CompileUncompiledInBundle(
        const std::filesystem::path& bundle_dir,
        std::string& error,
        const std::string& target_module = {}
    );
};

} // namespace OpenFruit
