#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace OpenFruit {

/* Windows-native implementation of Xcode's SiriKit Intent Definition compiler. */
class IntentDefinitionCompiler {
public:
    static std::filesystem::path Compile(
        const std::filesystem::path& intent_definition_path,
        const std::filesystem::path& output_dir,
        std::string& error
    );
};

} // namespace OpenFruit
