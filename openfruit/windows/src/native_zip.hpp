#pragma once

#include <filesystem>

namespace OpenFruit {

class NativeZipWriter {
public:
    /*
     * Stores the whole directory tree without compression.
     * For IPA this is valid ZIP32, very fast, deterministic, and removes the
     * Python dependency from packaging.
     */
    static bool CreateFromDirectory(
        const std::filesystem::path& root_directory,
        const std::filesystem::path& output_zip
    );
};

} // namespace OpenFruit
