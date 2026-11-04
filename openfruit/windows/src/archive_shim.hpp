#pragma once

#include <cstddef>
#include <filesystem>

namespace OpenFruit {

class ArchiveShim {
public:
    // Installs a copy of OPENFRUIT.exe named tar.exe in an OPENFRUIT-private
    // directory. SwiftPM sees it first in PATH; all non-problematic archives
    // are delegated to Windows' real bsdtar.
    static bool EnsureTarShim(
        const std::filesystem::path& repo_root,
        std::filesystem::path& out_shim_directory
    );

    // Direct C++ extraction path used by PackageEngine for SwiftPM binary
    // artifacts. This bypasses SwiftPM's hard-coded System32\\tar.exe while
    // preserving libarchive extraction semantics and materializing Unix
    // symlinks without requiring Developer Mode.
    static bool ExtractZipCompat(
        const std::filesystem::path& archive,
        const std::filesystem::path& destination,
        std::size_t* materialized_symlinks = nullptr
    );

    // Extracts any archive format supported by the system bsdtar (including
    // Carthage .tar.xz binary releases) while applying the same safe-path and
    // Unix-symlink materialization rules used for SwiftPM ZIP artifacts.
    static bool ExtractArchiveCompat(
        const std::filesystem::path& archive,
        const std::filesystem::path& destination,
        std::size_t* materialized_symlinks = nullptr
    );

    // Entry point used when the same OPENFRUIT binary is invoked as tar.exe.
    // Kept for standalone compatibility, but SwiftPM itself uses an absolute
    // System32 tar path on Windows and therefore cannot be intercepted by PATH.
    static int TarCompatMain(int argc, char* argv[]);
};

} // namespace OpenFruit
