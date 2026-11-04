#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace OpenFruit {

struct CacheCompressionReport {
    bool success = true;
    std::uint64_t directories_configured = 0;
    std::uint64_t files_compressed = 0;
    std::uint64_t uncompressed_bytes = 0;
    std::uint64_t compressed_bytes = 0;
    std::string error_message;
};

struct CachePackReport {
    bool success = true;
    std::filesystem::path archive_path;
    std::uint64_t original_bytes = 0;
    std::uint64_t archive_bytes = 0;
    std::string error_message;
};

struct CacheUnpackReport {
    bool success = true;
    std::filesystem::path unpacked_path;
    std::uint64_t restored_files = 0;
    std::string error_message;
};

struct CacheGarbageCollectionReport {
    bool success = true;
    std::uint64_t entries_removed = 0;
    std::uint64_t bytes_reclaimed = 0;
    std::vector<std::string> details;
    std::string error_message;
};

class CacheCompressionManager {
public:
    // Model A: Transparent NTFS / WOF Compression
    // Marks a directory with FILE_ATTRIBUTE_COMPRESSED via DeviceIoControl(FSCTL_SET_COMPRESSION)
    // so any new files written into it are automatically compressed on-the-fly by NTFS.
    static bool EnableNtfsDirectoryCompression(const std::filesystem::path& directory);

    // Recursively enables NTFS compression and compresses existing files in the directory.
    static CacheCompressionReport CompressDirectoryTree(
        const std::filesystem::path& root,
        bool use_xpress16k = true,
        const std::function<void(const std::string&)>& progress = nullptr
    );

    // Model B: Cold Storage Archiving
    // Packs an application's intermediate build workspace into a cold .tar.zst archive.
    // Deletes the hot unpacked folder once the archive is verified.
    static CachePackReport PackProjectCache(
        const std::filesystem::path& user_state_root,
        const std::string& project_identifier
    );

    // Unpacks an application's cold archive back into the hot workspace.
    static CacheUnpackReport UnpackProjectCache(
        const std::filesystem::path& user_state_root,
        const std::string& project_identifier
    );

    // Checks if a cold archive exists for the given project.
    static bool HasColdArchive(
        const std::filesystem::path& user_state_root,
        const std::string& project_identifier
    );

    // Checks if an active unpacked workspace is present on disk for the given project.
    static bool IsProjectCacheActive(
        const std::filesystem::path& user_state_root,
        const std::string& project_identifier
    );

    // Model C: Pruning & Garbage Collection
    // Prunes orphaned SwiftPM checkouts in c/s, stale APFS staging dirs in darwin-runtime-inputs,
    // and historical diagnostic folders.
    static CacheGarbageCollectionReport CollectGarbage(
        const std::filesystem::path& user_state_root,
        const std::filesystem::path& managed_cache_root,
        std::uint64_t max_age_days = 7
    );
};

} // namespace OpenFruit
