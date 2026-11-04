#include "cache_compression_manager.hpp"
#include "win32_process.hpp"
#include "json_value.hpp"
#include "text_util.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <regex>

namespace fs = std::filesystem;

namespace OpenFruit {

namespace {

std::wstring ExtendedWin32Path(const fs::path& input) {
    std::wstring path = input.wstring();
    if (path.starts_with(L"\\\\?\\")) return path;
    if (path.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + path.substr(2);
    return L"\\\\?\\" + path;
}

std::uint64_t GetDirectorySize(const fs::path& dir) {
    std::uint64_t total = 0;
    std::error_code ec;
    for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) continue;
        if (entry.is_regular_file(ec)) {
            total += entry.file_size(ec);
        }
    }
    return total;
}

std::string SanitizeName(const std::string& input) {
    std::string result;
    for (char ch : input) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
            result.push_back(ch);
        } else if (ch == '.' || ch == ' ' || ch == '/' || ch == '\\') {
            result.push_back('_');
        }
    }
    if (result.empty()) result = "app";
    return result;
}

fs::path SystemDirectory() {
    wchar_t buffer[MAX_PATH];
    const UINT length = GetSystemDirectoryW(buffer, MAX_PATH);
    return length > 0 && length < MAX_PATH ? fs::path(std::wstring(buffer, length)) : fs::path{};
}

fs::path FindSystemTar() {
    const fs::path system_tar = SystemDirectory() / "tar.exe";
    std::error_code ec;
    if (fs::exists(system_tar, ec)) return system_tar;
    return "tar.exe";
}

fs::path FindSystemCompact() {
    const fs::path system_compact = SystemDirectory() / "compact.exe";
    std::error_code ec;
    if (fs::exists(system_compact, ec)) return system_compact;
    return "compact.exe";
}

} // namespace

bool CacheCompressionManager::EnableNtfsDirectoryCompression(const fs::path& directory) {
    std::error_code ec;
    if (!fs::exists(directory, ec) || !fs::is_directory(directory, ec)) return false;

    const std::wstring ext_path = ExtendedWin32Path(directory);
    HANDLE h = CreateFileW(
        ext_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE) return false;

    USHORT format = COMPRESSION_FORMAT_DEFAULT;
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(
        h,
        FSCTL_SET_COMPRESSION,
        &format,
        sizeof(format),
        nullptr,
        0,
        &bytes_returned,
        nullptr
    );

    CloseHandle(h);
    return ok != FALSE;
}

CacheCompressionReport CacheCompressionManager::CompressDirectoryTree(
    const fs::path& root,
    bool use_xpress16k,
    const std::function<void(const std::string&)>& progress
) {
    CacheCompressionReport report;
    std::error_code ec;
    if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
        report.success = false;
        report.error_message = "Path does not exist or is not a directory: " + root.string();
        return report;
    }

    if (progress) progress("Scanning directory structure and enabling NTFS compression attribute...");

    report.uncompressed_bytes = GetDirectorySize(root);

    // 1. Mark root and all subdirectories with FILE_ATTRIBUTE_COMPRESSED
    EnableNtfsDirectoryCompression(root);
    report.directories_configured++;

    for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) continue;
        if (entry.is_directory(ec)) {
            if (EnableNtfsDirectoryCompression(entry.path())) {
                report.directories_configured++;
            }
        }
    }

    // 2. Invoke compact.exe to compress all existing files
    const fs::path compact_exe = FindSystemCompact();
    std::vector<std::wstring> args = {
        compact_exe.wstring(),
        L"/c"
    };
    if (use_xpress16k) {
        args.push_back(L"/exe:xpress16k");
    }
    args.push_back(L"/s:" + root.wstring());
    args.push_back(L"/q");
    args.push_back(L"/i");

    if (progress) progress("Running Windows filesystem compression engine...");

    ProcessResult res = Win32Process::Run(
        compact_exe.wstring(),
        args,
        root.wstring()
    );

    if (!res.success && use_xpress16k) {
        // Fallback to standard NTFS compression if /exe:xpress16k is not supported
        args = {
            compact_exe.wstring(),
            L"/c",
            L"/s:" + root.wstring(),
            L"/q",
            L"/i"
        };
        res = Win32Process::Run(compact_exe.wstring(), args, root.wstring());
    }

    // Re-measure logical and physical size
    // Parse compact.exe output for actual compression statistics
    std::string combined = res.std_out + "\n" + res.std_err;
    std::regex file_count_regex(R"((\d+)\s+file)");
    std::smatch match;
    if (std::regex_search(combined, match, file_count_regex)) {
        try {
            report.files_compressed = std::stoull(match[1].str());
        } catch (...) {}
    }

    report.success = true;
    return report;
}

CachePackReport CacheCompressionManager::PackProjectCache(
    const fs::path& user_state_root,
    const std::string& project_identifier
) {
    CachePackReport report;
    std::error_code ec;

    const std::string clean_id = SanitizeName(project_identifier);
    const std::string lower_hint = ToLowerAscii(project_identifier);

    const fs::path archives_dir = user_state_root / "cache" / "archives";
    fs::create_directories(archives_dir, ec);

    const fs::path archive_path = archives_dir / (clean_id + ".tar.zst");
    const fs::path manifest_path = archives_dir / (clean_id + ".manifest.json");

    // Locate candidate workspace entries in c/v and w
    const fs::path cv_root = user_state_root / "c" / "v";
    const fs::path w_root = user_state_root / "w";

    std::vector<fs::path> paths_to_pack;
    std::vector<std::string> relative_paths;

    // Search in c/v
    if (fs::exists(cv_root, ec)) {
        for (const auto& entry : fs::directory_iterator(cv_root, ec)) {
            if (!entry.is_directory(ec)) continue;
            const fs::path ctx_file = entry.path() / "OPENFRUIT-workspace-context.json";
            bool matches = false;
            if (fs::exists(ctx_file, ec)) {
                std::ifstream is(ctx_file);
                std::string content((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
                if (ToLowerAscii(content).find(lower_hint) != std::string::npos) {
                    matches = true;
                }
            } else if (ToLowerAscii(entry.path().filename().string()).find(lower_hint) != std::string::npos) {
                matches = true;
            }

            if (matches) {
                paths_to_pack.push_back(entry.path());
                relative_paths.push_back("c/v/" + entry.path().filename().string());
            }
        }
    }

    // Search in w
    if (fs::exists(w_root, ec)) {
        for (const auto& entry : fs::directory_iterator(w_root, ec)) {
            if (!entry.is_directory(ec)) continue;
            const fs::path sources_dir = entry.path() / "sources";
            const fs::path build_dir = entry.path() / "build";
            bool matches = false;
            if (fs::exists(sources_dir, ec)) {
                for (const auto& sub : fs::directory_iterator(sources_dir, ec)) {
                    if (ToLowerAscii(sub.path().filename().string()).find(lower_hint) != std::string::npos) {
                        matches = true;
                        break;
                    }
                }
            }
            if (!matches && fs::exists(build_dir, ec)) {
                for (const auto& sub : fs::directory_iterator(build_dir, ec)) {
                    if (ToLowerAscii(sub.path().filename().string()).find(lower_hint) != std::string::npos) {
                        matches = true;
                        break;
                    }
                }
            }

            if (matches) {
                paths_to_pack.push_back(entry.path());
                relative_paths.push_back("w/" + entry.path().filename().string());
            }
        }
    }

    if (paths_to_pack.empty()) {
        report.success = false;
        report.error_message = "No active build cache found matching project: " + project_identifier;
        return report;
    }

    // Measure total original uncompressed size
    for (const auto& p : paths_to_pack) {
        report.original_bytes += GetDirectorySize(p);
    }

    // Run tar.exe --zstd
    const fs::path tar_exe = FindSystemTar();
    std::vector<std::wstring> tar_args = {
        tar_exe.wstring(),
        L"--zstd",
        L"-cf",
        archive_path.wstring(),
        L"-C",
        user_state_root.wstring()
    };

    for (const auto& rel : relative_paths) {
        tar_args.push_back(Win32Process::ToWide(rel));
    }

    ProcessResult res = Win32Process::Run(
        tar_exe.wstring(),
        tar_args,
        user_state_root.wstring()
    );

    if (!res.success || !fs::exists(archive_path, ec) || fs::file_size(archive_path, ec) == 0) {
        report.success = false;
        report.error_message = "Archive compression failed: " + res.std_err + " " + res.std_out;
        fs::remove(archive_path, ec);
        return report;
    }

    report.archive_path = archive_path;
    report.archive_bytes = fs::file_size(archive_path, ec);

    // Save manifest
    auto manifest = JsonValue::ObjectValue();
    manifest.Set("project", JsonValue::String(project_identifier));
    manifest.Set("original_bytes", JsonValue::Number(std::to_string(report.original_bytes)));
    manifest.Set("archive_bytes", JsonValue::Number(std::to_string(report.archive_bytes)));
    auto rel_arr = JsonValue::ArrayValue();
    for (const auto& rel : relative_paths) {
        rel_arr.ArrayItems().push_back(JsonValue::String(rel));
    }
    manifest.Set("entries", std::move(rel_arr));

    std::ofstream os(manifest_path);
    os << manifest.Serialize(true);
    os.close();

    // Safely remove uncompressed directories
    for (const auto& p : paths_to_pack) {
        fs::remove_all(p, ec);
    }

    report.success = true;
    return report;
}

CacheUnpackReport CacheCompressionManager::UnpackProjectCache(
    const fs::path& user_state_root,
    const std::string& project_identifier
) {
    CacheUnpackReport report;
    std::error_code ec;

    const std::string clean_id = SanitizeName(project_identifier);
    const fs::path archive_path = user_state_root / "cache" / "archives" / (clean_id + ".tar.zst");

    if (!fs::exists(archive_path, ec)) {
        report.success = false;
        report.error_message = "Cold cache archive not found for: " + project_identifier;
        return report;
    }

    const fs::path tar_exe = FindSystemTar();
    std::vector<std::wstring> tar_args = {
        tar_exe.wstring(),
        L"--zstd",
        L"-xf",
        archive_path.wstring(),
        L"-C",
        user_state_root.wstring()
    };

    ProcessResult res = Win32Process::Run(
        tar_exe.wstring(),
        tar_args,
        user_state_root.wstring()
    );

    if (!res.success) {
        report.success = false;
        report.error_message = "Extraction failed: " + res.std_err + " " + res.std_out;
        return report;
    }

    report.success = true;
    report.unpacked_path = user_state_root;
    return report;
}

bool CacheCompressionManager::HasColdArchive(
    const fs::path& user_state_root,
    const std::string& project_identifier
) {
    const std::string clean_id = SanitizeName(project_identifier);
    const fs::path archive_path = user_state_root / "cache" / "archives" / (clean_id + ".tar.zst");
    std::error_code ec;
    return fs::exists(archive_path, ec) && fs::file_size(archive_path, ec) > 0;
}

bool CacheCompressionManager::IsProjectCacheActive(
    const fs::path& user_state_root,
    const std::string& project_identifier
) {
    std::error_code ec;
    const std::string lower_hint = ToLowerAscii(SanitizeName(project_identifier));
    const fs::path w_root = user_state_root / "w";
    if (fs::exists(w_root, ec)) {
        for (const auto& entry : fs::directory_iterator(w_root, ec)) {
            if (!entry.is_directory(ec)) continue;
            const fs::path sources_dir = entry.path() / "sources";
            const fs::path build_dir = entry.path() / "build";
            if (fs::exists(sources_dir, ec)) {
                for (const auto& sub : fs::directory_iterator(sources_dir, ec)) {
                    if (ToLowerAscii(sub.path().filename().string()).find(lower_hint) != std::string::npos) {
                        return true;
                    }
                }
            }
            if (fs::exists(build_dir, ec)) {
                for (const auto& sub : fs::directory_iterator(build_dir, ec)) {
                    if (ToLowerAscii(sub.path().filename().string()).find(lower_hint) != std::string::npos) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

CacheGarbageCollectionReport CacheCompressionManager::CollectGarbage(
    const fs::path& user_state_root,
    const fs::path& managed_cache_root,
    std::uint64_t max_age_days
) {
    CacheGarbageCollectionReport report;
    std::error_code ec;

    const auto now = fs::file_time_type::clock::now();
    const auto cutoff_duration = std::chrono::hours(24 * max_age_days);

    // 1. Clean stale SwiftPM checkouts in c/s
    const fs::path cs_root = user_state_root / "c" / "s";
    if (fs::exists(cs_root, ec)) {
        // Collect active checkout names if any
        for (const auto& entry : fs::directory_iterator(cs_root, ec)) {
            if (!entry.is_directory(ec)) continue;
            const auto mtime = entry.last_write_time(ec);
            if (!ec && (now - mtime) > cutoff_duration) {
                const std::uint64_t sz = GetDirectorySize(entry.path());
                fs::remove_all(entry.path(), ec);
                if (!ec) {
                    report.entries_removed++;
                    report.bytes_reclaimed += sz;
                    report.details.push_back("Pruned stale SwiftPM checkout: " + entry.path().filename().string());
                }
            }
        }
    }

    // 2. Clean stale diagnostic runs in diagnostics
    const fs::path diag_root = user_state_root / "diagnostics";
    if (fs::exists(diag_root, ec)) {
        for (const auto& entry : fs::directory_iterator(diag_root, ec)) {
            if (!entry.is_directory(ec)) continue;
            const std::string name = entry.path().filename().string();
            if (name.starts_with("architecture-") || name.starts_with("deferred-")) {
                const auto mtime = entry.last_write_time(ec);
                if (!ec && (now - mtime) > cutoff_duration) {
                    const std::uint64_t sz = GetDirectorySize(entry.path());
                    fs::remove_all(entry.path(), ec);
                    if (!ec) {
                        report.entries_removed++;
                        report.bytes_reclaimed += sz;
                        report.details.push_back("Pruned old diagnostic checkpoint: " + name);
                    }
                }
            }
        }
    }

    // 3. Content-addressed compilation caches: an entry's time is its last
    // use, so entries unused for a month (and abandoned staging) are removed.
    // A build that loses an entry concurrently recompiles it.
    const auto unused_cutoff = std::chrono::hours(24 * std::max<std::uint64_t>(max_age_days, 30));
    const auto prune_unused = [&](const fs::path& entry, const std::string& label) {
        std::error_code entry_error;
        const auto mtime = fs::last_write_time(entry, entry_error);
        if (entry_error || (now - mtime) <= unused_cutoff) return;
        const std::uint64_t sz = fs::is_directory(entry, entry_error) ? GetDirectorySize(entry) : fs::file_size(entry, entry_error);
        fs::remove_all(entry, entry_error);
        if (!entry_error) {
            report.entries_removed++;
            report.bytes_reclaimed += sz;
            report.details.push_back("Pruned unused " + label + ": " + entry.filename().string());
        }
    };
    // Enumerate first: entries are removed after the directory walk.
    std::vector<fs::path> catalogs, expansions;
    for (const auto& entry : fs::directory_iterator(managed_cache_root / "asset-catalogs", ec))
        catalogs.push_back(entry.path());
    ec.clear();
    for (const auto& entry : fs::recursive_directory_iterator(managed_cache_root / "macro-expansions", ec))
        if (entry.path().extension() == ".frame") expansions.push_back(entry.path());
    ec.clear();
    for (const auto& entry : catalogs) prune_unused(entry, "asset catalog compilation");
    for (const auto& entry : expansions) prune_unused(entry, "macro expansion");

    report.success = true;
    return report;
}

} // namespace OpenFruit
