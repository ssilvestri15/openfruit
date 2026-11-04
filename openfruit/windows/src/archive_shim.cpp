#include "archive_shim.hpp"

#include "win32_process.hpp"
#include "tool_paths.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

struct ArchiveEntry {
    std::string archive_path;
    char type = '?';
    std::string link_target;
};

std::vector<std::string> Lines(const std::string& text) {
    std::vector<std::string> result;
    std::size_t begin = 0;

    while (begin <= text.size()) {
        const std::size_t end = text.find('\n', begin);
        std::string line = text.substr(
            begin,
            end == std::string::npos ? std::string::npos : end - begin
        );

        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (!line.empty()) {
            result.push_back(std::move(line));
        }

        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }

    return result;
}


std::wstring ExtendedWin32Path(const fs::path& input) {
    fs::path absolute = input;
    std::error_code ec;

    if (!absolute.is_absolute()) {
        absolute = fs::absolute(absolute, ec);
        if (ec) {
            absolute = input;
        }
    }

    std::wstring value = absolute.lexically_normal().wstring();

    if (value.rfind(L"\\\\?\\", 0) == 0) {
        return value;
    }

    if (value.rfind(L"\\\\", 0) == 0) {
        return L"\\\\?\\UNC\\" + value.substr(2);
    }

    return L"\\\\?\\" + value;
}

fs::path ExtendedFsPath(const fs::path& input) {
    return fs::path(ExtendedWin32Path(input));
}

bool WinPathExists(const fs::path& input) {
    const std::wstring path = ExtendedWin32Path(input);
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool WinPathIsDirectory(const fs::path& input) {
    const std::wstring path = ExtendedWin32Path(input);
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool WinPathIsRegularFile(const fs::path& input) {
    const std::wstring path = ExtendedWin32Path(input);
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

fs::path CurrentExecutable() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr,
        buffer.data(),
        static_cast<DWORD>(buffer.size())
    );

    if (length == 0 || length >= buffer.size()) {
        return {};
    }

    buffer.resize(length);
    return fs::path(buffer);
}

fs::path RealSystemTar() {
    std::wstring buffer(32768, L'\0');
    const UINT length = GetSystemDirectoryW(
        buffer.data(),
        static_cast<UINT>(buffer.size())
    );

    if (length == 0 || length >= buffer.size()) {
        return {};
    }

    buffer.resize(length);
    const fs::path tar = fs::path(buffer) / L"tar.exe";
    return fs::exists(tar) ? tar : fs::path();
}

std::vector<std::wstring> OriginalArguments(int argc, char* argv[]) {
    std::vector<std::wstring> result;
    result.reserve(static_cast<std::size_t>(argc));

    for (int i = 1; i < argc; ++i) {
        result.push_back(Win32Process::ToWide(argv[i]));
    }

    return result;
}

bool IsExtractInvocation(const std::vector<std::wstring>& args) {
    for (const auto& arg : args) {
        if (arg == L"--extract") {
            return true;
        }

        if (arg.size() >= 2 && arg[0] == L'-' && arg[1] != L'-') {
            if (arg.find(L'x') != std::wstring::npos) {
                return true;
            }
        }
    }
    return false;
}

std::optional<fs::path> FindArchive(const std::vector<std::wstring>& args) {
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::wstring& arg = args[i];

        if ((arg == L"-f" || arg == L"--file") && i + 1 < args.size()) {
            return fs::path(args[i + 1]);
        }

        constexpr std::wstring_view prefix = L"--file=";
        if (arg.rfind(prefix, 0) == 0) {
            return fs::path(arg.substr(prefix.size()));
        }

        if (arg.size() > 2 && arg[0] == L'-' && arg[1] != L'-') {
            const std::size_t f = arg.find(L'f');
            if (f != std::wstring::npos) {
                if (f + 1 < arg.size()) {
                    return fs::path(arg.substr(f + 1));
                }
                if (i + 1 < args.size()) {
                    return fs::path(args[i + 1]);
                }
            }
        }
    }

    return std::nullopt;
}

fs::path FindDestination(const std::vector<std::wstring>& args) {
    fs::path destination = fs::current_path();

    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& arg = args[i];

        if ((arg == L"-C" || arg == L"--directory") && i + 1 < args.size()) {
            destination = fs::path(args[i + 1]);
            continue;
        }

        constexpr std::wstring_view prefix = L"--directory=";
        if (arg.rfind(prefix, 0) == 0) {
            destination = fs::path(arg.substr(prefix.size()));
        }
    }

    if (!destination.is_absolute()) {
        destination = fs::absolute(destination);
    }

    return destination.lexically_normal();
}

bool LooksLikeZip(const fs::path& archive) {
    // Official download caches need not retain the URL's filename suffix.
    // Inspect the container, leaving full format validation to the extractor.
    std::ifstream input(archive, std::ios::binary);
    unsigned char signature[4]{};
    if (!input.read(reinterpret_cast<char*>(signature), sizeof(signature))) return false;
    return signature[0] == 'P' && signature[1] == 'K' &&
        ((signature[2] == 3 && signature[3] == 4) ||
         (signature[2] == 5 && signature[3] == 6) ||
         (signature[2] == 7 && signature[3] == 8));
}

ProcessResult RunRealTar(
    const fs::path& tar,
    const std::vector<std::wstring>& arguments,
    const fs::path& cwd = {}
) {
    std::vector<std::wstring> command;
    command.reserve(arguments.size() + 1);
    command.push_back(tar.wstring());
    command.insert(command.end(), arguments.begin(), arguments.end());

    return Win32Process::Run(
        tar.wstring(),
        command,
        cwd.empty() ? L"" : cwd.wstring()
    );
}

std::vector<ArchiveEntry> InspectArchive(
    const fs::path& system_tar,
    const fs::path& archive
) {
    const ProcessResult names = RunRealTar(
        system_tar,
        {L"-tf", archive.wstring()}
    );

    const ProcessResult verbose = RunRealTar(
        system_tar,
        {L"-tvf", archive.wstring()}
    );

    if (!names.success || !verbose.success) {
        return {};
    }

    const auto name_lines = Lines(names.std_out);
    const auto verbose_lines = Lines(verbose.std_out);

    if (name_lines.empty() || name_lines.size() != verbose_lines.size()) {
        return {};
    }

    std::vector<ArchiveEntry> entries;
    entries.reserve(name_lines.size());

    for (std::size_t i = 0; i < name_lines.size(); ++i) {
        ArchiveEntry entry;
        entry.archive_path = name_lines[i];
        entry.type = verbose_lines[i].empty() ? '?' : verbose_lines[i][0];

        if (entry.type == 'l') {
            const std::size_t arrow = verbose_lines[i].rfind(" -> ");
            if (arrow == std::string::npos) {
                return {};
            }
            entry.link_target = verbose_lines[i].substr(arrow + 4);
        }

        entries.push_back(std::move(entry));
    }

    return entries;
}

bool SafeArchivePath(const fs::path& relative) {
    if (relative.empty() || relative.is_absolute()) {
        return false;
    }

    for (const auto& part : relative) {
        if (part == L"..") {
            return false;
        }
    }

    return true;
}

bool CreateHardLinkOrCopy(const fs::path& source, const fs::path& destination) {
    std::error_code ec;

    fs::create_directories(
        ExtendedFsPath(destination.parent_path()),
        ec
    );
    if (ec) {
        return false;
    }

    const std::wstring destination_w =
        ExtendedWin32Path(destination);
    const std::wstring source_w =
        ExtendedWin32Path(source);

    DeleteFileW(destination_w.c_str());

    if (CreateHardLinkW(
            destination_w.c_str(),
            source_w.c_str(),
            nullptr)) {
        return true;
    }

    return CopyFileW(
        source_w.c_str(),
        destination_w.c_str(),
        FALSE
    ) != FALSE;
}

bool MaterializedClone(const fs::path& source, const fs::path& destination) {
    std::error_code ec;

    if (WinPathIsRegularFile(source)) {
        return CreateHardLinkOrCopy(source, destination);
    }

    if (!WinPathIsDirectory(source)) {
        return false;
    }

    const fs::path source_native =
        ExtendedFsPath(source);
    const fs::path destination_native =
        ExtendedFsPath(destination);

    fs::remove_all(destination_native, ec);
    ec.clear();
    fs::create_directories(destination_native, ec);
    if (ec) {
        return false;
    }

    for (fs::recursive_directory_iterator it(
             source_native,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {

        if (ec) {
            return false;
        }

        const fs::path relative =
            fs::relative(it->path(), source_native, ec);
        if (ec) {
            return false;
        }

        const fs::path target =
            destination / relative;

        if (it->is_directory(ec)) {
            fs::create_directories(
                ExtendedFsPath(target),
                ec
            );
            if (ec) {
                return false;
            }
        } else if (it->is_regular_file(ec)) {
            if (!CreateHardLinkOrCopy(
                    fs::path(it->path()),
                    target)) {
                return false;
            }
        }
    }

    return true;
}

fs::path ResolveVirtualLinkTarget(
    const fs::path& destination_root,
    const fs::path& link_relative,
    const std::string& raw_target,
    const std::unordered_map<std::string, std::string>& links
) {
    fs::path target_relative =
        (link_relative.parent_path() / fs::path(raw_target)).lexically_normal();

    // Resolve symlink components using the archive's own link table. This
    // avoids recursively cloning an entire Framework Versions/A tree merely
    // because Versions/Current is a symlink.
    for (int pass = 0; pass < 32; ++pass) {
        bool changed = false;
        fs::path prefix;
        fs::path rebuilt;

        for (auto it = target_relative.begin(); it != target_relative.end(); ++it) {
            prefix /= *it;
            const std::string key = prefix.generic_string();
            const auto found = links.find(key);

            if (found == links.end()) {
                rebuilt /= *it;
                continue;
            }

            fs::path replacement =
                (prefix.parent_path() / fs::path(found->second)).lexically_normal();

            fs::path remainder;
            auto rest = it;
            ++rest;
            for (; rest != target_relative.end(); ++rest) {
                remainder /= *rest;
            }

            target_relative = (replacement / remainder).lexically_normal();
            changed = true;
            break;
        }

        if (!changed) {
            break;
        }
    }

    if (!SafeArchivePath(target_relative)) {
        return {};
    }

    return (destination_root / target_relative).lexically_normal();
}

bool MaterializeArchiveLinks(
    const fs::path& destination_root,
    const std::vector<ArchiveEntry>& entries,
    std::size_t& materialized_count
) {
    materialized_count = 0;

    std::unordered_map<std::string, std::string> links;
    links.reserve(entries.size());

    for (const auto& entry : entries) {
        if (entry.type == 'l') {
            links.insert_or_assign(entry.archive_path, entry.link_target);
        }
    }

    for (const auto& entry : entries) {
        if (entry.type != 'l') {
            continue;
        }

        const fs::path relative(entry.archive_path);
        if (!SafeArchivePath(relative)) {
            return false;
        }

        const fs::path destination =
            (destination_root / relative).lexically_normal();

        const fs::path source = ResolveVirtualLinkTarget(
            destination_root,
            relative,
            entry.link_target,
            links
        );

        if (source.empty() || !WinPathExists(source)) {
            // Some link targets depend on another link's materialized path.
            // They will be handled by the iterative fallback below.
            continue;
        }

        if (!MaterializedClone(source, destination)) {
            std::cerr
                << "OPENFRUIT archive shim: failed materializing link "
                << entry.archive_path
                << " -> "
                << entry.link_target
                << " (resolved source: "
                << source.string()
                << ", destination: "
                << destination.string()
                << ")"
                << std::endl;
            return false;
        }

        ++materialized_count;
    }

    // Resolve any remaining links whose targets only appeared after another
    // materialization pass.
    for (std::size_t pass = 0; pass < links.size() + 1; ++pass) {
        bool progress = false;
        std::size_t unresolved = 0;

        for (const auto& entry : entries) {
            if (entry.type != 'l') {
                continue;
            }

            const fs::path relative(entry.archive_path);
            const fs::path destination =
                (destination_root / relative).lexically_normal();

            if (WinPathExists(destination)) {
                continue;
            }

            ++unresolved;

            const fs::path source = ResolveVirtualLinkTarget(
                destination_root,
                relative,
                entry.link_target,
                links
            );

            if (source.empty() || !WinPathExists(source)) {
                continue;
            }

            if (!MaterializedClone(source, destination)) {
                return false;
            }

            ++materialized_count;
            progress = true;
        }

        if (unresolved == 0) {
            return true;
        }

        if (!progress) {
            break;
        }
    }

    for (const auto& entry : entries) {
        if (entry.type != 'l') {
            continue;
        }

        const fs::path relative(entry.archive_path);
        if (!WinPathExists(destination_root / relative)) {
            std::cerr
                << "OPENFRUIT archive shim: unresolved archive link after all passes: "
                << entry.archive_path
                << " -> "
                << entry.link_target
                << std::endl;
            return false;
        }
    }

    return true;
}

bool ValidateExtraction(
    const fs::path& destination_root,
    const std::vector<ArchiveEntry>& entries
) {
    for (const auto& entry : entries) {
        fs::path relative(entry.archive_path);
        if (!SafeArchivePath(relative)) {
            return false;
        }

        if (!WinPathExists(destination_root / relative)) {
            std::cerr
                << "OPENFRUIT archive shim: extracted member missing after recovery: "
                << relative.generic_string()
                << std::endl;
            return false;
        }
    }

    return true;
}

} // namespace


bool ArchiveShim::ExtractZipCompat(
    const fs::path& archive_input,
    const fs::path& destination_input,
    std::size_t* materialized_symlinks
) {
    if (!LooksLikeZip(archive_input)) {
        return false;
    }
    return ExtractArchiveCompat(
        archive_input,
        destination_input,
        materialized_symlinks
    );
}

bool ArchiveShim::ExtractArchiveCompat(
    const fs::path& archive_input,
    const fs::path& destination_input,
    std::size_t* materialized_symlinks
) {
    if (materialized_symlinks) {
        *materialized_symlinks = 0;
    }

    fs::path archive = archive_input;
    fs::path destination = destination_input;

    if (!archive.is_absolute()) {
        archive = fs::absolute(archive);
    }
    if (!destination.is_absolute()) {
        destination = fs::absolute(destination);
    }

    archive = archive.lexically_normal();
    destination = destination.lexically_normal();

    if (!fs::exists(archive) || !fs::is_regular_file(archive)) {
        return false;
    }

    const fs::path system_tar = RealSystemTar();
    if (system_tar.empty()) {
        return false;
    }

    std::error_code ec;
    fs::create_directories(ExtendedFsPath(destination), ec);
    if (ec) {
        return false;
    }

    const std::vector<ArchiveEntry> entries =
        InspectArchive(system_tar, archive);

    if (entries.empty()) {
        return false;
    }

    const bool has_symlinks = std::any_of(
        entries.begin(),
        entries.end(),
        [](const ArchiveEntry& entry) {
            return entry.type == 'l';
        }
    );

    /*
     * Windows bsdtar can read these ZIPs correctly; the failure is creating
     * Unix symbolic-link entries on NTFS. Do not let the extractor attempt
     * those entries at all. Extract every non-link entry in a single process,
     * then materialize the link graph using ordinary NTFS files/directories.
     *
     * This is both faster and more reliable than repairing a partially
     * extracted archive after bsdtar aborts: some archives stop before the
     * real target of a symlink has been written, which made the old repair
     * path fail for Firebase/Google binary artifacts.
     */
    std::vector<std::wstring> extraction_args = {
        L"-x",
        L"-f",
        archive.wstring(),
        L"-C",
        destination.wstring()
    };

    if (has_symlinks) {
        for (const auto& entry : entries) {
            if (entry.type != 'l') {
                continue;
            }

            extraction_args.push_back(L"--exclude");
            extraction_args.push_back(
                Win32Process::ToWide(entry.archive_path)
            );
        }
    }

    const ProcessResult extraction = RunRealTar(
        system_tar,
        extraction_args
    );

    if (!extraction.success) {
        std::cerr << extraction.std_err;
        std::cerr
            << "OPENFRUIT archive shim: filtered non-symlink extraction failed.\n";
        return false;
    }

    if (!has_symlinks) {
        return ValidateExtraction(destination, entries);
    }

    std::size_t materialized = 0;
    const bool repaired = MaterializeArchiveLinks(
        destination,
        entries,
        materialized
    );

    if (!repaired || !ValidateExtraction(destination, entries)) {
        std::cerr
            << "OPENFRUIT archive shim: symlink materialization after filtered "
               "extraction failed.\n";
        return false;
    }

    if (materialized_symlinks) {
        *materialized_symlinks = materialized;
    }

    std::cout
        << "OPENFRUIT archive shim: materialized "
        << materialized
        << " Unix archive symlink(s) using NTFS hard links/directories."
        << std::endl;

    return true;
}

bool ArchiveShim::EnsureTarShim(
    const fs::path& repo_root,
    fs::path& out_shim_directory
) {
    const fs::path executable = CurrentExecutable();
    if (executable.empty() || !fs::exists(executable)) {
        return false;
    }

    const fs::path shim_dir =
        ToolPaths::CacheRoot() / "shims" / "archive-v4";
    const fs::path shim = shim_dir / "tar.exe";

    std::error_code ec;
    fs::create_directories(shim_dir, ec);
    if (ec) {
        return false;
    }

    // Refresh on every parent OPENFRUIT invocation. The copy is tiny compared
    // with a SwiftPM build and guarantees the shim logic exactly matches the
    // currently running core revision.
    fs::copy_file(
        executable,
        shim,
        fs::copy_options::overwrite_existing,
        ec
    );
    if (ec) {
        return false;
    }

    out_shim_directory = shim_dir;
    return true;
}

int ArchiveShim::TarCompatMain(int argc, char* argv[]) {
    const fs::path system_tar = RealSystemTar();
    if (system_tar.empty()) {
        std::cerr << "OPENFRUIT archive shim: Windows system tar.exe not found.\n";
        return 127;
    }

    const std::vector<std::wstring> args = OriginalArguments(argc, argv);

    // Listing, creation and non-ZIP operations are transparent pass-throughs.
    if (!IsExtractInvocation(args)) {
        const ProcessResult result = RunRealTar(system_tar, args);
        std::cout << result.std_out;
        std::cerr << result.std_err;
        return result.exit_code;
    }

    const auto archive_opt = FindArchive(args);
    if (!archive_opt || !LooksLikeZip(*archive_opt)) {
        const ProcessResult result = RunRealTar(system_tar, args);
        std::cout << result.std_out;
        std::cerr << result.std_err;
        return result.exit_code;
    }

    fs::path archive = *archive_opt;
    if (!archive.is_absolute()) {
        archive = fs::absolute(archive);
    }

    const fs::path destination = FindDestination(args);
    const std::vector<ArchiveEntry> entries = InspectArchive(system_tar, archive);

    if (entries.empty()) {
        const ProcessResult result = RunRealTar(system_tar, args);
        std::cout << result.std_out;
        std::cerr << result.std_err;
        return result.exit_code;
    }

    const bool has_symlinks = std::any_of(
        entries.begin(),
        entries.end(),
        [](const ArchiveEntry& entry) {
            return entry.type == 'l';
        }
    );

    const ProcessResult extraction = RunRealTar(system_tar, args);

    if (extraction.success || !has_symlinks) {
        std::cout << extraction.std_out;
        std::cerr << extraction.std_err;
        return extraction.exit_code;
    }

    std::size_t materialized = 0;
    const bool repaired = MaterializeArchiveLinks(
        destination,
        entries,
        materialized
    );

    if (repaired && ValidateExtraction(destination, entries)) {
        std::cerr
            << "OPENFRUIT archive shim: materialized "
            << materialized
            << " Unix archive symlink(s) using NTFS hard links/directories.\n";
        return 0;
    }

    // Preserve the real extractor diagnostics if the failure was not purely
    // caused by unsupported symlink creation.
    std::cout << extraction.std_out;
    std::cerr << extraction.std_err;
    std::cerr << "OPENFRUIT archive shim: extraction repair failed.\n";
    return extraction.exit_code == 0 ? 1 : extraction.exit_code;
}

} // namespace OpenFruit
