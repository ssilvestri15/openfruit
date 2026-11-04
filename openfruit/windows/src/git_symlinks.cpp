#include "git_symlinks.hpp"
#include "git_source_view.hpp"
#include "win32_process.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <windows.h>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

static std::mutex s_git_cache_mutex;
static std::unordered_map<std::string, std::unordered_set<std::string>> s_indexed_symlinks_cache;
static std::unordered_map<std::string, std::vector<fs::path>> s_discovered_repos_cache;
static std::unordered_set<std::string> s_initialized_submodules_cache;


std::wstring GitExtendedWin32Path(const fs::path& input) {
    std::error_code ec;
    fs::path absolute = fs::absolute(input, ec);
    if (ec) {
        absolute = input;
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

bool IsHeaderLikeGitSymlink(const fs::path& path) {
    std::string extension = ToLowerAscii(path.extension().string());
    return extension == ".h" || extension == ".hh" ||
           extension == ".hpp" || extension == ".hxx" ||
           extension == ".inc" || extension == ".inl";
}


bool CopyRecursively(const fs::path& source, const fs::path& destination) {
    std::error_code ec;
    fs::create_directories(destination, ec);
    if (ec) {
        return false;
    }

    for (fs::recursive_directory_iterator it(
             source,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }

        const fs::path rel = fs::relative(it->path(), source, ec);
        if (ec) {
            ec.clear();
            continue;
        }

        const fs::path target_item = destination / rel;
        if (it->is_directory(ec)) {
            fs::create_directories(target_item, ec);
        } else if (it->is_regular_file(ec)) {
            fs::copy_file(
                it->path(),
                target_item,
                fs::copy_options::overwrite_existing,
                ec
            );
        }
        ec.clear();
    }
    return true;
}

std::unordered_set<std::string> IndexedGitSymlinkPaths(const fs::path& repo_dir) {
    const std::string cache_key = repo_dir.lexically_normal().string();
    {
        std::lock_guard<std::mutex> lock(s_git_cache_mutex);
        auto it = s_indexed_symlinks_cache.find(cache_key);
        if (it != s_indexed_symlinks_cache.end()) {
            return it->second;
        }
    }

    std::unordered_set<std::string> paths;

    const ProcessResult listing = Win32Process::Run(
        L"git.exe",
        {
            L"git.exe",
            L"-c",
            L"core.symlinks=false",
            L"-C",
            repo_dir.wstring(),
            L"ls-files",
            L"-s",
            L"-z"
        }
    );

    if (!listing.success) {
        return paths;
    }

    const std::string& data = listing.std_out;
    std::size_t begin = 0;

    while (begin < data.size()) {
        const std::size_t end = data.find('\0', begin);
        const std::size_t actual_end = (end == std::string::npos) ? data.size() : end;
        const std::string entry = data.substr(begin, actual_end - begin);
        begin = (end == std::string::npos) ? data.size() : end + 1;

        if (entry.rfind("120000 ", 0) != 0) {
            continue;
        }

        const std::size_t tab = entry.find('\t');
        if (tab == std::string::npos) {
            continue;
        }

        paths.insert(entry.substr(tab + 1));
    }

    {
        std::lock_guard<std::mutex> lock(s_git_cache_mutex);
        s_indexed_symlinks_cache[cache_key] = paths;
    }

    return paths;
}

std::vector<std::string> ParseNulSeparatedPaths(const std::string& data) {
    std::vector<std::string> paths;
    std::size_t begin = 0;

    while (begin < data.size()) {
        const std::size_t end = data.find('\0', begin);
        const std::size_t actual_end = (end == std::string::npos) ? data.size() : end;
        if (actual_end > begin) {
            paths.push_back(data.substr(begin, actual_end - begin));
        }
        begin = (end == std::string::npos) ? data.size() : end + 1;
    }

    return paths;
}

} // namespace

bool MaterializeGitSymlinksInRepo(const fs::path& repo_dir) {
    if (!fs::exists(repo_dir)) {
        return true;
    }

    const auto symlink_paths = IndexedGitSymlinkPaths(repo_dir);
    if (symlink_paths.empty()) {
        return true;
    }

    std::error_code ec;
    std::size_t count = 0;

    for (const auto& relative_str : symlink_paths) {
        const fs::path relative(relative_str);
        const fs::path placeholder = repo_dir / relative;

        if (!fs::exists(placeholder)) {
            continue;
        }

        const std::string target_text = ReadFileText(placeholder);
        if (target_text.empty() || target_text.size() > 2048) {
            continue;
        }
        if (target_text.find('\n') != std::string::npos &&
            target_text.find('\n') != target_text.size() - 1 &&
            target_text.find('\n') != target_text.size() - 2) {
            continue;
        }

        const fs::path target = (
            placeholder.parent_path() / fs::path(TrimWhitespace(target_text))
        ).lexically_normal();

        if (!fs::exists(target)) {
            continue;
        }

        // P0.2 Zero-Touch: Header symlinks are shadowed virtually via binary .hmap,
        // NEVER deleted, modified, or overwritten on disk.
        if (IsHeaderLikeGitSymlink(placeholder)) {
            continue;
        }

        fs::remove_all(placeholder, ec);
        ec.clear();

        bool materialized = false;
        std::string materialization_kind;

        const bool target_is_file = fs::is_regular_file(target, ec);
        ec.clear();

        if (target_is_file) {
            fs::create_directories(placeholder.parent_path(), ec);
            const std::wstring destination = GitExtendedWin32Path(placeholder);
            const std::wstring source = GitExtendedWin32Path(target);

            constexpr DWORD kAllowUnprivilegedCreate = 0x2;
            bool created = CreateSymbolicLinkW(
                destination.c_str(),
                source.c_str(),
                kAllowUnprivilegedCreate
            ) != FALSE;

            if (!created && GetLastError() == ERROR_INVALID_PARAMETER) {
                created = CreateSymbolicLinkW(
                    destination.c_str(),
                    source.c_str(),
                    0
                ) != FALSE;
            }

            if (created) {
                materialized = true;
                materialization_kind = "native symlink";
            } else if (CreateHardLinkW(
                           destination.c_str(),
                           source.c_str(),
                           nullptr)) {
                materialized = true;
                materialization_kind = "hard-link alias";
            }
        } else if (fs::is_directory(target, ec)) {
            fs::create_directories(placeholder.parent_path(), ec);
            const std::wstring destination = GitExtendedWin32Path(placeholder);
            const std::wstring source = GitExtendedWin32Path(target);

            constexpr DWORD kAllowUnprivilegedCreate = 0x2;
            constexpr DWORD kSymlinkDirFlags = 0x1 | kAllowUnprivilegedCreate;
            bool created = CreateSymbolicLinkW(
                destination.c_str(),
                source.c_str(),
                kSymlinkDirFlags
            ) != FALSE;

            if (!created && GetLastError() == ERROR_INVALID_PARAMETER) {
                created = CreateSymbolicLinkW(
                    destination.c_str(),
                    source.c_str(),
                    0x1
                ) != FALSE;
            }

            if (created) {
                materialized = true;
                materialization_kind = "native directory symlink";
            } else {
                materialized = CopyRecursively(target, placeholder);
                if (materialized) {
                    materialization_kind = "directory projection";
                }
            }
        }

        if (materialized) {
            ++count;
        }
    }

    if (count > 0) {
        std::cout << "OPENFRUIT: Materialized " << count
                  << " Git symlink(s) in repository: " << repo_dir.string() << std::endl;
    }

    return true;
}

bool RestoreGitSymlinkPlaceholdersInRepo(const fs::path& repo_dir) {
    if (!fs::exists(repo_dir)) {
        return true;
    }

    const auto symlink_paths = IndexedGitSymlinkPaths(repo_dir);
    if (symlink_paths.empty()) {
        return true;
    }

    const ProcessResult dirty = Win32Process::Run(
        L"git.exe",
        {
            L"git.exe",
            L"-c",
            L"core.symlinks=false",
            L"-C",
            repo_dir.wstring(),
            L"diff",
            L"--name-only",
            L"-z",
            L"HEAD",
            L"--"
        }
    );

    if (!dirty.success) {
        return false;
    }

    const auto changed_paths = ParseNulSeparatedPaths(dirty.std_out);
    std::vector<std::string> restore_paths;

    for (const auto& relative : changed_paths) {
        if (symlink_paths.find(relative) != symlink_paths.end()) {
            restore_paths.push_back(relative);
        }
    }

    if (restore_paths.empty()) {
        return true;
    }

    std::error_code ec;
    for (const auto& relative : restore_paths) {
        fs::remove_all(repo_dir / fs::path(relative), ec);
        ec.clear();
    }

    constexpr std::size_t kCheckoutBatchSize = 48;
    for (std::size_t offset = 0; offset < restore_paths.size(); offset += kCheckoutBatchSize) {
        const std::size_t limit = std::min(restore_paths.size(), offset + kCheckoutBatchSize);
        std::vector<std::wstring> args = {
            L"git.exe",
            L"-c",
            L"core.symlinks=false",
            L"-C",
            repo_dir.wstring(),
            L"checkout-index",
            L"-f",
            L"--"
        };
        for (std::size_t i = offset; i < limit; ++i) {
            args.push_back(Win32Process::ToWide(restore_paths[i]));
        }
        Win32Process::Run(L"git.exe", args);
    }

    std::cout << "OPENFRUIT: Restored " << restore_paths.size()
              << " Git symlink placeholder(s) in repository: " << repo_dir.string() << std::endl;

    return true;
}

std::vector<fs::path> DiscoverGitRepositories(const fs::path& root) {
    if (!fs::exists(root)) {
        return {};
    }

    const std::string cache_key = root.lexically_normal().string();
    {
        std::lock_guard<std::mutex> lock(s_git_cache_mutex);
        auto it = s_discovered_repos_cache.find(cache_key);
        if (it != s_discovered_repos_cache.end()) {
            return it->second;
        }
    }

    std::vector<fs::path> repos;

    if (fs::exists(root / ".git")) {
        repos.push_back(root);

        const ProcessResult submodules = Win32Process::Run(
            L"git.exe",
            {
                L"git.exe",
                L"-C",
                root.wstring(),
                L"submodule",
                L"status",
                L"--recursive"
            }
        );

        if (submodules.success && !submodules.std_out.empty()) {
            std::istringstream stream(submodules.std_out);
            std::string line;
            while (std::getline(stream, line)) {
                if (line.empty()) continue;
                std::istringstream line_stream(line);
                std::string hash_token, path_token;
                if (line_stream >> hash_token >> path_token) {
                    fs::path sub_path = (root / path_token).lexically_normal();
                    if (fs::exists(sub_path)) {
                        repos.push_back(sub_path);
                    }
                }
            }
        }
    } else {
        std::error_code ec;
        for (fs::directory_iterator it(
                 root,
                 fs::directory_options::skip_permission_denied,
                 ec);
             it != fs::directory_iterator();
             it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            if (it->is_directory(ec) && fs::exists(it->path() / ".git")) {
                repos.push_back(it->path());
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(s_git_cache_mutex);
        s_discovered_repos_cache[cache_key] = repos;
    }

    return repos;
}

bool InitializeMissingGitSubmodules(const fs::path& repo_dir) {
    if (!fs::exists(repo_dir / ".git")) {
        return true;
    }

    const std::string cache_key = repo_dir.lexically_normal().string();
    {
        std::lock_guard<std::mutex> lock(s_git_cache_mutex);
        if (s_initialized_submodules_cache.find(cache_key) != s_initialized_submodules_cache.end()) {
            return true;
        }
    }

    const auto status = [&]() {
        return Win32Process::Run(
            L"git.exe",
            {
                L"git.exe",
                L"-C",
                repo_dir.wstring(),
                L"submodule",
                L"status",
                L"--recursive"
            }
        );
    };

    ProcessResult before = status();
    if (!before.success) {
        std::cerr << "OPENFRUIT: failed to inspect Git submodules in: "
                  << repo_dir.string() << std::endl;
        return false;
    }

    bool has_missing = false;
    std::istringstream lines(before.std_out);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.front() == '-') {
            has_missing = true;
            break;
        }
    }
    if (!has_missing) {
        std::lock_guard<std::mutex> lock(s_git_cache_mutex);
        s_initialized_submodules_cache.insert(cache_key);
        return true;
    }

    std::cout << "OPENFRUIT: Initializing missing Git submodules recursively..."
              << std::endl;
    ProcessResult update = Win32Process::Run(
        L"git.exe",
        {
            L"git.exe",
            L"-C",
            repo_dir.wstring(),
            L"submodule",
            L"update",
            L"--init",
            L"--recursive"
        }
    );
    if (!update.success) {
        std::cerr << "OPENFRUIT: Git submodule initialization failed.\n"
                  << update.std_err << std::endl;
        return false;
    }

    ProcessResult after = status();
    if (!after.success) {
        return false;
    }
    std::istringstream verified(after.std_out);
    while (std::getline(verified, line)) {
        if (!line.empty() && line.front() == '-') {
            std::cerr << "OPENFRUIT: a required Git submodule remains "
                         "uninitialized: " << line << std::endl;
            return false;
        }
    }

    {
        std::lock_guard<std::mutex> lock(s_git_cache_mutex);
        s_initialized_submodules_cache.insert(cache_key);
    }
    return true;
}

fs::path ResolveGitSymlinkPlaceholderTarget(const fs::path& path) {
    const auto absolute = fs::absolute(path).lexically_normal();
    for (auto root = absolute.parent_path(); !root.empty(); root = root.parent_path()) {
        if (fs::exists(root / ".git")) {
            const auto resolved = ResolveGitSourcePath(root, absolute);
            return resolved == absolute ? path : resolved;
        }
        if (root.parent_path() == root) break;
    }
    // A projected tree has no Git placeholders. Its file contents cannot be
    // evidence that an ordinary header is a link.
    return path;
}

std::vector<GitSymlinkHeaderMapping> DiscoverGitSymlinkHeaderMappings(const fs::path& repo_dir) {
    std::vector<GitSymlinkHeaderMapping> mappings;
    if (!fs::exists(repo_dir)) {
        return mappings;
    }

    auto repos = DiscoverGitRepositories(repo_dir);
    if (repos.empty()) {
        repos.push_back(repo_dir);
    }

    std::error_code ec;
    for (const auto& repo : repos) {
        const auto symlink_paths = IndexedGitSymlinkPaths(repo);
        if (symlink_paths.empty()) {
            continue;
        }

        for (const auto& relative_str : symlink_paths) {
            const fs::path relative(relative_str);
            if (!IsHeaderLikeGitSymlink(relative)) {
                continue;
            }

            const fs::path placeholder = repo / relative;
            if (!fs::is_regular_file(placeholder, ec)) {
                ec.clear();
                continue;
            }

            fs::path target = ResolveGitSymlinkPlaceholderTarget(placeholder);
            if (target == placeholder || !fs::is_regular_file(target, ec)) {
                ec.clear();
                continue;
            }

            const std::string filename = placeholder.filename().string();
            mappings.push_back({filename, target});

            const fs::path parent = placeholder.parent_path();
            if (!parent.filename().empty()) {
                mappings.push_back({parent.filename().string() + "/" + filename, target});
            }

            std::string rel_generic = relative.generic_string();
            mappings.push_back({rel_generic, target});

            const std::string kPublicPrefix = "Headers/Public/";
            const std::string kPrivatePrefix = "Headers/Private/";
            const std::string kIncludePrefix = "include/";

            auto pub_idx = rel_generic.find(kPublicPrefix);
            if (pub_idx != std::string::npos) {
                std::string sub = rel_generic.substr(pub_idx + kPublicPrefix.size());
                if (!sub.empty()) {
                    mappings.push_back({sub, target});
                }
            }
            auto priv_idx = rel_generic.find(kPrivatePrefix);
            if (priv_idx != std::string::npos) {
                std::string sub = rel_generic.substr(priv_idx + kPrivatePrefix.size());
                if (!sub.empty()) {
                    mappings.push_back({sub, target});
                }
            }
            auto inc_idx = rel_generic.find(kIncludePrefix);
            if (inc_idx != std::string::npos) {
                std::string sub = rel_generic.substr(inc_idx + kIncludePrefix.size());
                if (!sub.empty()) {
                    mappings.push_back({sub, target});
                }
            }
        }
    }

    return mappings;
}

GitSymlinkGuard::GitSymlinkGuard(fs::path root)
    : root_(std::move(root)) {
}

GitSymlinkGuard::~GitSymlinkGuard() {
    if (active_) {
        RestoreNow();
    }
}

bool GitSymlinkGuard::Materialize() {
    auto repos = DiscoverGitRepositories(root_);
    for (const auto& repo : repos) {
        if (MaterializeGitSymlinksInRepo(repo)) {
            modified_repos_.push_back(repo);
        }
    }
    active_ = !modified_repos_.empty();
    return true;
}

bool GitSymlinkGuard::RestoreNow() {
    if (!active_) {
        return true;
    }
    for (auto it = modified_repos_.rbegin(); it != modified_repos_.rend(); ++it) {
        RestoreGitSymlinkPlaceholdersInRepo(*it);
    }
    modified_repos_.clear();
    active_ = false;
    return true;
}

void GitSymlinkGuard::Disarm() {
    active_ = false;
}

} // namespace OpenFruit
