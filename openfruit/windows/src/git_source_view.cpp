#include "utf8_path.hpp"
#include "git_source_view.hpp"
#include "operation_events.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"

#include <algorithm>
#include <atomic>
#include <deque>
#include <fstream>
#include <map>
#include <tuple>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <windows.h>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {

[[noreturn]] void Fail(const char* reason, const fs::path& path) {
    throw std::runtime_error(std::string("OPENFRUIT source view: ") + reason +
                             ": " + Win32Process::ToNarrow(path.wstring()));
}

bool Same(const fs::path& a, const fs::path& b) {
    const auto x = a.wstring(), y = b.wstring();
    return CompareStringOrdinal(x.data(), static_cast<int>(x.size()),
                                y.data(), static_cast<int>(y.size()), TRUE) == CSTR_EQUAL;
}

struct InsensitiveLess {
    bool operator()(const fs::path& a, const fs::path& b) const {
        const auto x = a.wstring(), y = b.wstring();
        return CompareStringOrdinal(x.data(), static_cast<int>(x.size()),
            y.data(), static_cast<int>(y.size()), TRUE) == CSTR_LESS_THAN;
    }
};

bool Within(const fs::path& path, const fs::path& root) {
    auto p = path.begin();
    for (auto r = root.begin(); r != root.end(); ++r, ++p)
        // Conservatively require the canonical root spelling. Folding the root
        // could admit a different sibling on a case-sensitive Windows volume.
        if (p == path.end() || *p != *r) return false;
    return true;
}


struct StatDigestCache {
    struct Entry {
        uint64_t size = 0;
        uint64_t mtime = 0;
        std::string digest;
    };
    std::unordered_map<std::wstring, Entry> entries;
    bool dirty = false;

    void Load(const fs::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return;
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty()) continue;
            size_t t1 = line.find('\t');
            size_t t2 = (t1 != std::string::npos) ? line.find('\t', t1 + 1) : std::string::npos;
            size_t t3 = (t2 != std::string::npos) ? line.find('\t', t2 + 1) : std::string::npos;
            if (t1 != std::string::npos && t2 != std::string::npos && t3 != std::string::npos) {
                try {
                    uint64_t size = std::stoull(line.substr(0, t1));
                    uint64_t mtime = std::stoull(line.substr(t1 + 1, t2 - t1 - 1));
                    std::string digest = line.substr(t2 + 1, t3 - t2 - 1);
                    std::string path_str = line.substr(t3 + 1);
                    entries[Win32Process::ToWide(path_str)] = {size, mtime, digest};
                } catch (...) {
                    continue;
                }
            }
        }
    }

    void Save(const fs::path& path) const {
        if (!dirty) return;
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file) return;
        for (const auto& [p, entry] : entries) {
            file << entry.size << "\t" << entry.mtime << "\t" << entry.digest << "\t" << Win32Process::ToNarrow(p) << "\n";
        }
    }

    std::optional<std::string> Get(const fs::path& file_path) {
        WIN32_FILE_ATTRIBUTE_DATA data;
        const auto wpath = file_path.lexically_normal().wstring();
        std::wstring query_path = wpath;
        if (query_path.rfind(L"\\\\?\\", 0) != 0 && query_path.length() >= 240) {
            query_path = L"\\\\?\\" + query_path;
        }
        if (!GetFileAttributesExW(query_path.c_str(), GetFileExInfoStandard, &data)) {
            return std::nullopt;
        }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            return std::nullopt;
        }
        uint64_t size = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
        uint64_t mtime = (static_cast<uint64_t>(data.ftLastWriteTime.dwHighDateTime) << 32) | data.ftLastWriteTime.dwLowDateTime;

        auto it = entries.find(wpath);
        if (it != entries.end() && it->second.size == size && it->second.mtime == mtime) {
            return it->second.digest;
        }
        return std::nullopt;
    }

    // Lookup by size and write time the caller already read from the file.
    std::optional<std::string> Get(const fs::path& file_path, uint64_t size, uint64_t mtime) const {
        const auto found = entries.find(file_path.lexically_normal().wstring());
        if (found != entries.end() && found->second.size == size && found->second.mtime == mtime)
            return found->second.digest;
        return std::nullopt;
    }

    void Put(const fs::path& file_path, const std::string& digest) {
        WIN32_FILE_ATTRIBUTE_DATA data;
        const auto wpath = file_path.lexically_normal().wstring();
        std::wstring query_path = wpath;
        if (query_path.rfind(L"\\\\?\\", 0) != 0 && query_path.length() >= 240) {
            query_path = L"\\\\?\\" + query_path;
        }
        if (!GetFileAttributesExW(query_path.c_str(), GetFileExInfoStandard, &data)) {
            return;
        }
        uint64_t size = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
        uint64_t mtime = (static_cast<uint64_t>(data.ftLastWriteTime.dwHighDateTime) << 32) | data.ftLastWriteTime.dwLowDateTime;
        entries[wpath] = {size, mtime, digest};
        dirty = true;
    }
};

// What an in-place edit of a published file cannot keep: NTFS updates
// ChangeTime on every content or attribute change and ordinary tools cannot
// set it, unlike LastWriteTime; volume and file index catch a replacement.
struct OutputStat {
    uint64_t size = 0, write = 0, change = 0, volume = 0, index = 0;
    bool operator==(const OutputStat&) const = default;
};

std::optional<OutputStat> ReadOutputStat(const fs::path& path) {
    auto wide = path.lexically_normal().wstring();
    if (wide.rfind(L"\\\\?\\", 0) != 0) wide = L"\\\\?\\" + wide;
    const HANDLE handle = CreateFileW(wide.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return std::nullopt;
    FILE_BASIC_INFO basic{};
    BY_HANDLE_FILE_INFORMATION info{};
    const bool read = GetFileInformationByHandleEx(handle, FileBasicInfo, &basic, sizeof(basic)) &&
        GetFileInformationByHandle(handle, &info);
    CloseHandle(handle);
    if (!read || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) return std::nullopt;
    OutputStat stat;
    stat.size = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    stat.write = static_cast<uint64_t>(basic.LastWriteTime.QuadPart);
    stat.change = static_cast<uint64_t>(basic.ChangeTime.QuadPart);
    stat.volume = info.dwVolumeSerialNumber;
    stat.index = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    return stat;
}

// Content digests of the files a sync published, valid while their
// OutputStat is unchanged.
struct OutputDigestCache {
    std::unordered_map<std::wstring, std::pair<OutputStat, std::string>> entries;
    bool dirty = false;

    void Load(const fs::path& path) {
        std::ifstream file(path, std::ios::binary);
        for (std::string line; std::getline(file, line);) {
            std::istringstream fields(line);
            OutputStat stat;
            std::string digest, relative;
            if (!(fields >> stat.size >> stat.write >> stat.change >> stat.volume >> stat.index >> digest)) continue;
            fields.get();
            std::getline(fields, relative);
            if (!relative.empty()) entries[Win32Process::ToWide(relative)] = {stat, digest};
        }
    }
    void Save(const fs::path& path) const {
        if (!dirty) return;
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        for (const auto& [relative, value] : entries) {
            const auto& [stat, digest] = value;
            file << stat.size << ' ' << stat.write << ' ' << stat.change << ' ' << stat.volume << ' '
                 << stat.index << ' ' << digest << ' ' << Win32Process::ToNarrow(relative) << '\n';
        }
    }
    const std::string* Find(const fs::path& relative, const OutputStat& stat) const {
        const auto found = entries.find(relative.generic_wstring());
        return found != entries.end() && found->second.first == stat ? &found->second.second : nullptr;
    }
    void Put(const fs::path& relative, const OutputStat& stat, const std::string& digest) {
        entries[relative.generic_wstring()] = {stat, digest};
        dirty = true;
    }
};

std::optional<std::string> CachedSha256File(StatDigestCache* cache, const fs::path& path,
                                            CancellationToken cancellation = {},
                                            std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max()) {
    if (cache) {
        if (auto cached = cache->Get(path)) {
            return cached;
        }
    }
    auto digest = Sha256File(path, cancellation, deadline);
    if (digest && cache) {
        cache->Put(path, *digest);
    }
    return digest;
}

// Everything an inventory needs from one file, read through one handle that
// does not follow a final reparse point.
struct FileFacts {
    DWORD attributes = 0, links = 0, volume = 0, index_high = 0, index_low = 0;
    uint64_t size = 0, mtime = 0;
};

std::wstring LongName(const fs::path& path) {
    auto name = path.wstring();
    if (name.rfind(L"\\\\?\\", 0) != 0)
        name = name.rfind(L"\\\\", 0) == 0 ? L"\\\\?\\UNC\\" + name.substr(2) : L"\\\\?\\" + name;
    return name;
}

std::optional<FileFacts> ReadFileFacts(const fs::path& path) {
    const auto name = LongName(path);
    const HANDLE handle = CreateFileW(name.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return std::nullopt;
    BY_HANDLE_FILE_INFORMATION info{};
    const bool known = GetFileInformationByHandle(handle, &info) != FALSE;
    CloseHandle(handle);
    if (!known) return std::nullopt;
    FileFacts facts;
    facts.attributes = info.dwFileAttributes;
    facts.links = info.nNumberOfLinks;
    facts.volume = info.dwVolumeSerialNumber;
    facts.index_high = info.nFileIndexHigh;
    facts.index_low = info.nFileIndexLow;
    facts.size = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    facts.mtime = (static_cast<uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) | info.ftLastWriteTime.dwLowDateTime;
    return facts;
}

struct ViewEntry {
    fs::path relative, resolved, target;
    std::string type, digest;
    std::string input_kind, input_target;
};

struct Builder {
    fs::path source, staging, destination;
    ProcessRunOptions control;
    bool resolve_git_placeholders = true;
    OperationContextPtr operation = CurrentOperationContext();
    std::map<fs::path, std::set<fs::path, InsensitiveLess>> indexes;
    std::map<fs::path, std::optional<fs::path>> git_roots;
    std::set<fs::path> plain_directories;
    std::map<fs::path, fs::path, InsensitiveLess> active_directories;
    GitSourceView result;
    bool inventory_only = false;
    std::vector<ViewEntry> entries;
    bool include_git_metadata = false;
    std::vector<fs::path> excluded_root_entries;
    std::set<fs::path, InsensitiveLess> regular_files;
    std::vector<std::pair<fs::path, fs::path>> file_aliases;
    // First published spelling of each multiply linked file, by file identity.
    std::map<std::tuple<DWORD, DWORD, DWORD>, fs::path> hard_links;

    static std::optional<std::tuple<DWORD, DWORD, DWORD>> HardLinkIdentity(const fs::path& path) {
        auto name = path.wstring();
        if (name.rfind(L"\\\\?\\", 0) != 0)
            name = name.rfind(L"\\\\", 0) == 0 ? L"\\\\?\\UNC\\" + name.substr(2) : L"\\\\?\\" + name;
        const HANDLE handle = CreateFileW(name.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (handle == INVALID_HANDLE_VALUE) return std::nullopt;
        BY_HANDLE_FILE_INFORMATION info{};
        const bool known = GetFileInformationByHandle(handle, &info) != FALSE;
        CloseHandle(handle);
        if (!known || info.nNumberOfLinks < 2) return std::nullopt;
        return std::tuple{info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow};
    }
    StatDigestCache* stat_cache = nullptr;

    void ValidateFileAliases() const {
        for (const auto& [alias, canonical] : file_aliases)
            if (!regular_files.contains(canonical))
                Fail("file alias canonical target is not published", source / alias);
    }

    void Check() const {
        if (control.cancellation && control.cancellation->load())
            Fail("cancelled", source);
        if (operation && operation->CancellationRequested()) Fail("cancelled", source);
        if (std::chrono::steady_clock::now() >= control.deadline)
            Fail("deadline exceeded", source);
        if (operation && operation->DeadlineExceeded()) Fail("deadline exceeded", source);
    }

    bool IndexedLink(const fs::path& path) {
        if (!resolve_git_placeholders) return false;
        // Each directory's enclosing checkout is looked up once per inventory.
        const auto directory = path.parent_path();
        auto cached_root = git_roots.find(directory);
        if (cached_root == git_roots.end()) {
            std::optional<fs::path> located;
            for (auto root = directory;;) {
                if (fs::exists(root / ".git")) { located = root; break; }
                const auto parent = root.parent_path();
                if (parent == root || root.empty()) break;
                root = parent;
            }
            cached_root = git_roots.emplace(directory, std::move(located)).first;
        }
        if (!cached_root->second) return false;
        const auto& root = *cached_root->second;
        auto found = indexes.find(root);
        if (found == indexes.end()) {
            const auto listing = Win32Process::Run(L"git.exe",
                {L"git.exe", L"-C", root.wstring(), L"ls-files", L"-s", L"-z"},
                L"", {}, nullptr, nullptr, control);
            Check();
            if (!listing.success || listing.output_truncated)
                Fail("cannot read complete Git index", root);
            std::set<fs::path, InsensitiveLess> links;
            std::size_t begin = 0;
            while (begin < listing.std_out.size()) {
                const auto end = listing.std_out.find('\0', begin);
                if (end == std::string::npos) Fail("malformed Git index", root);
                const auto entry = listing.std_out.substr(begin, end - begin);
                const auto tab = entry.find('\t');
                if (tab == std::string::npos || tab == 0 || entry[tab - 1] != '0')
                    Fail("malformed or unmerged Git index", root);
                if (entry.rfind("120000 ", 0) == 0 &&
                    !links.insert((root / Utf8Path(entry.substr(tab + 1))).lexically_normal()).second)
                    Fail("case-ambiguous Git symlink entries", root);
                begin = end + 1;
            }
            found = indexes.emplace(root, std::move(links)).first;
        }
        return found->second.contains(path);
    }

    fs::path Resolve(fs::path path) { return *ResolvePath(std::move(path), false); }

    std::optional<fs::path> ResolvePath(fs::path path, bool optional, bool admit_dangling = false) {
        source.make_preferred();
        path.make_preferred();
        if (!Within(path, source)) {
            // Windows can spell the same root with different casing. Admit a
            // spelling only after its complete physical root prefix resolves
            // to this exact canonical root. Blind case folding would admit a
            // distinct sibling in a case-sensitive directory.
            auto requested = path.begin();
            fs::path prefix;
            for (auto component = source.begin(); component != source.end(); ++component) {
                if (requested == path.end()) Fail("link escapes source root", path);
                prefix /= *requested++;
            }
            std::error_code error;
            const auto physical_prefix = fs::canonical(prefix, error).make_preferred();
            if (error || physical_prefix != source) Fail("link escapes source root", path);
            // Keep suffix components intact: interpreting '..' before expanding
            // a directory symlink would change the requested lookup semantics.
            fs::path rebased = source;
            for (; requested != path.end(); ++requested) rebased /= *requested;
            path = std::move(rebased);
        }
        struct PendingComponent { fs::path path; bool from_link_target = false; };
        std::deque<PendingComponent> remaining;
        for (const auto& component : path.lexically_relative(source))
            remaining.push_back({component, false});
        path = source;
        // A path may legitimately revisit the same link after '..'. Bound
        // expansions as POSIX path lookup does rather than treating every
        // repeated link as a cycle (for example alias/../alias/file).
        unsigned expansions = 0;
        while (!remaining.empty()) {
            Check();
            const auto pending = remaining.front();
            remaining.pop_front();
            const auto& component = pending.path;
            if (component == L"." || component.empty()) continue;
            if (component == L"..") {
                path = path.parent_path();
                if (!Within(path, source)) Fail("link escapes source root", path);
                continue;
            }
            path /= component;
            if (!Within(path, source)) Fail("link escapes source root", path);
            // A directory already found to be a plain, physically contained
            // directory during this inventory needs no further lookups.
            if (plain_directories.contains(path)) continue;
            std::error_code status_error;
            const auto status = fs::symlink_status(path, status_error);
            if (status_error && status_error != std::errc::no_such_file_or_directory)
                throw fs::filesystem_error("OPENFRUIT source metadata status", path, status_error);
            fs::path target;
            if (fs::is_symlink(status)) {
                target = fs::read_symlink(path);
            } else if (IndexedLink(path)) {
                if (!fs::is_regular_file(status)) Fail("missing Git placeholder", path);
                if (fs::file_size(path) > 1024 * 1024) Fail("invalid Git placeholder size", path);
                std::ifstream input(path, std::ios::binary);
                if (!input) Fail("cannot read Git placeholder", path);
                const std::string text((std::istreambuf_iterator<char>(input)), {});
                if (input.bad() || text.empty() || text.find('\0') != std::string::npos)
                    Fail("invalid Git placeholder", path);
                target = Utf8Path(text); // Never trim: spaces belong to the target name.
            } else {
                if (!fs::exists(status)) {
                    if (optional && (!pending.from_link_target || admit_dangling)) return std::nullopt;
                    Fail("missing source or link target", path);
                }
                // Reject junctions/reparse paths that bypass lexical containment.
                // A regular file that is not a reparse point, inside a
                // directory already verified as plain and contained, is
                // contained itself.
                const bool contained_by_parent = fs::is_regular_file(status) &&
                    (path.parent_path() == source || plain_directories.contains(path.parent_path())) && [&] {
                        const auto attributes = GetFileAttributesW(path.c_str());
                        return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
                    }();
                if (!contained_by_parent && !Within(fs::canonical(path), source))
                    Fail("physical path escapes source root", path);
                if (!remaining.empty() && !fs::is_directory(status))
                    Fail("link traverses a non-directory", path);
                if (fs::is_directory(status)) plain_directories.insert(path);
                continue;
            }
            if (++expansions > 40) Fail("symlink cycle or expansion limit exceeded", path);
            if (target.is_absolute() || target.has_root_name() || target.has_root_directory())
                Fail("absolute symlink target", path);
            // Expand before interpreting '..': an intermediate directory link
            // changes its meaning. Normalizing the text first loses semantics.
            std::vector<PendingComponent> components;
            for (const auto& item : target) components.push_back({item, true});
            remaining.insert(remaining.begin(), components.begin(), components.end());
            path = path.parent_path();
        }
        return path;
    }

    void Record(ViewEntry entry, const fs::path& original) {
        std::error_code error;
        const auto status = fs::symlink_status(original, error);
        if (error || !fs::exists(status)) {
            // Logical descendants below a Git directory placeholder have no
            // physical entry at their logical spelling. Resolve() supplies
            // their actual input and the parent entry records its link text.
            entry.input_kind = "projected-descendant";
        } else if (fs::is_symlink(status)) {
            entry.input_kind = "native-symlink";
            entry.input_target = Win32Process::ToNarrow(fs::read_symlink(original).wstring());
        } else if (IndexedLink(original)) {
            entry.input_kind = "git-120000";
            std::ifstream input(original, std::ios::binary);
            entry.input_target.assign(std::istreambuf_iterator<char>(input), {});
            if (!input || input.bad()) Fail("cannot read inventoried Git placeholder", original);
        } else {
            entry.input_kind = fs::is_directory(status) ? "directory" : "file";
        }
        entries.push_back(std::move(entry));
    }

    // An inventoried directory entry that its enumeration reports as a
    // regular file, inside a directory already verified as plain and
    // contained, is resolved, classified and keyed from one handle. Those
    // handles are read concurrently once the traversal is complete; anything
    // they show is not a plain singly linked file (a reparse point, a hard
    // link) then takes the general path. Links and Git placeholders take it
    // during the traversal.
    struct PendingPlainFile { fs::path original, relative; };
    std::vector<PendingPlainFile> pending_plain_files;

    bool RecordPlainFile(const fs::path& original, const fs::path& relative) {
        const auto parent = original.parent_path();
        if (!inventory_only || relative.empty() || (parent != source && !plain_directories.contains(parent)) ||
            IndexedLink(original))
            return false;
        pending_plain_files.push_back({original, relative});
        return true;
    }

    void ResolvePendingPlainFiles() {
        struct Outcome { std::optional<FileFacts> facts; std::optional<std::string> digest; bool hashed = false; };
        std::vector<Outcome> outcomes(pending_plain_files.size());
        const auto plain = [](const std::optional<FileFacts>& facts) {
            return facts && !(facts->attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                facts->links < 2;
        };
        std::atomic<std::size_t> next{0};
        std::exception_ptr failure;
        std::mutex failure_mutex;
        const auto read = [&] {
            try {
                for (std::size_t index; (index = next++) < pending_plain_files.size();) {
                    if (control.cancellation && control.cancellation->load()) break;
                    const auto& original = pending_plain_files[index].original;
                    auto& outcome = outcomes[index];
                    outcome.facts = ReadFileFacts(original);
                    if (!plain(outcome.facts)) continue;
                    // The digest cache is only read here; misses are recorded below.
                    if (stat_cache) outcome.digest = stat_cache->Get(original, outcome.facts->size, outcome.facts->mtime);
                    if (!outcome.digest) {
                        outcome.digest = Sha256File(original, {}, control.deadline);
                        outcome.hashed = true;
                    }
                }
            } catch (...) {
                next = pending_plain_files.size();
                std::lock_guard lock(failure_mutex);
                if (!failure) failure = std::current_exception();
            }
        };
        const std::size_t workers = std::min<std::size_t>(pending_plain_files.size(),
            std::clamp<std::size_t>(std::thread::hardware_concurrency(), 1, 8));
        std::vector<std::thread> threads;
        for (std::size_t worker = 1; worker < workers; ++worker) threads.emplace_back(read);
        if (workers) read();
        for (auto& thread : threads) thread.join();
        if (failure) std::rethrow_exception(failure);
        Check();
        auto pending = std::move(pending_plain_files);
        pending_plain_files.clear();
        for (std::size_t index = 0; index < pending.size(); ++index) {
            const auto& [original, relative] = pending[index];
            auto& outcome = outcomes[index];
            if (!plain(outcome.facts)) {
                // A file that became a directory after its listing would be
                // entered without its ancestors' loop guard.
                if (outcome.facts && (outcome.facts->attributes & FILE_ATTRIBUTE_DIRECTORY))
                    Fail("source entry changed during inventory", original);
                Copy(original, relative);
                continue;
            }
            if (!outcome.digest) Fail("cannot hash source", original);
            if (outcome.hashed && stat_cache) {
                stat_cache->entries[original.lexically_normal().wstring()] =
                    {outcome.facts->size, outcome.facts->mtime, *outcome.digest};
                stat_cache->dirty = true;
            }
            result.mappings.push_back({source / relative, original, destination / relative});
            regular_files.insert(relative);
            ViewEntry entry{relative, original, {}, "file", std::move(*outcome.digest)};
            entry.input_kind = "file";
            entries.push_back(std::move(entry));
        }
    }

    // A listed directory that is not a reparse point, inside a directory
    // already verified as plain and contained, is its own physical and
    // canonical path.
    bool PlainDirectory(const fs::path& original, const fs::path& relative) {
        const auto parent = original.parent_path();
        if (!inventory_only || relative.empty() || (parent != source && !plain_directories.contains(parent)) ||
            IndexedLink(original))
            return false;
        const auto attributes = GetFileAttributesW(LongName(original).c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            return false;
        plain_directories.insert(original);
        return true;
    }

    void Copy(const fs::path& original, const fs::path& relative, const fs::file_status* listed = nullptr) {
        Check();
        if (listed && fs::is_regular_file(*listed) && RecordPlainFile(original, relative)) return;
        const bool plain_directory = listed && fs::is_directory(*listed) && PlainDirectory(original, relative);
        const auto physical_opt = plain_directory ? std::optional<fs::path>(original)
                                                  : ResolvePath(original, true, !relative.empty());
        // A link whose target is absent from the checkout (for example a
        // fixture fetched separately) stays dangling, as a POSIX checkout
        // keeps it; only a consumer that reads through it fails.
        if (!physical_opt) {
            if (relative.empty()) Fail("missing source or link target", original);
            fs::path text;
            if (fs::is_symlink(fs::symlink_status(original))) text = fs::read_symlink(original);
            else if (IndexedLink(original)) {
                std::ifstream input(original, std::ios::binary);
                const std::string raw((std::istreambuf_iterator<char>(input)), {});
                if (!input && !input.eof()) Fail("cannot read Git placeholder", original);
                text = Utf8Path(raw);
            } else Fail("missing source or link target", original);
            text.make_preferred();
            const auto lexical = (relative.parent_path() / text).lexically_normal();
            if (text.empty() || text.has_root_name() || text.has_root_directory() ||
                lexical.empty() || *lexical.begin() == L"..")
                Fail("link escapes source root", original);
            if (inventory_only) {
                Record({relative, original, text, "dangling", {}}, original);
                return;
            }
            const auto output = staging / relative;
            auto link = output.wstring();
            if (link.rfind(L"\\\\?\\", 0) != 0)
                link = link.rfind(L"\\\\", 0) == 0
                    ? L"\\\\?\\UNC\\" + link.substr(2) : L"\\\\?\\" + link;
            bool created = CreateSymbolicLinkW(link.c_str(), text.c_str(), 0x2) != FALSE;
            if (!created && GetLastError() == ERROR_INVALID_PARAMETER)
                created = CreateSymbolicLinkW(link.c_str(), text.c_str(), 0) != FALSE;
            if (!created) Fail("cannot create dangling source link", output);
            return;
        }
        const auto physical = *physical_opt;
        const auto output = staging / relative;
        result.mappings.push_back({source / relative, physical, destination / relative});
        if (plain_directory || fs::is_directory(physical)) {
            const auto identity = plain_directory ? physical : fs::canonical(physical);
            const auto [ancestor, entered] = active_directories.emplace(identity, relative);
            if (!entered) {
                // A finite lookup back to an ancestor is valid (e.g. a test
                // fixture pointing to its package root). Preserve the graph
                // inside the independent view instead of unfolding it forever.
                // Relative targets survive the staging-to-publication rename.
                const auto target = (staging / ancestor->second).lexically_relative(output.parent_path());
                if (target.empty() || target.is_absolute()) Fail("invalid owned ancestor alias", original);
                if (inventory_only) {
                    Record({relative, physical, target, "alias", {}}, original);
                    return;
                }
                fs::create_directories(fs::path(LongName(output.parent_path())));
                auto link = output.wstring();
                if (link.rfind(L"\\\\?\\", 0) != 0)
                    link = link.rfind(L"\\\\", 0) == 0
                        ? L"\\\\?\\UNC\\" + link.substr(2) : L"\\\\?\\" + link;
                bool created = CreateSymbolicLinkW(link.c_str(), target.c_str(),
                    SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2 /* allow unprivileged creation */) != FALSE;
                if (!created && GetLastError() == ERROR_INVALID_PARAMETER)
                    created = CreateSymbolicLinkW(link.c_str(), target.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY) != FALSE;
                if (!created) {
                    const auto reason = "cannot create owned ancestor directory alias (Win32 error " +
                        std::to_string(GetLastError()) + ")";
                    Fail(reason.c_str(), original);
                }
                return;
            }
            if (inventory_only && plain_directory)
                entries.push_back({relative, physical, {}, "directory", {}, "directory", {}});
            else if (inventory_only) Record({relative, physical, {}, "directory", {}}, original);
            else fs::create_directories(fs::path(LongName(output)));
            std::set<fs::path, InsensitiveLess> names;
            for (const auto& entry : fs::directory_iterator(physical)) {
                const auto name = entry.path().filename();
                if (!include_git_metadata && Same(name, L".git")) continue;
                if (relative.empty() && std::any_of(excluded_root_entries.begin(), excluded_root_entries.end(),
                        [&](const fs::path& excluded) { return Same(name, excluded); })) continue;
                if (!names.insert(name).second)
                    Fail("case-ambiguous directory entries", entry.path());
                std::error_code listed_error;
                const auto listed = entry.symlink_status(listed_error);
                Copy(entry.path(), relative / name, listed_error ? nullptr : &listed);
            }
            active_directories.erase(identity);
        } else if (fs::is_regular_file(physical)) {
            // Only an actual file link carries file-identity semantics. A
            // normal child encountered while expanding a directory alias is
            // copied into that directory, so exporting/copying the subtree
            // does not leave links to nodes outside that subtree.
            // Hard links share one file identity, which consumers such as
            // #import deduplication observe; later links alias the first.
            fs::path linked;
            if (Same(original, physical))
                if (const auto identity = HardLinkIdentity(physical)) {
                    const auto [first, inserted] = hard_links.emplace(*identity, relative);
                    if (!inserted) linked = first->second;
                }
            if (!Same(original, physical) || !linked.empty()) {
                const auto canonical = linked.empty() ? physical.lexically_relative(source) : linked;
                const auto target = (staging / canonical).lexically_relative(output.parent_path());
                if (canonical.empty() || target.empty() || target.is_absolute())
                    Fail("invalid owned file alias", original);
                file_aliases.emplace_back(relative, canonical);
                if (inventory_only) {
                    const auto digest = CachedSha256File(stat_cache, physical, {}, control.deadline);
                    Check();
                    if (!digest) Fail("cannot hash file alias target", original);
                    Record({relative, physical, target, "file_alias", *digest}, original);
                    return;
                }
                auto link = output.wstring();
                if (link.rfind(L"\\\\?\\", 0) != 0)
                    link = link.rfind(L"\\\\", 0) == 0
                        ? L"\\\\?\\UNC\\" + link.substr(2) : L"\\\\?\\" + link;
                bool created = CreateSymbolicLinkW(link.c_str(), target.c_str(), 0x2) != FALSE;
                if (!created && GetLastError() == ERROR_INVALID_PARAMETER)
                    created = CreateSymbolicLinkW(link.c_str(), target.c_str(), 0) != FALSE;
                if (!created) Fail("cannot create owned file alias", output);
                return;
            }
            regular_files.insert(relative);
            if (inventory_only) {
                const auto digest = CachedSha256File(stat_cache, physical, {}, control.deadline);
                Check();
                if (!digest) Fail("cannot hash source", original);
                Record({relative, physical, {}, "file", *digest}, original);
                return;
            }
            // Extended-length names: a projection can pass MAX_PATH even
            // where the process is not long-path aware.
            std::ifstream input(fs::path(LongName(physical)), std::ios::binary);
            std::ofstream out(fs::path(LongName(output)), std::ios::binary | std::ios::trunc);
            if (!input || !out) Fail("cannot copy source", original);
            std::vector<char> block(65536);
            while (input) {
                Check();
                input.read(block.data(), static_cast<std::streamsize>(block.size()));
                out.write(block.data(), input.gcount());
            }
            out.close();
            if (input.bad() || !out) Fail("incomplete source copy", original);
        } else {
            Fail("unsupported source entry type", original);
        }
    }
};
} // namespace

GitSourceView CreateGitSourceView(const fs::path& source, const fs::path& destination,
                                  const ProcessRunOptions& control) {
    const auto root = fs::canonical(source);
    if (!fs::is_directory(root)) Fail("source is not a directory", source);
    const auto published = fs::weakly_canonical(fs::absolute(destination));
    if (Within(published, root)) Fail("destination is inside source root", destination);
    for (auto ancestor = root; !ancestor.empty(); ancestor = ancestor.parent_path()) {
        if (fs::exists(ancestor / ".git") && Within(published, ancestor))
            Fail("destination is inside source checkout", destination);
        if (ancestor.parent_path() == ancestor) break;
    }
    if (fs::exists(published)) Fail("destination already exists", destination);
    fs::create_directories(published.parent_path());
    static std::atomic<unsigned long long> serial{0};
    auto staging = published;
    staging += L".pending-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
               std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++serial);
    if (!fs::create_directory(staging)) Fail("cannot reserve staging directory", staging);
    try {
        Builder builder{root, staging, published, control};
        builder.result.root = published;
        builder.Copy(root, {});
        builder.ValidateFileAliases();
        builder.Check();
        // Windows rename refuses an existing destination; competing publishers
        // never replace each other's output or expose a partial view.
        fs::rename(staging, published);
        return std::move(builder.result);
    } catch (...) {
        std::error_code ec;
        fs::remove_all(staging, ec); // Only our newly reserved external directory.
        throw;
    }
}

namespace {
constexpr const char* kSyncSchema = "openfruit.git-source-view-sync.v1";
using OwnedEntries = std::map<fs::path, ViewEntry, InsensitiveLess>;

bool Reparse(const fs::path& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}
bool Present(const fs::path& path) {
    std::error_code error;
    const auto status = fs::symlink_status(path, error);
    if (error && error != std::errc::no_such_file_or_directory && error != std::errc::not_a_directory)
        Fail("cannot inspect owned entry", path);
    return fs::exists(status);
}
std::string PathText(const fs::path& path) { return Win32Process::ToNarrow(path.wstring()); }

void ValidateRelative(const fs::path& relative) {
    if (relative.is_absolute() || relative.has_root_name() || relative.has_root_directory())
        Fail("invalid receipt relative path", relative);
    for (const auto& component : relative)
        if (component == L".." || component == L"." || component.empty() ||
            component.wstring().find(L':') != std::wstring::npos ||
            component.wstring().find(L'\0') != std::wstring::npos)
            Fail("invalid receipt relative path", relative);
}

JsonValue Receipt(const fs::path& source, const fs::path& destination,
                  const OwnedEntries& entries, const char* state, const std::string& source_identity) {
    auto value = JsonValue::ObjectValue();
    value.Set("schema", JsonValue::String(kSyncSchema));
    value.Set("state", JsonValue::String(state));
    value.Set("source", JsonValue::String(PathText(source)));
    value.Set("source_identity", JsonValue::String(source_identity));
    value.Set("destination", JsonValue::String(PathText(destination)));
    auto list = JsonValue::ArrayValue();
    for (const auto& [relative, entry] : entries) {
        auto item = JsonValue::ObjectValue();
        item.Set("path", JsonValue::String(PathText(relative)));
        item.Set("type", JsonValue::String(entry.type));
        item.Set("resolved", JsonValue::String(PathText(entry.resolved)));
        item.Set("target", JsonValue::String(PathText(entry.target)));
        item.Set("sha256", JsonValue::String(entry.digest));
        item.Set("input_kind", JsonValue::String(entry.input_kind));
        item.Set("input_target", JsonValue::String(entry.input_target));
        list.ArrayItems().push_back(std::move(item));
    }
    value.Set("entries", std::move(list));
    return value;
}

OwnedEntries LoadReceipt(const fs::path& receipt, const fs::path& source,
                         const fs::path& destination, const std::string& source_identity,
                         std::string* state = nullptr) {
    if (Reparse(receipt) || !fs::is_regular_file(fs::symlink_status(receipt)) ||
        fs::file_size(receipt) > 256 * 1024 * 1024)
        Fail("invalid source view ownership receipt", receipt);
    std::ifstream input(receipt, std::ios::binary);
    if (!input) Fail("cannot read source view receipt", receipt);
    const std::string text((std::istreambuf_iterator<char>(input)), {});
    if (input.bad()) Fail("cannot read source view receipt", receipt);
    const auto value = JsonValue::Parse(text);
    if (!value || !value->IsObject() || value->GetString("schema") != kSyncSchema ||
        (value->GetString("state") != "complete" && value->GetString("state") != "updating") ||
        value->GetString("source_identity") != source_identity ||
        (source_identity.empty() && value->GetString("source") != PathText(source)) ||
        value->GetString("destination") != PathText(destination))
        Fail("source view receipt ownership mismatch", receipt);
    if (state) *state = value->GetString("state");
    const auto registered_source = Utf8Path(value->GetString("source"));
    if (registered_source.empty() || !registered_source.is_absolute() ||
        registered_source.lexically_normal() != registered_source)
        Fail("invalid registered source view root", receipt);
    const auto* list = value->Get("entries");
    if (!list || !list->IsArray()) Fail("invalid source view entry inventory", receipt);
    OwnedEntries entries;
    for (const auto& item : list->ArrayItems()) {
        if (!item.IsObject()) Fail("invalid source view entry", receipt);
        for (const auto* field : {"path", "type", "resolved", "target", "sha256", "input_kind", "input_target"}) {
            const auto* content = item.Get(field);
            if (!content || !content->IsString()) Fail("invalid source view entry field", receipt);
        }
        ViewEntry entry{Utf8Path(item.GetString("path")), Utf8Path(item.GetString("resolved")),
            Utf8Path(item.GetString("target")), item.GetString("type"), item.GetString("sha256"),
            item.GetString("input_kind"), item.GetString("input_target")};
        ValidateRelative(entry.relative);
        if ((entry.type != "file" && entry.type != "directory" && entry.type != "alias" &&
             entry.type != "file_alias" && entry.type != "dangling") ||
            !Within(entry.resolved, registered_source) ||
            entry.resolved.lexically_normal() != entry.resolved ||
            ((entry.type == "file" || entry.type == "file_alias") && (entry.digest.size() != 64 ||
                entry.digest.find_first_not_of("0123456789abcdef") != std::string::npos)))
            Fail("invalid source view entry identity", receipt);
        if (entry.type == "alias" || entry.type == "file_alias" || entry.type == "dangling") {
            const auto target = (entry.relative.parent_path() / entry.target).lexically_normal();
            if (entry.target.empty() || entry.target.is_absolute() || entry.target.has_root_name() ||
                target.is_absolute() || (!target.empty() && *target.begin() == L".."))
                Fail("invalid source view ancestor alias", receipt);
        }
        // The old root need not exist. Validate against the recorded root first,
        // then rebase ownership provenance for a recoverable updating receipt.
        if (registered_source != source)
            entry.resolved = source / entry.resolved.lexically_relative(registered_source);
        if (!entries.emplace(entry.relative, std::move(entry)).second)
            Fail("duplicate source view entry", receipt);
    }
    if (!entries.contains(fs::path{}) || entries.at(fs::path{}).type != "directory")
        Fail("missing source view root ownership", receipt);
    return entries;
}

// Never traverse a substituted output junction/symlink while hashing or deleting.
// An owned ancestor that has become a link can itself be unlinked safely.
// Output directories already verified during one synchronization. Entries
// stay valid until the synchronization removes something.
using VerifiedParents = std::unordered_set<std::wstring>;

bool SafeParents(const fs::path& root, const fs::path& relative,
                 const OwnedEntries& owned, GitSourceViewSyncStats& stats,
                 VerifiedParents* verified = nullptr) {
    auto current = root;
    fs::path accumulated;
    for (const auto& component : relative.parent_path()) {
        accumulated /= component;
        current /= component;
        if (verified && verified->contains(current.native())) continue;
        if (!Present(current)) return false;
        if (Reparse(current)) {
            if (!owned.contains(accumulated)) Fail("unowned output parent alias", current);
            if (!fs::remove(current)) Fail("cannot remove corrupt output parent alias", current);
            ++stats.entries_removed;
            return false;
        }
        if (!fs::is_directory(fs::symlink_status(current))) return false;
        if (verified) verified->insert(current.native());
    }
    return true;
}
void RemoveOwned(const fs::path& root, const fs::path& relative,
                 const OwnedEntries& owned, GitSourceViewSyncStats& stats) {
    if (relative.empty() || !SafeParents(root, relative, owned, stats)) return;
    const auto path = root / relative;
    if (Present(path)) {
        // remove() unlinks a reparse point, and refuses nonempty directories.
        // Unrecorded contents therefore cannot be recursively erased.
        if (!fs::remove(path)) Fail("cannot remove owned output entry", path);
        ++stats.entries_removed;
    }
}
} // namespace

GitSourceViewSyncResult SynchronizeGitSourceView(const fs::path& source,
    const fs::path& destination, const fs::path& receipt_path, const ProcessRunOptions& control,
    const GitSourceViewSyncOptions& options) {
    const auto root = fs::canonical(source);
    const auto output = fs::absolute(destination).lexically_normal();
    const auto receipt = fs::absolute(receipt_path).lexically_normal();
    if (!fs::is_directory(root)) Fail("source is not a directory", source);
    if (Reparse(output)) Fail("source view root is an alias", output);
    const auto published = fs::weakly_canonical(output);
    const auto receipt_physical = fs::weakly_canonical(receipt);
    if (Within(published, root)) Fail("destination is inside source root", destination);
    if (Within(receipt_physical, published) || Within(receipt_physical, root))
        Fail("receipt must be outside source and view", receipt);
    for (auto ancestor = root; !ancestor.empty(); ancestor = ancestor.parent_path()) {
        if (fs::exists(ancestor / ".git") &&
            (Within(published, ancestor) || Within(receipt_physical, ancestor)))
            Fail("destination or receipt is inside source checkout", destination);
        if (ancestor.parent_path() == ancestor) break;
    }
    const auto stat_cache_path = receipt.wstring() + L".stat_cache";
    StatDigestCache stat_cache;
    stat_cache.Load(stat_cache_path);

    Builder builder{root, published, published, control};
    builder.stat_cache = &stat_cache;
    builder.inventory_only = true;
    builder.resolve_git_placeholders = options.resolve_git_placeholders;
    builder.include_git_metadata = options.include_git_metadata;
    for (const auto& excluded : options.excluded_root_entries) {
        ValidateRelative(excluded);
        if (excluded.empty() || std::distance(excluded.begin(), excluded.end()) != 1)
            Fail("excluded entry must be a single root name", excluded);
    }
    builder.excluded_root_entries = options.excluded_root_entries;
    builder.result.root = published;
    builder.Copy(root, {});
    builder.ResolvePendingPlainFiles();
    builder.ValidateFileAliases();
    builder.Check();
    OwnedEntries desired;
    for (auto& entry : builder.entries) desired.emplace(entry.relative, entry);
    OwnedEntries owned;
    std::string receipt_state;
    if (Present(receipt)) owned = LoadReceipt(receipt, root, published, options.source_identity, &receipt_state);
    else if (Present(published)) Fail("existing source view has no ownership receipt", published);
    if (Present(published) && !fs::is_directory(fs::symlink_status(published)))
        Fail("source view root is not a directory", published);

    GitSourceViewSyncResult result;
    result.view = std::move(builder.result);
    // Reject collisions before claiming any new entry. Known ancestor links
    // are repaired later without following them during this inspection.
    for (const auto& [relative, entry] : desired) {
        if (relative.empty() || owned.contains(relative)) continue;
        auto parent = relative.parent_path();
        bool blocked = false;
        while (!parent.empty()) {
            const auto path = published / parent;
            if (Present(path) && (Reparse(path) || !fs::is_directory(fs::symlink_status(path)))) {
                if (!owned.contains(parent)) Fail("unowned output parent collision", path);
                blocked = true; break;
            }
            parent = parent.parent_path();
        }
        if (!blocked && Present(published / relative)) Fail("unowned source view output collision", published / relative);
    }
    auto updating = owned;
    for (const auto& [relative, entry] : desired) updating.insert_or_assign(relative, entry);
    // An unchanged inventory owns exactly what the complete receipt already
    // records, so neither the updating receipt nor the final one changes.
    const auto same_entry = [](const ViewEntry& a, const ViewEntry& b) {
        return a.type == b.type && a.resolved == b.resolved && a.target == b.target && a.digest == b.digest &&
            a.input_kind == b.input_kind && a.input_target == b.input_target;
    };
    const bool inventory_unchanged = receipt_state == "complete" && owned.size() == desired.size() &&
        std::equal(owned.begin(), owned.end(), desired.begin(), [&](const auto& a, const auto& b) {
            return !InsensitiveLess{}(a.first, b.first) && !InsensitiveLess{}(b.first, a.first) && same_entry(a.second, b.second);
        });
    fs::create_directories(receipt.parent_path());
    builder.Check();
    if (!inventory_unchanged &&
        !AtomicFile::Publish(receipt, Receipt(root, published, updating, "updating", options.source_identity).Serialize(true)))
        Fail("cannot publish updating source view receipt", receipt);
    fs::create_directories(published);
    if (builder.operation) {
        auto metadata = JsonValue::ObjectValue();
        metadata.Set("source", JsonValue::String(PathText(root)));
        metadata.Set("destination", JsonValue::String(PathText(published)));
        metadata.Set("state", JsonValue::String("updating"));
        builder.operation->Emit("source.view.sync", std::move(metadata));
    }
    builder.Check();

    // Decide canonical writes before visiting aliases: aliases may sort before
    // their targets, and Windows build engines can observe a symlink's own
    // timestamp rather than the target's. Guard parents before hashing, and
    // reuse this decision below instead of hashing every canonical twice.
    std::set<fs::path, InsensitiveLess> files_to_copy;
    // Outputs are verified by content (an edit may keep size and mtime) unless
    // their OutputStat still matches the one recorded when they were last
    // verified or written. Parent guards run serially; the independent
    // hashes run concurrently.
    const auto output_cache_path = receipt.wstring() + L".output_stat";
    OutputDigestCache output_cache;
    output_cache.Load(output_cache_path);
    std::vector<const ViewEntry*> candidates;
    VerifiedParents verified_parents;
    for (const auto& entry : builder.entries) {
        if (entry.type != "file") continue;
        builder.Check();
        bool candidate = false;
        if (std::any_of(options.caller_maintained_files.begin(), options.caller_maintained_files.end(),
                [&](const fs::path& maintained) { return Same(maintained, entry.relative); })) {
            const auto previous = owned.find(entry.relative);
            const auto path = published / entry.relative;
            if (previous != owned.end() && previous->second.digest == entry.digest &&
                SafeParents(published, entry.relative, updating, result.stats, &verified_parents) &&
                fs::is_regular_file(fs::symlink_status(path)) && !Reparse(path))
                continue;
        }
        // The concurrent check below reads each candidate through a handle
        // that does not follow a final reparse point and rejects anything
        // but a regular file, so no separate status query is needed here.
        candidate = SafeParents(published, entry.relative, updating, result.stats, &verified_parents);
        if (candidate) candidates.push_back(&entry);
        else files_to_copy.insert(entry.relative);
    }
    std::vector<char> unchanged(candidates.size(), 0);
    std::vector<std::optional<OutputStat>> verified_stats(candidates.size());
    {
        std::atomic<std::size_t> next{0};
        std::exception_ptr failure;
        std::mutex failure_mutex;
        const auto verify = [&] {
            OperationBinding binding(builder.operation);
            try {
                for (std::size_t index; (index = next++) < candidates.size();) {
                    const auto path = published / candidates[index]->relative;
                    const auto before = ReadOutputStat(path);
                    // Missing, a directory or a reparse point: republish it.
                    if (!before) continue;
                    if (const auto* known = output_cache.Find(candidates[index]->relative, *before)) {
                        unchanged[index] = *known == candidates[index]->digest;
                        continue;
                    }
                    const auto digest = Sha256File(path, {}, control.deadline);
                    builder.Check();
                    unchanged[index] = digest && *digest == candidates[index]->digest;
                    // Record only a stat that held across the whole read.
                    if (unchanged[index] && before && ReadOutputStat(path) == before) verified_stats[index] = before;
                }
            } catch (...) {
                next = candidates.size();
                std::lock_guard lock(failure_mutex);
                if (!failure) failure = std::current_exception();
            }
        };
        const std::size_t workers = std::min<std::size_t>(candidates.size(),
            std::max(1u, std::min(8u, std::thread::hardware_concurrency())));
        std::vector<std::thread> threads;
        for (std::size_t worker = 1; worker < workers; ++worker) threads.emplace_back(verify);
        verify();
        for (auto& thread : threads) thread.join();
        if (failure) std::rethrow_exception(failure);
    }
    for (std::size_t index = 0; index < candidates.size(); ++index) {
        if (!unchanged[index]) files_to_copy.insert(candidates[index]->relative);
        else if (verified_stats[index]) output_cache.Put(candidates[index]->relative, *verified_stats[index], candidates[index]->digest);
    }

    // Remove obsolete leaves before their directories. The ownership union is
    // durable already, including entries from any interrupted earlier update.
    std::vector<fs::path> removed;
    for (const auto& [relative, entry] : owned)
        if (!desired.contains(relative)) removed.push_back(relative);
    std::sort(removed.begin(), removed.end(), [](const fs::path& a, const fs::path& b) {
        return std::distance(a.begin(), a.end()) > std::distance(b.begin(), b.end());
    });
    for (const auto& relative : removed) {
        builder.Check();
        RemoveOwned(published, relative, updating, result.stats);
    }
    if (!removed.empty()) verified_parents.clear();
    // Builder inventory order is parents before children, including aliases.
    for (const auto& entry : builder.entries) {
        builder.Check();
        if (entry.relative.empty()) continue;
        const auto path = published / entry.relative;
        if (!SafeParents(published, entry.relative, updating, result.stats, &verified_parents))
            Fail("source view parent is missing or invalid", path);
        // A verified unchanged file needs no further query.
        if (entry.type == "file" && !files_to_copy.contains(entry.relative)) { ++result.stats.files_reused; continue; }
        const auto status = fs::symlink_status(path);
        if (entry.type == "directory") {
            if (fs::exists(status) && (Reparse(path) || !fs::is_directory(status))) {
                RemoveOwned(published, entry.relative, updating, result.stats);
                verified_parents.clear();
            }
            fs::create_directory(path);
        } else if (entry.type == "alias" || entry.type == "file_alias" || entry.type == "dangling") {
            bool refresh_file_alias = false;
            if (entry.type == "file_alias") {
                const auto previous = owned.find(entry.relative);
                const auto canonical = (entry.relative.parent_path() / entry.target).lexically_normal();
                refresh_file_alias = previous == owned.end() || previous->second.digest != entry.digest ||
                    files_to_copy.contains(canonical);
            }
            if (!refresh_file_alias && fs::is_symlink(status) && fs::read_symlink(path) == entry.target) {
                if (entry.type == "file_alias") ++result.stats.files_reused;
                continue;
            }
            RemoveOwned(published, entry.relative, updating, result.stats);
            verified_parents.clear();
            auto link = path.wstring();
            if (link.rfind(L"\\\\?\\", 0) != 0)
                link = link.rfind(L"\\\\", 0) == 0
                    ? L"\\\\?\\UNC\\" + link.substr(2) : L"\\\\?\\" + link;
            const DWORD flags = entry.type == "alias" ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
            bool created = CreateSymbolicLinkW(link.c_str(), entry.target.c_str(), flags | 0x2) != FALSE;
            if (!created && GetLastError() == ERROR_INVALID_PARAMETER)
                created = CreateSymbolicLinkW(link.c_str(), entry.target.c_str(), flags) != FALSE;
            if (!created) Fail("cannot create owned source alias", path);
        } else {
            if (!files_to_copy.contains(entry.relative)) { ++result.stats.files_reused; continue; }
            RemoveOwned(published, entry.relative, updating, result.stats);
            verified_parents.clear();
            std::ifstream input(entry.resolved, std::ios::binary);
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!input || !out) Fail("cannot synchronize source file", path);
            std::vector<char> block(65536);
            std::uint64_t bytes = 0;
            while (input) {
                builder.Check();
                input.read(block.data(), static_cast<std::streamsize>(block.size()));
                out.write(block.data(), input.gcount());
                bytes += static_cast<std::uint64_t>(input.gcount());
            }
            out.close();
            if (input.bad() || !out) Fail("incomplete synchronized source file", path);
            const auto digest = Sha256File(path, {}, control.deadline);
            builder.Check();
            if (!digest || *digest != entry.digest) Fail("source changed during synchronization", path);
            if (const auto stat = ReadOutputStat(path)) output_cache.Put(entry.relative, *stat, entry.digest);
            ++result.stats.files_copied;
            result.stats.bytes_copied += bytes;
        }
    }
    builder.Check();
    if (!inventory_unchanged &&
        !AtomicFile::Publish(receipt, Receipt(root, published, desired, "complete", options.source_identity).Serialize(true)))
        Fail("cannot publish complete source view receipt", receipt);
    if (builder.operation) {
        auto metadata = JsonValue::ObjectValue();
        metadata.Set("destination", JsonValue::String(PathText(published)));
        metadata.Set("state", JsonValue::String("complete"));
        metadata.Set("files_copied", JsonValue::Number(std::to_string(result.stats.files_copied)));
        metadata.Set("files_reused", JsonValue::Number(std::to_string(result.stats.files_reused)));
        metadata.Set("bytes_copied", JsonValue::Number(std::to_string(result.stats.bytes_copied)));
        builder.operation->Emit("source.view.sync", std::move(metadata));
    }
    stat_cache.Save(stat_cache_path);
    output_cache.Save(output_cache_path);
    return result;
}

fs::path ResolveGitSourcePath(const fs::path& source, const fs::path& path,
                             const ProcessRunOptions& control, bool resolve_git_placeholders) {
    Builder resolver{fs::canonical(source), {}, {}, control};
    resolver.resolve_git_placeholders = resolve_git_placeholders;
    resolver.Check();
    // Resolve '..' after expanding directory links, never before.
    // Some Windows standard-library implementations use GetFullPathName for
    // absolute(), which also folds '..'. Already absolute paths must retain
    // their original components; ordinary relative paths can be anchored
    // without asking Win32 to normalize them.
    if (path.is_absolute()) return resolver.Resolve(path);
    if (path.has_root_name()) Fail("ambiguous drive-relative source path", path);
    return resolver.Resolve(fs::current_path() / path);
}

std::optional<fs::path> TryResolveGitSourcePath(const fs::path& source, const fs::path& path,
    const ProcessRunOptions& control, bool resolve_git_placeholders) {
    Builder resolver{fs::canonical(source), {}, {}, control};
    resolver.resolve_git_placeholders = resolve_git_placeholders;
    resolver.Check();
    if (path.is_absolute()) return resolver.ResolvePath(path, true);
    if (path.has_root_name() || path.has_root_directory()) Fail("ambiguous source-relative metadata path", path);
    return resolver.ResolvePath(resolver.source / path, true);
}
} // namespace OpenFruit
