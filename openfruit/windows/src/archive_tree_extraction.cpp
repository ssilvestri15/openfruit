#include "archive_tree_extraction.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <vector>
namespace OpenFruit {
namespace {
namespace fs = std::filesystem;
constexpr unsigned type_mask = 0170000, regular_type = 0100000, directory_type = 0040000, symlink_type = 0120000;
struct Failure { ArchiveExtractionStatus status; std::string code; DWORD native = 0; };
[[noreturn]] void Fail(ArchiveExtractionStatus status, const char* code, DWORD native = 0) { throw Failure{status, code, native}; }
void Check(const ArchiveExtractionOptions& options) {
    if (options.read.cancellation.Requested()) Fail(ArchiveExtractionStatus::Cancelled, "archive.extraction.cancelled");
    if (std::chrono::steady_clock::now() >= options.read.deadline) Fail(ArchiveExtractionStatus::TimedOut, "archive.extraction.deadline");
}
class Capture final : public XipVisitor {
public:
    Capture(XipVisitor& visitor, std::optional<Failure>& failure) : visitor(visitor), failure(failure) {}
    void Begin(const XipEntry& entry) override { Call([&] { visitor.Begin(entry); }); }
    void Data(std::span<const std::uint8_t> bytes) override { Call([&] { visitor.Data(bytes); }); }
    XipVisit End() override { XipVisit result = XipVisit::Continue; Call([&] { result = visitor.End(); }); return result; }
private:
    template<class F> void Call(F function) {
        try { function(); }
        catch (const Failure& error) { failure = error; throw; }
        catch (const std::bad_alloc&) { failure = Failure{ArchiveExtractionStatus::ResourceLimit, "archive.extraction.memory_limit"}; throw; }
    }
    XipVisitor& visitor; std::optional<Failure>& failure;
};
std::wstring Native(const fs::path& path) {
    auto preferred = path; preferred.make_preferred();
    const auto value = preferred.wstring();
    return value.starts_with(L"\\\\?\\") ? value : value.starts_with(L"\\\\") ? L"\\\\?\\UNC\\" + value.substr(2) : L"\\\\?\\" + value;
}
std::wstring Wide(const std::string& value) {
    if (value.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (!length) Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.invalid_utf8");
    std::wstring result(length, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), length);
    return result;
}
std::vector<std::string> Parts(const std::string& path) {
    std::vector<std::string> result;
    std::size_t start = 0;
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto part = path.substr(start, end == std::string::npos ? end : end - start);
        if (!part.empty()) result.push_back(part);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}
std::string Join(const std::vector<std::string>& parts) {
    std::string result;
    for (const auto& part : parts) { if (!result.empty()) result += '/'; result += part; }
    return result;
}
std::string MemberPath(const std::string& path) {
    if (path.empty() || path.front() == '/' || path.find('\\') != std::string::npos) Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.unsafe_member");
    std::vector<std::string> normalized;
    for (const auto& part : Parts(path)) {
        if (part == ".") continue;
        if (part == "..") Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.parent_member");
        normalized.push_back(part);
    }
    return Join(normalized);
}
void Portable(const std::string& path) {
    Wide(path);
    for (const auto& part : Parts(path)) {
        if (part.empty() || part.back() == '.' || part.back() == ' ') Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.windows_path");
        for (const unsigned char ch : part) if (ch < 32 || std::string("<>:\"\\|?*").find(ch) != std::string::npos)
            Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.windows_path");
        auto base = part.substr(0, part.find('.'));
        for (auto& ch : base) if (ch >= 'a' && ch <= 'z') ch -= 'a' - 'A';
        if (base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
            (base.size() == 4 && (base.starts_with("COM") || base.starts_with("LPT")) && base[3] >= '1' && base[3] <= '9'))
            Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.windows_reserved_path");
    }
}
std::wstring Fold(const std::string& path) {
    const auto wide = Wide(path);
    const int size = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr, 0);
    if (!size) Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.case_mapping");
    std::wstring result(size, L'\0');
    LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, wide.data(), static_cast<int>(wide.size()), result.data(), size, nullptr, nullptr, 0);
    return result;
}
struct Record { XipEntry entry; std::string link, prefix; bool selected = false; };
using Identity = std::pair<std::uint32_t, std::uint32_t>;
Identity Id(const Record& record) { return {record.entry.device, record.entry.inode}; }
bool Linked(const Record& record) { return (record.entry.mode & type_mask) == regular_type && record.entry.links > 1; }
class Plan final : public XipVisitor {
public:
    explicit Plan(const ArchiveExtractionOptions& options) : options(options) {}
    void Begin(const XipEntry& original) override {
        Check(options);
        if (records.size() >= options.max_plan_entries || original.path.size() > options.max_plan_string_bytes - string_bytes)
            Fail(ArchiveExtractionStatus::ResourceLimit, "archive.extraction.plan_limit");
        Record record; record.entry = original; record.entry.path = MemberPath(original.path);
        string_bytes += original.path.size();
        if (!record.entry.path.empty() && !paths.emplace(record.entry.path, records.size()).second)
            Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.duplicate_member");
        records.push_back(std::move(record));
    }
    void Data(std::span<const std::uint8_t> data) override {
        auto& record = records.back();
        if ((record.entry.mode & type_mask) == symlink_type) {
            if (record.link.size() + data.size() > 32768 || data.size() > options.max_plan_string_bytes - string_bytes)
                Fail(ArchiveExtractionStatus::ResourceLimit, "archive.extraction.link_limit");
            record.link.append(reinterpret_cast<const char*>(data.data()), data.size()); string_bytes += data.size();
        } else if ((record.entry.mode & type_mask) == regular_type && record.prefix.size() < 10) {
            record.prefix.append(reinterpret_cast<const char*>(data.data()), std::min<std::size_t>(data.size(), 10 - record.prefix.size()));
        }
    }
    XipVisit End() override { return XipVisit::Continue; }
    void Mark(std::size_t index) { if (!records[index].selected) { records[index].selected = true; queue.push_back(index); } }
    void MarkTree(const std::string& path) {
        if (const auto it = paths.find(path); it != paths.end()) Mark(it->second);
        const auto prefix = path + '/';
        for (auto it = paths.lower_bound(prefix); it != paths.end() && it->first.starts_with(prefix); ++it) Mark(it->second);
    }
    std::string Resolve(std::string path) {
        std::deque<std::string> pending;
        for (auto& part : Parts(path)) pending.push_back(std::move(part));
        std::vector<std::string> resolved;
        unsigned expansions = 0;
        while (!pending.empty()) {
            auto part = std::move(pending.front()); pending.pop_front();
            if (part == ".") continue;
            if (part == "..") { if (resolved.empty()) Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.link_escape"); resolved.pop_back(); continue; }
            resolved.push_back(std::move(part));
            const auto name = Join(resolved); const auto found = paths.find(name);
            if (found == paths.end() || (records[found->second].entry.mode & type_mask) != symlink_type) continue;
            Mark(found->second);
            const auto& target = records[found->second].link;
            if (++expansions > 64) Fail(ArchiveExtractionStatus::UnresolvedLink, "archive.extraction.link_cycle");
            if (target.empty() || target.front() == '/' || target.find('\\') != std::string::npos || target.find('\0') != std::string::npos)
                Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.unsupported_link_target");
            Wide(target); resolved.pop_back();
            const auto parts = Parts(target);
            for (auto it = parts.rbegin(); it != parts.rend(); ++it) pending.push_front(*it);
        }
        return Join(resolved);
    }
    void Select(const std::vector<std::string>& roots) {
        if (roots.empty()) Fail(ArchiveExtractionStatus::MissingSelection, "archive.extraction.empty_selection");
        for (const auto& root : roots) {
            if (root.empty()) Fail(ArchiveExtractionStatus::MissingSelection, "archive.extraction.empty_selection");
            const auto prefix = root + '/'; const auto descendant = paths.lower_bound(prefix);
            if (!paths.contains(root) && (descendant == paths.end() || !descendant->first.starts_with(prefix)))
                Fail(ArchiveExtractionStatus::MissingSelection, "archive.extraction.member_missing");
            MarkTree(root);
        }
        while (!queue.empty()) {
            Check(options);
            const auto index = queue.front(); queue.pop_front();
            const auto& entry = records[index].entry;
            const auto type = entry.mode & type_mask;
            if (type != directory_type && type != regular_type && type != symlink_type)
                Fail(ArchiveExtractionStatus::UnsupportedEntry, "archive.extraction.unsupported_member_type");
            if (type != symlink_type) continue;
            const auto parent = entry.path.substr(0, entry.path.rfind('/') == std::string::npos ? 0 : entry.path.rfind('/'));
            const auto& target = records[index].link;
            if (target.empty() || target.front() == '/' || target.find('\\') != std::string::npos || target.find('\0') != std::string::npos)
                Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.unsupported_link_target");
            const auto resolved = Resolve(parent.empty() ? target : parent + '/' + target);
            const auto prefix = resolved + '/'; const auto descendant = paths.lower_bound(prefix);
            if (!paths.contains(resolved) && (descendant == paths.end() || !descendant->first.starts_with(prefix)))
                Fail(ArchiveExtractionStatus::UnresolvedLink, "archive.extraction.missing_link_target");
            MarkTree(resolved);
            resolved_links[index] = resolved;
        }
        std::map<std::wstring, std::string> windows_paths;
        std::set<Identity> wanted;
        for (std::size_t i = 0; i < records.size(); ++i) if (records[i].selected) {
            const auto& record = records[i]; Portable(record.entry.path);
            std::vector<std::string> parent;
            for (const auto& component : Parts(record.entry.path)) {
                parent.push_back(component); const auto name = Join(parent);
                const auto [found, inserted] = windows_paths.emplace(Fold(name), name);
                if (!inserted && found->second != name) Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.case_collision");
                const auto entry = paths.find(name);
                if (entry != paths.end() && entry->second != i && (records[entry->second].entry.mode & type_mask) != directory_type)
                    Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.non_directory_parent");
            }
            if (Linked(record)) wanted.insert(Id(record));
        }
        // Canonical sources can occur outside the selected SDK or after an empty
        // hardlink entry. NULLcanary is the XIP clone marker, never real content.
        for (std::size_t i = 0; i < records.size(); ++i) {
            const auto& record = records[i];
            if (!Linked(record) || !wanted.contains(Id(record)) || record.prefix == "NULLcanary") continue;
            auto [source, inserted] = sources.emplace(Id(record), i);
            if (!inserted && !records[source->second].entry.size && record.entry.size) source->second = i;
        }
        for (const auto& identity : wanted) if (!sources.contains(identity))
            Fail(ArchiveExtractionStatus::ArchiveFailure, "archive.extraction.missing_clone_source");
        for (const auto& record : records) if (record.selected && Linked(record)) {
            const auto& source = records[sources.at(Id(record))];
            if (record.entry.size && record.entry.size != source.entry.size)
                Fail(ArchiveExtractionStatus::ArchiveFailure, "archive.extraction.hardlink_size_mismatch");
        }
    }
    std::vector<Record> records;
    std::map<std::string, std::size_t> paths;
    std::map<Identity, std::size_t> sources;
    std::map<std::size_t, std::string> resolved_links;
    const ArchiveExtractionOptions& options;
private:
    std::deque<std::size_t> queue;
    std::uint64_t string_bytes = 0;
};
class Lease {
public:
    Lease(const fs::path& path, bool directory) {
        const auto native = Native(path);
        handle = CreateFileW(native.c_str(), GENERIC_READ, directory ? FILE_SHARE_READ | FILE_SHARE_WRITE : FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            directory ? FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT : FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(handle, &information) ||
            (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            bool(information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory) {
            const auto error = GetLastError(); if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); handle = INVALID_HANDLE_VALUE;
            Fail(ArchiveExtractionStatus::IoFailure, "archive.extraction.lease_failed", error);
        }
    }
    ~Lease() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;
    HANDLE handle = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION information{};
};
class Tree {
public:
    explicit Tree(const fs::path& root) : root(root), parent(root.parent_path(), true) {
        const auto native = Native(root);
        if (!CreateDirectoryW(native.c_str(), nullptr)) {
            const auto error = GetLastError();
            Fail(error == ERROR_ALREADY_EXISTS ? ArchiveExtractionStatus::DestinationExists : ArchiveExtractionStatus::IoFailure,
                "archive.extraction.create_staging", error);
        }
        owned = true;
        try { Directory(""); } catch (...) { Cleanup(); throw; }
    }
    ~Tree() { if (!keep) Cleanup(); Close(); }
    void Directory(const std::string& relative) {
        if (directories.contains(relative)) return;
        if (!relative.empty()) {
            const auto slash = relative.rfind('/'); Directory(slash == std::string::npos ? "" : relative.substr(0, slash));
            if (!CreateDirectoryW(Native(Path(relative)).c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
                Fail(ArchiveExtractionStatus::IoFailure, "archive.extraction.create_directory", GetLastError());
        }
        auto guard = std::make_unique<Lease>(Path(relative), true);
        if (relative.empty()) { root_identity = guard->information; identity_valid = true; }
        directories.emplace(relative, std::move(guard));
    }
    fs::path Path(const std::string& relative) const { return relative.empty() ? root : root / fs::path(Wide(relative)); }
    void Parent(const std::string& relative) { const auto slash = relative.rfind('/'); Directory(slash == std::string::npos ? "" : relative.substr(0, slash)); }
    void RequireSymlinks() {
        const auto probe = Path(".OPENFRUIT-link-probe-" + NewOperationId());
        if (!CreateSymbolicLinkW(Native(probe).c_str(), L".", SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
            Fail(ArchiveExtractionStatus::SymbolicLinksUnavailable, "archive.extraction.windows_symbolic_links_required", GetLastError());
        if (!RemoveDirectoryW(Native(probe).c_str())) Fail(ArchiveExtractionStatus::IoFailure, "archive.extraction.link_probe_cleanup", GetLastError());
    }
    void Cleanup() noexcept {
        try {
            Close();
            if (!owned) return;
            const auto attributes = GetFileAttributesW(Native(root).c_str());
            // Only the newly created, explicitly named staging directory. Never
            // follow a reparse root or delete a pre-existing/replaced destination.
            if (attributes == INVALID_FILE_ATTRIBUTES) { owned = false; return; }
            if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) return;
            if (!identity_valid) { if (RemoveDirectoryW(Native(root).c_str())) owned = false; return; } // Empty root only.
            {
                Lease current(root, true); const auto& identity = current.information;
                if (identity.dwVolumeSerialNumber != root_identity.dwVolumeSerialNumber || identity.nFileIndexHigh != root_identity.nFileIndexHigh ||
                    identity.nFileIndexLow != root_identity.nFileIndexLow) return;
            }
            std::error_code error; fs::remove_all(fs::path(Native(root)), error);
            if (!error) owned = false;
        } catch (...) { /* Preserve uncertain staging rather than delete another tree. */ }
    }
    void Close() noexcept { directories.clear(); }
    bool Present() const { return GetFileAttributesW(Native(root).c_str()) != INVALID_FILE_ATTRIBUTES; }
    fs::path root; Lease parent; bool keep = false;
private:
    bool owned = false;
    bool identity_valid = false;
    BY_HANDLE_FILE_INFORMATION root_identity{};
    std::map<std::string, std::unique_ptr<Lease>> directories;
};
void ReaderFailure(const XipReadResult& read) {
    if (read.status == XipStatus::Completed || read.status == XipStatus::Stopped) return;
    throw Failure{read.status == XipStatus::Cancelled ? ArchiveExtractionStatus::Cancelled : read.status == XipStatus::TimedOut ? ArchiveExtractionStatus::TimedOut :
        read.status == XipStatus::ResourceLimit ? ArchiveExtractionStatus::ResourceLimit : ArchiveExtractionStatus::ArchiveFailure,
        read.error.empty() ? "archive.extraction.archive_read_failed" : read.error};
}
class Writer final : public XipVisitor {
public:
    Writer(Plan& plan, Tree& tree, ArchiveExtractionResult& result) : plan(plan), tree(tree), result(result) {
        planned_entries = std::count_if(plan.records.begin(), plan.records.end(), [](const auto& record) { return record.selected; });
        cache = ".OPENFRUIT-clone-sources-" + NewOperationId();
        for (const auto& [identity, index] : plan.sources) {
            const auto& record = plan.records[index];
            source_paths[index] = record.selected ? record.entry.path : cache + '/' + std::to_string(identity.first) + '-' + std::to_string(identity.second);
        }
    }
    ~Writer() { CloseFile(); }
    void Begin(const XipEntry& original) override {
        Check(plan.options); CloseFile();
        if (index >= plan.records.size()) Fail(ArchiveExtractionStatus::ArchiveFailure, "archive.extraction.plan_changed");
        const auto& record = plan.records[index]; current = &record;
        if (MemberPath(original.path) != record.entry.path || original.size != record.entry.size || original.mode != record.entry.mode ||
            original.device != record.entry.device || original.inode != record.entry.inode || original.links != record.entry.links)
            Fail(ArchiveExtractionStatus::ArchiveFailure, "archive.extraction.plan_changed");
        const auto type = record.entry.mode & type_mask;
        const auto source = source_paths.find(index);
        if (source != source_paths.end()) Open(source->second, record.entry.size);
        else if (record.selected && type == regular_type && !Linked(record)) Open(record.entry.path, record.entry.size);
        else if (record.selected && type == directory_type) tree.Directory(record.entry.path);
    }
    void Data(std::span<const std::uint8_t> bytes) override {
        Check(plan.options);
        if (file == INVALID_HANDLE_VALUE) return;
        while (!bytes.empty()) {
            DWORD count = 0;
            if (!WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) || !count)
                Fail(ArchiveExtractionStatus::IoFailure, "archive.extraction.write_failed", GetLastError());
            result.written_bytes += count; bytes = bytes.subspan(count);
        }
    }
    XipVisit End() override {
        if (file != INVALID_HANDLE_VALUE && current->selected) ++result.files;
        if (file != INVALID_HANDLE_VALUE) { if (!FlushFileBuffers(file)) Fail(ArchiveExtractionStatus::IoFailure, "archive.extraction.flush_failed", GetLastError()); CloseFile(); }
        if (current->selected) { ++result.selected_entries; Publish(); }
        ++index; return XipVisit::Continue;
    }
    void Finish() {
        if (index != plan.records.size()) Fail(ArchiveExtractionStatus::ArchiveFailure, "archive.extraction.plan_changed");
        for (std::size_t i = 0; i < plan.records.size(); ++i) {
            Check(plan.options); const auto& record = plan.records[i];
            if (!record.selected || !Linked(record)) continue;
            const auto canonical = plan.sources.at(Id(record));
            if (canonical == i) continue;
            tree.Parent(record.entry.path);
            if (!CreateHardLinkW(Native(tree.Path(record.entry.path)).c_str(), Native(tree.Path(source_paths.at(canonical))).c_str(), nullptr))
                Fail(ArchiveExtractionStatus::IoFailure, "archive.extraction.hardlink_failed", GetLastError());
            ++result.hardlinks;
            ++result.files;
        }
        // Symlinks are created last: no archive write ever traverses one.
        for (const auto& [i, resolved] : plan.resolved_links) {
            Check(plan.options); const auto& record = plan.records[i]; tree.Parent(record.entry.path);
            const auto target = plan.paths.find(resolved);
            const bool directory = target == plan.paths.end() || (plan.records[target->second].entry.mode & type_mask) == directory_type;
            const DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE | (directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0);
            auto target_path = fs::path(Wide(record.link)); target_path.make_preferred();
            if (!CreateSymbolicLinkW(Native(tree.Path(record.entry.path)).c_str(), target_path.c_str(), flags))
                Fail(ArchiveExtractionStatus::IoFailure, "archive.extraction.symlink_failed", GetLastError());
            ++result.symlinks;
        }
        tree.Close();
        const auto cache_path = tree.Path(cache);
        const auto attrs = GetFileAttributesW(Native(cache_path).c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) Fail(ArchiveExtractionStatus::UnsafePath, "archive.extraction.cache_reparse");
            std::error_code error; fs::remove_all(fs::path(Native(cache_path)), error);
            if (error) Fail(ArchiveExtractionStatus::IoFailure, "archive.extraction.cache_cleanup");
        }
    }
private:
    void Open(const std::string& path, std::uint64_t size) {
        if (size > plan.options.max_written_bytes - planned_written) Fail(ArchiveExtractionStatus::ResourceLimit, "archive.extraction.output_limit");
        planned_written += size; tree.Parent(path);
        file = CreateFileW(Native(tree.Path(path)).c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) Fail(ArchiveExtractionStatus::IoFailure, "archive.extraction.create_file", GetLastError());
    }
    void CloseFile() { if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); file = INVALID_HANDLE_VALUE; } }
    void Publish() {
        const auto now = std::chrono::steady_clock::now();
        if (!context || now - last_progress < std::chrono::milliseconds(100)) return;
        auto data = JsonValue::ObjectValue();
        data.Set("basis", JsonValue::String("archive_selected_entries_read"));
        data.Set("completed_units", JsonValue::Number(std::to_string(result.selected_entries)));
        data.Set("planned_units", JsonValue::Number(std::to_string(planned_entries)));
        data.Set("source_path", JsonValue::String(current->entry.path));
        data.Set("written_bytes", JsonValue::Number(std::to_string(result.written_bytes)));
        context->Emit("progress.updated", std::move(data)); last_progress = now;
    }
    Plan& plan; Tree& tree; ArchiveExtractionResult& result;
    std::map<std::size_t, std::string> source_paths;
    std::string cache; std::size_t index = 0, planned_entries = 0; std::uint64_t planned_written = 0;
    const Record* current = nullptr; HANDLE file = INVALID_HANDLE_VALUE;
    OperationContextPtr context = CurrentOperationContext();
    std::chrono::steady_clock::time_point last_progress = std::chrono::steady_clock::now();
};
}
ArchiveExtractionResult ArchiveTreeExtraction::Extract(const fs::path& archive, const fs::path& destination,
    const ArchiveTreeSelector& selector, const ArchiveExtractionOptions& options) {
    OperationSpan span("archive.tree.extract"); ArchiveExtractionResult result;
    std::unique_ptr<Tree> tree;
    try {
        Check(options);
        if (!archive.is_absolute() || !destination.is_absolute() || destination.filename().empty() ||
            destination.lexically_normal() != destination || destination == destination.root_path())
            Fail(ArchiveExtractionStatus::InvalidDestination, "archive.extraction.absolute_paths_required");
        if (GetFileAttributesW(Native(destination).c_str()) != INVALID_FILE_ATTRIBUTES)
            Fail(ArchiveExtractionStatus::DestinationExists, "archive.extraction.destination_exists");
        Lease source(archive, false);
        if (!selector) Fail(ArchiveExtractionStatus::MissingSelection, "archive.extraction.empty_selector");
        const auto selection = selector(archive, options.read);
        if (selection.status != ArchiveExtractionStatus::Succeeded)
            throw Failure{selection.status, selection.diagnostic_code};
        std::vector<std::string> roots;
        for (const auto& path : selection.member_paths) roots.push_back(MemberPath(path));
        Plan plan(options); std::optional<Failure> consumer_failure;
        Capture capture(plan, consumer_failure);
        const auto read = XipArchive::Walk(archive, capture, options.read);
        if (consumer_failure) throw *consumer_failure; ReaderFailure(read);
        plan.Select(roots);
        tree = std::make_unique<Tree>(destination);
        if (!plan.resolved_links.empty()) tree->RequireSymlinks();
        Writer writer(plan, *tree, result); Capture writing(writer, consumer_failure);
        const auto extracted = XipArchive::Walk(archive, writing, options.read);
        if (consumer_failure) throw *consumer_failure; ReaderFailure(extracted);
        writer.Finish();
        result.toc_checksum_verified = extracted.toc_checksum_verified;
        result.content_checksum_verified = extracted.content_checksum_verified;
        result.xar_signature_valid = extracted.xar_signature_valid;
        result.apple_signing_chain_valid = extracted.apple_signing_chain_valid;
        result.apple_revocation_valid = extracted.apple_revocation_valid;
        result.member_paths = std::move(roots); result.status = ArchiveExtractionStatus::Succeeded; tree->keep = true;
    } catch (const Failure& error) { result.status = error.status; result.diagnostic_code = error.code; result.native_error = error.native; }
    catch (const std::bad_alloc&) { result.status = ArchiveExtractionStatus::ResourceLimit; result.diagnostic_code = "archive.extraction.memory_limit"; }
    catch (...) { result.status = ArchiveExtractionStatus::IoFailure; result.diagnostic_code = "archive.extraction.internal_failure"; }
    if (tree && !tree->keep) tree->Cleanup();
    result.staging_present = tree && tree->Present();
    span.Complete(result.ToJson(), result.status == ArchiveExtractionStatus::Cancelled ? OperationOutcome::Cancelled : result.Succeeded() ? OperationOutcome::Succeeded : OperationOutcome::Failed);
    return result;
}
ArchiveExtractionResult ArchiveTreeExtraction::ExtractMembers(const fs::path& archive, const fs::path& destination,
    const std::vector<std::string>& paths, const ArchiveExtractionOptions& options) {
    return Extract(archive, destination, [&paths](const fs::path&, const XipReadOptions&) {
        ArchiveTreeSelection selection; selection.member_paths = paths; return selection;
    }, options);
}
const char* ArchiveExtractionStatusName(ArchiveExtractionStatus status) noexcept {
    switch (status) {
    case ArchiveExtractionStatus::Succeeded: return "succeeded";
    case ArchiveExtractionStatus::InvalidDestination: return "invalid_destination";
    case ArchiveExtractionStatus::DestinationExists: return "destination_exists";
    case ArchiveExtractionStatus::ArchiveFailure: return "archive_failure";
    case ArchiveExtractionStatus::MissingSelection: return "missing_selection";
    case ArchiveExtractionStatus::UnsafePath: return "unsafe_path";
    case ArchiveExtractionStatus::UnresolvedLink: return "unresolved_link";
    case ArchiveExtractionStatus::UnsupportedEntry: return "unsupported_entry";
    case ArchiveExtractionStatus::SymbolicLinksUnavailable: return "symbolic_links_unavailable";
    case ArchiveExtractionStatus::IoFailure: return "io_failure";
    case ArchiveExtractionStatus::ResourceLimit: return "resource_limit";
    case ArchiveExtractionStatus::Cancelled: return "cancelled";
    case ArchiveExtractionStatus::TimedOut: return "timed_out";
    }
    return "io_failure";
}
JsonValue ArchiveExtractionResult::ToJson() const {
    auto data = JsonValue::ObjectValue();
    data.Set("schema_version", JsonValue::Number("1")); data.Set("status", JsonValue::String(ArchiveExtractionStatusName(status)));
    auto paths = JsonValue::ArrayValue();
    for (const auto& path : member_paths) paths.ArrayItems().push_back(JsonValue::String(path));
    data.Set("member_paths", std::move(paths));
    data.Set("diagnostic_code", JsonValue::String(diagnostic_code)); data.Set("native_error", JsonValue::Number(std::to_string(native_error)));
    data.Set("files", JsonValue::Number(std::to_string(files))); data.Set("hardlinks", JsonValue::Number(std::to_string(hardlinks)));
    data.Set("selected_entries", JsonValue::Number(std::to_string(selected_entries)));
    data.Set("symlinks", JsonValue::Number(std::to_string(symlinks))); data.Set("written_bytes", JsonValue::Number(std::to_string(written_bytes)));
    data.Set("staging_present", JsonValue::Boolean(staging_present)); data.Set("publisher_verified", JsonValue::Boolean(false));
    data.Set("toc_checksum_verified", JsonValue::Boolean(toc_checksum_verified));
    data.Set("content_checksum_verified", JsonValue::Boolean(content_checksum_verified));
    data.Set("xar_signature_valid", JsonValue::Boolean(xar_signature_valid));
    data.Set("apple_signing_chain_valid", JsonValue::Boolean(apple_signing_chain_valid));
    data.Set("apple_revocation_valid", JsonValue::Boolean(apple_revocation_valid));
    data.Set("published", JsonValue::Boolean(false));
    if (status == ArchiveExtractionStatus::SymbolicLinksUnavailable) data.Set("required_capability", JsonValue::String("windows.symbolic_links"));
    return data;
}
}
