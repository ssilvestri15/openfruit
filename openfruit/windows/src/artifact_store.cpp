#include "artifact_store.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include <windows.h>
#include <algorithm>
#include <cwctype>
#include <optional>
#include <string_view>
#include <stdexcept>
#include <vector>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
std::wstring ExtendedWin32Path(const fs::path& input) {
    std::error_code ec;
    fs::path absolute = input.is_absolute() ? input : fs::absolute(input, ec);
    if (ec) absolute = input;
    fs::path normalized = absolute.lexically_normal();
    normalized.make_preferred();
    std::wstring value = normalized.wstring();
    if (value.rfind(L"\\\\?\\", 0) == 0) return value;
    if (value.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + value.substr(2);
    return L"\\\\?\\" + value;
}

fs::path ExtendedFsPath(const fs::path& input) {
    return fs::path(ExtendedWin32Path(input));
}

bool LongPathExists(const fs::path& input) {
    return GetFileAttributesW(ExtendedWin32Path(input).c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool CheckPruneControl(const ProcessRunOptions& control, CachePruneReport& report) {
    if (report.cancelled || report.timed_out) return false;
    const auto context = CurrentOperationContext();
    if ((control.cancellation && control.cancellation->load(std::memory_order_relaxed)) ||
        (context && context->CancellationRequested())) {
        report.cancelled = true;
        report.partial = true;
        report.success = false;
        report.error_message = "Cache retention prune was cancelled.";
        return false;
    }
    if (std::chrono::steady_clock::now() >= control.deadline ||
        (context && context->DeadlineExceeded())) {
        report.timed_out = true;
        report.partial = true;
        report.success = false;
        report.error_message = "Cache retention prune timed out.";
        return false;
    }
    return true;
}

bool RemoveTreeBestEffort(const fs::path& input,
        const ProcessRunOptions* control = nullptr, CachePruneReport* report = nullptr) {
    if (control && report && !CheckPruneControl(*control, *report)) return false;
    if (input.empty() || !LongPathExists(input)) return true;
    std::error_code ec;
    fs::remove_all(ExtendedFsPath(input), ec);
    return !ec || !LongPathExists(input);
}

bool SameVolume(const fs::path& a, const fs::path& b) {
    const std::wstring ar = fs::absolute(a).root_name().wstring();
    const std::wstring br = fs::absolute(b).root_name().wstring();
    if (ar.size() != br.size()) return false;
    for (std::size_t i = 0; i < ar.size(); ++i) {
        if (std::towlower(ar[i]) != std::towlower(br[i])) return false;
    }
    return true;
}

bool MoveFileExWithRetryW(const wchar_t* src, const wchar_t* dst, DWORD flags) {
    int delay_ms = 5;
    for (int attempt = 0; attempt < 6; ++attempt) {
        if (MoveFileExW(src, dst, flags)) {
            return true;
        }
        const DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
            Sleep(delay_ms);
            delay_ms *= 2;
            continue;
        }
        break;
    }
    return false;
}

bool NestedPath(const fs::path& child, const fs::path& parent) {
    std::error_code child_error, parent_error;
    const auto resolved_child = fs::weakly_canonical(child, child_error);
    const auto resolved_parent = fs::weakly_canonical(parent, parent_error);
    if (child_error || parent_error) return true; // Refuse uncertain destructive publication.
    auto component = resolved_child.begin();
    for (const auto& expected : resolved_parent) {
        if (component == resolved_child.end()) return false;
        auto left = component->wstring(), right = expected.wstring();
        if (left.size() != right.size()) return false;
        for (std::size_t index = 0; index < left.size(); ++index)
            if (std::towlower(left[index]) != std::towlower(right[index])) return false;
        ++component;
    }
    return true;
}

void CheckLeaseControl(const ProcessRunOptions& control) {
    const auto context = CurrentOperationContext();
    if ((control.cancellation && control.cancellation->load()) ||
        (context && context->CancellationRequested()))
        throw std::runtime_error("Artifact lease acquisition cancelled.");
    if (std::chrono::steady_clock::now() >= control.deadline ||
        (context && context->DeadlineExceeded()))
        throw std::runtime_error("Artifact lease acquisition deadline exceeded.");
}

bool IsReparse(const fs::path& path) {
    const auto attributes = GetFileAttributesW(ExtendedWin32Path(path).c_str());
    return attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

bool LockName(const fs::path& path) {
    const auto name = path.filename().wstring();
    return name.empty() || name[0] == L'.' || name.ends_with(L"-lock") ||
        name.ends_with(L".import-lock");
}

// Refuse uncertain entries rather than following a junction/symlink during
// accounting. Nested links contribute no target bytes and are unlinked only.
// Retention only accepts immediate owned children.
bool InspectPruneEntry(const fs::path& path, const fs::path& root,
        std::uint64_t& bytes, fs::file_time_type& latest,
        const ProcessRunOptions* control = nullptr, CachePruneReport* report = nullptr) {
    if (control && report && !CheckPruneControl(*control, *report)) return false;
    std::error_code ec;
    if (path.parent_path() != root || IsReparse(path) ||
        fs::weakly_canonical(path, ec) != path || ec) return false;
    latest = fs::last_write_time(path, ec);
    if (ec) return false;
    if (fs::is_regular_file(path, ec)) {
        bytes = fs::file_size(path, ec);
        return !ec;
    }
    if (ec || !fs::is_directory(path, ec) || ec) return false;
    fs::recursive_directory_iterator it(path, fs::directory_options::none, ec), end;
    if (ec) return false;
    for (; it != end; it.increment(ec)) {
        if (ec) return false;
        if (control && report && !CheckPruneControl(*control, *report)) return false;
        const auto attributes = GetFileAttributesW(ExtendedWin32Path(it->path()).c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) return false;
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            // This entry owns only the link, never the target or its bytes.
            it.disable_recursion_pending();
            continue;
        }
        const auto status = it->symlink_status(ec);
        if (ec || (!fs::is_directory(status) && !fs::is_regular_file(status))) return false;
        if (fs::is_regular_file(status)) {
            const auto size = it->file_size(ec);
            if (ec || size > UINT64_MAX - bytes) return false;
            bytes += size;
        }
        const auto modified = it->last_write_time(ec);
        if (ec) return false;
        latest = std::max(latest, modified);
    }
    return !ec;
}

struct RetentionHandle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~RetentionHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    void Close() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); value = INVALID_HANDLE_VALUE; }
};

bool SameFileIdentity(const BY_HANDLE_FILE_INFORMATION& a, const BY_HANDLE_FILE_INFORMATION& b) {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
        a.nFileIndexHigh == b.nFileIndexHigh &&
        a.nFileIndexLow == b.nFileIndexLow;
}

bool VerifyPinnedDirectoryIdentity(const fs::path& path, const BY_HANDLE_FILE_INFORMATION& expected) {
    RetentionHandle held;
    held.value = CreateFileW(ExtendedWin32Path(path).c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (held.value == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(held.value, &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        return false;
    }
    return SameFileIdentity(info, expected);
}

std::string ObjectIdentity(const BY_HANDLE_FILE_INFORMATION& info) {
    return std::to_string(info.dwVolumeSerialNumber) + ":" +
        std::to_string(info.nFileIndexHigh) + ":" + std::to_string(info.nFileIndexLow);
}

std::optional<std::string> OrdinaryDirectoryIdentity(const fs::path& path) {
    RetentionHandle held;
    held.value = CreateFileW(ExtendedWin32Path(path).c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (held.value == INVALID_HANDLE_VALUE) return {};
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(held.value, &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return {};
    return ObjectIdentity(info);
}

bool ReadLeaseLastUse(const fs::path& destination, fs::file_time_type& last_use) {
    last_use = fs::file_time_type::min();
    const auto path = fs::path(destination.wstring() + L".import-lock");
    RetentionHandle held;
    held.value = CreateFileW(ExtendedWin32Path(path).c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (held.value == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(held.value, &information) ||
        (information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) return false;
    const auto ticks = (static_cast<std::uint64_t>(information.ftLastWriteTime.dwHighDateTime) << 32) |
        information.ftLastWriteTime.dwLowDateTime;
    // A lock first created by TryAcquire carries the Unix epoch sentinel,
    // not a fabricated recent use. Accept zero from older receipts as unused.
    if (!ticks || ticks == 116444736000000000ULL) return true;
    // MSVC filesystem's clock uses signed 100ns ticks since 1601, exactly
    // FILETIME's epoch. Swift's bundled STL does not expose C++20 from_sys.
    static_assert(fs::file_time_type::duration::period::num == 1 &&
        fs::file_time_type::duration::period::den == 10000000);
    if (ticks > static_cast<std::uint64_t>(INT64_MAX)) return false;
    last_use = fs::file_time_type(fs::file_time_type::duration(static_cast<std::int64_t>(ticks)));
    return true;
}

// Pin ordinary directories against rename while enumerating. Open final links
// themselves, unlink reparse entries, and never enumerate their destinations.
bool RemoveOwnedNode(const fs::path& path, const std::string& expected_identity = {},
        const ProcessRunOptions* control = nullptr, CachePruneReport* report = nullptr) {
    if (control && report && !CheckPruneControl(*control, *report)) return false;
    RetentionHandle held;
    held.value = CreateFileW(ExtendedWin32Path(path).c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (held.value == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(held.value, &information)) return false;
    if (!expected_identity.empty() && ObjectIdentity(information) != expected_identity) return false;
    const bool directory = (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (directory && !(information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        std::error_code ec;
        fs::directory_iterator it(ExtendedFsPath(path), fs::directory_options::none, ec), end;
        for (; !ec && it != end; it.increment(ec)) {
            if (control && report && !CheckPruneControl(*control, *report)) return false;
            if (!RemoveOwnedNode(it->path(), {}, control, report)) return false;
        }
        if (ec) return false;
    }
    if (control && report && !CheckPruneControl(*control, *report)) return false;
    held.Close();
    return directory ? RemoveDirectoryW(ExtendedWin32Path(path).c_str()) != FALSE :
        DeleteFileW(ExtendedWin32Path(path).c_str()) != FALSE;
}

struct ImportedBytes {
    bool exists = false;
    std::string bytes;
    DWORD links = 0;
};

bool ReadImportedBytes(const fs::path& path, ImportedBytes& result) {
    RetentionHandle held;
    held.value = CreateFileW(ExtendedWin32Path(path).c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (held.value == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    BY_HANDLE_FILE_INFORMATION before{}, after{};
    LARGE_INTEGER length{};
    if (!GetFileInformationByHandle(held.value, &before) ||
        (before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileSizeEx(held.value, &length) || length.QuadPart < 0 || length.QuadPart > 64LL * 1024 * 1024)
        return false;
    result.bytes.resize(static_cast<std::size_t>(length.QuadPart));
    std::size_t offset = 0;
    while (offset < result.bytes.size()) {
        DWORD count = 0;
        const auto requested = static_cast<DWORD>(std::min<std::size_t>(64 * 1024, result.bytes.size() - offset));
        if (!ReadFile(held.value, result.bytes.data() + offset, requested, &count, nullptr) || !count)
            return false;
        offset += count;
    }
    char extra;
    DWORD count = 0;
    if (!ReadFile(held.value, &extra, 1, &count, nullptr) || count ||
        !GetFileInformationByHandle(held.value, &after) ||
        before.nFileSizeHigh != after.nFileSizeHigh || before.nFileSizeLow != after.nFileSizeLow ||
        CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) != 0) return false;
    result.exists = true;
    result.links = after.nNumberOfLinks;
    return true;
}

fs::path ScratchOwnerFile(const fs::path& staging) {
    const auto name = staging.filename().wstring();
    if (name.size() <= 41) return {};
    const auto digest = Sha256(Win32Process::ToNarrow(name.substr(0, name.size() - 41)));
    if (!digest) return {};
    return staging.parent_path() / (L".OPENFRUIT-import-" + Win32Process::ToWide(digest->substr(0, 16)) +
        L"-" + name.substr(name.size() - 32) + L".json");
}

bool PublishScratchOwner(const fs::path& destination, const fs::path& staging,
        const std::string& identity, const char* phase) {
    auto record = JsonValue::ObjectValue();
    record.Set("schema", JsonValue::String("openfruit.import-scratch.v1"));
    record.Set("destination", JsonValue::String(Win32Process::ToNarrow(fs::absolute(destination).lexically_normal().wstring())));
    record.Set("staging", JsonValue::String(Win32Process::ToNarrow(staging.filename().wstring())));
    record.Set("backup", JsonValue::String(Win32Process::ToNarrow(destination.filename().wstring() +
        L".previous-" + staging.filename().wstring().substr(staging.filename().wstring().size() - 32))));
    record.Set("identity", JsonValue::String(identity));
    record.Set("phase", JsonValue::String(phase));
    const auto receipt = ScratchOwnerFile(staging);
    return !receipt.empty() && AtomicFile::Publish(receipt, record.Serialize(true));
}

void ScratchCleanupEvent(const fs::path& path, bool removed) {
    if (const auto context = CurrentOperationContext()) {
        auto data = JsonValue::ObjectValue();
        data.Set("path", JsonValue::String(Win32Process::ToNarrow(path.wstring())));
        data.Set("kind", JsonValue::String("private_import_scratch"));
        data.Set("removed", JsonValue::Boolean(removed));
        context->Emit(removed ? "artifact.import_scratch_recovered" : "artifact.cleanup_pending",
                      std::move(data), removed ? "info" : "warning");
    }
}

// Caller holds the destination lease. Never interpret a publication-phase
// record as permission to remove either the installed artifact or its backup.
// Root identity is checked again on the handle pinned by RemoveOwnedNode.
bool DiscardPrivateScratch(const fs::path& staging, const std::string& identity) {
    const auto attributes = GetFileAttributesW(ExtendedWin32Path(staging).c_str());
    const DWORD error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    bool removed = attributes == INVALID_FILE_ATTRIBUTES &&
        (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
    if (attributes == INVALID_FILE_ATTRIBUTES && !removed) {
        ScratchCleanupEvent(staging, false);
        return false;
    }
    if (!removed) removed = RemoveOwnedNode(staging, identity);
    if (removed) {
        const auto receipt = ScratchOwnerFile(staging);
        if (receipt.empty()) return false;
        removed = DeleteFileW(ExtendedWin32Path(receipt).c_str()) != FALSE;
        if (!removed) {
            const auto code = GetLastError();
            removed = code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND;
        }
    }
    ScratchCleanupEvent(staging, removed);
    return removed;
}

void RecoverPrivateScratch(const fs::path& destination, const fs::path& source) {
    std::error_code ec;
    const auto absolute = fs::absolute(destination, ec).lexically_normal();
    if (ec) return;
    const auto parent = fs::canonical(absolute.parent_path(), ec);
    if (ec) return;
    const auto digest = Sha256(Win32Process::ToNarrow(absolute.filename().wstring()));
    if (!digest) return;
    const auto prefix = L".OPENFRUIT-import-" + Win32Process::ToWide(digest->substr(0, 16)) + L"-";
    constexpr std::wstring_view suffix = L".json";
    std::size_t inspected = 0, candidates = 0;
    fs::directory_iterator it(ExtendedFsPath(parent), ec), end;
    for (; !ec && it != end && inspected < 4096 && candidates < 32; it.increment(ec), ++inspected) {
        const auto name = it->path().filename().wstring();
        if (!name.starts_with(prefix) || !name.ends_with(suffix) ||
            name.size() != prefix.size() + 32 + suffix.size()) continue;
        const auto operation = name.substr(prefix.size(), 32);
        if (operation.find_first_not_of(L"0123456789abcdef") != std::wstring::npos) continue;
        ++candidates;
        const auto receipt = parent / name;
        ImportedBytes contents;
        if (!ReadImportedBytes(receipt, contents) || !contents.exists || contents.links != 1 ||
            contents.bytes.size() > 64 * 1024) continue;
        const auto record = JsonValue::Parse(contents.bytes);
        const auto stage_name = absolute.filename().wstring() + L".partial-" + operation;
        if (!record || !record->IsObject() ||
            record->GetString("schema") != "openfruit.import-scratch.v1" ||
            record->GetString("phase") != "discardable" ||
            record->GetString("staging") != Win32Process::ToNarrow(stage_name)) continue;
        const auto owner = fs::path(Win32Process::ToWide(record->GetString("destination")));
        // Receipt text is data: do not resolve a supplied alias/UNC path or
        // reuse NestedPath's deliberately conservative "uncertain=true" result
        // as positive ownership authority. Different path spellings stay protected.
        if (!owner.is_absolute() || owner.lexically_normal() != absolute) continue;
        const auto stage = parent / stage_name;
        // A previous private tree may itself be the caller's import input.
        // Uncertain or overlapping paths never authorize its removal.
        if (NestedPath(source, stage) || NestedPath(stage, source)) continue;
        const auto identity = record->GetString("identity");
        if (identity.empty()) continue;
        if (LongPathExists(stage)) {
            const auto actual = OrdinaryDirectoryIdentity(stage);
            if (!actual || *actual != identity) continue;
        }
        DiscardPrivateScratch(stage, identity);
    }
}

fs::path ImportedPath(const fs::path& input) {
    const auto path = fs::absolute(input).lexically_normal();
    if (input.empty() || path.filename().empty() || path == path.root_path())
        throw std::runtime_error("Imported metadata requires a non-root file path.");
    const auto attributes = GetFileAttributesW(ExtendedWin32Path(path).c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        throw std::runtime_error("Imported metadata cannot be a directory or alias.");
    return fs::weakly_canonical(path.parent_path()) / path.filename();
}

bool ImportedHash(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

bool ValidImportedReceipt(const JsonValue& value, const fs::path& destination) {
    if (!value.IsObject() || value.GetString("schema") != "openfruit.imported-file.v1" ||
        value.GetString("destination") != Win32Process::ToNarrow(destination.wstring()) ||
        !ImportedHash(value.GetString("source_sha256"))) return false;
    const auto source = fs::path(Win32Process::ToWide(value.GetString("source")));
    if (!source.is_absolute() || source != source.lexically_normal() ||
        source.filename().empty() || source == destination) return false;
    const auto phase = value.GetString("phase");
    return phase == "importing" || phase == "complete" || phase == "removing";
}

bool PublishImportedReceipt(const fs::path& path, const JsonValue& value, std::string& previous) {
    const auto bytes = value.Serialize(true);
    if (bytes == previous) return true;
    if (!AtomicFile::Publish(path, bytes)) return false;
    previous = bytes;
    return true;
}

} // namespace

std::shared_ptr<ArtifactLease> ArtifactLease::TryAcquire(const fs::path& destination) {
    return TryAcquireMode(destination, false);
}

std::shared_ptr<ArtifactLease> ArtifactLease::TryAcquireSharedRead(const fs::path& destination) {
    return TryAcquireMode(destination, true);
}

std::shared_ptr<ArtifactLease> ArtifactLease::TryAcquireMode(const fs::path& destination, bool shared_read) {
    if (destination.empty()) throw std::runtime_error("Artifact lease destination is empty.");
    std::error_code ec;
    const auto absolute = fs::absolute(destination, ec).lexically_normal();
    if (ec || absolute.filename().empty() || absolute == absolute.root_path())
        throw std::runtime_error("Artifact lease requires a non-root destination.");
    if (!shared_read) fs::create_directories(ExtendedFsPath(absolute.parent_path()), ec);
    if (ec) throw std::runtime_error("Cannot create artifact lease parent: " + ec.message());
    const auto parent = fs::canonical(absolute.parent_path(), ec);
    if (ec) throw std::runtime_error("Cannot resolve artifact lease parent: " + ec.message());
    const auto lock_path = fs::path((parent / absolute.filename()).wstring() + L".import-lock");
    const DWORD access = shared_read ? GENERIC_READ | FILE_WRITE_ATTRIBUTES : GENERIC_READ | GENERIC_WRITE;
    HANDLE handle = CreateFileW(ExtendedWin32Path(lock_path).c_str(), access,
        FILE_SHARE_READ, nullptr, shared_read ? OPEN_EXISTING : OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    const auto open_error = GetLastError();
    if (handle == INVALID_HANDLE_VALUE) {
        const auto error = open_error;
        if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) return {};
        throw std::runtime_error("Cannot acquire artifact lease (Win32 " + std::to_string(error) + ").");
    }
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(handle, &information) ||
        information.nNumberOfLinks != 1 ||
        (information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) {
        CloseHandle(handle);
        throw std::runtime_error("Artifact lease lock is not an ordinary file.");
    }
    if (!shared_read && open_error != ERROR_ALREADY_EXISTS) {
        constexpr std::uint64_t never_used = 116444736000000000ULL;
        const FILETIME unused{static_cast<DWORD>(never_used), static_cast<DWORD>(never_used >> 32)};
        if (!SetFileTime(handle, nullptr, nullptr, &unused)) {
            CloseHandle(handle);
            throw std::runtime_error("Cannot initialize artifact lease last-use record.");
        }
    }
    try {
        auto lease = std::shared_ptr<ArtifactLease>(new ArtifactLease(nullptr));
        lease->handle_ = handle;
        return lease;
    }
    catch (...) { CloseHandle(handle); throw; }
}

std::shared_ptr<ArtifactLease> ArtifactLease::Acquire(const fs::path& destination,
        const ProcessRunOptions& control) {
    for (;;) {
        CheckLeaseControl(control);
        if (auto lease = TryAcquire(destination)) {
            lease->TouchLastUse();
            return lease;
        }
        Sleep(25);
    }
}

std::shared_ptr<ArtifactLease> ArtifactLease::AcquireSharedRead(const fs::path& destination,
        const ProcessRunOptions& control) {
    for (;;) {
        CheckLeaseControl(control);
        if (auto lease = TryAcquireSharedRead(destination)) {
            lease->TouchLastUse();
            return lease;
        }
        Sleep(25);
    }
}

void ArtifactLease::TouchLastUse() {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    if (!SetFileTime(static_cast<HANDLE>(handle_), nullptr, nullptr, &now))
        throw std::runtime_error("Cannot record artifact lease last use.");
}

ArtifactLease::~ArtifactLease() {
    if (handle_) CloseHandle(static_cast<HANDLE>(handle_));
}

bool NativeArtifactStore::SynchronizeImportedFile(const fs::path& source_or_empty,
        const fs::path& destination, const fs::path& receipt) {
    try {
        const auto target = ImportedPath(destination), record = ImportedPath(receipt);
        if (target == record) return false;
        ImportedBytes old_record, old_target;
        if (!ReadImportedBytes(record, old_record)) return false;
        std::optional<JsonValue> provenance;
        if (old_record.exists) {
            provenance = JsonValue::Parse(old_record.bytes);
            if (old_record.links != 1 || !provenance || !ValidImportedReceipt(*provenance, target)) return false;
        }
        if (source_or_empty.empty() && !provenance) return true;
        if (!ReadImportedBytes(target, old_target)) return false;
        if (source_or_empty.empty()) {
            // A solver is free to generate its own lock. Its presence alone
            // never authorizes this import service to delete or adopt it.
            provenance->Set("phase", JsonValue::String("removing"));
            if (!PublishImportedReceipt(record, *provenance, old_record.bytes)) return false;
            if (old_target.exists && !DeleteFileW(ExtendedWin32Path(target).c_str())) return false;
            return DeleteFileW(ExtendedWin32Path(record).c_str()) != FALSE;
        }
        const auto source = ImportedPath(source_or_empty);
        if (source == target || source == record) return false;
        ImportedBytes input;
        // Finish reading the complete unchanged input before recording intent
        // or replacing any existing destination/receipt.
        if (!ReadImportedBytes(source, input) || !input.exists) return false;
        const auto hash = Sha256(input.bytes);
        if (!hash) return false;
        auto next = JsonValue::ObjectValue();
        next.Set("schema", JsonValue::String("openfruit.imported-file.v1"));
        next.Set("source", JsonValue::String(Win32Process::ToNarrow(source.wstring())));
        next.Set("destination", JsonValue::String(Win32Process::ToNarrow(target.wstring())));
        next.Set("source_sha256", JsonValue::String(*hash));
        next.Set("phase", JsonValue::String("complete"));
        const bool unchanged = old_target.exists && old_target.links == 1 && old_target.bytes == input.bytes;
        if (unchanged) return PublishImportedReceipt(record, next, old_record.bytes);
        next.Set("phase", JsonValue::String("importing"));
        if (!PublishImportedReceipt(record, next, old_record.bytes)) return false;
        if (!AtomicFile::Publish(target, input.bytes)) return false;
        next.Set("phase", JsonValue::String("complete"));
        return PublishImportedReceipt(record, next, old_record.bytes);
    } catch (...) { return false; }
}

bool NativeArtifactStore::ImportFile(const fs::path& source, const fs::path& destination) {
    std::error_code ec;
    fs::create_directories(ExtendedFsPath(destination.parent_path()), ec);
    if (ec) return false;
    if (LongPathExists(destination)) return true;

    const std::wstring destination_w = ExtendedWin32Path(destination);
    const std::wstring source_w = ExtendedWin32Path(source);
    if (SameVolume(source, destination) &&
        CreateHardLinkW(destination_w.c_str(), source_w.c_str(), nullptr)) {
        return true;
    }

    return CopyFileW(source_w.c_str(), destination_w.c_str(), FALSE) != FALSE;
}

bool NativeArtifactStore::CreateNtfsHardLink(const fs::path& source, const fs::path& destination) {
    std::error_code ec;
    fs::create_directories(ExtendedFsPath(destination.parent_path()), ec);
    if (ec) return false;
    if (LongPathExists(destination)) {
        DeleteFileW(ExtendedWin32Path(destination).c_str());
    }
    const std::wstring destination_w = ExtendedWin32Path(destination);
    const std::wstring source_w = ExtendedWin32Path(source);
    if (SameVolume(source, destination) &&
        CreateHardLinkW(destination_w.c_str(), source_w.c_str(), nullptr)) {
        return true;
    }
    return CopyFileW(source_w.c_str(), destination_w.c_str(), FALSE) != FALSE;
}

bool NativeArtifactStore::CreateDirectoryJunction(const fs::path& link, const fs::path& target) {
    if (link.empty() || target.empty()) return false;
    std::error_code ec;
    if (!fs::is_directory(target, ec)) return false;

    fs::create_directories(ExtendedFsPath(link.parent_path()), ec);
    if (ec) return false;

    if (fs::exists(link, ec) && fs::equivalent(link, target, ec)) {
        return true;
    }
    if (fs::exists(link, ec)) {
        RemoveDirectoryW(ExtendedWin32Path(link).c_str());
    }

    if (CreateSymbolicLinkW(ExtendedWin32Path(link).c_str(),
                            ExtendedWin32Path(target).c_str(),
                            SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2 /*SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE*/)) {
        return true;
    }

    std::wstring cmd = L"cmd.exe /c mklink /J \"" + link.wstring() + L"\" \"" + target.wstring() + L"\" >nul 2>&1";
    int res = _wsystem(cmd.c_str());
    return res == 0 && fs::exists(link, ec);
}

bool NativeArtifactStore::ImportTree(const fs::path& source, const fs::path& destination, std::size_t* imported_files) {
    std::error_code ec;
    if (!fs::is_directory(source, ec) || ec) return false;
    fs::create_directories(ExtendedFsPath(destination), ec);
    if (ec) return false;

    std::size_t count = 0;
    for (fs::recursive_directory_iterator it(source, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        const fs::path rel = it->path().lexically_relative(source);
        if (rel.empty()) continue;
        const fs::path out = destination / rel;

        if (it->is_directory(ec)) {
            ec.clear();
            fs::create_directories(ExtendedFsPath(out), ec);
            if (ec) return false;
            continue;
        }
        ec.clear();

        if (it->is_regular_file(ec) || it->is_symlink(ec)) {
            ec.clear();
            if (!ImportFile(it->path(), out)) return false;
            ++count;
        }
        ec.clear();
    }
    if (imported_files) *imported_files = count;
    return true;
}


bool NativeArtifactStore::ImportTreeTransactional(
    const fs::path& source,
    const fs::path& destination,
    const std::function<bool(const fs::path&)>& validator,
    std::size_t* imported_files
) {
    if (source.empty() || destination.empty()) return false;
    if (NestedPath(source, destination) || NestedPath(destination, source)) return false;
    std::shared_ptr<ArtifactLease> lease;
    try {
        lease = ArtifactLease::TryAcquire(destination);
        if (lease) lease->TouchLastUse();
    }
    catch (...) { return false; }
    if (!lease) return false;
    RecoverPrivateScratch(destination, source);
    const auto operation_id = Win32Process::ToWide(NewOperationId());
    const fs::path staging = fs::path(destination.wstring() + L".partial-" + operation_id);
    const fs::path backup = fs::path(destination.wstring() + L".previous-" + operation_id);

    std::error_code staging_error;
    if (!fs::create_directory(ExtendedFsPath(staging), staging_error) || staging_error) return false;
    const auto staging_identity = OrdinaryDirectoryIdentity(staging);
    if (!staging_identity || LongPathExists(ScratchOwnerFile(staging)) ||
        !PublishScratchOwner(destination, staging, *staging_identity, "discardable")) {
        RemoveTreeBestEffort(staging);
        return false;
    }
    const auto discard_staging = [&]() {
        // Never turn an uncertain publication into permission to delete the
        // installed artifact; keep its publication marker for explicit recovery.
        const auto installed = OrdinaryDirectoryIdentity(destination);
        if (installed && *installed == *staging_identity) {
            ScratchCleanupEvent(staging, false);
            return false;
        }
        if (!PublishScratchOwner(destination, staging, *staging_identity, "discardable")) {
            ScratchCleanupEvent(staging, false);
            return false;
        }
        return DiscardPrivateScratch(staging, *staging_identity);
    };

    std::size_t count = 0;
    const auto validates = [&](const fs::path& path) {
        try { return !validator || validator(path); }
        catch (...) { return false; }
    };
    if (!ImportTree(source, staging, &count) || !validates(staging)) {
        discard_staging();
        return false;
    }

    if (!PublishScratchOwner(destination, staging, *staging_identity, "publishing")) {
        discard_staging();
        return false;
    }

    const bool had_previous = LongPathExists(destination);
    if (had_previous && !MoveFileExWithRetryW(ExtendedWin32Path(destination).c_str(),
            ExtendedWin32Path(backup).c_str(), MOVEFILE_WRITE_THROUGH)) {
        discard_staging();
        return false;
    }

    const std::wstring staging_w = ExtendedWin32Path(staging);
    const std::wstring destination_w = ExtendedWin32Path(destination);
    const auto rollback_failed = [&]() {
        if (const auto context = CurrentOperationContext()) {
            auto data = JsonValue::ObjectValue();
            data.Set("previous_artifact", JsonValue::String(backup.string()));
            context->Emit("artifact.rollback_failed", std::move(data), "error");
        }
    };
    if (!MoveFileExWithRetryW(staging_w.c_str(), destination_w.c_str(), MOVEFILE_WRITE_THROUGH)) {
        if (had_previous && !MoveFileExWithRetryW(ExtendedWin32Path(backup).c_str(),
                destination_w.c_str(), MOVEFILE_WRITE_THROUGH)) {
            rollback_failed();
        }
        discard_staging();
        return false;
    }

    if (!validates(destination)) {
        // Keep an invalid published product separate so the previous product
        // can be restored without deleting it or overwriting either tree.
        if (MoveFileExWithRetryW(destination_w.c_str(), staging_w.c_str(), MOVEFILE_WRITE_THROUGH)) {
            if (had_previous && !MoveFileExWithRetryW(ExtendedWin32Path(backup).c_str(),
                    destination_w.c_str(), MOVEFILE_WRITE_THROUGH)) rollback_failed();
            discard_staging();
        } else rollback_failed();
        return false;
    }
    if (!DeleteFileW(ExtendedWin32Path(ScratchOwnerFile(staging)).c_str()))
        ScratchCleanupEvent(ScratchOwnerFile(staging), false);
    if (had_previous && !RemoveTreeBestEffort(backup)) {
        if (const auto context = CurrentOperationContext()) {
            auto data = JsonValue::ObjectValue();
            data.Set("previous_artifact", JsonValue::String(backup.string()));
            context->Emit("artifact.cleanup_pending", std::move(data), "warning");
        }
    }
    if (imported_files) *imported_files = count;
    return true;
}

CachePruneReport NativeArtifactStore::PruneCache(
    const fs::path& cache_root,
    std::optional<std::uint64_t> max_bytes_quota,
    std::uint64_t max_age_seconds,
    bool require_existing_consumer_lease,
    const std::function<bool(const fs::path&)>& eligible_entry
) {
    CachePruneOptions options;
    options.max_bytes_quota = max_bytes_quota;
    options.max_age_seconds = max_age_seconds;
    options.require_existing_consumer_lease = require_existing_consumer_lease;
    options.eligible_entry = eligible_entry;
    return PruneCache(cache_root, options);
}

CachePruneReport NativeArtifactStore::PruneCache(
    const fs::path& cache_root,
    const CachePruneOptions& options
) {
    CachePruneReport report;
    if (!CheckPruneControl(options.control, report)) return report;
    std::error_code ec;
    if (cache_root.empty()) return report;
    const bool exists = fs::exists(cache_root, ec);
    if (!ec && !exists && !fs::is_symlink(fs::symlink_status(cache_root, ec))) return report;
    if (ec || IsReparse(cache_root)) {
        report.success = false;
        report.error_message = "Cache retention root is inaccessible or a reparse point.";
        return report;
    }
    const auto root = fs::canonical(cache_root, ec);
    if (ec || root == root.root_path() || !fs::is_directory(root, ec) || ec) {
        report.success = false;
        report.error_message = "Cache retention requires an ordinary non-root directory.";
        return report;
    }
    RetentionHandle root_handle;
    root_handle.value = CreateFileW(ExtendedWin32Path(root).c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    BY_HANDLE_FILE_INFORMATION root_information{};
    if (root_handle.value == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(root_handle.value, &root_information) ||
        !(root_information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (root_information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        report.success = false;
        report.error_message = "Cannot pin ordinary cache retention root.";
        return report;
    }
    if (!CheckPruneControl(options.control, report)) return report;
    struct CacheEntryInfo {
        fs::path path;
        std::uint64_t bytes = 0;
        fs::file_time_type last_write_time;
        fs::file_time_type last_use;
    };
    std::vector<CacheEntryInfo> entries;
    std::uint64_t total_bytes = 0;
    const auto now = fs::file_time_type::clock::now();
    fs::directory_iterator it(root, fs::directory_options::none, ec), end;
    for (; !ec && it != end; it.increment(ec)) {
        if (!CheckPruneControl(options.control, report)) return report;
        const auto path = it->path();
        if (LockName(path)) continue;
        if (options.max_entries_scanned > 0 && report.entries_scanned >= options.max_entries_scanned) {
            report.partial = true;
            ++report.entries_deferred_budget;
            break;
        }
        ++report.entries_scanned;
        if (options.eligible_entry && !options.eligible_entry(path)) {
            ++report.entries_skipped_unmanaged;
            continue;
        }
        // Opt-in namespaces only: older consumers do not participate in this
        // lease protocol, so absence of contention is not proof of inactivity.
        if (options.require_existing_consumer_lease) {
            const auto lock = fs::path(path.wstring() + L".import-lock");
            const auto attributes = GetFileAttributesW(ExtendedWin32Path(lock).c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
                ++report.entries_skipped_unmanaged;
                continue;
            }
        }
        CacheEntryInfo entry{path};
        if (!InspectPruneEntry(path, root, entry.bytes, entry.last_write_time, &options.control, &report)) {
            if (report.cancelled || report.timed_out) return report;
            continue;
        }
        if (!ReadLeaseLastUse(path, entry.last_use)) continue;
        if (entry.bytes > UINT64_MAX - total_bytes) {
            report.success = false;
            report.error_message = "Cache retention byte accounting overflow.";
            return report;
        }
        total_bytes += entry.bytes;
        ++report.entries_eligible;
        entries.push_back(std::move(entry));
    }
    if (ec) {
        report.success = false;
        report.error_message = "Cannot enumerate cache retention root: " + ec.message();
        return report;
    }
    // Content writes and successful lease acquisition both record real use.
    std::sort(entries.begin(), entries.end(), [](const CacheEntryInfo& a, const CacheEntryInfo& b) {
        return std::max(a.last_write_time, a.last_use) < std::max(b.last_write_time, b.last_use);
    });
    for (const auto& entry : entries) {
        if (!CheckPruneControl(options.control, report)) return report;
        const bool over_quota = options.max_bytes_quota && total_bytes > *options.max_bytes_quota;
        const auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - std::max(entry.last_write_time, entry.last_use)).count();
        const bool expired = options.max_age_seconds > 0 && age > 0 &&
            static_cast<std::uint64_t>(age) > options.max_age_seconds;
        if (!over_quota && !expired) continue;
        if (options.max_entries_deleted > 0 && report.entries_removed >= options.max_entries_deleted) {
            report.partial = true;
            ++report.entries_deferred_budget;
            continue;
        }
        try {
            auto lease = ArtifactLease::TryAcquire(entry.path);
            if (!lease) { ++report.entries_skipped_in_use; continue; }
            // Revalidate under the same lease used by publishers/consumers.
            std::uint64_t bytes = 0;
            fs::file_time_type modified, last_use;
            if (!VerifyPinnedDirectoryIdentity(cache_root, root_information) ||
                !VerifyPinnedDirectoryIdentity(root, root_information) ||
                IsReparse(root) || fs::canonical(root, ec) != root || ec ||
                !InspectPruneEntry(entry.path, root, bytes, modified, &options.control, &report) ||
                !ReadLeaseLastUse(entry.path, last_use)) {
                if (report.cancelled || report.timed_out) return report;
                continue;
            }
            // A successful user may have refreshed the entry since enumeration.
            // Do not discard that newer state during this retention pass.
            if (bytes != entry.bytes || modified != entry.last_write_time || last_use != entry.last_use) continue;
            if (RemoveOwnedNode(entry.path, {}, &options.control, &report)) {
                ++report.entries_removed;
                report.bytes_reclaimed += bytes;
                total_bytes -= entry.bytes;
            } else {
                if (report.cancelled || report.timed_out) return report;
                report.success = false;
                report.error_message = "Cannot remove an unleased cache entry.";
            }
        } catch (const std::exception& error) {
            report.success = false;
            report.error_message = error.what();
        }
    }

    if (const auto context = CurrentOperationContext()) {
        auto data = JsonValue::ObjectValue();
        data.Set("cache_root", JsonValue::String(cache_root.string()));
        data.Set("entries_scanned", JsonValue::Number(std::to_string(report.entries_scanned)));
        data.Set("entries_eligible", JsonValue::Number(std::to_string(report.entries_eligible)));
        data.Set("entries_removed", JsonValue::Number(std::to_string(report.entries_removed)));
        data.Set("entries_deferred_budget", JsonValue::Number(std::to_string(report.entries_deferred_budget)));
        data.Set("bytes_reclaimed", JsonValue::Number(std::to_string(report.bytes_reclaimed)));
        data.Set("entries_skipped_in_use", JsonValue::Number(std::to_string(report.entries_skipped_in_use)));
        data.Set("entries_skipped_unmanaged", JsonValue::Number(std::to_string(report.entries_skipped_unmanaged)));
        data.Set("partial", JsonValue::Boolean(report.partial));
        data.Set("cancelled", JsonValue::Boolean(report.cancelled));
        data.Set("timed_out", JsonValue::Boolean(report.timed_out));
        data.Set("byte_accounting", JsonValue::String("logical_deleted_file_lengths"));
        context->Emit("cache.prune", std::move(data), "info");
    }

    return report;
}

} // namespace OpenFruit

