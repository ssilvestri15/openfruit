#include "sdk_selection.hpp"
#include "sdk_catalog.hpp"
#include "operation_events.hpp"
#include "artifact_store.hpp"
#include "atomic_file.hpp"
#include "content_hash.hpp"
#include "sdk_usage.hpp"
#include "tool_paths.hpp"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <vector>
#include <windows.h>
namespace OpenFruit {
namespace {
enum class Recovery { None, Restored, Preserved, PresentUnproven };
Recovery RecoverPrepared(const Config&, const std::wstring&, const std::filesystem::path&);
bool CurrentMutationBase(const Config&, const std::filesystem::path&, Config&, std::string* before_digest = nullptr);
}
SDKSelectionResult SDKSelection::Select(Config& snapshot, const std::wstring& version,
    const std::filesystem::path& configuration_path) {
    OperationSpan span("sdk.select");
    SDKSelectionResult result;
    const auto recovery = RecoverPrepared(snapshot, version, configuration_path);
    const auto registered = snapshot.ios_sdk_paths.find(version);
    const char* status = "not_registered";
    if (registered == snapshot.ios_sdk_paths.end()) {
        result.message = "Requested SDK version is not registered.";
    } else if (!std::filesystem::path(registered->second).is_absolute()) {
        result.status = SDKSelectionStatus::InvalidPath;
        status = "invalid_path";
        result.message = "Registered SDK requires an absolute path.";
    } else if (recovery == Recovery::Preserved) {
        result.status = SDKSelectionStatus::IncompleteLayout;
        status = "recovery_pending";
        result.message = "Interrupted SDK removal cannot be restored safely; retained payload and configuration require inspection.";
    } else {
        // Keep the same SDK root in place through selection publication.
        SDKUsage usage(registered->second);
        if (!usage.Held() || !SDKCatalog::HasUsableLayout(registered->second)) {
            result.status = SDKSelectionStatus::IncompleteLayout;
            status = "incomplete_layout";
            result.message = "Registered SDK layout is unavailable or incomplete.";
        } else {
            Config candidate;
            std::string before_digest;
            const bool current = CurrentMutationBase(snapshot, configuration_path, candidate, &before_digest);
            candidate.ios_sdk_version = version;
            candidate.sdk_path = registered->second;
            if (!current || !candidate.SaveIfUnchanged(configuration_path.wstring(), before_digest)) {
                result.status = SDKSelectionStatus::PublicationFailed;
                status = "publication_failed";
                result.message = "Unable to publish SDK selection; previous selection is retained.";
            } else {
                snapshot = std::move(candidate);
                result.status = SDKSelectionStatus::Succeeded;
                status = "succeeded";
                result.message = "SDK selection saved.";
            }
        }
    }
    auto data = JsonValue::ObjectValue();
    data.Set("status", JsonValue::String(status));
    data.Set("message", JsonValue::String(result.message));
    span.Complete(std::move(data), result.Succeeded());
    return result;
}


namespace {
namespace fs = std::filesystem;
std::wstring Extended(const fs::path& path) {
    // Extended Win32 paths require backslashes, including when the public
    // operation receives an ordinary Windows path with mixed separators.
    auto text = path.lexically_normal().make_preferred().wstring();
    if (text.rfind(LR"(\\?\)", 0) == 0) return text;
    return text.rfind(LR"(\\)", 0) == 0 ? LR"(\\?\UNC\)" + text.substr(2) : LR"(\\?\)" + text;
}

bool SamePart(const fs::path& left, const fs::path& right) {
    // Separator spelling is not a different Windows pathname. Preserve dot
    // components here: admission checks decide whether normalization is allowed.
    const auto a = fs::path(left).make_preferred().native();
    const auto b = fs::path(right).make_preferred().native();
    return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(),
        static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}
bool Contains(const fs::path& parent, const fs::path& child) {
    auto a = parent.begin(), b = child.begin();
    for (; a != parent.end(); ++a, ++b)
        if (b == child.end() || !SamePart(*a, *b)) return false;
    return true;
}
bool Overlap(const fs::path& left, const fs::path& right) {
    return Contains(left, right) || Contains(right, left);
}
// FILE_RENAME_INFO accepts an absolute destination with RootDirectory=nullptr.
// ReplaceIfExists=false preserves any independently created destination.
bool RenameHeld(HANDLE handle, const fs::path& destination) noexcept {
    try {
        const auto name = Extended(destination);
        const auto bytes = name.size() * sizeof(wchar_t);
        if (bytes > MAXDWORD - sizeof(FILE_RENAME_INFO)) return false;
        std::vector<unsigned char> storage(sizeof(FILE_RENAME_INFO) + bytes, 0);
        auto* info = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
        info->ReplaceIfExists = FALSE;
        info->RootDirectory = nullptr;
        info->FileNameLength = static_cast<DWORD>(bytes);
        std::memcpy(info->FileName, name.c_str(), bytes + sizeof(wchar_t));
        return SetFileInformationByHandle(handle, FileRenameInfo, info,
            static_cast<DWORD>(storage.size())) != FALSE;
    } catch (...) { return false; }
}
struct RootHandle {
    HANDLE value = INVALID_HANDLE_VALUE;
    fs::path restore_path;
    bool restore_on_exit = false;
    ~RootHandle() {
        if (restore_on_exit) RenameHeld(value, restore_path);
        Close();
    }
    void Close() { if (value != INVALID_HANDLE_VALUE) { CloseHandle(value); value = INVALID_HANDLE_VALUE; } }
};
bool Ordinary(HANDLE handle, bool directory, BY_HANDLE_FILE_INFORMATION& info) {
    return handle != INVALID_HANDLE_VALUE && GetFileInformationByHandle(handle, &info) &&
        !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
        ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory &&
        (directory || info.nNumberOfLinks == 1);
}
bool PinConfiguration(const fs::path& path, RootHandle& pin, std::string& digest) {
    if (path.empty() || !path.is_absolute()) return false;
    pin.value = CreateFileW(Extended(path.lexically_normal()).c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    BY_HANDLE_FILE_INFORMATION info{};
    if (!Ordinary(pin.value, false, info)) return false;
    const auto hash = Sha256FileHandle(pin.value);
    if (!hash) return false;
    digest = *hash;
    return true;
}
bool SameSDKState(const Config& supplied, const Config& current) {
    const auto path_equal = [](const std::wstring& a, const std::wstring& b) {
        return SamePart(fs::path(a).lexically_normal(), fs::path(b).lexically_normal());
    };
    const auto maps_equal = [&](const auto& a, const auto& b) {
        if (a.size() != b.size()) return false;
        for (const auto& [version, path] : a) {
            const auto other = b.find(version);
            if (other == b.end() || !path_equal(path, other->second)) return false;
        }
        return true;
    };
    const auto selected = [](const Config& config) {
        const auto registration = config.ios_sdk_paths.find(config.ios_sdk_version);
        return !config.ios_sdk_version.empty() && registration != config.ios_sdk_paths.end() ?
            registration->second : config.sdk_path;
    };
    const auto home = [](const Config& config) {
        return config.OPENFRUIT_home.empty() ? ToolPaths::LocalHome().wstring() : config.OPENFRUIT_home;
    };
    const auto state = [](const Config& config) {
        return config.user_state_root.empty() ? ToolPaths::UserStateRoot().wstring() : config.user_state_root;
    };
    return supplied.ios_sdk_version == current.ios_sdk_version &&
        maps_equal(supplied.ios_sdk_paths, current.ios_sdk_paths) &&
        maps_equal(supplied.macos_sdk_paths, current.macos_sdk_paths) &&
        path_equal(selected(supplied), selected(current)) &&
        path_equal(supplied.macos_sdk_path, current.macos_sdk_path) &&
        path_equal(supplied.xcode_path, current.xcode_path) &&
        path_equal(home(supplied), home(current)) && path_equal(state(supplied), state(current));
}
bool CurrentMutationBase(const Config& snapshot, const fs::path& configuration, Config& current, std::string* before_digest) {
    RootHandle pin;
    std::string digest;
    if (!PinConfiguration(configuration, pin, digest)) return false;
    current = Config::Load(configuration.wstring(), false);
    if (before_digest) *before_digest = digest;
    return SameSDKState(snapshot, current);
}
bool DigestText(const std::string& digest) {
    return digest.size() == 64 && std::all_of(digest.begin(), digest.end(),
        [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool PinReceipt(const fs::path& path, RootHandle& pin, JsonValue& record) {
    pin.value = CreateFileW(Extended(path).c_str(), GENERIC_READ | DELETE, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    if (!Ordinary(pin.value, false, info) || !GetFileSizeEx(pin.value, &size) ||
        size.QuadPart <= 0 || size.QuadPart > 16384) return false;
    std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD count = 0;
    if (!ReadFile(pin.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) || count != bytes.size()) return false;
    const auto parsed = JsonValue::Parse(bytes);
    if (!parsed || !parsed->IsObject()) return false;
    record = *parsed;
    return true;
}
bool UniqueReceipt(const fs::path& original, const fs::path& receipt) {
    const auto prefix = original.filename().wstring() + L".sdk-removal-";
    WIN32_FIND_DATAW entry{};
    HANDLE search = FindFirstFileW(Extended(original.parent_path() / (prefix + L"*.json")).c_str(), &entry);
    if (search == INVALID_HANDLE_VALUE) return false;
    struct Search { HANDLE value; ~Search() { FindClose(value); } } find{search};
    unsigned count = 0;
    do {
        if (++count > 256 || !SamePart(original.parent_path() / entry.cFileName, receipt)) return false;
    } while (FindNextFileW(search, &entry));
    return GetLastError() == ERROR_NO_MORE_FILES && count == 1;
}
bool ExistingLeaseMarker(const fs::path& target) {
    const auto attributes = GetFileAttributesW(Extended(fs::path(target.wstring() + L".import-lock")).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}
bool Interrupted() {
    const auto context = CurrentOperationContext();
    return context && (context->CancellationRequested() || context->DeadlineExceeded());
}
enum class DeleteOutcome { Done, Pending, Cancelled };
DeleteOutcome DeleteHeld(RootHandle& held, const fs::path& path) {
    if (Interrupted()) return DeleteOutcome::Cancelled;
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(held.value, &info)) return DeleteOutcome::Pending;
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        std::error_code error;
        fs::directory_iterator entries(path, error), end;
        for (; !error && entries != end; entries.increment(error)) {
            if (Interrupted()) return DeleteOutcome::Cancelled;
            RootHandle child;
            child.value = CreateFileW(Extended(entries->path()).c_str(), DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (child.value == INVALID_HANDLE_VALUE) return DeleteOutcome::Pending;
            const auto deleted = DeleteHeld(child, entries->path());
            if (deleted != DeleteOutcome::Done) return deleted;
            if (const auto context = CurrentOperationContext()) {
                auto data = JsonValue::ObjectValue();
                data.Set("entry", JsonValue::String(Win32Process::ToNarrow(entries->path().filename().wstring())));
                context->Emit("sdk.removal.cleanup.entry", std::move(data));
            }
        }
        if (error) return DeleteOutcome::Pending;
    }
    if (Interrupted()) return DeleteOutcome::Cancelled;
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    if (!SetFileInformationByHandle(held.value, FileDispositionInfo, &disposition, sizeof(disposition))) return DeleteOutcome::Pending;
    held.Close();
    return DeleteOutcome::Done;
}
SDKRemovalResult CleanupTransaction(const fs::path& receipt_path, const fs::path& configuration,
        const std::shared_ptr<ArtifactLease>& retained_lease = {}, RootHandle* retained_root = nullptr) {
    SDKRemovalResult result;
    result.status = SDKRemovalStatus::InvalidPath;
    result.message = "SDK cleanup requires an unambiguous owned v3 receipt and the exact committed configuration.";
    result.retained_receipt = receipt_path;
    result.cleanup_pending = true;
    try {
        if (receipt_path.empty() || !receipt_path.is_absolute() || configuration.empty() || !configuration.is_absolute() ||
            receipt_path != receipt_path.lexically_normal() || configuration != configuration.lexically_normal()) return result;
        RootHandle receipt;
        JsonValue record;
        if (!PinReceipt(receipt_path, receipt, record) || record.GetString("schema") != "openfruit.sdk-removal.v3" ||
            (record.GetString("phase") != "prepared" && record.GetString("phase") != "committed") ||
            !DigestText(record.GetString("configuration_before_sha256")) ||
            !DigestText(record.GetString("configuration_after_sha256")) ||
            record.GetString("configuration_before_sha256") == record.GetString("configuration_after_sha256")) return result;
        const auto original = fs::path(Win32Process::ToWide(record.GetString("original")));
        const auto quarantine = fs::path(Win32Process::ToWide(record.GetString("quarantine")));
        const auto version = Win32Process::ToWide(record.GetString("version"));
        const auto prefix = original.filename().wstring() + L".sdk-removal-";
        const auto qname = quarantine.filename().wstring();
        if (version.empty() || !original.is_absolute() || original == original.root_path() ||
            original != original.lexically_normal() || !SamePart(original.parent_path(), quarantine.parent_path()) ||
            qname.size() != prefix.size() + 32 || qname.rfind(prefix, 0) != 0 ||
            !std::all_of(qname.begin() + prefix.size(), qname.end(),
                [](wchar_t c) { return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'); }) ||
            !SamePart(receipt_path, fs::path(quarantine.wstring() + L".json")) ||
            !SamePart(configuration, fs::path(Win32Process::ToWide(record.GetString("configuration"))))) return result;
        result.retained_directory = quarantine;
        RootHandle parent;
        parent.value = CreateFileW(Extended(original.parent_path()).c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        BY_HANDLE_FILE_INFORMATION info{};
        if (!Ordinary(parent.value, true, info) || !UniqueReceipt(original, receipt_path)) return result;
        if (Interrupted()) { result.status = SDKRemovalStatus::Cancelled; result.message = "SDK cleanup cancelled; owned receipt is retained."; return result; }
        if (!ExistingLeaseMarker(original) || !ExistingLeaseMarker(configuration)) return result;
        const auto lease = retained_lease ? retained_lease : ArtifactLease::TryAcquire(original);
        const auto config_writer = ArtifactLease::TryAcquire(configuration);
        if (!lease || !config_writer) { result.status = SDKRemovalStatus::InUse; result.message = "SDK or configuration publication is active; cleanup retained."; return result; }
        RootHandle config_pin;
        std::string digest;
        if (!PinConfiguration(configuration, config_pin, digest) || digest != record.GetString("configuration_after_sha256")) {
            if (Interrupted()) { result.status = SDKRemovalStatus::Cancelled; result.message = "SDK cleanup cancelled while inspecting configuration; payload retained."; }
            return result;
        }
        const auto current = Config::Load(configuration.wstring(), false);
        if (current.ios_sdk_paths.count(version) || current.ios_sdk_version == version ||
            GetFileAttributesW(Extended(original).c_str()) != INVALID_FILE_ATTRIBUTES ||
            !SDKCatalog::RegistrationTargetMissing(original)) return result;
        // Registered and protected paths are compared physically: the receipt
        // may spell the same directories through an alias or a short name.
        std::error_code physical_error;
        const auto physical_original = fs::weakly_canonical(original, physical_error);
        if (physical_error) return result;
        const auto physical_quarantine = fs::weakly_canonical(quarantine, physical_error);
        if (physical_error) return result;
        const auto overlaps = [&](const fs::path& candidate) {
            if (candidate.empty()) return false;
            std::error_code error;
            const auto resolved = fs::weakly_canonical(candidate, error);
            return error || Overlap(original, resolved) || Overlap(quarantine, resolved) ||
                Overlap(physical_original, resolved) || Overlap(physical_quarantine, resolved);
        };
        if (overlaps(current.sdk_path) || overlaps(current.macos_sdk_path)) return result;
        for (const auto& [_, path] : current.ios_sdk_paths) if (overlaps(path)) return result;
        for (const auto& [_, path] : current.macos_sdk_paths) if (overlaps(path)) return result;
        const auto protected_inside = [&](const fs::path& path) {
            if (path.empty()) return false;
            std::error_code error;
            const auto resolved = fs::weakly_canonical(path, error);
            return error || Contains(original, resolved) || Contains(quarantine, resolved) ||
                Contains(physical_original, resolved) || Contains(physical_quarantine, resolved);
        };
        if (protected_inside(configuration) || protected_inside(current.OPENFRUIT_home) ||
            protected_inside(current.user_state_root) || protected_inside(current.xcode_path)) return result;
        if (GetFileAttributesW(Extended(quarantine).c_str()) != INVALID_FILE_ATTRIBUTES ||
            !SDKCatalog::RegistrationTargetMissing(quarantine)) {
            RootHandle owned_root;
            RootHandle& root = retained_root ? *retained_root : owned_root;
            if (!retained_root) root.value = CreateFileW(Extended(quarantine).c_str(), DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (root.value == INVALID_HANDLE_VALUE) {
                result.status = SDKRemovalStatus::InUse; result.message = "Detached SDK is in use; cleanup retained."; return result;
            }
            if (!Ordinary(root.value, true, info) || record.GetString("volume") != std::to_string(info.dwVolumeSerialNumber) ||
                record.GetString("file_index_high") != std::to_string(info.nFileIndexHigh) ||
                record.GetString("file_index_low") != std::to_string(info.nFileIndexLow)) return result;
            const auto deleted = DeleteHeld(root, quarantine);
            if (deleted != DeleteOutcome::Done) {
                result.status = deleted == DeleteOutcome::Cancelled ? SDKRemovalStatus::Cancelled : SDKRemovalStatus::RemovalFailed;
                result.message = deleted == DeleteOutcome::Cancelled ? "SDK cleanup cancelled after commit; retained payload can be retried." :
                    "SDK cleanup is blocked after commit; retained payload can be retried.";
                return result;
            }
            if (const auto context = CurrentOperationContext()) context->Emit("sdk.removal.cleanup.payload_removed");
        }
        if (Interrupted()) { result.status = SDKRemovalStatus::Cancelled; result.message = "SDK payload cleanup finished; receipt retirement was cancelled."; return result; }
        FILE_DISPOSITION_INFO disposition{};
        disposition.DeleteFile = TRUE;
        if (!SetFileInformationByHandle(receipt.value, FileDispositionInfo, &disposition, sizeof(disposition))) {
            result.status = SDKRemovalStatus::RemovalFailed; result.message = "SDK payload is absent; receipt retirement remains pending."; return result;
        }
        result.status = SDKRemovalStatus::Succeeded;
        result.cleanup_pending = false;
        result.retained_directory.clear(); result.retained_receipt.clear();
        result.message = "Committed SDK removal cleanup finished.";
    } catch (...) { result.status = SDKRemovalStatus::RemovalFailed; result.message = "SDK cleanup encountered an I/O failure; receipt and remaining payload are retained."; }
    return result;
}
// Only an exact, still-registered before-image authorizes restoration. No
// recovery path deletes an SDK or rewrites configuration, including committed
// receipts whose phase update was interrupted after Config::Save.
Recovery RecoverPrepared(const Config& snapshot, const std::wstring& version,
        const fs::path& configuration) {
    try {
        const auto registered = snapshot.ios_sdk_paths.find(version);
        if (registered == snapshot.ios_sdk_paths.end()) return Recovery::None;
        const auto target = fs::path(registered->second).lexically_normal();
        if (!target.is_absolute() || target == target.root_path() || target.filename().empty()) return Recovery::None;
        const bool target_missing = SDKCatalog::RegistrationTargetMissing(target);
        const auto unresolved = target_missing ? Recovery::Preserved : Recovery::PresentUnproven;
        RootHandle parent;
        parent.value = CreateFileW(Extended(target.parent_path()).c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        BY_HANDLE_FILE_INFORMATION parent_info{};
        if (!Ordinary(parent.value, true, parent_info)) {
            // A missing parent cannot contain a sibling quarantine. All other
            // uncertainty is preserved rather than treated as an empty scan.
            return SDKCatalog::RegistrationTargetMissing(target.parent_path()) ?
                Recovery::None : unresolved;
        }
        const auto prefix = target.filename().wstring() + L".sdk-removal-";
        WIN32_FIND_DATAW entry{};
        HANDLE search = FindFirstFileW(Extended(target.parent_path() / (prefix + L"*.json")).c_str(), &entry);
        if (search == INVALID_HANDLE_VALUE)
            return GetLastError() == ERROR_FILE_NOT_FOUND ? Recovery::None : unresolved;
        struct Search { HANDLE value; ~Search() { FindClose(value); } } find{search};
        std::vector<fs::path> receipts;
        std::size_t inspected = 0;
        do {
            if (++inspected > 256) return unresolved;
            const std::wstring name(entry.cFileName);
            // The namespace is case-insensitive on the supported filesystem.
            // Any unexpected matching name is uncertain evidence, not absence.
            if (name.size() != prefix.size() + 32 + 5 ||
                !SamePart(fs::path(name.substr(0, prefix.size())), fs::path(prefix)) ||
                !SamePart(fs::path(name.substr(name.size() - 5)), fs::path(L".json")) ||
                !std::all_of(name.begin() + prefix.size(), name.end() - 5,
                    [](wchar_t c) { return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'); }))
                return unresolved;
            receipts.push_back(target.parent_path() / name);
        } while (FindNextFileW(search, &entry));
        if (GetLastError() != ERROR_NO_MORE_FILES) return unresolved;
        if (receipts.empty()) return Recovery::None;
        if (receipts.size() != 1) return unresolved;
        const auto receipt_path = receipts.front();
        const auto quarantine = fs::path(receipt_path.wstring().substr(0, receipt_path.wstring().size() - 5));
        // A receipt alone cannot enroll an unrelated destination in recovery.
        const auto marker = fs::path(target.wstring() + L".import-lock");
        const auto marker_attributes = GetFileAttributesW(Extended(marker).c_str());
        if (marker_attributes == INVALID_FILE_ATTRIBUTES ||
            (marker_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) return unresolved;
        auto lease = ArtifactLease::TryAcquire(target);
        if (!lease) return unresolved;
        RootHandle receipt;
        receipt.value = CreateFileW(Extended(receipt_path).c_str(), GENERIC_READ | DELETE,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        BY_HANDLE_FILE_INFORMATION receipt_info{};
        LARGE_INTEGER size{};
        if (!Ordinary(receipt.value, false, receipt_info) || !GetFileSizeEx(receipt.value, &size) ||
            size.QuadPart <= 0 || size.QuadPart > 16384) return unresolved;
        std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0');
        DWORD count = 0;
        if (!ReadFile(receipt.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) ||
            count != bytes.size()) return unresolved;
        const auto record = JsonValue::Parse(bytes);
        if (!record || (record->GetString("schema") != "openfruit.sdk-removal.v2" &&
            record->GetString("schema") != "openfruit.sdk-removal.v3") ||
            record->GetString("phase") != "prepared" ||
            record->GetString("version") != Win32Process::ToNarrow(version) ||
            !SamePart(fs::path(Win32Process::ToWide(record->GetString("original"))).lexically_normal(), target) ||
            !SamePart(fs::path(Win32Process::ToWide(record->GetString("quarantine"))).lexically_normal(), quarantine) ||
            !SamePart(fs::path(Win32Process::ToWide(record->GetString("configuration"))).lexically_normal(),
                configuration.lexically_normal())) return unresolved;
        RootHandle config_pin;
        std::string before_digest;
        if (!PinConfiguration(configuration, config_pin, before_digest) ||
            before_digest != record->GetString("configuration_before_sha256")) return unresolved;
        // Config::Load reads the same ordinary, write/delete-pinned object.
        const auto current = Config::Load(configuration.wstring(), false);
        const auto current_registration = current.ios_sdk_paths.find(version);
        if (current_registration == current.ios_sdk_paths.end() ||
            !SamePart(fs::path(current_registration->second).lexically_normal(), target)) return unresolved;
        RootHandle payload;
        const auto payload_path = target_missing ? quarantine : target;
        payload.value = CreateFileW(Extended(payload_path).c_str(), DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        BY_HANDLE_FILE_INFORMATION info{};
        if (!Ordinary(payload.value, true, info) ||
            record->GetString("volume") != std::to_string(info.dwVolumeSerialNumber) ||
            record->GetString("file_index_high") != std::to_string(info.nFileIndexHigh) ||
            record->GetString("file_index_low") != std::to_string(info.nFileIndexLow) ||
            !SDKCatalog::HasUsableLayout(payload_path)) return unresolved;
        if (target_missing) {
            if (!SDKCatalog::RegistrationTargetMissing(target) || !RenameHeld(payload.value, target)) return unresolved;
        } else {
            // Death after receipt publication but before detach leaves this exact
            // original in place. Retire metadata only when nothing was moved.
            if (GetFileAttributesW(Extended(quarantine).c_str()) != INVALID_FILE_ATTRIBUTES ||
                !SDKCatalog::RegistrationTargetMissing(quarantine)) return unresolved;
        }
        FILE_DISPOSITION_INFO disposition{};
        disposition.DeleteFile = TRUE;
        // Failure to retire metadata never rolls back a restored payload, but
        // must not permit a second removal transaction to accumulate receipts.
        if (!SetFileInformationByHandle(receipt.value, FileDispositionInfo, &disposition, sizeof(disposition)))
            return Recovery::PresentUnproven;
        if (const auto context = CurrentOperationContext()) {
            auto data = JsonValue::ObjectValue();
            data.Set("status", JsonValue::String(target_missing ? "restored" : "prepared_not_detached"));
            context->Emit("sdk.removal.recovered", std::move(data));
        }
        return Recovery::Restored;
    } catch (...) { return Recovery::Preserved; }
}
}

SDKRemovalResult SDKRemoval::Remove(Config& snapshot, const std::wstring& version,
    const std::filesystem::path& configuration_path, bool remove_directory) {
    OperationSpan span("sdk.remove");
    SDKRemovalResult result;
    const char* status = "not_registered";
    const auto execute = [&]() {
        if (Interrupted()) {
            result.status = SDKRemovalStatus::Cancelled; status = "cancelled";
            result.message = "SDK removal cancelled before configuration or payload changes.";
            return;
        }
        const auto recovery = RecoverPrepared(snapshot, version, configuration_path);
        if (recovery == Recovery::Preserved || recovery == Recovery::PresentUnproven) {
            result.status = SDKRemovalStatus::RemovalFailed;
            status = "recovery_pending";
            result.message = "Interrupted SDK removal cannot be restored safely; retained payload and registration require inspection.";
            return;
        }
        const auto registered = snapshot.ios_sdk_paths.find(version);
        if (registered == snapshot.ios_sdk_paths.end()) {
            result.message = "Requested SDK version is not registered.";
            return;
        }
        const auto fail = [&](SDKRemovalStatus code, const char* name, const char* message) {
            result.status = code; status = name; result.message = message;
        };
        if (configuration_path.empty() || !configuration_path.is_absolute()) {
            fail(SDKRemovalStatus::PublicationFailed, "publication_failed", "SDK removal requires an absolute configuration path.");
            return;
        }
        const fs::path requested(registered->second);
        const auto target = requested.lexically_normal();
        if (!target.is_absolute() || target == target.root_path() || target.filename().empty()) {
            fail(SDKRemovalStatus::InvalidPath, "invalid_path", "Registered SDK removal requires an absolute non-root directory.");
            return;
        }
        std::error_code ec;
        const auto attributes = GetFileAttributesW(Extended(target).c_str());
        const bool absent = attributes == INVALID_FILE_ATTRIBUTES && SDKCatalog::RegistrationTargetMissing(target);
        if (attributes == INVALID_FILE_ATTRIBUTES && !absent) {
            fail(SDKRemovalStatus::RemovalFailed, "removal_failed", "SDK directory could not be inspected; registration is retained.");
            return;
        }
        if (!absent && (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))) {
            fail(SDKRemovalStatus::InvalidPath, "invalid_path", "SDK removal refuses non-directory or reparse roots.");
            return;
        }
        const auto canonical = fs::weakly_canonical(target, ec);
        if (ec || canonical.empty()) {
            fail(SDKRemovalStatus::InvalidPath, "invalid_path", "SDK removal could not establish directory identity.");
            return;
        }
        const auto protects = [&](const fs::path& path, bool either_direction) {
            if (path.empty()) return false;
            std::error_code error;
            const auto resolved = fs::weakly_canonical(path, error);
            return error || (either_direction ? Overlap(canonical, resolved) : Contains(canonical, resolved));
        };
        if (remove_directory && !absent) {
            bool unsafe = !SDKCatalog::HasUsableLayout(target) ||
                protects(configuration_path, false) || protects(snapshot.OPENFRUIT_home, false) ||
                protects(snapshot.user_state_root, false);
            for (const auto& [other_version, path] : snapshot.ios_sdk_paths)
                if (other_version != version && protects(path, true)) unsafe = true;
            for (const auto& [other_version, path] : snapshot.macos_sdk_paths)
                if (protects(path, true)) unsafe = true;
            if (protects(snapshot.macos_sdk_path, true) ||
                (snapshot.ios_sdk_version != version && protects(snapshot.sdk_path, true))) unsafe = true;
            if (unsafe) {
                fail(SDKRemovalStatus::InvalidPath, "invalid_path", "SDK removal refuses incomplete layouts, protected ancestors or overlapping registrations; unregister without deleting instead.");
                return;
            }
        }
        Config candidate;
        std::string candidate_before_digest;
        if (!CurrentMutationBase(snapshot, configuration_path, candidate, &candidate_before_digest)) {
            fail(SDKRemovalStatus::PublicationFailed, "publication_failed", "SDK registrations or protected roots changed on disk; stale removal snapshot is refused.");
            return;
        }
        if (remove_directory && !absent &&
            (protects(candidate.OPENFRUIT_home, false) || protects(candidate.user_state_root, false))) {
            fail(SDKRemovalStatus::InvalidPath, "invalid_path", "SDK removal refuses protected roots from the persisted configuration.");
            return;
        }
        candidate.ios_sdk_paths.erase(version);
        if (candidate.ios_sdk_version == version) {
            candidate.ios_sdk_version.clear();
            std::error_code selected_error;
            const auto selected = fs::weakly_canonical(candidate.sdk_path, selected_error);
            if (candidate.sdk_path == registered->second ||
                (!candidate.sdk_path.empty() && !selected_error && SamePart(canonical, selected)))
                candidate.sdk_path.clear();
        }
        std::shared_ptr<ArtifactLease> lease;
        RootHandle root;
        fs::path quarantine, receipt;
        JsonValue ownership = JsonValue::ObjectValue();
        if (!absent) {
            lease = ArtifactLease::TryAcquire(target);
            if (!lease) {
                fail(SDKRemovalStatus::InUse, "in_use", "SDK publication or removal is already active.");
                return;
            }
            // DELETE participates in Windows share checks. Retaining this handle
            // excludes new SDKUsage readers until commit/rollback, with no gap.
            root.value = CreateFileW(Extended(target).c_str(), DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (root.value == INVALID_HANDLE_VALUE) {
                const auto error = GetLastError();
                const bool busy = error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED;
                fail(busy ? SDKRemovalStatus::InUse : SDKRemovalStatus::RemovalFailed,
                    busy ? "in_use" : "removal_failed", "SDK directory is in use or unavailable; registration is retained.");
                return;
            }
            BY_HANDLE_FILE_INFORMATION info{};
            if (!GetFileInformationByHandle(root.value, &info) ||
                !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                fail(SDKRemovalStatus::InvalidPath, "invalid_path", "SDK root identity changed before removal.");
                return;
            }
            if (remove_directory) {
                quarantine = fs::path(target.wstring() + L".sdk-removal-" + Win32Process::ToWide(NewOperationId()));
                receipt = fs::path(quarantine.wstring() + L".json");
                if (GetFileAttributesW(Extended(quarantine).c_str()) != INVALID_FILE_ATTRIBUTES ||
                    GetFileAttributesW(Extended(receipt).c_str()) != INVALID_FILE_ATTRIBUTES) {
                    fail(SDKRemovalStatus::RemovalFailed, "removal_failed", "Private SDK removal destination already exists.");
                    return;
                }
                root.restore_path = target;
                RootHandle config_before;
                std::string config_digest;
                if (!PinConfiguration(configuration_path, config_before, config_digest) ||
                    config_digest != candidate_before_digest) {
                    fail(SDKRemovalStatus::PublicationFailed, "publication_failed", "SDK removal requires a stable ordinary configuration before-image.");
                    return;
                }
                const auto persisted = Config::Load(configuration_path.wstring(), false);
                const auto persisted_registration = persisted.ios_sdk_paths.find(version);
                if (persisted_registration == persisted.ios_sdk_paths.end() ||
                    !SamePart(fs::path(persisted_registration->second).lexically_normal(), target) ||
                    !SameSDKState(snapshot, persisted)) {
                    fail(SDKRemovalStatus::PublicationFailed, "publication_failed", "SDK registration changed on disk; stale removal snapshot is refused.");
                    return;
                }
                const auto after_digest = candidate.PublicationSha256();
                if (!after_digest) {
                    fail(SDKRemovalStatus::PublicationFailed, "publication_failed", "SDK removal configuration digest could not be computed.");
                    return;
                }
                ownership.Set("schema", JsonValue::String("openfruit.sdk-removal.v3"));
                ownership.Set("configuration_after_sha256", JsonValue::String(*after_digest));
                ownership.Set("configuration", JsonValue::String(Win32Process::ToNarrow(configuration_path.lexically_normal().wstring())));
                ownership.Set("configuration_before_sha256", JsonValue::String(config_digest));
                ownership.Set("version", JsonValue::String(Win32Process::ToNarrow(version)));
                ownership.Set("phase", JsonValue::String("prepared"));
                ownership.Set("original", JsonValue::String(Win32Process::ToNarrow(target.wstring())));
                ownership.Set("quarantine", JsonValue::String(Win32Process::ToNarrow(quarantine.wstring())));
                ownership.Set("volume", JsonValue::String(std::to_string(info.dwVolumeSerialNumber)));
                ownership.Set("file_index_high", JsonValue::String(std::to_string(info.nFileIndexHigh)));
                ownership.Set("file_index_low", JsonValue::String(std::to_string(info.nFileIndexLow)));
                if (!AtomicFile::Publish(receipt, ownership.Serialize())) {
                    fail(SDKRemovalStatus::RemovalFailed, "removal_failed", "SDK removal ownership could not be recorded; original payload is retained.");
                    return;
                }
                if (const auto context = span.Context()) context->Emit("sdk.removal.prepared", ownership);
                if (Interrupted()) {
                    fs::remove(receipt, ec);
                    fail(SDKRemovalStatus::Cancelled, "cancelled", "SDK removal cancelled before detachment; original payload and registration retained.");
                    return;
                }
                if (!RenameHeld(root.value, quarantine)) {
                    fs::remove(receipt, ec);
                    fail(SDKRemovalStatus::RemovalFailed, "removal_failed", "SDK could not be detached; original registration and payload are retained.");
                    return;
                }
                root.restore_on_exit = true;
                // A cooperative Config writer may now publish. Conditional Save
                // detects that conflict and restores this SDK before any delete.
                config_before.Close();
                if (const auto context = span.Context()) context->Emit("sdk.removal.detached", ownership);
            }
        }
        bool published = false;
        const bool cancelled_before_commit = Interrupted();
        if (!cancelled_before_commit)
            try { published = candidate.SaveIfUnchanged(configuration_path.wstring(), candidate_before_digest); } catch (...) {}
        if (!published) {
            root.restore_on_exit = false;
            if (!quarantine.empty() && !RenameHeld(root.value, target)) {
                result.retained_directory = quarantine;
                result.retained_receipt = receipt;
                fail(SDKRemovalStatus::RemovalFailed, "rollback_failed", "Configuration publication failed and SDK restoration was blocked; original payload is retained in the recorded quarantine.");
            } else {
                if (!receipt.empty()) fs::remove(receipt, ec);
                if (cancelled_before_commit)
                    fail(SDKRemovalStatus::Cancelled, "cancelled", "SDK removal cancelled before commit; original SDK and registration are retained.");
                else fail(SDKRemovalStatus::PublicationFailed, "publication_failed", "Configuration publication failed; original SDK and registration are retained.");
            }
            return;
        }
        root.restore_on_exit = false;
        if (!quarantine.empty())
            if (const auto context = span.Context()) context->Emit("sdk.removal.configuration_committed", ownership);
        snapshot = std::move(candidate);
        result.status = SDKRemovalStatus::Succeeded;
        status = "succeeded";
        result.message = remove_directory ? "SDK removed." : "SDK unregistered; directory retained.";
        if (!quarantine.empty()) {
            // Before-image recovery refuses a committed configuration even if
            // a crash leaves the receipt phase at prepared.
            result.cleanup_pending = true;
            result.retained_directory = quarantine;
            ownership.Set("phase", JsonValue::String("committed"));
            result.retained_receipt = receipt;
            if (AtomicFile::Publish(receipt, ownership.Serialize())) {
                const auto cleanup = CleanupTransaction(receipt, configuration_path, lease, &root);
                result.cleanup_pending = cleanup.cleanup_pending;
                result.retained_directory = cleanup.retained_directory;
                result.retained_receipt = cleanup.retained_receipt;
                if (result.cleanup_pending) result.message = "SDK unregistered; " + cleanup.message;
            }
            if (result.cleanup_pending && result.message == "SDK removed.")
                result.message = "SDK unregistered; detached files remain for deferred cleanup.";
        }
    };
    try { execute(); }
    catch (...) {
        result.status = SDKRemovalStatus::RemovalFailed;
        status = "removal_failed";
        result.message = "SDK removal encountered an I/O failure; retained quarantine receipts require inspection.";
    }
    auto data = JsonValue::ObjectValue();
    data.Set("status", JsonValue::String(status));
    data.Set("message", JsonValue::String(result.message));
    data.Set("cleanup_pending", JsonValue::Boolean(result.cleanup_pending));
    if (!result.retained_directory.empty())
        data.Set("retained_directory", JsonValue::String(result.retained_directory.string()));
    if (!result.retained_receipt.empty())
        data.Set("retained_receipt", JsonValue::String(Win32Process::ToNarrow(result.retained_receipt.wstring())));
    span.Complete(std::move(data), result.status == SDKRemovalStatus::Cancelled ? OperationOutcome::Cancelled :
        result.Succeeded() ? OperationOutcome::Succeeded : OperationOutcome::Failed);
    return result;
}
SDKRemovalResult SDKRemoval::Cleanup(const fs::path& receipt_path, const fs::path& configuration_path) {
    OperationSpan span("sdk.cleanup");
    auto result = CleanupTransaction(receipt_path, configuration_path);
    auto data = JsonValue::ObjectValue();
    data.Set("status", JsonValue::String(result.Succeeded() ? "succeeded" :
        result.status == SDKRemovalStatus::Cancelled ? "cancelled" : "cleanup_pending"));
    data.Set("message", JsonValue::String(result.message));
    data.Set("cleanup_pending", JsonValue::Boolean(result.cleanup_pending));
    if (!result.retained_directory.empty()) data.Set("retained_directory", JsonValue::String(Win32Process::ToNarrow(result.retained_directory.wstring())));
    if (!result.retained_receipt.empty()) data.Set("retained_receipt", JsonValue::String(Win32Process::ToNarrow(result.retained_receipt.wstring())));
    span.Complete(std::move(data), result.status == SDKRemovalStatus::Cancelled ? OperationOutcome::Cancelled :
        result.Succeeded() ? OperationOutcome::Succeeded : OperationOutcome::Failed);
    return result;
}
}
