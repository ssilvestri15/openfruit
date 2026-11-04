#pragma once
#include "transport.hpp"
#include "content_hash.hpp"
#include <filesystem>
#include <optional>

namespace OpenFruit::MacroHost {
// Hash the held directory identity, not textual casing, so aliases/junctions to
// the same managed home cannot accidentally create independent session pools.
inline std::optional<std::string> BudgetNamespace(const std::filesystem::path& managed_home) {
    Handle directory(CreateFileW(managed_home.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!directory.value || directory.value == INVALID_HANDLE_VALUE) return {};
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(directory.value, &info) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        !info.dwVolumeSerialNumber || (!info.nFileIndexHigh && !info.nFileIndexLow)) return {};
    return Sha256("OPENFRUIT-native-macro-managed-root-v1:" + std::to_string(info.dwVolumeSerialNumber) + ":" +
                  std::to_string(info.nFileIndexHigh) + ":" + std::to_string(info.nFileIndexLow));
}
enum class BudgetStatus { Acquired, Cancelled, InputClosed, Failed };
class SessionBudget {
public:
    SessionBudget() = default;
    SessionBudget(const SessionBudget&) = delete;
    SessionBudget& operator=(const SessionBudget&) = delete;
    ~SessionBudget() { Release(); }
    BudgetStatus Acquire(const std::string& root_identity, const Control& cancelled = {}, HANDLE input = nullptr) {
        if (owned_ || root_identity.size() != 64 || root_identity.find_first_not_of("0123456789abcdef") != std::string::npos)
            return BudgetStatus::Failed;
        abandoned_ = false;
        for (auto& slot : slots_) slot.Reset();
        for (unsigned slot = 0; slot < 2; ++slot) {
            const std::wstring name = L"Local\\OPENFRUITNativeMacroSlots-v1-" +
                std::wstring(root_identity.begin(), root_identity.end()) + L"-" + std::to_wstring(slot);
            slots_[slot].value = CreateMutexW(nullptr, FALSE, name.c_str());
            if (!slots_[slot].value) return BudgetStatus::Failed;
        }
        const HANDLE handles[] = {slots_[0].value, slots_[1].value};
        for (;;) {
            if (cancelled && cancelled()) return BudgetStatus::Cancelled;
            // Do not consume compiler bytes while queued. Physical closed-pipe
            // input with no remaining requests needs no original runtime slot.
            if (input && input != INVALID_HANDLE_VALUE && GetFileType(input) == FILE_TYPE_PIPE) {
                DWORD available = 0;
                if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) {
                    const auto error = GetLastError();
                    if (error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF) return BudgetStatus::InputClosed;
                    return BudgetStatus::Failed;
                }
            }
            const DWORD waited = WaitForMultipleObjects(2, handles, FALSE, 50);
            if (waited < WAIT_OBJECT_0 + 2) {
                owned_ = handles[waited - WAIT_OBJECT_0]; owner_ = GetCurrentThreadId(); return BudgetStatus::Acquired;
            }
            if (waited >= WAIT_ABANDONED_0 && waited < WAIT_ABANDONED_0 + 2) {
                owned_ = handles[waited - WAIT_ABANDONED_0]; owner_ = GetCurrentThreadId(); abandoned_ = true;
                return BudgetStatus::Acquired;
            }
            if (waited != WAIT_TIMEOUT) return BudgetStatus::Failed;
        }
    }
    bool AbandonedOwnerRecovered() const noexcept { return abandoned_; }
    bool Release() noexcept {
        if (!owned_) return true;
        if (owner_ != GetCurrentThreadId() || !ReleaseMutex(owned_)) return false;
        owned_ = nullptr; owner_ = 0; return true;
    }
private:
    Handle slots_[2];
    HANDLE owned_ = nullptr;
    DWORD owner_ = 0;
    bool abandoned_ = false;
};
}
