#include "atomic_file.hpp"
#include "operation_events.hpp"
#include <windows.h>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
std::wstring ExtendedWin32Path(const fs::path& input) {
    std::error_code ec;
    fs::path absolute = input.is_absolute() ? input : fs::absolute(input, ec);
    if (ec) absolute = input;
    std::wstring value = absolute.lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\", 0) == 0) return value;
    if (value.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + value.substr(2);
    return L"\\\\?\\" + value;
}
} // namespace

bool AtomicFile::Publish(const fs::path& destination, const std::string& bytes) {
    std::error_code ec;
    const fs::path target = fs::absolute(destination, ec).lexically_normal();
    if (ec || target.filename().empty() || bytes.size() > MAXDWORD) return false;
    fs::create_directories(target.parent_path(), ec);
    if (ec) return false;
    const fs::path temporary = target.parent_path() / (".OPENFRUIT-credential-" + NewOperationId() + ".tmp");
    const std::wstring temp_w = ExtendedWin32Path(temporary);
    const std::wstring target_w = ExtendedWin32Path(target);
    HANDLE file = CreateFileW(temp_w.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr)
        && written == bytes.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (ok) {
        bool replaced = false;
        int delay_ms = 5;
        for (int attempt = 0; attempt < 6; ++attempt) {
            if (MoveFileExW(temp_w.c_str(), target_w.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                replaced = true;
                break;
            }
            const DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
                Sleep(delay_ms);
                delay_ms *= 2;
                continue;
            }
            break;
        }
        ok = replaced;
    }
    if (!ok) DeleteFileW(temp_w.c_str());
    return ok;
}
}
