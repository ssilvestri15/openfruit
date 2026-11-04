#include "sdk_usage.hpp"
#include <windows.h>
namespace OpenFruit {
SDKUsage::SDKUsage(const std::filesystem::path& sdk) : context_(CurrentOperationContext()) {
    std::error_code error;
    const auto absolute = std::filesystem::absolute(sdk, error).lexically_normal();
    if (sdk.empty() || error) native_error_ = ERROR_INVALID_NAME;
    else {
        auto path = absolute.wstring();
        if (path.rfind(L"\\\\?\\", 0) != 0)
            path = path.rfind(L"\\\\", 0) == 0 ? L"\\\\?\\UNC\\" + path.substr(2) : L"\\\\?\\" + path;
        // Attribute-only handles do not participate in Windows sharing checks.
        HANDLE directory = CreateFileW(path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (directory == INVALID_HANDLE_VALUE) native_error_ = GetLastError();
        else {
            BY_HANDLE_FILE_INFORMATION information{};
            if (!GetFileInformationByHandle(directory, &information)) native_error_ = GetLastError();
            else if (!(information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) native_error_ = ERROR_DIRECTORY;
            else handle_ = directory;
            if (!handle_) CloseHandle(directory);
        }
    }
    if (context_) {
        auto data = JsonValue::ObjectValue();
        data.Set("native_error", JsonValue::Number(std::to_string(native_error_)));
        data.Set("status", JsonValue::String(Held() ? "held" : "unavailable"));
        context_->Emit("sdk.usage.acquired", std::move(data), Held() ? "info" : "error");
    }
}
SDKUsage::~SDKUsage() {
    if (handle_) {
        CloseHandle(handle_);
        if (context_) context_->Emit("sdk.usage.released");
    }
}
}
