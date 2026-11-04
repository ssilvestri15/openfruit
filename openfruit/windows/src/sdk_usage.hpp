#pragma once
#include "operation_events.hpp"
#include <filesystem>
namespace OpenFruit {
// Holds the existing SDK directory without FILE_SHARE_DELETE. Concurrent
// readers/builds are allowed; directory rename/replacement is denied by Windows.
// This does not protect arbitrary child-file writes or noncooperating tree deletion.
class SDKUsage {
public:
    explicit SDKUsage(const std::filesystem::path&);
    ~SDKUsage();
    bool Held() const noexcept { return handle_ != nullptr; }
    unsigned long NativeError() const noexcept { return native_error_; }
    SDKUsage(const SDKUsage&) = delete;
    SDKUsage& operator=(const SDKUsage&) = delete;
private:
    void* handle_ = nullptr;
    unsigned long native_error_ = 0;
    OperationContextPtr context_;
};
}
