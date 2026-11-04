#include "utf8_path.hpp"
#include "operation_adapter.hpp"
#include "device_usbmux.hpp"
#include "device_deployer.hpp"
#include "ipa_verification.hpp"
#include "json_value.hpp"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>
#include <sstream>

namespace fs = std::filesystem;

namespace OpenFruit {

namespace {

std::wstring FullPipePath(const std::wstring& name) {
    if (name.rfind(L"\\\\.\\pipe\\", 0) == 0) return name;
    return L"\\\\.\\pipe\\" + name;
}

bool WriteFrame(HANDLE handle, const std::string& data, std::chrono::milliseconds timeout) {
    (void)timeout;
    uint32_t length = static_cast<uint32_t>(data.size());
    DWORD written = 0;
    if (!WriteFile(handle, &length, sizeof(length), &written, nullptr) || written != sizeof(length)) {
        return false;
    }
    size_t total = 0;
    while (total < data.size()) {
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(data.size() - total, 65536));
        if (!WriteFile(handle, data.data() + total, chunk, &written, nullptr) || written == 0) {
            return false;
        }
        total += written;
    }
    return true;
}

bool ReadFrame(HANDLE handle, std::string& data, size_t max_bytes, std::chrono::milliseconds timeout) {
    (void)timeout;
    uint32_t length = 0;
    DWORD read_bytes = 0;
    if (!ReadFile(handle, &length, sizeof(length), &read_bytes, nullptr) || read_bytes != sizeof(length)) {
        return false;
    }
    if (length > max_bytes) {
        return false;
    }
    data.resize(length);
    size_t total = 0;
    while (total < length) {
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(length - total, 65536));
        if (!ReadFile(handle, data.data() + total, chunk, &read_bytes, nullptr) || read_bytes == 0) {
            return false;
        }
        total += read_bytes;
    }
    return true;
}

} // namespace

class OperationAdapter::Impl {
public:
    BuildContext context_;
    OperationAdapterOptions options_;
    std::wstring pipe_name_;
    std::wstring full_path_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    HANDLE stop_event_ = INVALID_HANDLE_VALUE;
    HANDLE started_event_ = INVALID_HANDLE_VALUE;
    std::thread server_thread_;
    std::string last_error_;
    mutable std::mutex mutex_;

    Impl(BuildContext host_snapshot, OperationAdapterOptions options)
        : context_(std::move(host_snapshot)), options_(std::move(options)) {
        if (options_.pipe_name.empty()) {
            std::wostringstream ss;
            ss << L"openfruit-adapter-" << GetCurrentProcessId() << L"-" << GetTickCount64();
            pipe_name_ = ss.str();
        } else {
            pipe_name_ = options_.pipe_name;
        }
        full_path_ = FullPipePath(pipe_name_);
    }

    ~Impl() {
        Stop();
    }

    bool Start(std::string& error) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (running_.load()) return true;

        stop_requested_.store(false);
        stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (stop_event_ == INVALID_HANDLE_VALUE || !stop_event_) {
            error = "Failed to create adapter stop event";
            last_error_ = error;
            return false;
        }

        started_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        running_.store(true);
        server_thread_ = std::thread([this]() {
            RunServer();
        });

        if (started_event_ != INVALID_HANDLE_VALUE && started_event_) {
            WaitForSingleObject(started_event_, 5000);
            CloseHandle(started_event_);
            started_event_ = INVALID_HANDLE_VALUE;
        }
        return true;
    }

    void Stop() {
        if (!running_.load()) return;
        stop_requested_.store(true);
        if (stop_event_ != INVALID_HANDLE_VALUE && stop_event_) {
            SetEvent(stop_event_);
        }
        // Wake up any waiting pipe connection by doing a dummy client connection
        HANDLE dummy = CreateFileW(full_path_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (dummy != INVALID_HANDLE_VALUE) {
            CloseHandle(dummy);
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
        if (stop_event_ != INVALID_HANDLE_VALUE && stop_event_) {
            CloseHandle(stop_event_);
            stop_event_ = INVALID_HANDLE_VALUE;
        }
        running_.store(false);
    }

    void RunServer() {
        while (!stop_requested_.load()) {
            HANDLE hPipe = CreateNamedPipeW(
                full_path_.c_str(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                static_cast<DWORD>(options_.max_frame_bytes),
                static_cast<DWORD>(options_.max_frame_bytes),
                0,
                nullptr
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                last_error_ = "Failed to create named pipe instance: " + std::to_string(GetLastError());
                if (started_event_ != INVALID_HANDLE_VALUE && started_event_) {
                    SetEvent(started_event_);
                }
                break;
            }

            if (started_event_ != INVALID_HANDLE_VALUE && started_event_) {
                SetEvent(started_event_);
            }

            OVERLAPPED ov{};
            ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            BOOL connected = ConnectNamedPipe(hPipe, &ov);
            DWORD error = GetLastError();

            if (!connected && error == ERROR_IO_PENDING) {
                HANDLE events[2] = { ov.hEvent, stop_event_ };
                DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
                if (wait == WAIT_OBJECT_0 + 1 || stop_requested_.load()) {
                    CancelIo(hPipe);
                    CloseHandle(ov.hEvent);
                    CloseHandle(hPipe);
                    break;
                }
            } else if (!connected && error != ERROR_PIPE_CONNECTED) {
                CloseHandle(ov.hEvent);
                CloseHandle(hPipe);
                continue;
            }

            CloseHandle(ov.hEvent);

            if (stop_requested_.load()) {
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
                break;
            }

            // Process request
            std::string request_data;
            if (ReadFrame(hPipe, request_data, options_.max_frame_bytes, options_.io_timeout)) {
                auto req_json_opt = JsonValue::Parse(request_data);
                JsonValue response;
                if (req_json_opt) {
                    response = HandleRequest(*req_json_opt);
                } else {
                    response = JsonValue::ObjectValue();
                    response.Set("status", JsonValue::String("error"));
                    response.Set("error", JsonValue::String("Malformed JSON request frame"));
                }
                std::string resp_data = response.Serialize(false);
                WriteFrame(hPipe, resp_data, options_.io_timeout);
                FlushFileBuffers(hPipe);
            }

            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
    }

    JsonValue HandleRequest(const JsonValue& req) {
        std::string command = req.GetString("command");
        if (command.empty()) command = req.GetString("method");

        if (command == "ping" || command == "status") {
            auto resp = JsonValue::ObjectValue();
            resp.Set("status", JsonValue::String("ok"));
            resp.Set("running", JsonValue::Boolean(running_.load()));
            resp.Set("pipe_name", JsonValue::String(Win32Process::ToNarrow(pipe_name_)));
            return resp;
        }

        if (command == "devices") {
            auto devices = DeviceDeployer::ListDevices(context_.repository_root.wstring());
            auto resp = JsonValue::ObjectValue();
            resp.Set("status", JsonValue::String("ok"));
            auto arr = JsonValue::ArrayValue();
            for (const auto& dev : devices) {
                auto d = JsonValue::ObjectValue();
                d.Set("udid", JsonValue::String(dev.udid));
                d.Set("name", JsonValue::String(dev.name));
                d.Set("connection", JsonValue::String(dev.connection_type));
                arr.ArrayItems().push_back(std::move(d));
            }
            resp.Set("devices", std::move(arr));
            return resp;
        }

        if (command == "verify") {
            std::string archive_path_str = req.GetString("archive_path");
            if (archive_path_str.empty()) {
                auto err = JsonValue::ObjectValue();
                err.Set("status", JsonValue::String("error"));
                err.Set("error", JsonValue::String("Missing archive_path in verify request"));
                return err;
            }
            IpaVerificationRequest vreq;
            vreq.archive = Utf8Path(archive_path_str);
            auto vres = VerifyIpa(vreq);
            return vres.ToJson();
        }

        if (command == "build") {
            BuildRequest build_req;
            std::string proj_str = req.GetString("project_path");
            if (proj_str.empty()) {
                auto err = JsonValue::ObjectValue();
                err.Set("status", JsonValue::String("error"));
                err.Set("error", JsonValue::String("Missing project_path in build request"));
                return err;
            }
            build_req.project.path = fs::absolute(Utf8Path(proj_str));
            std::string mode_str = req.GetString("mode");
            build_req.mode = (mode_str == "package") ? BuildProductMode::UnsignedPackage : BuildProductMode::BuildAndSign;
            build_req.configuration = Win32Process::ToWide(req.GetString("configuration", "debug"));

            std::string scheme = req.GetString("scheme");
            if (!scheme.empty()) build_req.project.scheme = scheme;

            std::string target_id = req.GetString("target_id");
            if (!target_id.empty()) {
                ProjectTargetSelection sel;
                sel.uuid = target_id;
                build_req.project.target = sel;
            }

            std::string sdk_ver = req.GetString("sdk_version");
            if (!sdk_ver.empty()) build_req.sdk_version = Win32Process::ToWide(sdk_ver);

            std::string bundle_id = req.GetString("bundle_id");
            if (!bundle_id.empty()) build_req.bundle_id = Win32Process::ToWide(bundle_id);

            if (const auto* dep = req.Get("deploy")) {
                build_req.deploy = dep->Bool();
            }
            std::string udid = req.GetString("udid");
            if (!udid.empty()) build_req.device_udid = Win32Process::ToWide(udid);

            const auto result = ApplicationService::Build(build_req, context_);
            return result.ToJson();
        }

        auto unknown = JsonValue::ObjectValue();
        unknown.Set("status", JsonValue::String("error"));
        unknown.Set("error", JsonValue::String("Unknown command: " + command));
        return unknown;
    }
};

OperationAdapter::OperationAdapter(BuildContext host_snapshot, OperationAdapterOptions options)
    : impl_(std::make_unique<Impl>(std::move(host_snapshot), std::move(options))) {}

OperationAdapter::~OperationAdapter() = default;

bool OperationAdapter::Start(std::string& error) {
    return impl_->Start(error);
}

void OperationAdapter::Stop() {
    impl_->Stop();
}

bool OperationAdapter::IsRunning() const noexcept {
    return impl_->running_.load();
}

std::wstring OperationAdapter::PipeName() const {
    return impl_->pipe_name_;
}

std::string OperationAdapter::LastError() const {
    return impl_->last_error_;
}

JsonValue OperationAdapter::HandleRequest(const JsonValue& request) {
    return impl_->HandleRequest(request);
}

bool OperationAdapter::Call(
    const std::wstring& pipe_name,
    const JsonValue& request,
    JsonValue& response,
    std::string& error,
    std::chrono::milliseconds timeout,
    std::size_t max_frame_bytes
) {
    std::wstring full_path = FullPipePath(pipe_name);
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    HANDLE hPipe = INVALID_HANDLE_VALUE;
    while (std::chrono::steady_clock::now() < deadline) {
        hPipe = CreateFileW(
            full_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        if (hPipe != INVALID_HANDLE_VALUE) break;
        DWORD err = GetLastError();
        if (err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND) {
            error = "Cannot connect to named pipe: " + std::to_string(err);
            return false;
        }
        WaitNamedPipeW(full_path.c_str(), 50);
        Sleep(10);
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
        error = "Timeout connecting to named pipe adapter";
        return false;
    }

    std::string req_str = request.Serialize(false);
    if (!WriteFrame(hPipe, req_str, timeout)) {
        error = "Failed to write request frame to named pipe";
        CloseHandle(hPipe);
        return false;
    }

    std::string resp_str;
    if (!ReadFrame(hPipe, resp_str, max_frame_bytes, timeout)) {
        error = "Failed to read response frame from named pipe";
        CloseHandle(hPipe);
        return false;
    }

    CloseHandle(hPipe);

    auto parsed = JsonValue::Parse(resp_str, &error);
    if (!parsed) {
        error = "Failed to parse JSON response: " + error;
        return false;
    }
    response = std::move(*parsed);
    return true;
}

} // namespace OpenFruit
