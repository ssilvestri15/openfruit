#include "http_transfer.hpp"
#include "content_hash.hpp"
#include "atomic_file.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include "openfruit_version.hpp"
#include <windows.h>
#include <winhttp.h>
#include <shlwapi.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <condition_variable>
#include <cwctype>
#include <exception>
#include <fstream>
#include <mutex>
#include <optional>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
struct InternetHandle {
    HINTERNET value = nullptr;
    ~InternetHandle() { if (value) WinHttpCloseHandle(value); }
};
struct FileHandle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~FileHandle() { Close(); }
    void Close() { if (value != INVALID_HANDLE_VALUE) { CloseHandle(value); value = INVALID_HANDLE_VALUE; } }
};
struct Url {
    std::wstring host, path;
    INTERNET_PORT port = 0;
    bool secure = false;
};
bool ParseUrl(const std::wstring& text, bool allow_loopback_http, Url& url) {
    if (text.size() > 8192) return false;
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength =
        parts.dwUserNameLength = parts.dwPasswordLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(text.c_str(), static_cast<DWORD>(text.size()), 0, &parts) ||
        parts.dwUserNameLength || parts.dwPasswordLength) return false;
    url.host.assign(parts.lpszHostName, parts.dwHostNameLength);
    url.path.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    if (url.path.empty()) url.path = L"/";
    url.path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    const auto fragment = url.path.find(L'#');
    if (fragment != std::wstring::npos) url.path.resize(fragment);
    url.port = parts.nPort;
    url.secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
    return url.secure || (parts.nScheme == INTERNET_SCHEME_HTTP && allow_loopback_http &&
        (url.host == L"127.0.0.1" || url.host == L"[::1]"));
}
class AsyncRequest {
public:
    HINTERNET value = nullptr;
    std::array<char, 64 * 1024> buffer{};
    std::wstring headers;
    DWORD count = 0, error = 0;
    TransferStatus interruption = TransferStatus::NetworkFailure;
    explicit AsyncRequest(HINTERNET handle, CancellationToken cancellation,
        std::chrono::steady_clock::time_point deadline)
        : value(handle), cancellation_(std::move(cancellation)), deadline_(deadline) {
        if (!value) return;
        DWORD_PTR context = reinterpret_cast<DWORD_PTR>(this);
        if (!WinHttpSetOption(value, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context))) return;
        attached_ = WinHttpSetStatusCallback(value, Callback,
            WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS | WINHTTP_CALLBACK_FLAG_HANDLES, 0) != WINHTTP_INVALID_STATUS_CALLBACK;
    }
    ~AsyncRequest() {
        if (value) {
            WinHttpCloseHandle(value);
            if (attached_) {
                std::unique_lock lock(mutex_);
                changed_.wait(lock, [&] { return closed_; }); // Preserve callback context/buffer until final notification.
            }
        }
        SecureZeroMemory(headers.data(), headers.size() * sizeof(wchar_t));
        SecureZeroMemory(buffer.data(), buffer.size());
    }
    bool Ready() const { return value && attached_; }
    DWORD Error() { std::lock_guard lock(mutex_); return error; }
    void Begin(DWORD expected) {
        std::lock_guard lock(mutex_);
        expected_ = expected; completed_ = false; error = 0; count = 0;
    }
    bool Wait() {
        std::unique_lock lock(mutex_);
        for (;;) {
            if (cancellation_.Requested()||(context_&&context_->CancellationRequested())) { interruption = TransferStatus::Cancelled; return false; }
            if (std::chrono::steady_clock::now() >= deadline_||(context_&&context_->DeadlineExceeded())) { interruption = TransferStatus::TimedOut; return false; }
            if (error) return false;
            if (completed_) return true;
            changed_.wait_for(lock, std::chrono::milliseconds(25));
        }
    }
private:
    CancellationToken cancellation_;
    OperationContextPtr context_=CurrentOperationContext();
    std::chrono::steady_clock::time_point deadline_;
    std::mutex mutex_;
    std::condition_variable changed_;
    DWORD expected_ = 0;
    bool completed_ = false, closed_ = false, attached_ = false;
    static void CALLBACK Callback(HINTERNET, DWORD_PTR context, DWORD status, LPVOID info, DWORD length) {
        auto* state = reinterpret_cast<AsyncRequest*>(context);
        if (!state) return;
        std::lock_guard lock(state->mutex_);
        if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) state->closed_ = true;
        else if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR && info)
            state->error = static_cast<WINHTTP_ASYNC_RESULT*>(info)->dwError;
        else if (status == state->expected_) {
            state->completed_ = true;
            if (status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) state->count = length;
        }
        state->changed_.notify_all();
    }
};
std::wstring Header(HINTERNET request, DWORD name) {
    DWORD size = 0;
    WinHttpQueryHeaders(request, name, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size > 32 * 1024) return {};
    std::wstring text(size / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(request, name, WINHTTP_HEADER_NAME_BY_INDEX, text.data(), &size, WINHTTP_NO_HEADER_INDEX)) return {};
    text.resize(size / sizeof(wchar_t));
    while (!text.empty() && text.back() == L'\0') text.pop_back();
    return text;
}
bool SetCookieHeaders(HINTERNET request, std::vector<std::wstring>& output) {
    DWORD next = 0;
    std::size_t total = 0;
    for (unsigned count = 0; count < 32; ++count) {
        DWORD query_index = next, size = 0;
        WinHttpQueryHeaders(request, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX,
            nullptr, &size, &query_index);
        if (GetLastError() == ERROR_WINHTTP_HEADER_NOT_FOUND) return true;
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !size || size > 16 * 1024 ||
            total + size > 64 * 1024) return false;
        std::wstring header(size / sizeof(wchar_t), L'\0');
        DWORD read_index = next;
        if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX,
            header.data(), &size, &read_index)) return false;
        header.resize(size / sizeof(wchar_t));
        while (!header.empty() && header.back() == L'\0') header.pop_back();
        if (header.empty() || read_index <= next) return false;
        total += size;
        output.push_back(std::move(header));
        next = read_index;
    }
    return false;
}
bool Number(const std::string& text, std::uint64_t& value) {
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
bool ValidHash(const std::string& hash) {
    return hash.size() == 64 && std::all_of(hash.begin(), hash.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}
const char* Status(TransferStatus value) {
    switch (value) {
    case TransferStatus::Succeeded: return "succeeded";
    case TransferStatus::InvalidRequest: return "invalid_request";
    case TransferStatus::Busy: return "busy";
    case TransferStatus::IoFailure: return "io_failure";
    case TransferStatus::NetworkFailure: return "network_failure";
    case TransferStatus::HttpFailure: return "http_failure";
    case TransferStatus::IntegrityFailure: return "integrity_failure";
    case TransferStatus::Cancelled: return "cancelled";
    case TransferStatus::TimedOut: return "timed_out";
    }
    return "invalid_request";
}
}
JsonPostResult::~JsonPostResult() {
    SecureZeroMemory(body.data(), body.size());
    SecureZeroMemory(redirect_url.data(), redirect_url.size()*sizeof(wchar_t));
    for (auto& header : set_cookie_headers)
        SecureZeroMemory(header.data(), header.size() * sizeof(wchar_t));
}
TransferResult HttpTransfer::RunTransfer(const TransferRequest& options, std::uint64_t expected_bytes, bool staging) {
    OperationSpan span(staging ? "artifact.stage" : "artifact.download");
    TransferResult result;
    auto execute = [&]() -> TransferStatus {
        Url initial;
        if (!options.destination.is_absolute() || options.destination.filename().empty() ||
            (!staging && !ValidHash(options.expected_sha256)) ||
            (staging && (!expected_bytes || expected_bytes > options.max_bytes)) || !options.max_bytes ||
            !ParseUrl(options.url, options.allow_loopback_http, initial))
            return TransferStatus::InvalidRequest;
        if (options.cancellation.Requested()) return TransferStatus::Cancelled;
        if (std::chrono::steady_clock::now() >= options.deadline) return TransferStatus::TimedOut;
        std::error_code io_error;
        fs::create_directories(options.destination.parent_path(), io_error);
        if (io_error) return TransferStatus::IoFailure;
        const fs::path partial(options.destination.wstring() + L".partial"), record(options.destination.wstring() + L".partial.json");
        for (const auto& path : {options.destination, partial, record,
                fs::path(options.destination.wstring() + L".transfer-lock")}) {
            const DWORD attributes = GetFileAttributesW(path.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return TransferStatus::IoFailure;
        }
        FileHandle lock;
        lock.value = CreateFileW((options.destination.wstring() + L".transfer-lock").c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (lock.value == INVALID_HANDLE_VALUE) {
            result.native_error = GetLastError();
            return result.native_error == ERROR_SHARING_VIOLATION ? TransferStatus::Busy : TransferStatus::IoFailure;
        }
        if (!staging && options.reuse_verified_destination) {
            // Inspect and hash one stable object. Never follow a late reparse
            // replacement or accept a size-only/receipt-only cache hit.
            const auto context = span.Context();
            const auto interrupted = [&]() -> std::optional<TransferStatus> {
                if (options.cancellation.Requested() || (context && context->CancellationRequested()))
                    return TransferStatus::Cancelled;
                if (std::chrono::steady_clock::now() >= options.deadline || (context && context->DeadlineExceeded()))
                    return TransferStatus::TimedOut;
                return {};
            };
            if (const auto status = interrupted()) return *status;
            FileHandle existing;
            existing.value = CreateFileW(options.destination.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (existing.value == INVALID_HANDLE_VALUE) {
                const auto error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                    result.native_error = error;
                    return TransferStatus::IoFailure;
                }
            } else {
                BY_HANDLE_FILE_INFORMATION info{};
                if (GetFileType(existing.value) != FILE_TYPE_DISK ||
                    !GetFileInformationByHandle(existing.value, &info) ||
                    (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
                    return TransferStatus::IoFailure;
                const auto size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
                if (size <= options.max_bytes) {
                    const auto actual = Sha256FileHandle(existing.value, options.cancellation, options.deadline);
                    if (const auto status = interrupted()) return *status;
                    if (!actual) return TransferStatus::IoFailure;
                    if (*actual == options.expected_sha256) {
                        result.bytes = size;
                        result.reused = true;
                        return TransferStatus::Succeeded;
                    }
                }
                // An oversized or mismatched final is kept until ordinary
                // verified atomic publication replaces it successfully.
            }
        }
        const auto identity = Sha256(Win32Process::ToNarrow(options.url));
        if (!identity) return TransferStatus::IoFailure;
        std::uint64_t offset = 0;
        std::uint64_t completed_hint = 0;
        std::wstring validator;
        if (fs::exists(record, io_error) && fs::file_size(record, io_error) < 32 * 1024 && !io_error) {
            std::ifstream input(record, std::ios::binary);
            const std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
            const auto parsed = JsonValue::Parse(text);
            if (parsed && parsed->GetString("source_identity") == *identity &&
                parsed->GetString("expected_sha256") == options.expected_sha256 &&
                parsed->GetString("expected_bytes") == std::to_string(expected_bytes)) {
                const auto size = fs::file_size(partial, io_error);
                if (!io_error && size <= options.max_bytes) offset = size;
                validator = Win32Process::ToWide(parsed->GetString("etag"));
                if (validator.size() > 1024 || validator.find_first_of(L"\r\n") != std::wstring::npos) validator.clear();
                Number(parsed->GetString("total_bytes"), completed_hint);
            }
        }
        if (offset && offset == completed_hint) {
            const auto actual = staging ? std::optional<std::string>{} :
                Sha256File(partial, options.cancellation, options.deadline);
            if (options.cancellation.Requested()) return TransferStatus::Cancelled;
            if (std::chrono::steady_clock::now() >= options.deadline) return TransferStatus::TimedOut;
            if (!staging && !actual) return TransferStatus::IoFailure;
            if ((staging && offset == expected_bytes) || (!staging && *actual == options.expected_sha256)) {
                result.bytes = offset; result.resumed = true;
                if (!MoveFileExW(partial.c_str(), options.destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                    return TransferStatus::IoFailure;
                fs::remove(record, io_error);
                return TransferStatus::Succeeded;
            }
            // A completed but corrupt partial is not a prefix to resume.
            fs::remove(partial, io_error); fs::remove(record, io_error);
            offset = 0; validator.clear();
        }
        InternetHandle session;
        session.value = WinHttpOpen(L"OpenFruit/" OPENFRUIT_VERSION_W L" native transfer", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
        if (!session.value || !WinHttpSetTimeouts(session.value, 30000, 30000, 30000, 30000)) {
            result.native_error = GetLastError(); return TransferStatus::NetworkFailure;
        }
        auto url_text = options.url;
        bool was_secure = initial.secure;
        for (unsigned int redirects = 0; redirects <= 8; ++redirects) {
            Url url;
            if (!ParseUrl(url_text, options.allow_loopback_http, url) || (was_secure && !url.secure))
                return TransferStatus::InvalidRequest;
            was_secure = url.secure;
            InternetHandle connection;
            connection.value = WinHttpConnect(session.value, url.host.c_str(), url.port, 0);
            AsyncRequest request(connection.value ? WinHttpOpenRequest(connection.value, L"GET", url.path.c_str(), nullptr,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, url.secure ? WINHTTP_FLAG_SECURE : 0) : nullptr,
                options.cancellation, options.deadline);
            if (!request.Ready()) { result.native_error = GetLastError(); return TransferStatus::NetworkFailure; }
            DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
            if (!WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)))
                return TransferStatus::NetworkFailure;
            auto& headers = request.headers;
            headers = L"Accept-Encoding: identity\r\n";
            if (offset) {
                headers += L"Range: bytes=" + std::to_wstring(offset) + L"-\r\n";
                if (!validator.empty()) headers += L"If-Range: " + validator + L"\r\n";
            }
            if (url.secure && options.cookie_header) {
                const auto cookie = options.cookie_header(url.host, url.path);
                if (cookie.size() > 16 * 1024 || cookie.find_first_of(L"\r\n") != std::wstring::npos) return TransferStatus::InvalidRequest;
                if (!cookie.empty()) headers += L"Cookie: " + cookie + L"\r\n";
            }
            request.Begin(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE);
            const bool sent = WinHttpSendRequest(request.value, headers.c_str(), static_cast<DWORD>(headers.size()),
                WINHTTP_NO_REQUEST_DATA, 0, 0, reinterpret_cast<DWORD_PTR>(&request)) != FALSE;
            if (!sent || !request.Wait()) {
                result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
                return request.interruption;
            }
            request.Begin(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE);
            if (!WinHttpReceiveResponse(request.value, nullptr) || !request.Wait()) {
                result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
                return request.interruption;
            }
            DWORD status = 0, size = sizeof(status);
            if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) return TransferStatus::NetworkFailure;
            result.http_status = status;
            if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                if (staging) return TransferStatus::HttpFailure; // Catalog URL remains the source identity.
                const auto location = Header(request.value, WINHTTP_QUERY_LOCATION);
                std::array<wchar_t, 8193> combined{};
                DWORD length = static_cast<DWORD>(combined.size());
                if (location.empty() || FAILED(UrlCombineW(url_text.c_str(), location.c_str(), combined.data(), &length, 0)))
                    return TransferStatus::HttpFailure;
                url_text.assign(combined.data(), length);
                continue;
            }
            if (status != 200 && status != 206) return TransferStatus::HttpFailure;
            std::uint64_t total = 0, content_size = 0;
            const auto content_length = Win32Process::ToNarrow(Header(request.value, WINHTTP_QUERY_CONTENT_LENGTH));
            if (!content_length.empty() && !Number(content_length, content_size)) return TransferStatus::HttpFailure;
            if (status == 206) {
                const auto range = Win32Process::ToNarrow(Header(request.value, WINHTTP_QUERY_CONTENT_RANGE));
                const auto dash = range.find('-'), slash = range.find('/');
                std::uint64_t first = 0, last = 0;
                if (!offset || !range.starts_with("bytes ") || dash == std::string::npos || slash == std::string::npos ||
                    dash >= slash || !Number(range.substr(6, dash - 6), first) || !Number(range.substr(dash + 1, slash - dash - 1), last) ||
                    !Number(range.substr(slash + 1), total) || first != offset || last < first || last >= total ||
                    (!content_length.empty() && content_size != last - first + 1)) return TransferStatus::HttpFailure;
                result.resumed = true;
            } else { offset = 0; total = content_size; }
            if (total > options.max_bytes || offset > options.max_bytes ||
                (staging && total != expected_bytes)) return TransferStatus::InvalidRequest;
            auto metadata = JsonValue::ObjectValue();
            metadata.Set("schema_version", JsonValue::Number("1"));
            metadata.Set("source_identity", JsonValue::String(*identity));
            metadata.Set("expected_sha256", JsonValue::String(options.expected_sha256));
            metadata.Set("expected_bytes", JsonValue::String(std::to_string(expected_bytes)));
            metadata.Set("total_bytes", JsonValue::String(std::to_string(total)));
            metadata.Set("etag", JsonValue::String(Win32Process::ToNarrow(Header(request.value, WINHTTP_QUERY_ETAG))));
            if (!AtomicFile::Publish(record, metadata.Serialize())) return TransferStatus::IoFailure;
            FileHandle output;
            output.value = CreateFileW(partial.c_str(), GENERIC_WRITE, 0, nullptr,
                offset ? OPEN_EXISTING : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            LARGE_INTEGER position{}; position.QuadPart = offset;
            if (output.value == INVALID_HANDLE_VALUE || !SetFilePointerEx(output.value, position, nullptr, FILE_BEGIN))
                return TransferStatus::IoFailure;
            result.bytes = offset;
            auto last_progress = std::chrono::steady_clock::time_point::min();
            for (;;) {
                request.Begin(WINHTTP_CALLBACK_STATUS_READ_COMPLETE);
                if (!WinHttpReadData(request.value, request.buffer.data(), static_cast<DWORD>(request.buffer.size()), nullptr) || !request.Wait()) {
                    result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
                    return request.interruption;
                }
                if (!request.count) break;
                if (request.count > options.max_bytes - result.bytes) return TransferStatus::InvalidRequest;
                DWORD written = 0;
                if (!WriteFile(output.value, request.buffer.data(), request.count, &written, nullptr) || written != request.count)
                    return TransferStatus::IoFailure;
                result.bytes += written;
                const auto now = std::chrono::steady_clock::now();
                if (last_progress == std::chrono::steady_clock::time_point::min() || now - last_progress >= std::chrono::milliseconds(100)) {
                    if (options.progress_callback) {
                        options.progress_callback(result.bytes, total);
                    }
                    auto progress = JsonValue::ObjectValue();
                    progress.Set("basis", JsonValue::String("bytes"));
                    progress.Set("completed", JsonValue::Number(std::to_string(result.bytes)));
                    if (total) progress.Set("planned", JsonValue::Number(std::to_string(total)));
                    if (span.Context()) span.Context()->Emit("task.progress", std::move(progress));
                    last_progress = now;
                }

            }
            if (!FlushFileBuffers(output.value)) return TransferStatus::IoFailure;
            output.Close();
            if ((total && result.bytes != total) || (!content_length.empty() && result.bytes - offset != content_size))
                return TransferStatus::NetworkFailure;
            const auto actual = staging ? std::optional<std::string>{} :
                Sha256File(partial, options.cancellation, options.deadline);
            if (options.cancellation.Requested()) return TransferStatus::Cancelled;
            if (std::chrono::steady_clock::now() >= options.deadline) return TransferStatus::TimedOut;
            if (!staging && !actual) return TransferStatus::IoFailure;
            if (!staging && *actual != options.expected_sha256) {
                fs::remove(partial, io_error); fs::remove(record, io_error);
                return TransferStatus::IntegrityFailure;
            }
            if (options.cancellation.Requested()) return TransferStatus::Cancelled;
            if (std::chrono::steady_clock::now() >= options.deadline) return TransferStatus::TimedOut;
            if (!MoveFileExW(partial.c_str(), options.destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                return TransferStatus::IoFailure;
            fs::remove(record, io_error);
            return TransferStatus::Succeeded;
        }
        return TransferStatus::HttpFailure;
    };
    // The exception text explains an I/O failure in the journal; it never
    // carries request bodies or credentials.
    std::string failure;
    try { result.status = execute(); }
    catch (const std::exception& error) { result.status = TransferStatus::IoFailure; failure = error.what(); }
    catch (...) { result.status = TransferStatus::IoFailure; }
    auto completion = JsonValue::ObjectValue();
    if (!failure.empty()) completion.Set("exception", JsonValue::String(failure));
    completion.Set("status", JsonValue::String(Status(result.status)));
    completion.Set("bytes", JsonValue::Number(std::to_string(result.bytes)));
    completion.Set("resumed", JsonValue::Boolean(result.resumed));
    completion.Set("reused", JsonValue::Boolean(result.reused));
    completion.Set("http_status", JsonValue::Number(std::to_string(result.http_status)));
    completion.Set("native_error", JsonValue::Number(std::to_string(result.native_error)));
    completion.Set("integrity_verified", JsonValue::Boolean(!staging && result.Succeeded()));
    span.Complete(std::move(completion), result.status == TransferStatus::Cancelled ? OperationOutcome::Cancelled :
        result.Succeeded() ? OperationOutcome::Succeeded : OperationOutcome::Failed);
    return result;
}
TransferResult HttpTransfer::Download(const TransferRequest& options) {
    return RunTransfer(options, 0, false);
}
StagedTransferResult HttpTransfer::Stage(const StagedTransferRequest& options) {
    StagedTransferResult result;
    if (!options.staging_directory.is_absolute() || !options.expected_bytes ||
        options.expected_bytes > 128ULL * 1024 * 1024 * 1024) {
        result.transfer.status = TransferStatus::InvalidRequest;
        return result;
    }
    const auto identity = Sha256(Win32Process::ToNarrow(options.url));
    if (!identity) { result.transfer.status = TransferStatus::InvalidRequest; return result; }
    result.path = options.staging_directory / (*identity + ".download");
    TransferRequest transfer;
    transfer.url = options.url;
    transfer.destination = result.path;
    transfer.max_bytes = options.expected_bytes;
    transfer.cancellation = options.cancellation;
    transfer.deadline = options.deadline;
    transfer.cookie_header = options.cookie_header;
    transfer.allow_loopback_http = options.allow_loopback_http;
    transfer.progress_callback = options.progress_callback;
    result.transfer = RunTransfer(transfer, options.expected_bytes, true);
    if (!result.Succeeded()) result.path.clear();
    return result;
}
static JsonPostResult RequestText(const JsonPostRequest& options, bool get_html, bool get_bytes = false) {
    const bool get = get_html || get_bytes;
    OperationSpan span(get_bytes ? "artifact.http_get_bytes" : get_html ? "catalog.http_get" : "catalog.http_post");
    JsonPostResult result;
    auto execute = [&]() -> TransferStatus {
        Url url;
        if (!ParseUrl(options.url, options.allow_loopback_http, url) ||
            !options.max_bytes || options.max_bytes > 64ULL * 1024 * 1024 ||
            options.body.size() > 64 * 1024 || (get_bytes && options.cookie_header)) return TransferStatus::InvalidRequest;
        if (options.cancellation.Requested()) return TransferStatus::Cancelled;
        if (std::chrono::steady_clock::now() >= options.deadline) return TransferStatus::TimedOut;
        InternetHandle session;
        session.value = WinHttpOpen(L"OpenFruit/" OPENFRUIT_VERSION_W L" native catalog", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
        if (!session.value || !WinHttpSetTimeouts(session.value, 30000, 30000, 30000, 30000)) {
            result.native_error = GetLastError(); return TransferStatus::NetworkFailure;
        }
        InternetHandle connection;
        connection.value = WinHttpConnect(session.value, url.host.c_str(), url.port, 0);
        AsyncRequest request(connection.value ? WinHttpOpenRequest(connection.value, get ? L"GET" : L"POST", url.path.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            url.secure ? WINHTTP_FLAG_SECURE : 0) : nullptr, options.cancellation, options.deadline);
        if (!request.Ready()) { result.native_error = GetLastError(); return TransferStatus::NetworkFailure; }
        DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
        if (!WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)))
            return TransferStatus::NetworkFailure;
        if (!get_bytes) {
            DWORD decompression = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
            if (!WinHttpSetOption(request.value, WINHTTP_OPTION_DECOMPRESSION,
                &decompression, sizeof(decompression))) return TransferStatus::NetworkFailure;
        }
        request.headers = get_bytes ? L"Accept: */*\r\nAccept-Encoding: identity\r\n" : get_html ? L"Accept: text/html\r\n" :
            L"Accept: application/json\r\nContent-Type: application/json\r\n";
        if (url.secure && options.cookie_header) {
            const auto cookie = options.cookie_header(url.host, url.path);
            if (cookie.size() > 16 * 1024 || cookie.find_first_of(L"\r\n") != std::wstring::npos)
                return TransferStatus::InvalidRequest;
            if (!cookie.empty()) request.headers += L"Cookie: " + cookie + L"\r\n";
        }
        request.Begin(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE);
        const DWORD body_size = get ? 0 : static_cast<DWORD>(options.body.size());
        if (!WinHttpSendRequest(request.value, request.headers.c_str(), static_cast<DWORD>(request.headers.size()),
            body_size ? const_cast<char*>(options.body.data()) : WINHTTP_NO_REQUEST_DATA,
            body_size, body_size, reinterpret_cast<DWORD_PTR>(&request)) || !request.Wait()) {
            result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
            return request.interruption;
        }
        request.Begin(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE);
        if (!WinHttpReceiveResponse(request.value, nullptr) || !request.Wait()) {
            result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
            return request.interruption;
        }
        DWORD status = 0, status_size = sizeof(status);
        if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
            return TransferStatus::NetworkFailure;
        result.http_status = status;
        if (status != 200) {
            if (get_bytes && (status==301||status==302||status==303||status==307||status==308)) {
                auto location=Header(request.value,WINHTTP_QUERY_LOCATION);
                if(location.size()<=4096&&location.find_first_of(L"\r\n") == std::wstring::npos)result.redirect_url=std::move(location);
            }
            return TransferStatus::HttpFailure; // Caller must validate any redirect destination.
        }
        if (!get_bytes && !SetCookieHeaders(request.value, result.set_cookie_headers)) return TransferStatus::HttpFailure;
        auto type = Header(request.value, WINHTTP_QUERY_CONTENT_TYPE);
        std::transform(type.begin(), type.end(), type.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
        const std::wstring expected_type = get_html ? L"text/html" : L"application/json";
        if (!get_bytes && (!type.starts_with(expected_type) || (type.size() > expected_type.size() &&
            type[expected_type.size()] != L';' && type[expected_type.size()] != L' ')))
            return TransferStatus::HttpFailure;
        if (get_bytes) {
            auto encoding = Header(request.value, WINHTTP_QUERY_CONTENT_ENCODING);
            std::transform(encoding.begin(), encoding.end(), encoding.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
            if (!encoding.empty() && encoding != L"identity") return TransferStatus::IntegrityFailure;
        }
        std::uint64_t advertised = 0;
        const auto length = Win32Process::ToNarrow(Header(request.value, WINHTTP_QUERY_CONTENT_LENGTH));
        if (!length.empty() && (!Number(length, advertised) || advertised > options.max_bytes))
            return TransferStatus::HttpFailure;
        for (;;) {
            request.Begin(WINHTTP_CALLBACK_STATUS_READ_COMPLETE);
            if (!WinHttpReadData(request.value, request.buffer.data(), static_cast<DWORD>(request.buffer.size()), nullptr) ||
                !request.Wait()) {
                result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
                return request.interruption;
            }
            if (!request.count) break;
            if (request.count > options.max_bytes - result.body.size()) return TransferStatus::InvalidRequest;
            result.body.append(request.buffer.data(), request.count);
        }
        // WinHTTP removes the compressed entity's Content-Length while
        // decompressing; the decoded body remains bounded by max_bytes above.
        return !length.empty() && result.body.size() != advertised ? TransferStatus::NetworkFailure : TransferStatus::Succeeded;
    };
    // The exception text explains an I/O failure in the journal; it never
    // carries request bodies or credentials.
    std::string failure;
    try { result.status = execute(); }
    catch (const std::exception& error) { result.status = TransferStatus::IoFailure; failure = error.what(); }
    catch (...) { result.status = TransferStatus::IoFailure; }
    if (!result.Succeeded()) {
        std::fill(result.body.begin(), result.body.end(), '\0'); result.body.clear();
    }
    auto completion = JsonValue::ObjectValue();
    if (!failure.empty()) completion.Set("exception", JsonValue::String(failure));
    completion.Set("status", JsonValue::String(Status(result.status)));
    completion.Set("bytes", JsonValue::Number(std::to_string(result.body.size())));
    completion.Set("http_status", JsonValue::Number(std::to_string(result.http_status)));
    completion.Set("native_error", JsonValue::Number(std::to_string(result.native_error)));
    span.Complete(std::move(completion), result.status == TransferStatus::Cancelled ? OperationOutcome::Cancelled :
        result.Succeeded() ? OperationOutcome::Succeeded : OperationOutcome::Failed);
    return result;
}
RangeTransferResult HttpTransfer::ReadRange(const RangeTransferRequest& options) {
    OperationSpan span("artifact.read_range");
    RangeTransferResult result;
    const auto strong_etag = [](const std::wstring& tag) {
        if (tag.size() < 2 || tag.size() > 4096 || tag.front() != L'"' || tag.back() != L'"') return false;
        return std::all_of(tag.begin() + 1, tag.end() - 1, [](wchar_t ch) {
            return ch == 0x21 || (ch >= 0x23 && ch <= 0x7e) || (ch >= 0x80 && ch <= 0xff);
        });
    };
    auto execute = [&]() -> TransferStatus {
        Url url;
        if (!ParseUrl(options.url, options.allow_loopback_http, url) ||
            !options.bytes || options.bytes > 64ULL * 1024 * 1024 ||
            options.offset > UINT64_MAX - (options.bytes - 1) ||
            (!options.expected_etag.empty() && !strong_etag(options.expected_etag)))
            return TransferStatus::InvalidRequest;
        const auto end = options.offset + options.bytes - 1;
        if (options.expected_total && end >= options.expected_total) return TransferStatus::InvalidRequest;
        if (options.cancellation.Requested()) return TransferStatus::Cancelled;
        if (std::chrono::steady_clock::now() >= options.deadline) return TransferStatus::TimedOut;
        InternetHandle session;
        session.value = WinHttpOpen(L"OpenFruit/" OPENFRUIT_VERSION_W L" native range", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
        if (!session.value || !WinHttpSetTimeouts(session.value, 30000, 30000, 30000, 30000)) {
            result.native_error = GetLastError(); return TransferStatus::NetworkFailure;
        }
        InternetHandle connection;
        connection.value = WinHttpConnect(session.value, url.host.c_str(), url.port, 0);
        AsyncRequest request(connection.value ? WinHttpOpenRequest(connection.value, L"GET", url.path.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            url.secure ? WINHTTP_FLAG_SECURE : 0) : nullptr, options.cancellation, options.deadline);
        if (!request.Ready()) { result.native_error = GetLastError(); return TransferStatus::NetworkFailure; }
        DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
        if (!WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)))
            return TransferStatus::NetworkFailure;
        request.headers = L"Accept-Encoding: identity\r\nRange: bytes=" + std::to_wstring(options.offset) +
            L"-" + std::to_wstring(end) + L"\r\n";
        if (!options.expected_etag.empty()) request.headers += L"If-Match: " + options.expected_etag + L"\r\n";
        request.Begin(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE);
        if (!WinHttpSendRequest(request.value, request.headers.c_str(), static_cast<DWORD>(request.headers.size()),
            WINHTTP_NO_REQUEST_DATA, 0, 0, reinterpret_cast<DWORD_PTR>(&request)) || !request.Wait()) {
            result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
            return request.interruption;
        }
        request.Begin(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE);
        if (!WinHttpReceiveResponse(request.value, nullptr) || !request.Wait()) {
            result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
            return request.interruption;
        }
        DWORD status = 0, status_size = sizeof(status);
        if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
            return TransferStatus::NetworkFailure;
        result.http_status = status;
        if (status != 206) return TransferStatus::HttpFailure;
        const auto range = Win32Process::ToNarrow(Header(request.value, WINHTTP_QUERY_CONTENT_RANGE));
        const auto prefix = "bytes " + std::to_string(options.offset) + "-" + std::to_string(end) + "/";
        if (!range.starts_with(prefix) || !Number(range.substr(prefix.size()), result.total) || result.total <= end ||
            (options.expected_total && result.total != options.expected_total)) return TransferStatus::IntegrityFailure;
        result.etag = Header(request.value, WINHTTP_QUERY_ETAG);
        if (!strong_etag(result.etag) || (!options.expected_etag.empty() && result.etag != options.expected_etag))
            return TransferStatus::IntegrityFailure;
        auto encoding = Header(request.value, WINHTTP_QUERY_CONTENT_ENCODING);
        std::transform(encoding.begin(), encoding.end(), encoding.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
        if (!encoding.empty() && encoding != L"identity") return TransferStatus::IntegrityFailure;
        std::uint64_t advertised = 0;
        if (!Number(Win32Process::ToNarrow(Header(request.value, WINHTTP_QUERY_CONTENT_LENGTH)), advertised) ||
            advertised != options.bytes) return TransferStatus::IntegrityFailure;
        result.body.reserve(static_cast<std::size_t>(options.bytes));
        for (;;) {
            request.Begin(WINHTTP_CALLBACK_STATUS_READ_COMPLETE);
            if (!WinHttpReadData(request.value, request.buffer.data(), static_cast<DWORD>(request.buffer.size()), nullptr) ||
                !request.Wait()) {
                result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
                return request.interruption;
            }
            if (!request.count) break;
            if (request.count > options.bytes - result.body.size()) return TransferStatus::IntegrityFailure;
            result.body.append(request.buffer.data(), request.count);
        }
        return result.body.size() == options.bytes ? TransferStatus::Succeeded : TransferStatus::IntegrityFailure;
    };
    // The exception text explains an I/O failure in the journal; it never
    // carries request bodies or credentials.
    std::string failure;
    try { result.status = execute(); }
    catch (const std::exception& error) { result.status = TransferStatus::IoFailure; failure = error.what(); }
    catch (...) { result.status = TransferStatus::IoFailure; }
    if (!result.Succeeded()) { result.body.clear(); result.etag.clear(); result.total = 0; }
    auto completion = JsonValue::ObjectValue();
    if (!failure.empty()) completion.Set("exception", JsonValue::String(failure));
    completion.Set("status", JsonValue::String(Status(result.status)));
    completion.Set("integrity_verified", JsonValue::Boolean(false)); // Range consistency does not authenticate Apple content.
    span.Complete(std::move(completion), result.status == TransferStatus::Cancelled ? OperationOutcome::Cancelled :
        result.Succeeded() ? OperationOutcome::Succeeded : OperationOutcome::Failed);
    return result;
}
JsonPostResult HttpTransfer::PostJson(const JsonPostRequest& options) { return RequestText(options, false); }
JsonPostResult HttpTransfer::GetText(const JsonPostRequest& options) { return RequestText(options, true); }
JsonPostResult HttpTransfer::GetBytes(const JsonPostRequest& options) { return RequestText(options, false, true); }
JsonPostResult HttpTransfer::GetJson(const JsonPostRequest& options) {
    OperationSpan span("catalog.http_get_json");
    JsonPostResult result;
    auto execute = [&]() -> TransferStatus {
        Url url;
        if (!ParseUrl(options.url, options.allow_loopback_http, url) ||
            !options.max_bytes || options.max_bytes > 64ULL * 1024 * 1024) return TransferStatus::InvalidRequest;
        if (options.cancellation.Requested()) return TransferStatus::Cancelled;
        if (std::chrono::steady_clock::now() >= options.deadline) return TransferStatus::TimedOut;
        InternetHandle session;
        session.value = WinHttpOpen(L"OpenFruit/" OPENFRUIT_VERSION_W L" native client", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
        if (!session.value || !WinHttpSetTimeouts(session.value, 30000, 30000, 30000, 30000)) {
            result.native_error = GetLastError(); return TransferStatus::NetworkFailure;
        }
        InternetHandle connection;
        connection.value = WinHttpConnect(session.value, url.host.c_str(), url.port, 0);
        AsyncRequest request(connection.value ? WinHttpOpenRequest(connection.value, L"GET", url.path.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            url.secure ? WINHTTP_FLAG_SECURE : 0) : nullptr, options.cancellation, options.deadline);
        if (!request.Ready()) { result.native_error = GetLastError(); return TransferStatus::NetworkFailure; }
        DWORD disabled = WINHTTP_DISABLE_AUTHENTICATION;
        WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled));
        DWORD decompression = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
        WinHttpSetOption(request.value, WINHTTP_OPTION_DECOMPRESSION, &decompression, sizeof(decompression));
        request.headers = L"Accept: application/vnd.github+json, application/json\r\nUser-Agent: OpenFruit/" OPENFRUIT_VERSION_W L"\r\n";
        request.Begin(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE);
        if (!WinHttpSendRequest(request.value, request.headers.c_str(), static_cast<DWORD>(request.headers.size()),
            WINHTTP_NO_REQUEST_DATA, 0, 0, reinterpret_cast<DWORD_PTR>(&request)) || !request.Wait()) {
            result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
            return request.interruption;
        }
        request.Begin(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE);
        if (!WinHttpReceiveResponse(request.value, nullptr) || !request.Wait()) {
            result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
            return request.interruption;
        }
        DWORD status = 0, status_size = sizeof(status);
        if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
            return TransferStatus::NetworkFailure;
        result.http_status = status;
        if (status != 200) return TransferStatus::HttpFailure;
        for (;;) {
            request.Begin(WINHTTP_CALLBACK_STATUS_READ_COMPLETE);
            if (!WinHttpReadData(request.value, request.buffer.data(), static_cast<DWORD>(request.buffer.size()), nullptr) ||
                !request.Wait()) {
                result.native_error = request.Error(); if (!result.native_error) result.native_error = GetLastError();
                return request.interruption;
            }
            if (!request.count) break;
            if (request.count > options.max_bytes - result.body.size()) return TransferStatus::InvalidRequest;
            result.body.append(request.buffer.data(), request.count);
        }
        return TransferStatus::Succeeded;
    };
    try { result.status = execute(); }
    catch (...) { result.status = TransferStatus::IoFailure; }
    if (!result.Succeeded()) {
        result.body.clear();
    }
    return result;
}
}
