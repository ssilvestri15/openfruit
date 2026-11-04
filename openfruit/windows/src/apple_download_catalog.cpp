#include "apple_download_catalog.hpp"
#include "http_transfer.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <algorithm>
#include <charconv>
#include <set>
#include <string_view>
namespace OpenFruit {
namespace {
constexpr std::string_view catalog_url =
    "https://developer.apple.com/services-account/QH65B2/downloadws/listDownloads.action";
constexpr std::string_view download_host = "https://download.developer.apple.com";
bool SafeText(std::string_view value, std::size_t maximum) {
    return !value.empty() && value.size() <= maximum &&
        std::all_of(value.begin(), value.end(), [](unsigned char ch) { return ch >= 32 && ch != 127; });
}
bool SafeRemotePath(std::string_view path) {
    if (path.size() < 6 || path.size() > 2048 || path.front() != '/' || path[1] == '/' ||
        !path.ends_with(".xip")) return false;
    for (const unsigned char ch : path)
        if (ch <= 32 || ch >= 127 || ch == '\\' || ch == '?' || ch == '#' || ch == '%') return false;
    std::size_t start = 1;
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto segment = path.substr(start, end == std::string_view::npos ? end : end - start);
        if (segment.empty() || segment == "." || segment == "..") return false;
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return true;
}
bool Size(const JsonValue* value, std::uint64_t& size) {
    if (!value || !value->IsNumber()) return false;
    const auto text = value->Serialize();
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), size);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() &&
        size > 0 && size <= 128ULL * 1024 * 1024 * 1024;
}
}
const AppleDownloadFile* AppleCatalogResult::SmallestXipForProduct(const std::string& product) const noexcept {
    const AppleDownloadFile* selected = nullptr;
    for (const auto& file : xip_files) {
        if (file.product_name != product) continue;
        if (!selected || file.bytes < selected->bytes ||
            (file.bytes == selected->bytes && file.remote_path < selected->remote_path)) selected = &file;
    }
    return selected;
}
AppleCatalogResult AppleDownloadCatalog::ParseUntrusted(const std::string& body) {
    AppleCatalogResult result;
    const auto fail = [&](const char* code) { result.diagnostic_code = code; return result; };
    if (body.empty() || body.size() > 8 * 1024 * 1024) return fail("catalog.response.size");
    const auto root = JsonValue::Parse(body);
    if (!root) {
        const auto first = body.find_first_not_of(" \t\r\n");
        if (body.size() >= 2 && static_cast<unsigned char>(body[0]) == 0x1f &&
            static_cast<unsigned char>(body[1]) == 0x8b) return fail("catalog.response.gzip_payload");
        if (first != std::string::npos && body[first] == '<') return fail("catalog.response.html_like");
        if (first != std::string::npos && body[first] == '{') return fail("catalog.response.json_parse");
        if (first != std::string::npos && body[first] == ')') return fail("catalog.response.xssi_prefix");
        return fail("catalog.response.non_json");
    }
    if (!root->IsObject()) return fail("catalog.response.json_root_type");
    if (!root->Get("resultCode") || !root->Get("resultCode")->IsNumber())
        return fail("catalog.response.result_code");
    if (root->Get("resultCode")->Int(-1) != 0) {
        result.diagnostic_code = "catalog.response.result_code." +
            std::to_string(root->Get("resultCode")->Int(-1));
        // Apple's developer services answer an expired or absent sign-in with
        // HTTP 200 and resultCode 1100 rather than an HTTP auth status.
        if (root->Get("resultCode")->Int(-1) == 1100) result.status = AppleCatalogStatus::Unauthorized;
        return result;
    }
    if (!root->Get("downloadHost")) return fail("catalog.response.download_host_missing");
    if (root->GetString("downloadHost") != download_host) return fail("catalog.response.download_host");
    const auto* downloads = root->Get("downloads");
    if (!downloads || !downloads->IsArray()) return fail("catalog.response.downloads");
    std::set<std::string> paths;
    for (const auto& item : downloads->ArrayItems()) {
        if (!item.IsObject()) return fail("catalog.response.download_entry");
        const auto id = item.GetString("id"), name = item.GetString("name");
        if (!SafeText(id, 64) || !SafeText(name, 256)) return fail("catalog.response.product_metadata");
        const auto* files = item.Get("files");
        if (!files || !files->IsArray()) return fail("catalog.response.files");
        for (const auto& file : files->ArrayItems()) {
            if (!file.IsObject()) return fail("catalog.response.file_entry");
            const auto* format = file.Get("fileFormat");
            if (!format || !format->IsObject()) return fail("catalog.response.file_format");
            if (format->GetString("extension") != ".xip") continue;
            const auto filename = file.GetString("filename"), path = file.GetString("remotePath");
            std::uint64_t bytes = 0;
            if (!SafeText(filename, 512) || !filename.ends_with(".xip") ||
                !SafeRemotePath(path) || !Size(file.Get("fileSize"), bytes) ||
                !paths.insert(path).second) return fail("catalog.response.xip_metadata");
            result.xip_files.push_back({id, name, filename, path,
                std::string(download_host) + path, bytes});
        }
    }
    result.status = AppleCatalogStatus::Succeeded;
    return result;
}
AppleCatalogResult AppleDownloadCatalog::Fetch(const AppleCookieJar& cookies,
    CancellationToken cancellation, std::chrono::steady_clock::time_point deadline) {
    OperationSpan span("sdk.apple_catalog.fetch");
    AppleCatalogResult result;
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto scoped_cookie = cookies.ForHttpsRequest("developer.apple.com",
        "/services-account/QH65B2/downloadws/listDownloads.action", static_cast<std::uint64_t>(now));
    if (scoped_cookie.empty()) result.status = AppleCatalogStatus::CredentialsUnavailable;
    else {
        JsonPostRequest request;
        request.url = Win32Process::ToWide(std::string(catalog_url));
        request.cancellation = cancellation; request.deadline = deadline;
        request.cookie_header = [&cookies, now](const std::wstring& host, const std::wstring& path) {
            return Win32Process::ToWide(cookies.ForHttpsRequest(Win32Process::ToNarrow(host),
                Win32Process::ToNarrow(path), static_cast<std::uint64_t>(now)));
        };
        auto response = HttpTransfer::PostJson(request);
        result.http_status = response.http_status;
        if (response.Succeeded()) {
            result = ParseUntrusted(response.body);
            result.http_status = response.http_status;
            result.origin_verified = result.Succeeded();
            if (result.Succeeded()) {
                auto scoped = cookies;
                bool valid = true;
                const auto root = JsonValue::Parse(response.body);
                const auto* embedded = root ? root->Get("httpResponseHeaders") : nullptr;
                if (embedded && !embedded->IsObject()) {
                    valid = false; result.diagnostic_code = "catalog.response.embedded_headers";
                }
                const auto* embedded_cookie = embedded ? embedded->Get("Set-Cookie") : nullptr;
                if (embedded_cookie) {
                    if (!embedded_cookie->IsString()) {
                        valid = false; result.diagnostic_code = "catalog.response.embedded_cookie_type";
                    } else if (!scoped.ImportHttpsResponseCookie("developer.apple.com",
                        "/services-account/QH65B2/downloadws/listDownloads.action",
                        embedded_cookie->StringValue(), static_cast<std::uint64_t>(now))) {
                        valid = false; result.diagnostic_code = "catalog.response.embedded_cookie_scope";
                    }
                }
                for (const auto& header : response.set_cookie_headers)
                    if (valid && !scoped.ImportHttpsResponseCookie("developer.apple.com",
                        "/services-account/QH65B2/downloadws/listDownloads.action",
                        Win32Process::ToNarrow(header), static_cast<std::uint64_t>(now))) {
                        valid = false; result.diagnostic_code = "catalog.response.http_cookie_scope";
                    }
                if (valid) result.download_cookies = std::move(scoped);
                else {
                    result.status = AppleCatalogStatus::InvalidResponse;
                    result.origin_verified = false;
                    result.xip_files.clear();
                }
            }
        } else if (response.http_status == 401 || response.http_status == 403)
            result.status = AppleCatalogStatus::Unauthorized;
        else if (response.status == TransferStatus::Cancelled) result.status = AppleCatalogStatus::Cancelled;
        else if (response.status == TransferStatus::TimedOut) result.status = AppleCatalogStatus::TimedOut;
        else result.status = AppleCatalogStatus::TransportFailure;
        SecureZeroMemory(response.body.data(), response.body.size());
    }
    SecureZeroMemory(scoped_cookie.data(), scoped_cookie.size());
    auto data = JsonValue::ObjectValue();
    data.Set("status", JsonValue::String(result.status == AppleCatalogStatus::Succeeded ? "succeeded" :
        result.status == AppleCatalogStatus::CredentialsUnavailable ? "credentials_unavailable" :
        result.status == AppleCatalogStatus::Unauthorized ? "unauthorized" :
        result.status == AppleCatalogStatus::InvalidResponse ? "invalid_response" :
        result.status == AppleCatalogStatus::Cancelled ? "cancelled" :
        result.status == AppleCatalogStatus::TimedOut ? "timed_out" : "transport_failure"));
    data.Set("xip_count", JsonValue::Number(std::to_string(result.xip_files.size())));
    data.Set("origin_verified", JsonValue::Boolean(result.origin_verified));
    data.Set("http_status", JsonValue::Number(std::to_string(result.http_status)));
    data.Set("diagnostic_code", JsonValue::String(result.diagnostic_code));
    span.Complete(std::move(data), result.status == AppleCatalogStatus::Cancelled ? OperationOutcome::Cancelled :
        result.Succeeded() ? OperationOutcome::Succeeded : OperationOutcome::Failed);
    return result;
}
}
