#include "browser_apple_auth.hpp"
#include "apple_cookies.hpp"
#include "apple_download_catalog.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "openfruit_version.hpp"
#include <windows.h>
#include <winhttp.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <thread>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {

struct BrowserChoice { fs::path executable; std::string name; bool is_default = false; };

std::wstring RegistryString(HKEY root, const wchar_t* key, const wchar_t* name) {
    DWORD type = 0, size = 0;
    if (RegGetValueW(root, key, name, RRF_RT_REG_SZ, &type, nullptr, &size) != ERROR_SUCCESS ||
        size < sizeof(wchar_t) || size > 4096) return {};
    std::wstring value(size / sizeof(wchar_t), L'\0');
    if (RegGetValueW(root, key, name, RRF_RT_REG_SZ, &type, value.data(), &size) != ERROR_SUCCESS) return {};
    value.resize(wcsnlen_s(value.c_str(), value.size()));
    return value;
}

std::optional<BrowserChoice> ChooseBrowser() {
    const auto default_id = RegistryString(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice", L"ProgId");
    const auto program_files = [](const wchar_t* variable) -> fs::path {
        wchar_t value[32768];
        const DWORD length = GetEnvironmentVariableW(variable, value, 32768);
        return length && length < 32768 ? fs::path(value) : fs::path{};
    };
    const auto chrome = program_files(L"ProgramFiles") / "Google" / "Chrome" / "Application" / "chrome.exe";
    const auto edge = program_files(L"ProgramFiles(x86)") / "Microsoft" / "Edge" / "Application" / "msedge.exe";
    const auto edge_64 = program_files(L"ProgramFiles") / "Microsoft" / "Edge" / "Application" / "msedge.exe";
    const auto local_chrome = program_files(L"LOCALAPPDATA") / "Google" / "Chrome" / "Application" / "chrome.exe";
    std::error_code ec;
    const auto present = [&](const fs::path& path) { return !path.empty() && fs::is_regular_file(path, ec); };
    if (default_id.starts_with(L"ChromeHTML")) {
        if (present(chrome)) return BrowserChoice{chrome, "Chrome", true};
        if (present(local_chrome)) return BrowserChoice{local_chrome, "Chrome", true};
    }
    if (default_id.starts_with(L"MSEdgeHTM")) {
        if (present(edge)) return BrowserChoice{edge, "Edge", true};
        if (present(edge_64)) return BrowserChoice{edge_64, "Edge", true};
    }
    if (present(edge)) return BrowserChoice{edge, "Edge", false};
    if (present(edge_64)) return BrowserChoice{edge_64, "Edge", false};
    if (present(chrome)) return BrowserChoice{chrome, "Chrome", false};
    if (present(local_chrome)) return BrowserChoice{local_chrome, "Chrome", false};
    return std::nullopt;
}

std::wstring Quote(const std::wstring& text) {
    std::wstring quoted = L"\"";
    for (wchar_t ch : text) {
        if (ch == L'"') quoted += L'\\';
        quoted += ch;
    }
    return quoted + L'"';
}

struct OwnedHandle {
    HANDLE value = nullptr;
    ~OwnedHandle() { if (value) CloseHandle(value); }
    OwnedHandle() = default;
    explicit OwnedHandle(HANDLE handle) : value(handle) {}
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
};

struct OwnedInternet {
    HINTERNET value = nullptr;
    ~OwnedInternet() { if (value) WinHttpCloseHandle(value); }
    explicit OwnedInternet(HINTERNET handle = nullptr) : value(handle) {}
    OwnedInternet(const OwnedInternet&) = delete;
    OwnedInternet& operator=(const OwnedInternet&) = delete;
};

bool ReadPort(const fs::path& profile, INTERNET_PORT& port, std::wstring& endpoint) {
    std::ifstream file(profile / "DevToolsActivePort", std::ios::binary);
    std::string port_text, endpoint_text;
    if (!file || !std::getline(file, port_text) || !std::getline(file, endpoint_text) ||
        endpoint_text.size() < 20 || endpoint_text.size() > 256 ||
        !endpoint_text.starts_with("/devtools/browser/")) return false;
    try {
        const unsigned long parsed = std::stoul(port_text);
        if (!parsed || parsed > 65535) return false;
        port = static_cast<INTERNET_PORT>(parsed);
    } catch (...) { return false; }
    endpoint = Win32Process::ToWide(endpoint_text);
    return true;
}

std::optional<JsonValue> ProtocolCommand(INTERNET_PORT port, const std::wstring& endpoint,
    int id, const char* method, const JsonValue* params = nullptr) {
    OwnedInternet session(WinHttpOpen(L"OpenFruit/" OPENFRUIT_VERSION_W L" Apple browser authentication",
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.value || !WinHttpSetTimeouts(session.value, 3000, 3000, 3000, 3000)) return std::nullopt;
    OwnedInternet connection(WinHttpConnect(session.value, L"127.0.0.1", port, 0));
    if (!connection.value) return std::nullopt;
    OwnedInternet request(WinHttpOpenRequest(connection.value, L"GET", endpoint.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
    if (!request.value || !WinHttpSetOption(request.value, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) ||
        !WinHttpSendRequest(request.value, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request.value, nullptr)) return std::nullopt;
    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) || status != 101) return std::nullopt;
    OwnedInternet socket(WinHttpWebSocketCompleteUpgrade(request.value, 0));
    if (!socket.value) return std::nullopt;
    auto command = JsonValue::ObjectValue();
    command.Set("id", JsonValue::Number(std::to_string(id)));
    command.Set("method", JsonValue::String(method));
    if (params) command.Set("params", *params);
    const std::string outgoing = command.Serialize();
    if (WinHttpWebSocketSend(socket.value, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
        const_cast<char*>(outgoing.data()), static_cast<DWORD>(outgoing.size())) != NO_ERROR) return std::nullopt;
    std::string incoming;
    for (int chunks = 0; chunks < 128; ++chunks) {
        char bytes[4096];
        DWORD received = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type;
        if (WinHttpWebSocketReceive(socket.value, bytes, sizeof(bytes), &received, &type) != NO_ERROR ||
            incoming.size() + received > 512 * 1024) return std::nullopt;
        incoming.append(bytes, received);
        if (type != WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) continue;
        auto response = JsonValue::Parse(incoming);
        SecureZeroMemory(incoming.data(), incoming.size());
        if (!response) return std::nullopt;
        if (const auto* response_id = response->Get("id"); response_id && response_id->Int() == id)
            return response;
        incoming.clear();
    }
    return std::nullopt;
}

std::optional<AppleCookieJar> BrowserCookies(const JsonValue& reply) {
    const auto* result = reply.Get("result");
    const auto* records = result ? result->Get("cookies") : nullptr;
    if (!records || !records->IsArray() || records->ArrayItems().size() > 2048) return std::nullopt;
    AppleCookieJar jar;
    for (const auto& record : records->ArrayItems()) {
        if (!record.IsObject()) continue;
        auto domain = record.GetString("domain");
        if (domain.starts_with('.')) domain.erase(0, 1);
        if (domain != "apple.com" && !domain.ends_with(".apple.com")) continue;
        const auto* expiry = record.Get("expires");
        std::uint64_t seconds = 0;
        if (expiry && expiry->IsNumber()) {
            try {
                const auto number = std::stold(expiry->Serialize());
                if (std::isfinite(number) && number > 0) seconds = static_cast<std::uint64_t>(number);
            } catch (...) { continue; }
        }
        AppleCookie cookie;
        cookie.domain = record.GetString("domain");
        cookie.path = record.GetString("path");
        cookie.name = record.GetString("name");
        cookie.value = record.GetString("value");
        cookie.subdomains = cookie.domain.starts_with('.');
        cookie.secure = record.Get("secure") && record.Get("secure")->Bool();
        cookie.http_only = record.Get("httpOnly") && record.Get("httpOnly")->Bool();
        cookie.expires = seconds;
        jar.AddBrowserCookie(std::move(cookie));
    }
    return jar.Count() ? std::optional<AppleCookieJar>(std::move(jar)) : std::nullopt;
}

bool RemoveOwnedProfile(const fs::path& profile, const fs::path& root) {
    std::error_code ec;
    if (profile.parent_path().lexically_normal() != root.lexically_normal() ||
        fs::is_symlink(profile, ec) || !fs::is_directory(profile, ec)) return false;
    for (fs::recursive_directory_iterator it(profile, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec || it->is_symlink(ec)) return false;
    }
    fs::remove_all(profile, ec);
    return !ec && !fs::exists(profile);
}

} // namespace

BrowserLoginResult BrowserAppleAuth::Login(Secrets& secrets, const fs::path& metadata) {
    OperationSpan span("credentials.apple.browser_login");
    BrowserLoginResult result;
    const auto choice = ChooseBrowser();
    if (!choice) { result.detail = "Chrome or Edge is required for browser session transfer."; return result; }
    result.browser = choice->name;
    std::cout << "OpenFruit: opening Apple Developer in " << choice->name
              << (choice->is_default ? " (default browser)." : " (compatible alternative to the default browser).")
              << std::endl;
    if (!metadata.is_absolute()) { result.status = BrowserLoginStatus::ProtectionFailed; return result; }
    const fs::path root = ToolPaths::UserStateRoot() / "state" / "auth-browser";
    const fs::path profile = root / NewOperationId();
    std::error_code ec;
    if (!fs::create_directories(profile, ec) || ec) {
        result.status = BrowserLoginStatus::BrowserLaunchFailed;
        result.detail = "Could not create an isolated browser profile.";
        return result;
    }
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    std::wstring command = Quote(choice->executable.wstring()) + L" --remote-debugging-port=0 --user-data-dir=" +
        Quote(profile.wstring()) + L" --no-first-run --no-default-browser-check --new-window " +
        L"https://developer.apple.com/account/";
    if (!CreateProcessW(choice->executable.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &startup, &process)) {
        result.status = BrowserLoginStatus::BrowserLaunchFailed;
        result.detail = "Could not start the selected browser.";
        RemoveOwnedProfile(profile, root);
        return result;
    }
    OwnedHandle process_handle(process.hProcess), thread_handle(process.hThread);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(5);
    INTERNET_PORT port = 0;
    std::wstring endpoint;
    while (std::chrono::steady_clock::now() < deadline && !ReadPort(profile, port, endpoint)) {
        if (WaitForSingleObject(process_handle.value, 0) == WAIT_OBJECT_0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    if (!port) {
        result.status = WaitForSingleObject(process_handle.value, 0) == WAIT_OBJECT_0 ?
            BrowserLoginStatus::BrowserClosed : BrowserLoginStatus::BrowserProtocolFailed;
        result.detail = "Browser debugging was unavailable or blocked by policy.";
    } else {
        std::string last_session_digest;
        bool saw_session = false;
        unsigned int protocol_failures = 0;
        while (std::chrono::steady_clock::now() < deadline) {
            if (WaitForSingleObject(process_handle.value, 0) == WAIT_OBJECT_0) {
                result.status = BrowserLoginStatus::BrowserClosed;
                result.detail = saw_session ? "The browser was closed before Apple accepted the session."
                                            : "The browser was closed before sign-in completed.";
                break;
            }
            const auto reply = ProtocolCommand(port, endpoint, 1, "Storage.getCookies");
            if (!reply) {
                if (++protocol_failures >= 3) {
                    result.status = BrowserLoginStatus::BrowserProtocolFailed;
                    result.detail = "Browser session transfer is unavailable or blocked by policy.";
                    break;
                }
            } else {
                protocol_failures = 0;
                const auto cookies = BrowserCookies(*reply);
                if (cookies) {
                    auto fingerprint = cookies->Serialize();
                    const auto digest = Sha256(fingerprint);
                    SecureZeroMemory(fingerprint.data(), fingerprint.size());
                    if (digest && *digest != last_session_digest) {
                        last_session_digest = *digest;
                        const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count());
                        if (!cookies->ForHttpsRequest("developer.apple.com",
                            "/services-account/QH65B2/downloadws/listDownloads.action", now).empty()) {
                            saw_session = true;
                            const auto catalog = AppleDownloadCatalog::Fetch(*cookies, {},
                                std::chrono::steady_clock::now() + std::chrono::seconds(30));
                            if (catalog.Succeeded() && catalog.origin_verified) {
                                // Verification can refresh cookies via Apple's HTTP or
                                // embedded response headers. Persist the verified session
                                // used for the following download, not its earlier snapshot.
                                result.status = AppleCookieStore::Protect(secrets, catalog.download_cookies, metadata).Succeeded() ?
                                    BrowserLoginStatus::Succeeded : BrowserLoginStatus::ProtectionFailed;
                                break;
                            }
                        }
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        if (std::chrono::steady_clock::now() >= deadline && !result.Succeeded())
        {
            result.status = saw_session ? BrowserLoginStatus::CatalogRejected : BrowserLoginStatus::TimedOut;
            result.detail = saw_session
                ? "Apple's download catalog rejected every browser session seen within 5 minutes (sign-in not completed?)."
                : "Sign-in was not completed within 5 minutes.";
        }
        if (result.Succeeded()) {
            auto params = JsonValue::ObjectValue();
            params.Set("url", JsonValue::String("data:text/html,%3Ctitle%3EOPENFRUIT%3C/title%3E%3Ch1%3EAccesso%20riuscito%3C/h1%3E%3Cp%3EOra%20puoi%20chiudere%20la%20pagina.%3C/p%3E"));
            ProtocolCommand(port, endpoint, 2, "Target.createTarget", &params);
            std::this_thread::sleep_for(std::chrono::seconds(8));
        }
        ProtocolCommand(port, endpoint, 3, "Browser.close");
    }
    if (WaitForSingleObject(process_handle.value, 5000) != WAIT_OBJECT_0) {
        TerminateProcess(process_handle.value, 1);
        WaitForSingleObject(process_handle.value, 5000);
    }
    if (!RemoveOwnedProfile(profile, root)) {
        result.status = BrowserLoginStatus::CleanupFailed;
        result.detail = "Isolated browser profile cleanup failed.";
    }
    auto data = JsonValue::ObjectValue();
    data.Set("status", JsonValue::String(result.Succeeded() ? "succeeded" : "failed"));
    data.Set("browser", JsonValue::String(result.browser));
    data.Set("default_browser", JsonValue::Boolean(choice->is_default));
    span.Complete(std::move(data), result.Succeeded());
    return result;
}

} // namespace OpenFruit
