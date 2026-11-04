#include "apple_cookies.hpp"
#include "apple_auth.hpp"
#include "protected_credential_store.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
namespace fs = std::filesystem;
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::size_t ProtectedCount(const fs::path& root) {
    std::size_t count = 0;
    for (const auto& item : fs::directory_iterator(root)) if (item.path().extension() == ".dpapi") ++count;
    return count;
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string exported =
        ".apple.com\tTRUE\t/\tTRUE\t0\towned_session\towned-cookie-secret\n"
        "#HttpOnly_download.developer.apple.com\tFALSE\t/Developer_Tools\tTRUE\t0\tscoped\towned-scoped-secret\n"
        "developer.apple.com\tFALSE\t/\tTRUE\t0\thostonly\towned-host-secret\n"
        ".apple.com\tTRUE\t/\tTRUE\t1\texpired\towned-expired-secret\n"
        "apple.com.attacker.invalid\tTRUE\t/\tTRUE\t0\tforeign\towned-foreign-secret\n";
    OpenFruit::AppleCookieJar jar;
    bool passed = OpenFruit::AppleCookieJar::Parse(exported, jar) && jar.Count() == 4;
    OpenFruit::AppleCookieJar browser;
    passed = passed && browser.AddBrowserCookie({".apple.com", "/", "session", "owned-browser-secret", true, true, true, 0});
    passed = passed && !browser.AddBrowserCookie({"apple.com.attacker.invalid", "/", "session", "foreign", false, true, false, 0});
    passed = passed && !browser.AddBrowserCookie({"apple.com", "/", "session", "bad; injected", false, true, false, 0});
    passed = passed && browser.ForHttpsRequest("developer.apple.com", "/", 100) == "session=owned-browser-secret";
    passed = passed && jar.ForHttpsRequest("download.developer.apple.com", "/Developer_Tools/Xcode.xip", 100)
        == "scoped=owned-scoped-secret; owned_session=owned-cookie-secret";
    passed = passed && jar.ForHttpsRequest("download.developer.apple.com", "/Developer_ToolsOther", 100)
        == "owned_session=owned-cookie-secret";
    passed = passed && jar.ForHttpsRequest("developer.apple.com", "/", 100)
        == "owned_session=owned-cookie-secret; hostonly=owned-host-secret";
    passed = passed && jar.ForHttpsRequest("apple.com.attacker.invalid", "/", 100).empty();
    OpenFruit::AppleCookieJar response = jar;
    passed = passed && response.ImportHttpsResponseCookie("developer.apple.com",
        "/services-account/QH65B2/downloadws/listDownloads.action",
        "ADCDownloadAuth=owned-response-secret; Domain=apple.com; Path=/; Max-Age=60; Secure; HttpOnly", 100);
    passed = passed && response.ForHttpsRequest("download.developer.apple.com", "/Developer_Tools/file.xip", 101)
        .find("ADCDownloadAuth=owned-response-secret") != std::string::npos;
    passed = passed && response.ForHttpsRequest("download.developer.apple.com", "/Developer_Tools/file.xip", 161)
        .find("ADCDownloadAuth=owned-response-secret") == std::string::npos;
    passed = passed && response.ImportHttpsResponseCookie("developer.apple.com", "/account/list",
        "hostonly=owned-hostonly-response; Secure", 100);
    passed = passed && response.ForHttpsRequest("download.developer.apple.com", "/account/file", 101)
        .find("owned-hostonly-response") == std::string::npos;
    passed = passed && !response.ImportHttpsResponseCookie("developer.apple.com", "/account/list",
        "foreign=owned-foreign-response; Domain=attacker.invalid; Path=/", 100);
    passed = passed && !response.ImportHttpsResponseCookie("developer.apple.com", "/account/list",
        "injected=owned-response\r\nCookie: stolen=true", 100);
    passed = passed && response.ImportHttpsResponseCookie("developer.apple.com", "/account/list",
        "ADCDownloadAuth=gone; Domain=apple.com; Path=/; Max-Age=0", 100)
        && response.ForHttpsRequest("download.developer.apple.com", "/Developer_Tools/file.xip", 101)
            .find("ADCDownloadAuth=") == std::string::npos;
    OpenFruit::AppleCookieJar roundtrip;
    passed = passed && OpenFruit::AppleCookieJar::Parse(jar.Serialize(), roundtrip)
        && roundtrip.ForHttpsRequest("download.developer.apple.com", "/Developer_Tools/file", 100)
            == jar.ForHttpsRequest("download.developer.apple.com", "/Developer_Tools/file", 100);
    for (const std::string invalid : {"{}", ".apple.com\tTRUE\t/\tTRUE\t0\tsid\tinjected; other=value\n",
            "apple.com\tFALSE\t/\tFALSE\t0\t__Secure-id\tvalue\n",
            ".apple.com\tTRUE\t/\tTRUE\t0\t__Host-id\tvalue\n",
            "apple.com\tFALSE\t/\tTRUE\tbad\tsid\tvalue\n"}) {
        passed = passed && !OpenFruit::AppleCookieJar::Parse(invalid, roundtrip) && roundtrip.Count() == 0;
    }
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-apple-cookies-" + OpenFruit::NewOperationId());
    fs::create_directories(root);
    const auto source = root / "cookies.txt", metadata = root / "secrets.json";
    { std::ofstream input(source, std::ios::binary); input << exported; }
    OpenFruit::Secrets secrets;
    secrets.apple_id = L"owned-account@example.invalid";
    secrets.signing_password = L"DPAPI:" + (root / "signing.dpapi").wstring();
    secrets.apple_session_dpapi_path = (root / "session.dpapi").wstring();
    const auto imported = OpenFruit::AppleCookieStore::Import(secrets, source, metadata);
    passed = passed && imported.Succeeded() && imported.count == 4 && Read(source) == exported;
    const auto stored = OpenFruit::Secrets::Load(metadata.wstring());
    passed = passed && stored.signing_password == secrets.signing_password
        && stored.apple_session_dpapi_path == secrets.apple_session_dpapi_path
        && OpenFruit::AppleCookieStore::Load(stored, roundtrip) && roundtrip.Count() == 4
        && Read(metadata).find("owned-cookie-secret") == std::string::npos
        && Read(stored.apple_cookies_dpapi_path).find("owned-cookie-secret") == std::string::npos;
    const auto protected_browser = OpenFruit::AppleCookieStore::Protect(secrets, browser, metadata);
    const auto browser_store = OpenFruit::Secrets::Load(metadata.wstring());
    passed = passed && protected_browser.Succeeded() && browser_store.apple_session_dpapi_path.empty()
        && OpenFruit::AppleCookieStore::Load(browser_store, roundtrip)
        && roundtrip.ForHttpsRequest("developer.apple.com", "/", 100) == "session=owned-browser-secret"
        && Read(metadata).find("owned-browser-secret") == std::string::npos
        && Read(browser_store.apple_cookies_dpapi_path).find("owned-browser-secret") == std::string::npos;
    std::wstring decoded;
    passed = passed && !OpenFruit::ProtectedCredentialStore::Read(stored.apple_cookies_dpapi_path,
        decoded, OpenFruit::CredentialPurpose::AppleSession)
        && !OpenFruit::ProtectedCredentialStore::Read(stored.apple_cookies_dpapi_path,
            decoded, OpenFruit::CredentialPurpose::SigningPassword);
    const auto before = Read(metadata);
    const auto previous_reference = secrets.apple_cookies_dpapi_path;
    const auto protected_count = ProtectedCount(root);
    HANDLE reader = CreateFileW(metadata.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (reader == INVALID_HANDLE_VALUE) return 3;
    passed = passed && OpenFruit::AppleCookieStore::Import(secrets, source, metadata).status
        == OpenFruit::AppleCookieImportStatus::PublicationFailed
        && Read(metadata) == before && secrets.apple_cookies_dpapi_path == previous_reference
        && ProtectedCount(root) == protected_count;
    passed = passed && !OpenFruit::AppleCookieStore::Clear(secrets, metadata)
        && Read(metadata) == before && secrets.apple_cookies_dpapi_path == previous_reference
        && OpenFruit::AppleCookieStore::Load(secrets, roundtrip);
    CloseHandle(reader);
    OpenFruit::Config config;
    config.user_state_root = root.wstring();
    config.secrets_path = metadata.wstring();
    passed = passed && config.Save((root / "config.toml").wstring());
    const auto executable = fs::absolute(argv[1]).wstring();
    const auto cli = OpenFruit::Win32Process::Run(executable,
        {executable, L"auth", L"cookies", L"import", source.wstring()}, L"", {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    passed = passed && cli.success && cli.std_out.find("owned-cookie-secret") == std::string::npos;
    const auto cli_store = OpenFruit::Secrets::Load(metadata.wstring());
    passed = passed && OpenFruit::AppleCookieStore::Load(cli_store, roundtrip) && roundtrip.Count() == 4;
    const auto cli_metadata = Read(metadata);
    const auto invalid_source = root / "invalid-cookies.txt";
    { std::ofstream invalid(invalid_source); invalid << "apple.com\tFALSE\t/\tTRUE\t0\tsid\towned-secret; injected=value\n"; }
    const auto rejected = OpenFruit::Win32Process::Run(executable,
        {executable, L"auth", L"cookies", L"import", invalid_source.wstring()}, L"", {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    passed = passed && rejected.launched && rejected.exit_code == 1 && Read(metadata) == cli_metadata
        && rejected.std_err.find("owned-secret") == std::string::npos;
    const auto clear_cli = OpenFruit::Win32Process::Run(executable,
        {executable, L"auth", L"cookies", L"clear"}, L"", {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    const auto cleared_store = OpenFruit::Secrets::Load(metadata.wstring());
    passed = passed && clear_cli.success && cleared_store.apple_cookies_dpapi_path.empty()
        && cleared_store.signing_password == cli_store.signing_password
        && cleared_store.apple_session_dpapi_path == cli_store.apple_session_dpapi_path
        && !OpenFruit::AppleCookieStore::Load(cleared_store, roundtrip) && roundtrip.Count() == 0
        && fs::exists(cli_store.apple_cookies_dpapi_path) && Read(source) == exported;
    const auto cleared_metadata = Read(metadata);
    const auto clear_again = OpenFruit::Win32Process::Run(executable,
        {executable, L"auth", L"cookies", L"clear"}, L"", {{L"OPENFRUIT_USER_STATE", root.wstring()}});
    passed = passed && clear_again.success && Read(metadata) == cleared_metadata;
    for (const auto& item : fs::recursive_directory_iterator(root / "diagnostics")) {
        if (item.path().extension() == ".jsonl") passed = passed && Read(item.path()).find("owned-cookie-secret") == std::string::npos;
    }
    passed = passed && OpenFruit::AppleAuth::Login(secrets, "other-owned-account@example.invalid", "", metadata.wstring())
        && secrets.apple_cookies_dpapi_path.empty() && secrets.apple_session_dpapi_path.empty();
    fs::remove_all(root); // Unique owned fixture only.
    if (!passed) std::cerr << "Apple cookie scope, protected storage or CLI contract failed.\n";
    return passed ? 0 : 1;
}
