#include "sdk_auto_selection.hpp"
#include "apple_cookies.hpp"
#include "apple_download_catalog.hpp"
#include "browser_apple_auth.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include "sdk_acquisition.hpp"
#include "sdk_catalog.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string_view>
#include <vector>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
// A person can answer a sign-in only when standard input is a console.
bool InteractiveConsole() {
    DWORD mode = 0;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) != FALSE;
}
std::string CatalogStatusText(const AppleCatalogResult& catalog) {
    std::string text;
    switch (catalog.status) {
    case AppleCatalogStatus::Succeeded: text = catalog.origin_verified ? "succeeded" : "unverified origin"; break;
    case AppleCatalogStatus::CredentialsUnavailable: text = "credentials unavailable"; break;
    case AppleCatalogStatus::Unauthorized: text = "session rejected"; break;
    case AppleCatalogStatus::TransportFailure: text = "network failure"; break;
    case AppleCatalogStatus::InvalidResponse: text = "invalid response"; break;
    case AppleCatalogStatus::Cancelled: text = "cancelled"; break;
    case AppleCatalogStatus::TimedOut: text = "timed out"; break;
    }
    if (catalog.http_status) text += ", HTTP " + std::to_string(catalog.http_status);
    if (!catalog.diagnostic_code.empty()) text += ", " + catalog.diagnostic_code;
    return text;
}
std::optional<std::vector<unsigned int>> VersionParts(const std::wstring& text) {
    if (text.empty() || text.size() > 32) return std::nullopt;
    std::vector<unsigned int> parts;
    std::size_t start = 0;
    for (;;) {
        const auto end = text.find(L'.', start);
        const auto segment = text.substr(start, end == std::wstring::npos ? end : end - start);
        if (segment.empty() || segment.size() > 5 ||
            !std::all_of(segment.begin(), segment.end(), [](wchar_t ch) { return ch >= L'0' && ch <= L'9'; }))
            return std::nullopt;
        try { parts.push_back(static_cast<unsigned int>(std::stoul(segment))); }
        catch (...) { return std::nullopt; }
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return parts;
}
bool LessVersion(const std::vector<unsigned int>& left, const std::vector<unsigned int>& right) {
    const auto count = std::max(left.size(), right.size());
    for (std::size_t i = 0; i < count; ++i) {
        const auto a = i < left.size() ? left[i] : 0, b = i < right.size() ? right[i] : 0;
        if (a != b) return a < b;
    }
    return false;
}
std::optional<std::wstring> VerifiedIosVersion(const fs::path& path) {
    if (!SDKCatalog::HasUsableLayout(path)) return std::nullopt;
    const fs::path settings = path / "SDKSettings.json";
    std::error_code ec;
    if (!fs::is_regular_file(settings, ec) || fs::file_size(settings, ec) > 4 * 1024 * 1024 || ec)
        return std::nullopt;
    std::ifstream input(settings, std::ios::binary);
    const std::string body((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const auto parsed = JsonValue::Parse(body);
    if (!parsed || !parsed->IsObject()) return std::nullopt;
    const std::wstring version = Win32Process::ToWide(parsed->GetString("Version"));
    const auto canonical = parsed->GetString("CanonicalName");
    if (!VersionParts(version) || canonical != "iphoneos" + Win32Process::ToNarrow(version)) return std::nullopt;
    return version;
}
std::optional<XcodeIosSupport> InstalledIosSupport(const fs::path& path, const std::wstring& version) {
    const auto settings = path / "SDKSettings.json";
    std::error_code ec;
    if (!fs::is_regular_file(settings, ec) || fs::file_size(settings, ec) > 4 * 1024 * 1024 || ec)
        return std::nullopt;
    std::ifstream input(settings, std::ios::binary);
    const std::string body((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const auto parsed = JsonValue::Parse(body);
    if (!parsed || parsed->GetString("Version") != Win32Process::ToNarrow(version) ||
        parsed->GetString("CanonicalName") != "iphoneos" + Win32Process::ToNarrow(version)) return std::nullopt;
    const auto targets = parsed->Get("SupportedTargets");
    const auto target = targets && targets->IsObject() ? targets->Get("iphoneos") : nullptr;
    if (!target || !target->IsObject() || target->GetString("LLVMTargetTripleVendor") != "apple" ||
        target->GetString("LLVMTargetTripleSys") != "ios" ||
        target->GetString("DeploymentTargetSettingName") != "IPHONEOS_DEPLOYMENT_TARGET") return std::nullopt;
    const auto minimum = Win32Process::ToWide(target->GetString("MinimumDeploymentTarget"));
    const auto maximum = Win32Process::ToWide(target->GetString("MaximumDeploymentTarget"));
    const auto min_parts = VersionParts(minimum), max_parts = VersionParts(maximum);
    if (!min_parts || !max_parts || LessVersion(*max_parts, *min_parts)) return std::nullopt;

    const auto module = path / "usr" / "lib" / "swift" / "Swift.swiftmodule";
    auto interface = module / "arm64-apple-ios.swiftinterface";
    if (!fs::exists(interface, ec) && !ec) interface = module / "arm64e-apple-ios.swiftinterface";
    if (ec || !fs::is_regular_file(interface, ec) || ec) return std::nullopt;
    std::ifstream swift(interface, std::ios::binary);
    constexpr std::string_view prefix = "// swift-compiler-version: Apple Swift version ";
    std::string line;
    unsigned int lines = 0;
    // Inspect the bounded metadata header, never the full SDK source module.
    for (std::size_t bytes = 0; bytes < 16384 && lines < 8; ++bytes) {
        char ch;
        if (!swift.get(ch)) break;
        if (ch != '\n') { line.push_back(ch); continue; }
        ++lines;
        if (line.starts_with(prefix)) {
            const auto end = line.find(' ', prefix.size());
            const auto compiler = Win32Process::ToWide(line.substr(prefix.size(), end - prefix.size()));
            const auto parts = VersionParts(compiler);
            if (!parts || parts->size() < 2 || (*parts)[0] == 0) return std::nullopt;
            return XcodeIosSupport{L"", version, minimum, maximum,
                std::to_wstring((*parts)[0]) + L"." + std::to_wstring((*parts)[1])};
        }
        line.clear();
    }
    return std::nullopt;
}
}
SDKAutoResult SDKAutoSelection::Resolve(Config& snapshot, const std::wstring& sdk_root,
    const std::wstring& deployment_target, bool allow_acquisition) {
    return ResolveWithSupport(snapshot, sdk_root, deployment_target, allow_acquisition,
        XcodeCompatibility::FetchAppleTable());
}
SDKAutoResult SDKAutoSelection::ResolveWithSupport(Config& snapshot, const std::wstring& sdk_root,
    const std::wstring& deployment_target, bool allow_acquisition,
    const std::vector<XcodeIosSupport>& support) {
    OperationSpan span("sdk.auto_select");
    SDKAutoResult result;
    auto finish = [&]() {
        auto data = JsonValue::ObjectValue();
        data.Set("status", JsonValue::String(result.succeeded ? "succeeded" : "failed"));
        data.Set("sdk_root", JsonValue::String(Win32Process::ToNarrow(sdk_root)));
        data.Set("deployment_target", JsonValue::String(Win32Process::ToNarrow(deployment_target)));
        data.Set("sdk_version", JsonValue::String(Win32Process::ToNarrow(result.version)));
        data.Set("xcode_version", JsonValue::String(Win32Process::ToNarrow(result.xcode_version)));
        data.Set("swift_compiler_version", JsonValue::String(Win32Process::ToNarrow(result.swift_compiler_version)));
        data.Set("compiler_metadata_from_sdk", JsonValue::Boolean(result.compiler_metadata_from_sdk));
        data.Set("acquired", JsonValue::Boolean(result.acquired));
        span.Complete(std::move(data), result.succeeded);
        return result;
    };
    std::wstring lower_sdk_root = sdk_root;
    std::transform(lower_sdk_root.begin(), lower_sdk_root.end(), lower_sdk_root.begin(), ::towlower);
    if (!lower_sdk_root.starts_with(L"iphoneos")) {
        result.message = "Target SDKROOT must resolve to iphoneos for an iOS build.";
        return finish();
    }
    const std::wstring requested_sdk = lower_sdk_root.substr(8);
    if (!requested_sdk.empty() && !VersionParts(requested_sdk)) {
        result.message = "Target SDKROOT has an invalid iPhoneOS SDK version.";
        return finish();
    }
    const auto minimum = VersionParts(deployment_target);
    if (!minimum) {
        result.message = "Target IPHONEOS_DEPLOYMENT_TARGET is missing or invalid.";
        return finish();
    }
    std::vector<unsigned int> best_parts;
    for (const auto& [registered, path] : snapshot.ios_sdk_paths) {
        const auto version = VerifiedIosVersion(path);
        if (!version || *version != registered) continue;
        if (!requested_sdk.empty() && *version != requested_sdk) continue;
        const auto parts = VersionParts(*version);
        const XcodeIosSupport* matched_release = nullptr;
        bool known_sdk = false;
        for (const auto& release : support) {
            if (release.sdk_version == *version) known_sdk = true;
            if (release.sdk_version == *version &&
                XcodeCompatibility::Supports(release, deployment_target) &&
                (!matched_release || XcodeCompatibility::LessVersion(
                    matched_release->xcode_version, release.xcode_version)))
                matched_release = &release;
        }
        std::optional<XcodeIosSupport> installed_support;
        if (!matched_release && !known_sdk) {
            installed_support = InstalledIosSupport(path, *version);
            if (installed_support && XcodeCompatibility::Supports(*installed_support, deployment_target))
                matched_release = &*installed_support;
        }
        if (!parts || !matched_release ||
            (result.succeeded && !LessVersion(best_parts, *parts))) continue;
        result.succeeded = true;
        result.version = *version;
        result.path = path;
        result.xcode_version = matched_release->xcode_version;
        result.swift_compiler_version = matched_release->swift_compiler_version;
        result.compiler_metadata_from_sdk = installed_support.has_value();
        best_parts = *parts;
    }
    if (result.succeeded) {
        result.message = "Selected the newest compatible registered iPhoneOS SDK.";
    } else if (allow_acquisition) {
        if (support.empty()) {
            result.message = "Apple's Xcode iOS support table is unavailable and no registered SDK has compatible compiler metadata.";
            return finish();
        }
        const fs::path metadata = snapshot.secrets_path.empty()
            ? ToolPaths::UserStateRoot() / "credentials" / "secrets.json" : fs::path(snapshot.secrets_path);
        // A missing, expired or revoked Apple session is renewed through the
        // browser login when a user is present, then the catalog is retried.
        AppleCookieJar cookies;
        const auto fetch = [&] {
            return AppleDownloadCatalog::Fetch(cookies, {}, std::chrono::steady_clock::now() + std::chrono::seconds(45));
        };
        bool session = AppleCookieStore::Load(Secrets::Load(metadata.wstring()), cookies);
        AppleCatalogResult catalog;
        if (session) catalog = fetch();
        const bool rejected = !session || catalog.status == AppleCatalogStatus::Unauthorized ||
                              catalog.status == AppleCatalogStatus::CredentialsUnavailable;
        if (rejected && InteractiveConsole()) {
            std::cout << (session ? "OPENFRUIT: The Apple Developer session was rejected"
                                  : "OPENFRUIT: No Apple Developer session is stored")
                      << "; an iPhoneOS SDK must be downloaded. Opening the Apple sign-in...\n" << std::flush;
            auto secrets = Secrets::Load(metadata.wstring());
            const auto login = BrowserAppleAuth::Login(secrets, fs::absolute(metadata));
            if (!login.Succeeded()) {
                result.message = "Apple sign-in did not complete: " + login.detail;
                return finish();
            }
            cookies = {};
            session = AppleCookieStore::Load(Secrets::Load(metadata.wstring()), cookies);
            if (session) catalog = fetch();
        }
        if (!session) {
            result.message = "No compatible installed iPhoneOS SDK or Apple session; run 'OPENFRUIT auth login'.";
            return finish();
        }
        if (!catalog.Succeeded() || !catalog.origin_verified) {
            result.message = "No compatible installed SDK and the authenticated Apple catalog is unavailable (" +
                CatalogStatusText(catalog) + ")." + (catalog.status == AppleCatalogStatus::Unauthorized ||
                catalog.status == AppleCatalogStatus::CredentialsUnavailable ? " Run 'OPENFRUIT auth login'." : "");
            return finish();
        }
        std::wstring xcode_version;
        std::vector<unsigned int> latest;
        for (const auto& file : catalog.xip_files) {
            if (!file.product_name.starts_with("Xcode ")) continue;
            // Do not erase beta/RC identity or compare Xcode numbering with iOS
            // deployment numbering. Only an exact release in Apple's support
            // metadata establishes SDK and compiler compatibility.
            const auto candidate = Win32Process::ToWide(file.product_name.substr(6));
            const auto parts = VersionParts(candidate);
            const bool supported = std::any_of(support.begin(), support.end(), [&](const XcodeIosSupport& release) {
                return release.xcode_version == candidate &&
                    (requested_sdk.empty() || release.sdk_version == requested_sdk) &&
                    XcodeCompatibility::Supports(release, deployment_target);
            });
            if (!parts || !supported || (!xcode_version.empty() && !LessVersion(latest, *parts))) continue;
            latest = *parts;
            xcode_version = candidate;
        }
        if (xcode_version.empty()) {
            result.message = "The authenticated catalog has no stable Xcode archive compatible with the deployment target and Apple's support table.";
            return finish();
        }
        const auto acquisition = SDKAcquisition::Download(Win32Process::ToNarrow(xcode_version),
            ToolPaths::LocalHome());
        if (!acquisition.Succeeded()) {
            result.message = acquisition.message;
            return finish();
        }
        const auto version = VerifiedIosVersion(acquisition.destination);
        const auto parts = version ? VersionParts(*version) : std::nullopt;
        const auto selected_release = std::find_if(support.begin(), support.end(), [&](const XcodeIosSupport& release) {
            return release.xcode_version == xcode_version && version && release.sdk_version == *version &&
                (requested_sdk.empty() || release.sdk_version == requested_sdk) &&
                XcodeCompatibility::Supports(release, deployment_target);
        });
        if (!parts || selected_release == support.end() || LessVersion(*parts, *minimum)) {
            result.message = "The verified Apple archive does not contain a compatible iPhoneOS SDK.";
            return finish();
        }
        result.succeeded = true;
        result.acquired = true;
        result.version = *version;
        result.path = acquisition.destination.wstring();
        result.xcode_version = selected_release->xcode_version;
        result.swift_compiler_version = selected_release->swift_compiler_version;
        result.message = "Acquired and selected the newest catalog Xcode with a compatible iPhoneOS SDK.";
        snapshot.ios_sdk_paths[result.version] = result.path;
    } else result.message = "No compatible registered iPhoneOS SDK.";
    if (result.succeeded) {
        snapshot.ios_sdk_version = result.version;
        snapshot.sdk_path = result.path;
    }
    return finish();
}
}
