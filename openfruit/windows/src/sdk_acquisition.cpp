#include "sdk_acquisition.hpp"
#include "apple_cookies.hpp"
#include "apple_download_catalog.hpp"
#include "config.hpp"
#include "http_transfer.hpp"
#include "operation_events.hpp"
#include "sdk_archive_extraction.hpp"
#include "sdk_catalog.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <system_error>
namespace OpenFruit {
namespace fs = std::filesystem;
namespace {
// One console line per stage, rewritten in place when the whole percent changes.
class ConsoleProgress {
public:
    explicit ConsoleProgress(std::string label) : label_(std::move(label)) {}
    void Update(std::uint64_t done, std::uint64_t total) {
        if (!total) return;
        const int percent = static_cast<int>(std::min<std::uint64_t>(100, done * 100 / total));
        if (percent == percent_) return;
        percent_ = percent;
        std::cout << "\rOPENFRUIT: " << label_ << ' ' << std::fixed << std::setprecision(2)
                  << static_cast<double>(done) / (1 << 30) << " / " << static_cast<double>(total) / (1 << 30)
                  << " GB (" << percent << "%)" << std::flush;
    }
    void Finish() { if (percent_ >= 0) std::cout << '\n' << std::flush; }
private:
    std::string label_;
    int percent_ = -1;
};
bool ValidVersion(const std::string& version) {
    if (version.empty() || version.size() > 32) return false;
    bool digit = false;
    for (const unsigned char character : version) {
        if (character >= '0' && character <= '9') digit = true;
        else if (character == '.' && digit) digit = false;
        else return false;
    }
    return digit;
}
const char* Status(SDKAcquisitionStatus status) {
    switch (status) {
    case SDKAcquisitionStatus::Succeeded: return "succeeded";
    case SDKAcquisitionStatus::InvalidVersion: return "invalid_version";
    case SDKAcquisitionStatus::InvalidManagedHome: return "invalid_managed_home";
    case SDKAcquisitionStatus::CredentialsUnavailable: return "credentials_unavailable";
    case SDKAcquisitionStatus::CatalogFailure: return "catalog_failure";
    case SDKAcquisitionStatus::VersionUnavailable: return "version_unavailable";
    case SDKAcquisitionStatus::TransferFailure: return "transfer_failure";
    case SDKAcquisitionStatus::VerificationFailure: return "verification_failure";
    case SDKAcquisitionStatus::AlreadyRegistered: return "already_registered";
    case SDKAcquisitionStatus::PublicationFailure: return "publication_failure";
    }
    return "publication_failure";
}
std::uint64_t Now() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
bool SafeDirectChild(const fs::path& parent, const fs::path& child) {
    if (!parent.is_absolute() || child.parent_path() != parent || child.filename().empty()) return false;
    std::error_code error;
    const auto resolved_parent = fs::weakly_canonical(parent, error);
    if (error) return false;
    const auto resolved_child = fs::weakly_canonical(child, error);
    return !error && resolved_child.parent_path() == resolved_parent;
}
bool WithinManaged(const fs::path& managed_home, const fs::path& candidate) {
    std::error_code error;
    const auto root = fs::weakly_canonical(managed_home, error);
    if (error) return false;
    const auto path = fs::weakly_canonical(candidate, error);
    if (error) return false;
    auto left = root.begin(), right = path.begin();
    for (; left != root.end(); ++left, ++right)
        if (right == path.end() || *left != *right) return false;
    return right != path.end();
}
struct TemporaryTree {
    fs::path root;
    ~TemporaryTree() {
        if (!root.empty() && SafeDirectChild(root.parent_path(), root)) {
            std::error_code ignored; fs::remove_all(root, ignored);
        }
    }
};
}
SDKAcquisitionResult SDKAcquisition::Download(const std::string& version, const fs::path& managed_home) {
    OperationSpan span("sdk.acquire");
    SDKAcquisitionResult result;
    auto finish = [&]() {
        auto data = JsonValue::ObjectValue();
        data.Set("status", JsonValue::String(Status(result.status)));
        data.Set("message", JsonValue::String(result.message));
        data.Set("publisher_verified", JsonValue::Boolean(result.publisher_verified));
        if (result.Succeeded()) data.Set("sdk_path", JsonValue::String(Win32Process::ToNarrow(result.destination.wstring())));
        span.Complete(std::move(data), result.Succeeded());
        return result;
    };
    if (!ValidVersion(version)) {
        result.status = SDKAcquisitionStatus::InvalidVersion;
        result.message = "Xcode version must be dotted numeric, for example 26.5.";
        return finish();
    }
    if (!managed_home.is_absolute() || managed_home == managed_home.root_path() ||
        managed_home.lexically_normal() != managed_home) {
        result.status = SDKAcquisitionStatus::InvalidManagedHome;
        result.message = "SDK installation requires a normalized absolute managed home.";
        return finish();
    }
    const Config settings = Config::Load();
    const fs::path credentials_path = settings.secrets_path.empty()
        ? ToolPaths::UserStateRoot() / "credentials" / "secrets.json" : fs::path(settings.secrets_path);
    AppleCookieJar cookies;
    if (!AppleCookieStore::Load(Secrets::Load(credentials_path.wstring()), cookies)) {
        result.status = SDKAcquisitionStatus::CredentialsUnavailable;
        result.message = "Apple Developer session unavailable; run 'OPENFRUIT auth login'.";
        return finish();
    }
    auto catalog = AppleDownloadCatalog::Fetch(cookies, {},
        std::chrono::steady_clock::now() + std::chrono::seconds(45));
    if (!catalog.Succeeded() || !catalog.origin_verified) {
        result.status = catalog.status == AppleCatalogStatus::CredentialsUnavailable
            ? SDKAcquisitionStatus::CredentialsUnavailable : SDKAcquisitionStatus::CatalogFailure;
        result.message = "A fresh authenticated Apple download catalog could not be verified.";
        return finish();
    }
    const AppleDownloadFile* chosen = catalog.SmallestXipForProduct("Xcode " + version);
    if (!chosen) {
        result.status = SDKAcquisitionStatus::VersionUnavailable;
        result.message = "The requested Xcode version has no XIP in the authenticated Apple catalog.";
        return finish();
    }
    const auto quarantine = managed_home / "cache" / "sdk-downloads";
    std::error_code error;
    fs::create_directories(quarantine, error);
    if (error || !fs::is_directory(quarantine) || !WithinManaged(managed_home, quarantine)) {
        result.status = SDKAcquisitionStatus::TransferFailure;
        result.message = "SDK download quarantine could not be created.";
        return finish();
    }
    StagedTransferRequest request;
    request.url = Win32Process::ToWide(chosen->url);
    request.staging_directory = quarantine;
    request.expected_bytes = chosen->bytes;
    request.deadline = std::chrono::steady_clock::now() + std::chrono::hours(4);
    request.cookie_header = [&catalog](const std::wstring& host, const std::wstring& path) {
        return Win32Process::ToWide(catalog.download_cookies.ForHttpsRequest(
            Win32Process::ToNarrow(host), Win32Process::ToNarrow(path), Now()));
    };
    ConsoleProgress download("downloading Xcode " + version);
    request.progress_callback = [&download](std::uint64_t done, std::uint64_t total) { download.Update(done, total); };
    const auto staged = HttpTransfer::Stage(request);
    download.Finish();
    if (!staged.Succeeded()) {
        result.status = SDKAcquisitionStatus::TransferFailure;
        result.message = "The Apple XIP could not be downloaded completely into quarantine.";
        return finish();
    }
    const auto staging_parent = managed_home / "sdk" / "_staging";
    fs::create_directories(staging_parent, error);
    if (error || !fs::is_directory(staging_parent) || !WithinManaged(managed_home, staging_parent)) {
        result.status = SDKAcquisitionStatus::PublicationFailure;
        result.message = "SDK extraction staging could not be created.";
        return finish();
    }
    TemporaryTree extraction{staging_parent / NewOperationId()};
    if (!SafeDirectChild(staging_parent, extraction.root) || !WithinManaged(managed_home, extraction.root)) {
        result.status = SDKAcquisitionStatus::PublicationFailure;
        result.message = "SDK staging path could not be validated.";
        return finish();
    }
    ConsoleProgress extracting("extracting the iPhoneOS SDK from Xcode " + version);
    SDKExtractionOptions extraction_options;
    extraction_options.read.progress = [&extracting](std::uint64_t done, std::uint64_t total) { extracting.Update(done, total); };
    const auto unpacked = SDKArchiveExtraction::ExtractIos(staged.path, extraction.root, extraction_options);
    extracting.Finish();
    if (!unpacked.Succeeded() || !unpacked.toc_checksum_verified ||
        !unpacked.content_checksum_verified || !unpacked.xar_signature_valid ||
        !unpacked.apple_signing_chain_valid || !unpacked.apple_revocation_valid ||
        !SDKCatalog::HasUsableLayout(unpacked.sdk_path)) {
        result.status = SDKAcquisitionStatus::VerificationFailure;
        result.message = "The complete Apple XIP or extracted iOS SDK failed verification; nothing was registered.";
        return finish();
    }
    // Provenance requires the fresh fixed-origin catalog, its exact transfer
    // size, and the original complete Apple-signed XIP. No local digest alone
    // is treated as publisher identity.
    result.publisher_verified = true;
    const auto ios_version = Win32Process::ToWide(unpacked.version);
    const auto final_parent = managed_home / "sdk" / "xcode";
    const auto final_root = final_parent / staged.path.stem(); // Stable URL identity, never an upstream filename.
    const auto sdk_relative = unpacked.sdk_path.lexically_relative(extraction.root);
    if (sdk_relative.empty() || sdk_relative.native().starts_with(L"..")) {
        result.status = SDKAcquisitionStatus::VerificationFailure;
        result.message = "Extracted SDK path escaped its staging tree.";
        return finish();
    }
    // A transfer may take hours. Read configuration again before registering
    // so an earlier snapshot cannot overwrite changes made during download.
    Config updated = Config::Load();
    const auto prior = updated.ios_sdk_paths.find(ios_version);
    const bool registration_blocks = prior != updated.ios_sdk_paths.end() &&
        !SDKCatalog::RegistrationTargetMissing(fs::path(prior->second));
    const bool destination_exists = fs::exists(final_root, error);
    if (registration_blocks || destination_exists || error) {
        result.status = SDKAcquisitionStatus::AlreadyRegistered;
        result.message = "An SDK with this version or Xcode archive identity already exists; previous installation was retained.";
        return finish();
    }
    fs::create_directories(final_parent, error);
    if (error || !fs::is_directory(final_parent) || !SafeDirectChild(final_parent, final_root) ||
        !WithinManaged(managed_home, final_root)) {
        result.status = SDKAcquisitionStatus::PublicationFailure;
        result.message = "Managed SDK publication directory could not be created.";
        return finish();
    }
    fs::rename(extraction.root, final_root, error);
    if (error) {
        result.status = SDKAcquisitionStatus::PublicationFailure;
        result.message = "Verified SDK tree could not be published atomically.";
        return finish();
    }
    extraction.root.clear();
    const auto installed_sdk = final_root / sdk_relative;
    updated.ios_sdk_paths[ios_version] = installed_sdk.wstring();
    if (updated.ios_sdk_version == ios_version) updated.sdk_path = installed_sdk.wstring();
    if (!updated.Save(Config::GetDefaultConfigPath())) {
        std::error_code ignored;
        if (SafeDirectChild(final_parent, final_root) && WithinManaged(managed_home, final_root))
            fs::remove_all(final_root, ignored); // Only the tree just published by this invocation.
        result.status = SDKAcquisitionStatus::PublicationFailure;
        result.message = "SDK registration failed; previous configuration was retained.";
        return finish();
    }
    result.status = SDKAcquisitionStatus::Succeeded;
    result.destination = installed_sdk;
    result.message = "Verified Apple iOS SDK installed and registered; select it with 'OPENFRUIT sdk select'.";
    return finish();
}
} // namespace OpenFruit
