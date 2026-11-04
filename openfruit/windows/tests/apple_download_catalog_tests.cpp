#include "apple_download_catalog.hpp"
#include <fstream>
#include <iostream>
#include <string>
using OpenFruit::AppleCatalogStatus;
using OpenFruit::AppleDownloadCatalog;
namespace {
std::string Catalog(std::string path = "/Developer_Tools/Xcode_28.7/Xcode_28.7_Apple_silicon.xip",
    std::string host = "https://download.developer.apple.com", std::string bytes = "2316428058") {
    return "{\"resultCode\":0,\"downloadHost\":\"" + host +
        "\",\"httpResponseHeaders\":{\"Set-Cookie\":\"owned-catalog-secret\"},"
        "\"downloads\":[{\"id\":\"OWNED28\",\"name\":\"Xcode 28.7\",\"files\":[{"
        "\"filename\":\"Xcode 28.7 Apple silicon.xip\",\"remotePath\":\"" + path +
        "\",\"fileSize\":" + bytes + ",\"fileFormat\":{\"extension\":\".xip\"}}]}]}";
}
}
int main(int argc, char** argv) {
    bool passed = true;
    // An Apple service error is not a catalog-host mismatch. Preserve the
    // origin restriction, but diagnose the earliest service contract failure.
    const auto service_error = AppleDownloadCatalog::ParseUntrusted("{\"resultCode\":1100}");
    passed = passed && !service_error.Succeeded() && !service_error.origin_verified &&
        service_error.diagnostic_code == "catalog.response.result_code.1100" &&
        service_error.status == OpenFruit::AppleCatalogStatus::Unauthorized;
    // Other service errors are not evidence of an expired sign-in.
    const auto other_error = AppleDownloadCatalog::ParseUntrusted("{\"resultCode\":2000}");
    passed = passed && other_error.status == OpenFruit::AppleCatalogStatus::InvalidResponse;
    const auto missing_host = AppleDownloadCatalog::ParseUntrusted("{\"resultCode\":0,\"downloads\":[]}");
    passed = passed && !missing_host.Succeeded() &&
        missing_host.diagnostic_code == "catalog.response.download_host_missing";
    const auto parsed = AppleDownloadCatalog::ParseUntrusted(Catalog());
    passed = passed && parsed.Succeeded() && !parsed.origin_verified && parsed.xip_files.size() == 1;
    auto choices = parsed;
    choices.xip_files.push_back({"OWNED28", "Xcode 28.7", "Universal.xip",
        "/Developer_Tools/Xcode_28.7/Universal.xip",
        "https://download.developer.apple.com/Developer_Tools/Xcode_28.7/Universal.xip", 2962751016ULL});
    passed = passed && choices.SmallestXipForProduct("Xcode 28.7") == &choices.xip_files.front()
        && choices.SmallestXipForProduct("Xcode 99.0") == nullptr;
    // Exact product identity is required: a stable request must not acquire a
    // beta, RC, or a numerically prefixed different release instead.
    auto prereleases = parsed;
    prereleases.xip_files.front().product_name = "Xcode 28.7 beta 2";
    prereleases.xip_files.push_back({"OWNED2871", "Xcode 28.7.1", "Other.xip",
        "/Developer_Tools/Other.xip", "https://download.developer.apple.com/Developer_Tools/Other.xip", 100});
    prereleases.xip_files.push_back({"OWNED287RC", "Xcode 28.7 RC", "RC.xip",
        "/Developer_Tools/RC.xip", "https://download.developer.apple.com/Developer_Tools/RC.xip", 50});
    passed = passed && prereleases.SmallestXipForProduct("Xcode 28.7") == nullptr &&
        prereleases.SmallestXipForProduct("Xcode 28.7 beta 2") == &prereleases.xip_files.front();
    if (parsed.xip_files.size() == 1) {
        const auto& file = parsed.xip_files.front();
        passed = passed && file.bytes == 2316428058ULL && file.product_name == "Xcode 28.7" &&
            file.url == "https://download.developer.apple.com/Developer_Tools/Xcode_28.7/Xcode_28.7_Apple_silicon.xip" &&
            file.filename.find("owned-catalog-secret") == std::string::npos;
    }
    for (const auto& invalid : {
            Catalog("//untrusted.example.invalid/archive.xip"),
            Catalog("/Developer_Tools/../archive.xip"),
            Catalog("/Developer_Tools/%2e%2e/archive.xip"),
            Catalog("/Developer_Tools/Xcode.xip", "https://untrusted.example.invalid"),
            Catalog("/Developer_Tools/Xcode.xip", "https://download.developer.apple.com", "0"),
            Catalog("/Developer_Tools/Xcode.xip", "https://download.developer.apple.com", "18446744073709551616")}) {
        passed = passed && AppleDownloadCatalog::ParseUntrusted(invalid).status == AppleCatalogStatus::InvalidResponse;
    }
    OpenFruit::AppleCookieJar empty;
    passed = passed && AppleDownloadCatalog::Fetch(empty).status == AppleCatalogStatus::CredentialsUnavailable;
    if (argc == 2) {
        std::ifstream input(argv[1], std::ios::binary);
        const std::string body((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        const auto snapshot = AppleDownloadCatalog::ParseUntrusted(body);
        passed = passed && snapshot.Succeeded() && !snapshot.origin_verified;
        bool matching_original = false;
        for (const auto& file : snapshot.xip_files)
            if (file.product_name == "Xcode 26.5" && file.bytes == 2316428058ULL &&
                file.remote_path == "/Developer_Tools/Xcode_26.5/Xcode_26.5_Apple_silicon.xip")
                matching_original = true;
        passed = passed && matching_original;
    }
    if (!passed) std::cerr << "Apple download catalog parsing contract failed.\n";
    return passed ? 0 : 1;
}
