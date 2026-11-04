#pragma once
#include <filesystem>
#include <string>
namespace OpenFruit {
enum class SDKAcquisitionStatus {
    Succeeded, InvalidVersion, InvalidManagedHome, CredentialsUnavailable,
    CatalogFailure, VersionUnavailable, TransferFailure, VerificationFailure,
    AlreadyRegistered, PublicationFailure
};
struct SDKAcquisitionResult {
    SDKAcquisitionStatus status = SDKAcquisitionStatus::CatalogFailure;
    std::filesystem::path destination;
    std::string message;
    bool publisher_verified = false;
    bool Succeeded() const noexcept { return status == SDKAcquisitionStatus::Succeeded; }
};
// Acquisition belongs to SDK management. Credential storage never downloads or
// creates SDK installations. No installation is published without a provider.
class SDKAcquisition {
public:
    static SDKAcquisitionResult Download(const std::string& version, const std::filesystem::path& managed_home);
};
} // namespace OpenFruit
