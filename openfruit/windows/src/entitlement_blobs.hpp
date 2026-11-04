#pragma once
#include "macho_code_directory.hpp"
namespace OpenFruit {
struct PreparedEntitlementRequest;
// Version-1 CoreEntitlements representation. These generic byte contracts do
// not authorize rights; provisioning APIs below revalidate their source.
bool EncodeEntitlementsDer(std::string_view xml, std::string& der, std::string& error);
bool VerifyEntitlementsDer(std::string_view xml, std::string_view der, std::string& error);
// Entitlement-derived execution bits only; the main-binary bit comes from
// Mach-O metadata. Nonboolean values do not enable execution privileges.
bool DeriveEntitlementExecutionFlags(std::string_view xml, uint64_t& flags, std::string& error);
// Atomic pair of complete XML/DER signature blobs in slots 5/7. Other signature
// inputs (requirements/resources) are produced by their respective owners.
bool BuildProvisioningEntitlementBlobs(const PreparedEntitlementRequest& binding,
    CodeDirectorySpecialSlots& blobs, std::string& error);
bool ValidateProvisioningEntitlementBlobs(const PreparedEntitlementRequest& binding,
    const CodeDirectorySpecialSlots& blobs, std::string& error);
}
