#pragma once
#include "macho_code_directory.hpp"
namespace OpenFruit {
struct PreparedEntitlementRequest;
class SigningCredential;
// Byte-level writer/verifier for the current thin-64-bit layout contract.
// External slots 1/3 are original Info.plist/CodeResources bytes; embedded
// slots 2/5/7 are complete framed requirements/XML/DER blobs. Slots 5/7 are
// mandatory, equivalent and bound to reconstructed profile-authorized inputs.
// Resources/requirements semantics and Apple trust remain outside this contract.
// Returns a complete in-memory image; source/files are never modified here.
bool SignProvisionedThinMachO(std::string_view image, const PreparedEntitlementRequest& binding,
    const SigningCredential& credential, const CodeDirectorySpecialSlots& external_slots,
    const CodeDirectorySpecialSlots& embedded_blobs, std::string& signed_image, std::string& error);
bool VerifyProvisionedThinMachO(std::string_view image, const PreparedEntitlementRequest& binding,
    const SigningCredential& credential, const CodeDirectorySpecialSlots& external_slots,
    const CodeDirectorySpecialSlots& expected_embedded_blobs, std::string& error);
}
