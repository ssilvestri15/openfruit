#pragma once
#include <string>
#include <vector>
namespace OpenFruit {
struct PreparedEntitlementRequest;
class SigningCredential;
// The first blob is the primary CodeDirectory, followed by actual alternates.
// Derives signed Apple hash-agility values from these bytes and checks their
// bundle/team against the checked profile. Does not verify code pages, special
// slots, entitlements/resources, Apple trust or complete Mach-O/IPA validity.
bool BuildProvisioningCodeDirectoryCms(const PreparedEntitlementRequest& bundle,
    const SigningCredential& credential, const std::vector<std::string>& directories,
    std::string& cms, std::string& error);
}
