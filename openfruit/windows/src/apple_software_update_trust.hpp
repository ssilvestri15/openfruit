#pragma once
#include <cstdint>
#include <vector>
namespace OpenFruit {
struct AppleSoftwareUpdateTrust {
    bool chain_valid = false;
    bool revocation_valid = false;
};
// Validates the embedded XAR chain against Apple's published Root and Software
// Update CA certificates, production signing usage and revocation state.
// Neither result binds the archive to a trusted download catalog.
AppleSoftwareUpdateTrust VerifyAppleSoftwareUpdateChain(
    const std::vector<std::vector<std::uint8_t>>& certificates);
}
