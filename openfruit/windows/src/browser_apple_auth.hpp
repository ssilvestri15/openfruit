#pragma once

#include "config.hpp"
#include <filesystem>
#include <string>

namespace OpenFruit {

enum class BrowserLoginStatus {
    Succeeded, BrowserUnavailable, BrowserLaunchFailed, BrowserProtocolFailed,
    TimedOut, BrowserClosed, CatalogRejected, ProtectionFailed, CleanupFailed
};

struct BrowserLoginResult {
    BrowserLoginStatus status = BrowserLoginStatus::BrowserUnavailable;
    std::string browser;
    std::string detail;
    bool Succeeded() const noexcept { return status == BrowserLoginStatus::Succeeded; }
};

class BrowserAppleAuth {
public:
    static BrowserLoginResult Login(Secrets& secrets, const std::filesystem::path& metadata);
};

} // namespace OpenFruit
