#pragma once

#include "sdk_manager.hpp"

#include <filesystem>
#include <vector>
#include <string>

namespace OpenFruit {

// The device port the preview agent listens on (loopback only); the host
// reaches it through usbmux.
inline constexpr std::uint16_t kPreviewAgentPort = 47101;

// Compiles the OPENFRUIT-owned preview agent (native/preview-agent) for the
// selected iOS SDK, reusing a cached object keyed by its source, compiler and
// SDK. Returns an empty path on failure.
std::filesystem::path EnsurePreviewAgentObject(
    const std::filesystem::path& repo_root,
    const std::filesystem::path& clang_executable,
    const SDKInfo& sdk_info
);

// System frameworks the agent object references.
const std::vector<std::wstring>& PreviewAgentFrameworks();

} // namespace OpenFruit
