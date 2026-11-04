#pragma once
#include "cancellation.hpp"
#include "json_value.hpp"
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
namespace OpenFruit {
using ApfsRead = std::function<std::string(std::uint64_t, std::uint64_t)>;
// Sink bytes are provisional. Callers must discard them unless complete=true.
using ApfsWrite = std::function<void(std::string_view)>;
JsonValue StreamApfsFile(const ApfsRead&, std::uint64_t bytes, const std::string& virtual_path,
    const ApfsWrite&, const std::function<void()>& control = {}, bool source_bound = false);
struct ApfsFileResult { JsonValue report; std::string bytes; };
ApfsFileResult ReadApfsFile(const ApfsRead&, std::uint64_t bytes, const std::string& virtual_path,
    const std::function<void()>& control = {}, bool source_bound = false);
JsonValue ExtractApfsStage(const std::filesystem::path& report, const std::string& virtual_path,
    const std::filesystem::path& fresh_directory, CancellationToken = {},
    std::chrono::steady_clock::time_point = std::chrono::steady_clock::time_point::max());
// Optional tree walk verifies sealed metadata hashes or ordinary object checksums
// and derives original paths and extent metadata. Neither mode mounts, approves
// file data or registers providers.
JsonValue InspectApfsMetadata(const ApfsRead&, std::uint64_t bytes, bool inspect_volume_trees = false);
// Derives the exact input and SHA256 from the authenticated decoded-stage report.
JsonValue InspectApfsStage(const std::filesystem::path&, CancellationToken = {},
    std::chrono::steady_clock::time_point = std::chrono::steady_clock::time_point::max(),
    bool inspect_volume_trees = false);
}
