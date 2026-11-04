#pragma once
#include "json_value.hpp"
#include "win32_process.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace OpenFruit {
enum class CacheReadStatus { Complete, Partial, InvalidRequest, Cancelled, TimedOut };
struct CacheReadRequest {
    std::filesystem::path user_state_root, managed_cache_root;
    std::size_t max_entries = 4096, max_nodes = 100000, max_depth = 64;
    ProcessRunOptions control;
};
struct CacheEntryObservation {
    std::filesystem::path path;
    std::string classification;
    // Marker presence is not ownership, an inactive consumer or safe deletion.
    std::string consumer_marker = "not_inspected";
    std::optional<std::uint64_t> observed_logical_file_bytes;
    std::uint64_t observed_files = 0, skipped_reparse = 0, errors = 0;
    bool measurement_complete = false;
    JsonValue ToJson() const;
};
struct CacheNamespaceObservation {
    std::filesystem::path path;
    std::string name, classification, retention_scope, observation;
    std::vector<CacheEntryObservation> entries;
    std::optional<std::uint64_t> observed_logical_file_bytes;
    std::uint64_t observed_files = 0, skipped_reparse = 0, errors = 0;
    bool measurement_complete = false;
    JsonValue ToJson() const;
};
struct CacheReadResult {
    CacheReadStatus status = CacheReadStatus::Complete;
    std::vector<CacheNamespaceObservation> namespaces;
    std::size_t visited_nodes = 0, entry_count = 0;
    std::uint64_t error_count = 0;
    bool limit_reached = false, deadline_exceeded = false, overflow = false;
    JsonValue ToJson() const;
};
// Metadata-only observation over explicit roots, never a cache manager. Does
// not read configuration, environment, file contents or secret directories.
// No import/prune/lease acquisition/touch is performed. Logical name lengths
// include repeated hardlink names; physical/reclaimable space stays unknown.
class CacheReadOperations {
public:
    static CacheReadResult Inspect(const CacheReadRequest&);
};
} // namespace OpenFruit
