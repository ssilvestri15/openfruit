#pragma once

#include "win32_process.hpp"
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace OpenFruit {

struct SourceViewMapping {
    std::filesystem::path original;
    std::filesystem::path resolved;
    std::filesystem::path projected;
};

struct GitSourceView {
    std::filesystem::path root;
    std::vector<SourceViewMapping> mappings;
};

// Publish a fresh independent copy outside the source tree. Git mode 120000
// supplies placeholder identity; ordinary short files are never interpreted.
// File aliases preserve canonical identity through relative links inside the view.
// Finite directory back-references stay inside the view as relative aliases.
// Throws on cancellation, conflicts, missing targets, non-terminating link
// resolution, root escapes or unavailable native directory-alias support.
// The caller owns the published directory; an existing destination is refused.
GitSourceView CreateGitSourceView(const std::filesystem::path& source,
                                  const std::filesystem::path& destination,
                                  const ProcessRunOptions& control = {});

struct GitSourceViewSyncStats {
    std::uint64_t files_copied = 0;
    std::uint64_t files_reused = 0;
    std::uint64_t bytes_copied = 0;
    std::uint64_t entries_removed = 0;
};
struct GitSourceViewSyncOptions {
    bool resolve_git_placeholders = true;
    bool include_git_metadata = false;
    std::vector<std::filesystem::path> excluded_root_entries;
    // Stable logical owner, supplied only by a caller that validates that owner.
    // Allows a physical input-root relocation without moving the output slot.
    std::string source_identity;
    // Files the caller rewrites in the view after every synchronization (for
    // example relocated Git metadata). While their source is unchanged since
    // the last synchronization, the rewritten output is kept as it is.
    std::vector<std::filesystem::path> caller_maintained_files;
};
struct GitSourceViewSyncResult {
    GitSourceView view;
    GitSourceViewSyncStats stats;
};

// Caller holds the owning workspace lease through synchronization AND use.
// The external receipt authorizes only recorded output entries; interrupted
// updates retain ownership and are repaired on the next call. Unchanged files
// are checked by content, independently of timestamps, and are never rewritten.
GitSourceViewSyncResult SynchronizeGitSourceView(const std::filesystem::path& source,
    const std::filesystem::path& destination, const std::filesystem::path& receipt_path,
    const ProcessRunOptions& control = {}, const GitSourceViewSyncOptions& options = {});

// Disable Git placeholder lookup only for tool-owned metadata/artifact trees;
// source checkouts must retain the default Git-aware resolution policy.
// Alternate root spelling is accepted only when the requested physical root
// prefix canonicalizes to the exact admitted root; suffix lookup is unchanged.
std::filesystem::path ResolveGitSourcePath(const std::filesystem::path& source,
    const std::filesystem::path& path, const ProcessRunOptions& control = {},
    bool resolve_git_placeholders = true);

// Optional metadata has a typed missing result. Only an ordinary missing
// component from the caller's path returns nullopt. Missing indexed placeholders
// and missing components of a link target remain integrity errors. Relative
// requests are anchored to source, independently of the process working directory.
std::optional<std::filesystem::path> TryResolveGitSourcePath(
    const std::filesystem::path& source, const std::filesystem::path& path,
    const ProcessRunOptions& control = {}, bool resolve_git_placeholders = true);

} // namespace OpenFruit
