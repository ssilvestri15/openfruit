#pragma once
#include "git_source_view.hpp"
#include "artifact_store.hpp"
#include <map>

namespace OpenFruit {
struct SwiftPMSourceWorkspace {
    std::filesystem::path scratch;
    std::filesystem::path package;
    std::filesystem::path ready_metadata;
    std::filesystem::path cache_path;
    std::shared_ptr<ArtifactLease> lease;
    bool reused = false;
    GitSourceViewSyncStats source_sync_stats;
    GitSourceViewSyncStats toolstate_sync_stats;
    GitSourceView root_view;
    std::map<std::string, GitSourceView> dependencies;
};

// The caller must hold exclusive ownership of a resolved, quiescent resolver
// workspace. Clone its execution state independently and expand source-control
// checkout aliases before SwiftPM reads its graph. No edits or restores occur
// in the input workspace. A caller may lend an already independent source view
// for fileSystem dependencies; it must own that view throughout graph and build
// consumption. Absolute manifest references retain their admitted view paths.
// Git repository roots inside the exclusively owned resolver scratch may also
// be consumed at their original paths, with explicit identity provenance.
// Unadmitted local/registry/edited states fail closed.
// An explicit shared cache stays outside the independent snapshot and must be
// held exclusively by the caller through graph/build consumption. Its contents
// are not copied or linked. With no override, fresh mode copies output/shared-cache;
// reusable mode keeps its existing owned s/shared-cache (initially empty).
// With reuse_context, destination is a persistent leased container: s holds
// execution state, i holds source ownership receipts. The lease must outlive all
// consumers of the returned products. Context identifies build dimensions, not
// source contents; synchronization validates and updates individual source inputs.
SwiftPMSourceWorkspace PrepareSwiftPMSourceWorkspace(
    const std::filesystem::path& swift,
    const std::filesystem::path& package,
    const std::filesystem::path& resolver_scratch,
    const std::filesystem::path& destination,
    const std::vector<std::pair<std::wstring, std::wstring>>& environment,
    const ProcessRunOptions& control = {},
    const GitSourceView* independent_sources = nullptr,
    const std::filesystem::path& shared_cache = {},
    const std::string& reuse_context = {});
} // namespace OpenFruit
