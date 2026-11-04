#pragma once
#include "git_source_view.hpp"
#include "artifact_store.hpp"
#include "universal_project.hpp"
#include "project_selection_metadata.hpp"

namespace OpenFruit {
struct BuildWorkspace {
    std::filesystem::path original_root;
    std::filesystem::path original_target;
    std::filesystem::path root;
    std::filesystem::path target;
    GitSourceView sources;
    DiscoveredProject project;
    std::shared_ptr<ArtifactLease> lease;
    GitSourceViewSyncStats sync_stats;
};

// Discover the containing checkout and re-evaluate the selected project from an
// independent source view. The original directory basename is preserved.
std::filesystem::path FindBuildSourceRoot(const std::filesystem::path& target);
std::filesystem::path StableBuildWorkspacePath(const std::filesystem::path& parent,
    const std::filesystem::path& target, const std::string& configuration);
BuildWorkspace PrepareBuildWorkspace(const std::filesystem::path& target,
    const std::filesystem::path& workspace,
    const std::string& configuration, const ProcessRunOptions& control = {},
    bool reuse = false);

BuildWorkspace PrepareBuildWorkspace(const ProjectInspectionRequest& request,
    const ResolvedProjectSelection& selection, const std::filesystem::path& workspace,
    const ProcessRunOptions& control = {}, bool reuse = false);
} // namespace OpenFruit
