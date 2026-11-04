#pragma once

#include "project_selection.hpp"
#include "xcode_scheme.hpp"
#include "git_source_view.hpp"
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace OpenFruit {
struct ProjectMetadataAdmission {
    std::filesystem::path logical_path;
    std::string sha256;
    bool present = true;
};

struct ResolvedProjectSelection {
    std::filesystem::path input_path;
    std::filesystem::path project_bundle;
    std::string target_id;
    std::string configuration;
    ProjectBuildAction action = ProjectBuildAction::Running;
    bool explicit_selection = false;
    std::vector<std::filesystem::path> source_roots;
    std::optional<XcodeSchemeSelection> scheme;
    std::vector<ProjectMetadataAdmission> admissions;
};

// Application-side metadata admission. The project domain parses these exact
// bytes while the existing Git-aware resolver owns file/directory aliases.
class ProjectSelectionMetadata {
public:
    // Canonicalize physical container spelling without following a PBX file
    // alias away from its logical owning project.
    static std::filesystem::path CanonicalInput(const std::filesystem::path& path);
    static std::optional<ResolvedProjectSelection> Resolve(
        const ProjectInspectionRequest&, std::string* error = nullptr);
    // When admissions is supplied it must outlive the returned project: its
    // deferred xcconfig reader appends to the same admission set. Resolve owns
    // both in one scope and never returns a project retaining that pointer.
    static std::optional<XcodeProject> LoadProject(
        const std::filesystem::path& logical_project,
        const std::filesystem::path& products = {},
        std::vector<ProjectMetadataAdmission>* admissions = nullptr,
        const std::filesystem::path& metadata_root = {});
    static std::optional<std::string> Read(
        const std::filesystem::path& logical_file,
        std::vector<ProjectMetadataAdmission>* admissions = nullptr);
    // Re-map only through admitted source mappings; preserve UUID, purpose and
    // configuration and verify every preselected metadata digest in the view.
    static ResolvedProjectSelection Project(
        const ResolvedProjectSelection&, const GitSourceView&);
};
} // namespace OpenFruit
