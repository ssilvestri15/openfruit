#pragma once

#include "project_selection.hpp"
#include "xcode_project.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace OpenFruit {

struct XcodeSchemeSelection {
    std::filesystem::path scheme_file;
    std::filesystem::path owner_container;
    ProjectBuildAction action = ProjectBuildAction::Running;
    std::string content_sha256;
    std::string configuration;
    // Build-purpose membership, in XML order; never PBX dependency edges.
    std::vector<XcodeTargetDependency> build_entries;
    std::optional<XcodeTargetDependency> runnable;
    std::optional<bool> build_implicit_dependencies;
    std::optional<bool> parallelize_buildables;
    std::vector<std::string> diagnostics;
};

class XcodeScheme {
public:
    // Pure metadata parsing: logical paths provide ownership, while callers
    // admit the bytes (including authoritative Git mode-120000 resolution).
    static std::optional<XcodeSchemeSelection> Parse(
        const std::filesystem::path& logical_scheme_path,
        const std::filesystem::path& owner_container,
        std::string_view bytes, ProjectBuildAction action,
        std::string* error = nullptr);
    static std::optional<XcodeSchemeSelection> Inspect(
        const std::filesystem::path& scheme_path,
        const std::filesystem::path& owner_container,
        ProjectBuildAction action, std::string* error = nullptr);
};

struct XcodeWorkspaceContents {
    std::vector<std::filesystem::path> projects;
    // Preserve non-project references without inventing target identities.
    std::vector<std::filesystem::path> other_references;
};

class XcodeWorkspace {
public:
    // This reads no files or directory contents. Group-relative bases are
    // carried through the XML structure, rather than flattened by filename.
    static std::optional<XcodeWorkspaceContents> Parse(
        const std::filesystem::path& logical_workspace_path,
        std::string_view bytes, std::string* error = nullptr);
};

} // namespace OpenFruit
