#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace OpenFruit {

// A build purpose selects BuildActionEntry membership. It does not execute a
// scheme's test runner, launch, analyzer or archive operation.
enum class ProjectBuildAction {
    LegacyProductBuild,
    Running,
    Testing,
    Profiling,
    Analyzing,
    Archiving
};

struct ProjectTargetSelection {
    // Optional for a single project; workspace UUID ambiguity requires an owner.
    std::filesystem::path project;
    std::string uuid;
};

// Data-only application input. Resolve it once before execution and preserve
// the resolved project/UUID/configuration through the source view and consumers.
// Existing overloads may explicitly request LegacyProductBuild for compatibility.
struct ProjectInspectionRequest {
    std::filesystem::path path;
    // A shared scheme name or an explicit .xcscheme file path, never a target name.
    std::optional<std::string> scheme;
    std::optional<ProjectTargetSelection> target;
    std::optional<std::string> configuration;
    ProjectBuildAction action = ProjectBuildAction::Running;
};

} // namespace OpenFruit
