#pragma once
#include "universal_project.hpp"
#include "json_value.hpp"
#include <string>

namespace OpenFruit {
struct ProjectInspectionResult {
    bool success = false;
    std::string error_message;
    DiscoveredProject project;
    JsonValue ToJson() const;
};

class ProjectInspection {
public:
    static ProjectInspectionResult Inspect(const ProjectInspectionRequest& request);
    static ProjectInspectionResult Inspect(const std::wstring& project_path, const std::string& configuration = "Debug");
};
}
