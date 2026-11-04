#include "project_inspection.hpp"
#include "win32_process.hpp"
#include "project_selection_metadata.hpp"
#include <stdexcept>

namespace OpenFruit {
ProjectInspectionResult ProjectInspection::Inspect(const std::wstring& project_path, const std::string& configuration) {
    ProjectInspectionResult result;
    result.project = UniversalProject::Inspect(project_path, configuration);
    result.success = result.project.is_valid;
    if (!result.success) {
        result.error_message = "Failed to discover or parse project at path.";
    }
    return result;
}

ProjectInspectionResult ProjectInspection::Inspect(const ProjectInspectionRequest& request) {
    ProjectInspectionResult result;
    try {
        const auto selection = ProjectSelectionMetadata::Resolve(request, &result.error_message);
        if (!selection) return result;
        GitSourceView identity;
        for (const auto& root : selection->source_roots) identity.mappings.push_back({root, root, root});
        (void)ProjectSelectionMetadata::Project(*selection, identity);
        auto admissions = selection->admissions;
        const auto project = ProjectSelectionMetadata::LoadProject(selection->project_bundle, {}, &admissions);
        if (!project) throw std::runtime_error("OPENFRUIT inspection: cannot parse selected project.");
        const auto target = project->FindTarget(selection->target_id);
        if (!target || target->id != selection->target_id)
            throw std::runtime_error("OPENFRUIT inspection: selected UUID is missing.");
        result.project = UniversalProject::InspectSelected(*project, *target,
            selection->configuration, selection->action, selection->scheme);
        (void)ProjectSelectionMetadata::Project(*selection, identity);
        result.success = result.project.is_valid;
        if (!result.success) result.error_message = "Selected target is unsupported or has no buildable inputs.";
    } catch (const std::exception& failure) { result.error_message = failure.what(); }
    return result;
}

JsonValue ProjectInspectionResult::ToJson() const {
    auto json = JsonValue::ObjectValue();
    json.Set("success", JsonValue::Boolean(success));
    if (!success) {
        json.Set("error", JsonValue::String(error_message));
        return json;
    }
    json.Set("target_uuid", JsonValue::String(project.target_id));
    json.Set("project_path", JsonValue::String(Win32Process::ToNarrow(project.pbxproj_path)));
    json.Set("selection_frozen", JsonValue::Boolean(project.selection_frozen));
    json.Set("scheme_path", JsonValue::String(Win32Process::ToNarrow(project.selected_scheme_file.wstring())));
    json.Set("scheme_sha256", JsonValue::String(project.selected_scheme_sha256));
    json.Set("project_name", JsonValue::String(Win32Process::ToNarrow(project.project_name)));
    json.Set("product_name", JsonValue::String(Win32Process::ToNarrow(project.product_name)));
    json.Set("module_name", JsonValue::String(Win32Process::ToNarrow(project.module_name)));
    json.Set("display_name", JsonValue::String(Win32Process::ToNarrow(project.display_name)));
    json.Set("bundle_id", JsonValue::String(Win32Process::ToNarrow(project.bundle_id)));
    json.Set("minimum_os_version", JsonValue::String(Win32Process::ToNarrow(project.minimum_os_version)));
    json.Set("swift_version", JsonValue::String(Win32Process::ToNarrow(project.swift_version)));
    json.Set("configuration", JsonValue::String(Win32Process::ToNarrow(project.configuration)));
    json.Set("swift_source_count", JsonValue::Number(std::to_string(project.swift_sources.size())));
    json.Set("c_source_count", JsonValue::Number(std::to_string(project.c_sources.size())));
    json.Set("resource_bundle_count", JsonValue::Number(std::to_string(project.resource_bundles.size())));
    json.Set("embedded_framework_count", JsonValue::Number(std::to_string(project.embedded_frameworks.size())));
    json.Set("system_framework_count", JsonValue::Number(std::to_string(project.system_frameworks.size())));

    auto frameworks = JsonValue::ArrayValue();
    for (const auto& fw : project.system_frameworks) {
        frameworks.ArrayItems().push_back(JsonValue::String(Win32Process::ToNarrow(fw)));
    }
    json.Set("system_frameworks", std::move(frameworks));

    return json;
}
}
