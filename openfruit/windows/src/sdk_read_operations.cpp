#include "sdk_read_operations.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
const char* Provenance(SDKReadProvenance provenance) {
    switch (provenance) {
    case SDKReadProvenance::ConfiguredRegistration: return "configured_registration";
    case SDKReadProvenance::SelectedPathOnly: return "selected_path_only";
    case SDKReadProvenance::ExplicitOverride: return "explicit_override";
    case SDKReadProvenance::ManagedDiscovery: return "managed_discovery";
    default: return "none";
    }
}
const char* Status(SDKReadStatus status) {
    switch (status) {
    case SDKReadStatus::Available: return "available";
    case SDKReadStatus::InvalidRequest: return "invalid_request";
    default: return "unavailable";
    }
}
JsonValue Layout(const SDKLayoutInspection& layout) {
    auto result = JsonValue::ObjectValue();
    result.Set("directory", JsonValue::Boolean(layout.directory));
    result.Set("libraries", JsonValue::Boolean(layout.libraries));
    result.Set("frameworks", JsonValue::Boolean(layout.frameworks));
    result.Set("settings", JsonValue::Boolean(layout.settings));
    result.Set("usable", JsonValue::Boolean(layout.Usable()));
    return result;
}
JsonValue Observation(const char* operation) {
    auto result = JsonValue::ObjectValue();
    result.Set("schema", JsonValue::String("openfruit.sdk-read.v1"));
    result.Set("operation", JsonValue::String(operation));
    result.Set("inspection_basis", JsonValue::String("filesystem_layout_only"));
    result.Set("tool_execution_verified", JsonValue::Boolean(false));
    return result;
}
}
JsonValue SDKReadEntry::ToJson() const {
    auto result = JsonValue::ObjectValue();
    result.Set("version", JsonValue::String(Win32Process::ToNarrow(catalog.registration.version)));
    result.Set("path", JsonValue::String(Win32Process::ToNarrow(catalog.registration.path.wstring())));
    result.Set("selected", JsonValue::Boolean(catalog.selected));
    result.Set("provenance", JsonValue::String(Provenance(provenance)));
    result.Set("layout", Layout(catalog.layout));
    return result;
}
JsonValue SDKReadListResult::ToJson() const {
    auto result = Observation("list");
    result.Set("catalog_query_succeeded", JsonValue::Boolean(true));
    auto catalog = JsonValue::ArrayValue();
    for (const auto& entry : entries) catalog.ArrayItems().push_back(entry.ToJson());
    result.Set("entries", std::move(catalog));
    return result;
}
JsonValue SDKReadPathResult::ToJson() const {
    auto result = Observation("path");
    result.Set("status", JsonValue::String(Status(status)));
    result.Set("path", JsonValue::String(Win32Process::ToNarrow(path.wstring())));
    result.Set("provenance", JsonValue::String(Provenance(provenance)));
    result.Set("layout", Layout(layout));
    return result;
}
SDKReadListResult SDKReadOperations::List(const SDKReadRequest& request) {
    std::vector<SDKRegistration> registrations;
    for (const auto& [version, path] : request.configuration.ios_sdk_paths)
        registrations.push_back({version, fs::path(path)});
    SDKReadListResult result;
    const bool path_only = registrations.empty();
    for (auto entry : SDKCatalog::List(registrations, request.configuration.ios_sdk_version,
            fs::path(request.configuration.sdk_path)))
        result.entries.push_back({std::move(entry), path_only ? SDKReadProvenance::SelectedPathOnly
                                                            : SDKReadProvenance::ConfiguredRegistration});
    return result;
}
SDKReadPathResult SDKReadOperations::Path(const SDKReadRequest& request) {
    SDKReadPathResult result;
    if (!request.managed_home.empty() && !request.managed_home.is_absolute()) {
        result.status = SDKReadStatus::InvalidRequest;
        return result;
    }
    fs::path configured;
    if (!request.sdk_override.empty()) {
        result.provenance = SDKReadProvenance::ExplicitOverride;
        configured = request.sdk_override;
    } else {
        const auto& config = request.configuration;
        const auto selected = config.ios_sdk_paths.find(config.ios_sdk_version);
        if (!config.ios_sdk_version.empty() && selected != config.ios_sdk_paths.end() && !selected->second.empty()) {
            configured = fs::path(selected->second);
            result.provenance = SDKReadProvenance::ConfiguredRegistration;
        } else if (!config.sdk_path.empty()) {
            configured = fs::path(config.sdk_path);
            result.provenance = SDKReadProvenance::SelectedPathOnly;
        }
    }
    if (!configured.empty() && !configured.is_absolute()) {
        if (!request.sdk_override.empty()) {
            result.status = SDKReadStatus::InvalidRequest;
            return result;
        }
        // A stale relative persisted path cannot be resolved using ambient CWD.
        // Keep managed fallback without changing the caller's selection.
        configured.clear();
    }
    // Explicit overrides are a requested input, never permission to silently
    // choose a different SDK. Persisted stale paths retain the existing managed
    // fallback policy, with its actual provenance reported separately.
    const auto resolved = ToolPaths::IosSdk(request.sdk_override.empty() ? request.managed_home : fs::path{}, configured);
    if (resolved.empty()) {
        result.layout = SDKCatalog::Inspect(configured);
        return result;
    }
    result.path = resolved;
    result.layout = SDKCatalog::Inspect(resolved);
    result.status = result.layout.Usable() ? SDKReadStatus::Available : SDKReadStatus::Unavailable;
    if (configured.empty() || resolved != configured) result.provenance = SDKReadProvenance::ManagedDiscovery;
    return result;
}
} // namespace OpenFruit
