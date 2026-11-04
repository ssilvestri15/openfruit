#pragma once
#include "config.hpp"
#include "sdk_catalog.hpp"
#include "json_value.hpp"
#include <filesystem>
#include <vector>

namespace OpenFruit {
enum class SDKReadStatus { Available, Unavailable, InvalidRequest };
enum class SDKReadProvenance {
    None, ConfiguredRegistration, SelectedPathOnly, ExplicitOverride, ManagedDiscovery
};
// Callers acquire this immutable configuration snapshot and any environment
// override at their boundary. Queries never discover or modify process state.
struct SDKReadRequest {
    Config configuration;
    std::filesystem::path managed_home;
    std::filesystem::path sdk_override;
};
struct SDKReadEntry {
    SDKCatalogEntry catalog;
    SDKReadProvenance provenance = SDKReadProvenance::None;
    JsonValue ToJson() const;
};
struct SDKReadListResult {
    std::vector<SDKReadEntry> entries;
    JsonValue ToJson() const;
};
struct SDKReadPathResult {
    SDKReadStatus status = SDKReadStatus::Unavailable;
    std::filesystem::path path;
    SDKReadProvenance provenance = SDKReadProvenance::None;
    SDKLayoutInspection layout;
    JsonValue ToJson() const;
};
// These operations report observed catalog/layout only. Available does not
// validate SDK provenance, compiler execution, overlays or Darwin behavior.
class SDKReadOperations {
public:
    static SDKReadListResult List(const SDKReadRequest&);
    static SDKReadPathResult Path(const SDKReadRequest&);
};
} // namespace OpenFruit
