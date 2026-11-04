#pragma once

#include "config.hpp"
#include "event_journal.hpp"
#include "project_selection.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace OpenFruit {

enum class BuildProductMode { BuildAndSign, UnsignedPackage };
enum class BuildOutcome { Succeeded, Failed, Cancelled, TimedOut, InvalidRequest };

// Transport-neutral input. CLI and local adapters resolve relative selectors at
// their own input boundary, then submit exactly this request to the same service.
// Optional values preserve the distinction between absent and explicit overrides.
struct BuildRequest {
    ProjectInspectionRequest project;
    BuildProductMode mode = BuildProductMode::BuildAndSign;
    std::wstring configuration = L"debug";
    unsigned int jobs = 0;
    std::optional<std::wstring> sdk_path;
    std::optional<std::wstring> sdk_version;
    std::optional<std::wstring> cache_path;
    std::optional<std::wstring> bundle_id;
    std::optional<std::wstring> display_name;
    std::optional<std::wstring> p12_path;
    std::optional<std::wstring> provisioning_profile_path;
    bool match_profile_bundle_id = false;
    bool deploy = false;
    // Link the preview agent into the application (IDE canvas preview).
    bool preview = false;
    bool pack_cache = false;
    std::wstring device_udid;
};

// Internal, non-serializable invocation snapshot. Never put Config/Secrets into
// adapter requests, event payloads or persisted operation results. Credential
// references are resolved by the host before it constructs this context.
struct BuildContext {
    std::filesystem::path repository_root;
    Config configuration;
    Secrets credentials;
    OperationContextPtr operation;
    std::shared_ptr<EventJournal> journal;
};

struct BuildResult {
    BuildOutcome outcome = BuildOutcome::Failed;
    int exit_code = 1;
    std::string diagnostic_code;
    std::filesystem::path workspace;
    std::filesystem::path product_path;
    std::filesystem::path unsigned_ipa;
    std::filesystem::path signed_ipa;
    JsonValue ToJson() const;
};

class ApplicationService {
public:
    // Owns the existing native pipeline, not an alternate backend. Request and
    // context are never mutated. Exceptions retain the existing caller boundary.
    // Legacy tool selection still modifies process environment: hosts must
    // serialize build execution until that separate contract is completed.
    static BuildResult Build(const BuildRequest&, const BuildContext&);
};

} // namespace OpenFruit
