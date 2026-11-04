#pragma once
#include "json_value.hpp"
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
namespace OpenFruit {
class ArtifactLease;
struct IosTargetRuntimeResult {
    bool available = false;
    std::vector<std::filesystem::path> library_directories;
    // Keep the immutable publication alive through every compiler/linker
    // consumer, including copies of this result.
    std::shared_ptr<ArtifactLease> artifact_lease;
    JsonValue evidence = JsonValue::ObjectValue();
    std::string error;
};
// Acquire target libraries only from the authenticated archive paired with this
// managed SDK. Unavailable is explicit and does not prevent C-only builds.
// Previously authenticated, source-bound outputs can be reused without keeping
// the XIP: current SDK/tool inputs, content key and all libraries are revalidated.
IosTargetRuntimeResult EnsureIosTargetRuntime(const std::filesystem::path& sdk_path,
    const std::filesystem::path& llvm_bin, const std::string& deployment_target,
    const std::filesystem::path& managed_home);
}
