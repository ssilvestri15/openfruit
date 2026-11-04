#pragma once

#include "config.hpp"
#include "json_value.hpp"

#include <string>
#include <functional>
#include <cstdint>
#include <vector>

namespace OpenFruit {

struct DependencyProgress {
    std::string tool_name;
    std::string phase; // "checking", "downloading", "extracting", "installing", "registering_path", "completed", "failed"
    std::uint64_t current_bytes = 0;
    std::uint64_t total_bytes = 0;
    std::string message;
};

using DependencyProgressCallback = std::function<void(const DependencyProgress&)>;

struct DependencyUpdateResult {
    bool success = true;
    std::vector<std::string> updated_tools;
    std::vector<std::string> path_entries_added;
    std::vector<std::string> errors;

    JsonValue ToJson() const;
};

class DependencyUpdater {
public:
    // Download and install all required/missing software tools, showing progress for each tool,
    // and ensuring each tool and OpenFruit bin are registered into the Windows PATH.
    static DependencyUpdateResult UpdateAll(
        Config& config,
        bool silent = true,
        DependencyProgressCallback on_progress = nullptr
    );

    // Ensure a specific directory is permanently added to the user's Windows PATH (HKCU\Environment)
    // and broadcast the WM_SETTINGCHANGE message to the system.
    static bool EnsureInPath(const std::wstring& directory_path, bool* out_already_present = nullptr);

    // Register OpenFruit (%LOCALAPPDATA%\OpenFruit\bin) into the Windows PATH.
    static bool EnsureOpenFruitInPath();
};

} // namespace OpenFruit
