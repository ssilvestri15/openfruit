#pragma once

#include <string>
#include <memory>
#include <utility>
#include <vector>

namespace OpenFruit {

struct DarwinMacroProvider;
struct CompilerPluginConfiguration {
    std::vector<std::wstring> arguments;
    std::vector<std::pair<std::wstring, std::wstring>> environment;
    std::shared_ptr<const DarwinMacroProvider> original_provider;
    std::wstring original_host;
};

class MacroEngine {
public:
    // Native plugins from the selected Windows compiler retain priority.
    // Original plugins are admitted only through the selected managed SDK receipt;
    // their frontend-only registration is forwarded through the Swift driver.
    // False clears output; process environment changes are returned, never global.
    static bool ConfigureCompilerPlugins(
        const std::wstring& repo_root,
        const std::wstring& selected_toolchain_bin,
        const std::wstring& selected_sdk,
        CompilerPluginConfiguration& output,
        std::string& error,
        const std::vector<std::string>& preferred_native_modules = {}
    );
    // Starts, outside any build job, the persistent broker of warm original
    // servers that this configuration's hosts will use, so its bootstrap
    // overlaps the build and later builds reuse it. A broker already serving
    // the same configuration makes the started process exit at once.
    static void PrewarmOriginalProvider(const CompilerPluginConfiguration& configuration) noexcept;
    // Prewarms now and again periodically until the returned handle is
    // released. Each prewarm refreshes a serving broker's idle clock or starts
    // a new one outside the build jobs, so a long phase without macro
    // requests never leaves hosts to start a broker inside a compile job.
    static std::shared_ptr<void> KeepOriginalProviderWarm(const CompilerPluginConfiguration& configuration);

    // Source-built native executables may appear only in the final compiler
    // invocation. Remove exact managed-original registrations they supersede,
    // including their complete -Xfrontend wrappers; preserve other registrations.
    static void PreferNativePluginExecutables(
        std::vector<std::wstring>& arguments,
        const DarwinMacroProvider& provider,
        const std::wstring& managed_host
    );

    // Resolve an ABI-matched native Windows provider. False clears outputs;
    // this never selects WSL/Darling or executes an original Mach-O plugin.
    static bool EnsureMacroBridge(
        const std::wstring& repo_root,
        std::wstring& out_bridge_path,
        std::wstring& out_plugin_view,
        const std::wstring& selected_toolchain_bin = {}
    );

    static std::vector<std::wstring>
    GetCompilerPluginArguments(
        const std::wstring& repo_root
    );
};

} // namespace OpenFruit
