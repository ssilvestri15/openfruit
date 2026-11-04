#include "macro_engine.hpp"
#include "darwin_macro_provider.hpp"
#include "tool_paths.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <unordered_set>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
// Extracted Apple plugins may have Windows-looking suffixes but Mach-O bytes.
bool IsNativeHostImage(const fs::path& path, bool dll) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) return false;
    const auto length = static_cast<std::streamoff>(input.tellg());
    if (length < static_cast<std::streamoff>(sizeof(IMAGE_DOS_HEADER))) return false;
    input.seekg(0);
    IMAGE_DOS_HEADER dos{};
    if (!input.read(reinterpret_cast<char*>(&dos), sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos))) return false;
    const auto offset = static_cast<std::streamoff>(dos.e_lfanew);
    if (offset > length - static_cast<std::streamoff>(sizeof(IMAGE_NT_HEADERS64))) return false;
    input.seekg(offset);
    IMAGE_NT_HEADERS64 nt{};
    if (!input.read(reinterpret_cast<char*>(&nt), sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        !(nt.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) ||
        ((nt.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0) != dll) return false;
#if defined(_M_ARM64) || defined(__aarch64__)
    return nt.FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64;
#else
    return nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
#endif
}
bool ResolveNativeProvider(const fs::path& bin, std::wstring& server, std::wstring& view) {
    server.clear(); view.clear();
    if (bin.empty()) return false;
    const fs::path executable = bin / "swift-plugin-server.exe";
    if (!IsNativeHostImage(executable, false)) return false;
    server = executable.wstring(); view = bin.wstring();
    return true;
}
std::vector<std::wstring> NativeArguments(const fs::path& bin) {
    std::vector<std::wstring> arguments;
    std::error_code error;
    if (!bin.empty() && fs::is_directory(bin, error) && !error) {
        arguments.push_back(L"-plugin-path"); arguments.push_back(bin.wstring());
    }
    std::wstring server, view;
    if (ResolveNativeProvider(bin, server, view)) {
        arguments.push_back(L"-external-plugin-path"); arguments.push_back(view + L"#" + server);
    }
    return arguments;
}
} // namespace
bool MacroEngine::ConfigureCompilerPlugins(const std::wstring& repo_root,
    const std::wstring& selected_toolchain_bin, const std::wstring& selected_sdk,
    CompilerPluginConfiguration& output, std::string& error,
    const std::vector<std::string>& preferred_native_modules) {
    output = {}; error.clear();
    try {
        const fs::path bin = selected_toolchain_bin.empty()
            ? ToolPaths::SwiftBin(fs::path(repo_root)) : fs::path(selected_toolchain_bin);
        CompilerPluginConfiguration configuration;
        configuration.arguments = NativeArguments(bin);
        if (selected_sdk.empty()) { output = std::move(configuration); return true; }
        const fs::path managed_root = ToolPaths::LocalHome();
        const fs::path receipt = FindDarwinMacroProviderReceipt(managed_root, fs::path(selected_sdk));
        if (receipt.empty()) { output = std::move(configuration); return true; }
        auto provider = std::make_shared<DarwinMacroProvider>();
        if (!ReadDarwinMacroProvider(receipt, managed_root, *provider, error, fs::path(selected_sdk))) {
            if (error.empty()) error = "Invalid managed original macro provider receipt: " + receipt.string();
            return false;
        }
        std::unordered_set<std::string> preferred(preferred_native_modules.begin(), preferred_native_modules.end());
        std::wstring native_server, native_view;
        const bool native_provider = ResolveNativeProvider(bin, native_server, native_view);
        std::vector<const DarwinMacroProviderPlugin*> original_plugins;
        for (const auto& plugin : provider->plugins) {
            if (preferred.contains(plugin.module)) continue;
            if (native_provider &&
                (IsNativeHostImage(bin / (plugin.module + ".dll"), true) ||
                 IsNativeHostImage(bin / ("lib" + plugin.module + ".dll"), true))) continue;
            original_plugins.push_back(&plugin);
        }
        if (original_plugins.empty()) { output = std::move(configuration); return true; }
        std::sort(original_plugins.begin(), original_plugins.end(), [](const auto* first, const auto* second) {
            return first->module < second->module;
        });
        const fs::path host = managed_root / "bin" / "openfruit-macro-host.exe";
        if (!IsNativeHostImage(host, false)) {
            error = "Managed original macro host is missing or is not a native Windows PE executable: " + host.string();
            return false;
        }
        std::wstring modules;
        for (const auto* plugin : original_plugins) {
            if (plugin->module.empty() || plugin->module.find(',') != std::string::npos ||
                plugin->module.find('#') != std::string::npos ||
                plugin->file.wstring().find(L'#') != std::wstring::npos || host.wstring().find(L'#') != std::wstring::npos) {
                error = "Admitted original plugin cannot be encoded in compiler plugin registration";
                return false;
            }
            const std::wstring module = fs::path(plugin->module).wstring();
            // This is a frontend option. The Swift driver accepts the bare
            // spelling but does not forward it to its frontend jobs.
            configuration.arguments.push_back(L"-Xfrontend");
            configuration.arguments.push_back(L"-load-resolved-plugin");
            configuration.arguments.push_back(L"-Xfrontend");
            configuration.arguments.push_back(plugin->file.wstring() + L"#" + host.wstring() + L"#" + module);
            if (!modules.empty()) modules += L",";
            modules += module;
        }
        configuration.environment.emplace_back(kDarwinMacroProviderEnvironment, provider->receipt.wstring());
        configuration.environment.emplace_back(kDarwinMacroModulesEnvironment, modules);
        // Hosts of this configuration share one broker of warm original
        // servers. The scope is per user and stable across builds; the host
        // adds the receipt, module selection and its own binary identity.
        wchar_t user[256] = {};
        DWORD user_length = static_cast<DWORD>(std::size(user));
        if (GetUserNameW(user, &user_length))
            configuration.environment.emplace_back(L"OPENFRUIT_MACRO_BROKER_SCOPE", std::wstring(L"user:") + user);
        configuration.original_provider = std::move(provider);
        configuration.original_host = host.wstring();
        output = std::move(configuration);
        return true;
    } catch (const std::exception& exception) {
        error = std::string("Cannot configure compiler plugin provider: ") + exception.what();
        return false;
    }
}
void MacroEngine::PrewarmOriginalProvider(const CompilerPluginConfiguration& configuration) noexcept {
    try {
        if (configuration.original_host.empty() || configuration.environment.empty()) return;
        wchar_t setting[8] = {};
        if (GetEnvironmentVariableW(L"OPENFRUIT_MACRO_PREWARM", setting, 8) && std::wstring(setting) == L"0") return;
        // The current environment with this configuration's values and the role.
        auto overrides = configuration.environment;
        overrides.emplace_back(L"OPENFRUIT_MACRO_HOST_ROLE", L"prewarm");
        const auto same_name = [](const std::wstring& entry, const std::wstring& name) {
            return entry.size() > name.size() && entry[name.size()] == L'=' &&
                   CompareStringOrdinal(entry.c_str(), static_cast<int>(name.size()), name.c_str(),
                                        static_cast<int>(name.size()), TRUE) == CSTR_EQUAL;
        };
        std::vector<wchar_t> block;
        if (wchar_t* strings = GetEnvironmentStringsW()) {
            for (const wchar_t* entry = strings; *entry; entry += wcslen(entry) + 1) {
                const std::wstring text(entry);
                if (std::any_of(overrides.begin(), overrides.end(),
                                [&](const auto& item) { return same_name(text, item.first); })) continue;
                block.insert(block.end(), text.begin(), text.end()); block.push_back(L'\0');
            }
            FreeEnvironmentStringsW(strings);
        }
        for (const auto& [name, value] : overrides) {
            const auto text = name + L"=" + value;
            block.insert(block.end(), text.begin(), text.end()); block.push_back(L'\0');
        }
        block.push_back(L'\0');
        std::wstring command = L"\"" + configuration.original_host + L"\"";
        std::vector<wchar_t> command_line(command.begin(), command.end()); command_line.push_back(L'\0');
        const auto directory = fs::path(configuration.original_host).parent_path().wstring();
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        // Not a Run child: the broker must outlive this build's kill-on-close jobs.
        const DWORD flags = CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
        BOOL created = CreateProcessW(configuration.original_host.c_str(), command_line.data(), nullptr, nullptr, FALSE,
                                      flags | CREATE_BREAKAWAY_FROM_JOB, block.data(), directory.c_str(), &startup, &process);
        if (!created && GetLastError() == ERROR_ACCESS_DENIED)
            created = CreateProcessW(configuration.original_host.c_str(), command_line.data(), nullptr, nullptr, FALSE,
                                     flags, block.data(), directory.c_str(), &startup, &process);
        if (created) { CloseHandle(process.hThread); CloseHandle(process.hProcess); }
    } catch (...) {}
}

std::shared_ptr<void> MacroEngine::KeepOriginalProviderWarm(const CompilerPluginConfiguration& configuration) {
    struct Warmer {
        std::mutex mutex;
        std::condition_variable stop_requested;
        bool stopping = false;
        std::thread thread;
        ~Warmer() {
            { std::lock_guard lock(mutex); stopping = true; }
            stop_requested.notify_all();
            if (thread.joinable()) thread.join();
        }
    };
    PrewarmOriginalProvider(configuration);
    if (configuration.original_host.empty() || configuration.environment.empty()) return {};
    auto warmer = std::make_shared<Warmer>();
    warmer->thread = std::thread([state = warmer.get(), configuration] {
        std::unique_lock lock(state->mutex);
        while (!state->stop_requested.wait_for(lock, std::chrono::seconds(60), [state] { return state->stopping; })) {
            lock.unlock();
            PrewarmOriginalProvider(configuration);
            lock.lock();
        }
    });
    return warmer;
}

void MacroEngine::PreferNativePluginExecutables(std::vector<std::wstring>& arguments,
    const DarwinMacroProvider& provider, const std::wstring& managed_host) {
    std::unordered_set<std::wstring> native_modules;
    const std::wstring executable_prefix = L"-load-plugin-executable=";
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        std::wstring registration;
        if (arguments[index] == L"-Xfrontend" && index + 3 < arguments.size() &&
            arguments[index + 1] == L"-load-plugin-executable" && arguments[index + 2] == L"-Xfrontend") {
            registration = arguments[index + 3]; index += 3;
        } else if (arguments[index] == L"-Xfrontend" && index + 1 < arguments.size() &&
            arguments[index + 1].rfind(executable_prefix, 0) == 0) {
            registration = arguments[index + 1].substr(executable_prefix.size()); ++index;
        } else if (arguments[index] == L"-load-plugin-executable" && index + 1 < arguments.size() &&
                   (index == 0 || arguments[index - 1] != L"-Xfrontend"))
            registration = arguments[++index];
        else if (arguments[index].rfind(executable_prefix, 0) == 0 &&
                 (index == 0 || arguments[index - 1] != L"-Xfrontend"))
            registration = arguments[index].substr(executable_prefix.size());
        const auto separator = registration.rfind(L'#');
        if (separator == std::wstring::npos || separator == 0) continue;
        std::size_t begin = separator + 1;
        while (begin < registration.size()) {
            const auto end = registration.find(L',', begin);
            const auto module = registration.substr(begin, end == std::wstring::npos ? end : end - begin);
            if (!module.empty()) native_modules.insert(module);
            if (end == std::wstring::npos) break;
            begin = end + 1;
        }
    }
    if (native_modules.empty()) return;
    std::unordered_set<std::wstring> superseded;
    for (const auto& plugin : provider.plugins) {
        const std::wstring module = fs::path(plugin.module).wstring();
        if (native_modules.contains(module))
            superseded.insert(plugin.file.wstring() + L"#" + managed_host + L"#" + module);
    }
    const std::wstring resolved_prefix = L"-load-resolved-plugin=";
    std::vector<std::wstring> filtered;
    filtered.reserve(arguments.size());
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        if (arguments[index] == L"-Xfrontend" && index + 3 < arguments.size() &&
            arguments[index + 1] == L"-load-resolved-plugin" && arguments[index + 2] == L"-Xfrontend" &&
            superseded.contains(arguments[index + 3])) { index += 3; continue; }
        if (arguments[index] == L"-Xfrontend" && index + 1 < arguments.size() &&
            arguments[index + 1].rfind(resolved_prefix, 0) == 0 &&
            superseded.contains(arguments[index + 1].substr(resolved_prefix.size()))) { ++index; continue; }
        const bool frontend_operand = index && arguments[index - 1] == L"-Xfrontend";
        if (arguments[index] == L"-load-resolved-plugin" && index + 1 < arguments.size() &&
            !frontend_operand && superseded.contains(arguments[index + 1])) { ++index; continue; }
        if (arguments[index].rfind(resolved_prefix, 0) == 0 &&
            !frontend_operand && superseded.contains(arguments[index].substr(resolved_prefix.size()))) continue;
        // Keep the original vector intact while recognizing wrapper boundaries.
        filtered.push_back(arguments[index]);
    }
    arguments = std::move(filtered);
}
bool MacroEngine::EnsureMacroBridge(const std::wstring& repo_root,
                                   std::wstring& out_bridge_path,
                                   std::wstring& out_plugin_view,
                                   const std::wstring& selected_toolchain_bin) {
    // The selected compiler owns its ABI-matched Windows server and plugins.
    // Keep the production interface, but never silently route to a legacy
    // Darling installation or an OPENFRUIT unsupported diagnostic scaffold.
    const fs::path bin = selected_toolchain_bin.empty()
        ? ToolPaths::SwiftBin(fs::path(repo_root)) : fs::path(selected_toolchain_bin);
    return ResolveNativeProvider(bin, out_bridge_path, out_plugin_view);
}
std::vector<std::wstring> MacroEngine::GetCompilerPluginArguments(const std::wstring& repo_root) {
    const fs::path bin = ToolPaths::SwiftBin(fs::path(repo_root));
    return NativeArguments(bin);
}
} // namespace OpenFruit
