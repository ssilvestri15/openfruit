#include "macro_engine.hpp"
#include "darwin_macro_provider.hpp"
#include "content_hash.hpp"
#include "win32_process.hpp"
#include "tool_paths.hpp"
#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <vector>
namespace fs = std::filesystem;
using OpenFruit::JsonValue;
using OpenFruit::Sha256File;
using OpenFruit::Win32Process;
namespace {
void Require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}
struct Environment {
    std::vector<std::pair<std::wstring, std::optional<std::wstring>>> saved;
    void Set(const wchar_t* key, const std::wstring& value) {
        const auto size = GetEnvironmentVariableW(key, nullptr, 0);
        std::optional<std::wstring> old;
        if (size) {
            std::wstring buffer(size, L'\0');
            buffer.resize(GetEnvironmentVariableW(key, buffer.data(), size));
            old = std::move(buffer);
        }
        saved.emplace_back(key, old);
        Require(SetEnvironmentVariableW(key, value.empty() ? nullptr : value.c_str()) != 0,
                "environment setup failed");
    }
    ~Environment() {
        for (auto it = saved.rbegin(); it != saved.rend(); ++it)
            SetEnvironmentVariableW(it->first.c_str(), it->second ? it->second->c_str() : nullptr);
    }
};
void File(const fs::path& path, const std::string& bytes = "owned structural path fixture") {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}
// Admission-only fixture, shared schema with receipt tests; never executes its synthetic original/cache bytes.
std::string Hash(const fs::path& path) {
    const auto hash = Sha256File(path); Require(hash.has_value(), "fixture hashing failed"); return *hash;
}
void Little(std::string& bytes, std::size_t offset, std::uint64_t value, unsigned count = 4) {
    for (unsigned n = 0; n < count; ++n) bytes[offset + n] = static_cast<char>(value >> (n * 8));
}
std::string MachO() {
    // Owned metadata fixture only: these bytes are never executed as a plugin.
    std::string bytes(4096, '\0'); Little(bytes, 0, 0xfeedfacf); Little(bytes, 4, 0x0100000c);
    Little(bytes, 12, 2); Little(bytes, 16, 1); Little(bytes, 20, 72);
    Little(bytes, 32, 0x19); Little(bytes, 36, 72); bytes.replace(40, 6, "__TEXT");
    Little(bytes, 56, 0x100000000ULL, 8); Little(bytes, 64, 4096, 8); Little(bytes, 80, 4096, 8);
    Little(bytes, 88, 5); Little(bytes, 92, 5); return bytes;
}
JsonValue Strings(std::initializer_list<std::string> values) {
    auto result = JsonValue::ArrayValue(); for (const auto& value : values) result.ArrayItems().push_back(JsonValue::String(value)); return result;
}
struct AdmissionFixture {
    fs::path root, managed, sdk, receipt, tree, executable, plugin;
    JsonValue document;
    explicit AdmissionFixture(const fs::path& directory) : root(directory), managed(root / "managed"),
        sdk(managed / "sdk" / "slot" / "Xcode.app" / "SDK.sdk"),
        receipt(managed / "sdk" / "slot" / "darwin-provider" / "provider.json"),
        tree(managed / "sdk" / "slot" / "darwin-provider" / "original"),
        executable(tree / "toolchain" / "swift-plugin-server"), plugin(tree / "plugins" / "nested" / "libOwnedMacro.dylib") {
        File(sdk / "SDKSettings.json", "{\"Version\":\"27.0\",\"CanonicalName\":\"iphoneos27.0\"}");
        File(executable, MachO()); File(plugin, "owned library metadata fixture");
        document = JsonValue::ObjectValue(); document.Set("schema", JsonValue::String("openfruit.darwin-provider.v1"));
        document.Set("path_anchor", JsonValue::String("managed-home"));
        auto selection = JsonValue::ObjectValue(); selection.Set("sdk", JsonValue::String(Relative(sdk)));
        selection.Set("sdk_settings_sha256", JsonValue::String(Hash(sdk / "SDKSettings.json")));
        selection.Set("archive_sha256", JsonValue::String(std::string(64, 'a')));
        selection.Set("xcode_build", JsonValue::String("owned-build")); selection.Set("toolchain_identifier", JsonValue::String("owned-toolchain"));
        document.Set("selection", std::move(selection));
        auto server = JsonValue::ObjectValue(); server.Set("virtual_path", JsonValue::String("/toolchain/swift-plugin-server"));
        server.Set("member", JsonValue::String(Relative(executable))); server.Set("sha256", JsonValue::String(Hash(executable)));
        document.Set("executable", std::move(server)); document.Set("original_trees", Strings({Relative(tree)}));
        document.Set("original_files", JsonValue::ArrayValue({Original(executable), Original(plugin)}));
        document.Set("plugin_directories", Strings({"/plugins"}));
        auto cache = JsonValue::ObjectValue(); cache.Set("parent", Cache("main"));
        cache.Set("children", JsonValue::ArrayValue({Cache("first"), Cache("second")})); document.Set("cache", std::move(cache));
        auto provenance = JsonValue::ObjectValue(); provenance.Set("source", JsonValue::String("owned-test-input"));
        provenance.Set("publisher_verified", JsonValue::Boolean(false)); provenance.Set("published", JsonValue::Boolean(false));
        document.Set("provenance", std::move(provenance)); Save(document);
    }
    std::string Relative(const fs::path& path) const { return Win32Process::ToNarrow(path.lexically_relative(managed).generic_wstring()); }
    JsonValue Original(const fs::path& path) const {
        auto value = JsonValue::ObjectValue(); value.Set("path", JsonValue::String(Relative(path)));
        value.Set("sha256", JsonValue::String(Hash(path))); value.Set("bytes", JsonValue::Number(std::to_string(fs::file_size(path)))); return value;
    }
    JsonValue Cache(const std::string& name) const {
        const auto payload = managed / "cache" / (name + ".bin"), report = managed / "cache" / (name + ".json");
        File(payload, std::string(512, name.front())); auto descriptor = JsonValue::ObjectValue();
        for (const auto* key : {"complete", "file_contents_verified", "metadata_verified", "volume_trees_verified", "quarantined"}) descriptor.Set(key, JsonValue::Boolean(true));
        descriptor.Set("scope", JsonValue::String("selected-original-apfs-file-decoded-data-hashes"));
        descriptor.Set("path", JsonValue::String(Win32Process::ToNarrow(payload.generic_wstring())));
        descriptor.Set("source_sha256", JsonValue::String(std::string(64, 'b')));
        descriptor.Set("sha256", JsonValue::String(Hash(payload))); descriptor.Set("decoded_bytes", JsonValue::Number("512"));
        descriptor.Set("virtual_path", JsonValue::String("/System/cache/" + name)); File(report, descriptor.Serialize());
        auto value = JsonValue::ObjectValue(); value.Set("report", JsonValue::String(Relative(report)));
        value.Set("report_sha256", JsonValue::String(Hash(report))); value.Set("payload", JsonValue::String(Relative(payload)));
        for (const auto* key : {"sha256", "source_sha256", "virtual_path"}) value.Set(key, *descriptor.Get(key));
        value.Set("bytes", JsonValue::Number("512")); return value;
    }
    void Save(const JsonValue& value) const { File(receipt, value.Serialize(true)); }
};

void StructuralToolchain(const fs::path& bin) {
    // Selection-contract fixture only. These files are never executed and this
    // suite does not claim plugin loading, macro expansion or iOS compilation.
    for (const auto* name : {"swift.exe", "swiftc.exe", "clang.exe", "llvm-ar.exe", "llvm-readobj.exe"})
        File(bin / name);
}
void HeaderMutation(const fs::path& server, bool dll, bool foreign_machine) {
    std::fstream stream(server, std::ios::binary | std::ios::in | std::ios::out);
    IMAGE_DOS_HEADER dos{};
    stream.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    stream.seekg(dos.e_lfanew + sizeof(DWORD));
    IMAGE_FILE_HEADER header{};
    stream.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (dll) header.Characteristics |= IMAGE_FILE_DLL;
    if (foreign_machine)
        header.Machine = header.Machine == IMAGE_FILE_MACHINE_AMD64
            ? IMAGE_FILE_MACHINE_ARM64 : IMAGE_FILE_MACHINE_AMD64;
    stream.seekp(dos.e_lfanew + sizeof(DWORD));
    stream.write(reinterpret_cast<const char*>(&header), sizeof(header));
}
} // namespace
int main() {
    wchar_t own_buffer[32768]{};
    const DWORD count = GetModuleFileNameW(nullptr, own_buffer, 32768);
    if (!count || count == 32768) return 2;
    const fs::path own(own_buffer);
    const fs::path root = fs::temp_directory_path() /
        ("OPENFRUIT-macro-provider-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
    try {
        // Capture the real selected compiler before the isolated fixture changes
        // OPENFRUIT_HOME/SWIFT_BIN. Dry-run only: no plugin or frontend executes.
        const fs::path real_driver = OpenFruit::ToolPaths::SwiftBin(fs::current_path()) / "swiftc.exe";
        Environment environment;
        const fs::path managed = root / "managed", first = root / "selected-compiler-a";
        const fs::path second = root / "selected-compiler-b", repo = root / "project";
        StructuralToolchain(first); StructuralToolchain(second);
        environment.Set(L"OPENFRUIT_HOME", managed.wstring());
        environment.Set(L"OPENFRUIT_SWIFT_BIN", first.wstring());
        fs::create_directories(repo);
        // A real legacy provider must never regain priority or be an implicit
        // fallback. Copy our owned test PE solely to test executable selection.
        const fs::path legacy = managed / "toolchains" / "darling";
        fs::create_directories(legacy / "bin");
        fs::create_directories(legacy / "windows-plugin-view");
        fs::copy_file(own, legacy / "bin" / "openfruit-macro-bridge.exe");
        const fs::path server_a = first / "swift-plugin-server.exe";
        const fs::path server_b = second / "swift-plugin-server.exe";
        std::wstring server = L"stale", view = L"stale";
        Require(!OpenFruit::MacroEngine::EnsureMacroBridge(repo.wstring(), server, view), "legacy fallback selected");
        Require(server.empty() && view.empty(), "failure retained previous provider outputs");
        auto arguments = OpenFruit::MacroEngine::GetCompilerPluginArguments(repo.wstring());
        Require(arguments == std::vector<std::wstring>{L"-plugin-path", first.wstring()}, "missing provider generated external arguments");
        File(server_a, std::string("\xcf\xfa\xed\xfe", 4));
        Require(!OpenFruit::MacroEngine::EnsureMacroBridge(repo.wstring(), server, view), "Mach-O disguised as exe selected");
        File(server_a, "MZ truncated");
        Require(!OpenFruit::MacroEngine::EnsureMacroBridge(repo.wstring(), server, view), "truncated executable selected");
        fs::copy_file(own, server_a, fs::copy_options::overwrite_existing);
        Require(OpenFruit::MacroEngine::EnsureMacroBridge(repo.wstring(), server, view), "owned host PE selection failed");
        Require(server == server_a.wstring() && view == first.wstring(), "provider detached from selected compiler");
        arguments = OpenFruit::MacroEngine::GetCompilerPluginArguments(repo.wstring());
        Require(arguments == std::vector<std::wstring>{L"-plugin-path", first.wstring(), L"-external-plugin-path", first.wstring() + L"#" + server_a.wstring()}, "compiler provider propagation failed");
        HeaderMutation(server_a, true, false);
        Require(!OpenFruit::MacroEngine::EnsureMacroBridge(repo.wstring(), server, view), "DLL selected as executable");
        fs::copy_file(own, server_a, fs::copy_options::overwrite_existing);
        HeaderMutation(server_a, false, true);
        Require(!OpenFruit::MacroEngine::EnsureMacroBridge(repo.wstring(), server, view), "foreign-machine provider selected");
        fs::copy_file(own, server_a, fs::copy_options::overwrite_existing);
        fs::copy_file(own, server_b);
        Require(OpenFruit::MacroEngine::EnsureMacroBridge(repo.wstring(), server, view, second.wstring()), "explicit compiler provider failed");
        Require(server == server_b.wstring() && view == second.wstring(), "explicit compiler silently replaced by environment compiler");
        OpenFruit::CompilerPluginConfiguration configuration;
        std::string configuration_error = "stale";
        Require(OpenFruit::MacroEngine::ConfigureCompilerPlugins(repo.wstring(), second.wstring(), L"",
                configuration, configuration_error), "explicit compiler configuration failed");
        const std::vector<std::wstring> second_arguments{L"-plugin-path", second.wstring(),
            L"-external-plugin-path", second.wstring() + L"#" + server_b.wstring()};
        Require(configuration.arguments == second_arguments && configuration_error.empty(),
                "configuration ignored selected compiler or retained error");
        Require(configuration.environment.empty() && !configuration.original_provider,
                "native-only configuration registered an original provider");
        const fs::path sdk_slot = managed / "sdk" / "owned-provider-selection";
        const fs::path selected_sdk = sdk_slot / "iPhoneOS.sdk";
        const fs::path receipt = sdk_slot / "darwin-provider" / "provider.json";
        fs::create_directories(selected_sdk);
        Require(OpenFruit::MacroEngine::ConfigureCompilerPlugins(repo.wstring(), second.wstring(), selected_sdk.wstring(),
                configuration, configuration_error), "missing optional receipt rejected native-only configuration");
        Require(configuration.arguments == second_arguments && configuration.environment.empty() && !configuration.original_provider,
                "missing receipt altered native configuration");
        File(receipt, "{malformed-owned-admission-fixture");
        Require(!OpenFruit::MacroEngine::ConfigureCompilerPlugins(repo.wstring(), second.wstring(), selected_sdk.wstring(),
                configuration, configuration_error), "present malformed receipt silently fell back to native-only");
        Require(!configuration_error.empty() && configuration.arguments.empty() && configuration.environment.empty() &&
                !configuration.original_provider, "receipt failure retained stale configuration");
        Require(OpenFruit::MacroEngine::ConfigureCompilerPlugins(repo.wstring(), second.wstring(), L"",
                configuration, configuration_error), "SDK-less legacy native selection inspected unrelated receipt");
        Require(configuration.arguments == second_arguments && configuration.environment.empty() && configuration_error.empty(),
                "SDK-less native configuration changed after malformed receipt");
        fs::remove(receipt);
        Require(!OpenFruit::MacroEngine::EnsureMacroBridge(repo.wstring(), server, view, (root / "missing-compiler").wstring()), "missing explicit compiler fell back to a different version");
        Require(server.empty() && view.empty(), "explicit compiler failure retained stale provider");
        environment.Set(L"OPENFRUIT_SWIFT_BIN", second.wstring());
        arguments = OpenFruit::MacroEngine::GetCompilerPluginArguments(repo.wstring());
        Require(arguments.back() == second.wstring() + L"#" + server_b.wstring(), "compiler switch retained stale provider");
        Require(!fs::exists(managed / "cache" / "external-plugins-filtered"), "native selection created legacy plugin cache");
        AdmissionFixture admitted(root / "admission");
        environment.Set(L"OPENFRUIT_HOME", admitted.managed.wstring());
        environment.Set(OpenFruit::kDarwinMacroProviderEnvironment, L"ambient-provider-must-not-change");
        environment.Set(OpenFruit::kDarwinMacroModulesEnvironment, L"ambient-modules-must-not-change");
        Require(!OpenFruit::MacroEngine::ConfigureCompilerPlugins(repo.wstring(), second.wstring(), admitted.sdk.wstring(),
                configuration, configuration_error), "original plugin selected without managed native host");
        Require(configuration.arguments.empty() && configuration.environment.empty() && !configuration.original_provider &&
                !configuration_error.empty(), "missing host left partial configuration");
        const auto managed_host = admitted.managed / "bin" / "openfruit-macro-host.exe";
        File(managed_host, MachO());
        Require(!OpenFruit::MacroEngine::ConfigureCompilerPlugins(repo.wstring(), second.wstring(), admitted.sdk.wstring(),
                configuration, configuration_error), "Mach-O disguised as managed host executable accepted");
        fs::copy_file(own, managed_host, fs::copy_options::overwrite_existing);
        const auto native_library = second / "OwnedMacro.dll";
        File(native_library, MachO());
        auto check_original = [&] {
            Require(OpenFruit::MacroEngine::ConfigureCompilerPlugins(repo.wstring(), second.wstring(), admitted.sdk.wstring(),
                    configuration, configuration_error), configuration_error);
            auto expected = second_arguments;
            expected.push_back(L"-Xfrontend");
            expected.push_back(L"-load-resolved-plugin");
            expected.push_back(L"-Xfrontend");
            expected.push_back(admitted.plugin.wstring() + L"#" + managed_host.wstring() + L"#OwnedMacro");
            Require(configuration.arguments == expected, "original compiler flags were not derived from admitted plugin metadata");
            Require(configuration.original_provider &&
                    configuration.original_provider->plugins.size() == admitted.document.Get("original_files")->ArrayItems().size() - 1 &&
                    configuration.original_provider->plugins.front().module == "OwnedMacro", "validated original provider/leases not retained");
            const std::vector<std::pair<std::wstring, std::wstring>> expected_environment{
                {OpenFruit::kDarwinMacroProviderEnvironment, admitted.receipt.wstring()},
                {OpenFruit::kDarwinMacroModulesEnvironment, L"OwnedMacro"}};
            Require(configuration.environment.size() == expected_environment.size() + 1 &&
                    std::equal(expected_environment.begin(), expected_environment.end(), configuration.environment.begin()),
                    "receipt/module environment not scoped to selected original inventory");
            Require(configuration.environment.back().first == L"OPENFRUIT_MACRO_BROKER_SCOPE" &&
                    !configuration.environment.back().second.empty(), "original provider configuration has no broker scope");
            wchar_t ambient[128]{};
            GetEnvironmentVariableW(OpenFruit::kDarwinMacroProviderEnvironment, ambient, 128);
            Require(std::wstring(ambient) == L"ambient-provider-must-not-change", "configuration mutated global provider environment");
            GetEnvironmentVariableW(OpenFruit::kDarwinMacroModulesEnvironment, ambient, 128);
            Require(std::wstring(ambient) == L"ambient-modules-must-not-change", "configuration mutated global module environment");
        };
        check_original(); // Mach-O with a .dll suffix must not hide an original plugin.
        if (fs::is_regular_file(real_driver)) {
            const auto dry_source = root / "driver-forwarding.swift";
            File(dry_source, "let ownedDriverForwarding = 1\n");
            std::vector<std::wstring> dry_arguments{real_driver.wstring(), L"-###", L"-c", dry_source.wstring(),
                L"-o", (root / "driver-forwarding.obj").wstring()};
            // Derive the registration through the actual configuration API;
            // avoid the fixture's native -plugin-path/-external-plugin-path.
            const auto original_flag = std::find(configuration.arguments.begin(), configuration.arguments.end(), L"-Xfrontend");
            Require(original_flag != configuration.arguments.end(), "configuration has no frontend forwarding arguments");
            dry_arguments.insert(dry_arguments.end(), original_flag, configuration.arguments.end());
            const auto dry_run = Win32Process::Run(real_driver.wstring(), dry_arguments);
            const auto printed_jobs = dry_run.std_out + dry_run.std_err;
            Require(dry_run.success && printed_jobs.find("-load-resolved-plugin") != std::string::npos &&
                    printed_jobs.find("#OwnedMacro") != std::string::npos,
                    "real Swift driver did not forward configured original plugin to frontend: " + printed_jobs);
            Require(!fs::exists(root / "driver-forwarding.obj"), "driver dry-run unexpectedly executed a frontend");
            std::cout << "Selected real Swift driver frontend registration forwarding PASS (-### only).\n";
        } else {
            std::cout << "Selected real Swift driver forwarding test SKIPPED: compiler unavailable.\n";
        }
        fs::copy_file(own, native_library, fs::copy_options::overwrite_existing);
        check_original(); // A PE executable with a .dll suffix is not a native plugin DLL.
        HeaderMutation(native_library, true, true);
        check_original(); // A DLL for a different host architecture has no native priority.
        configuration = {};
        const auto second_original = admitted.tree / "plugins" / "libOwnedNative.dylib";
        File(second_original, "owned second original library metadata fixture");
        admitted.document.Get("original_files")->ArrayItems().push_back(admitted.Original(second_original));
        admitted.Save(admitted.document);
        const auto second_native = second / "OwnedNative.dll";
        fs::copy_file(own, second_native);
        HeaderMutation(second_native, true, false);
        check_original(); // Mixed inventory: only OwnedMacro enters original flags/environment.
        const auto original_registration = admitted.plugin.wstring() + L"#" + managed_host.wstring() + L"#OwnedMacro";
        const auto other_host_registration = admitted.plugin.wstring() + L"#" + (root / "user-host.exe").wstring() + L"#OwnedMacro";
        const auto other_path_registration = (root / "user-plugin.dylib").wstring() + L"#" + managed_host.wstring() + L"#OwnedMacro";
        const std::vector<std::wstring> unrelated_arguments{
            L"-load-resolved-plugin", original_registration, L"-load-plugin-executable",
            own.wstring() + L"#UnrelatedNativeModule"};
        auto priority_arguments = unrelated_arguments;
        OpenFruit::MacroEngine::PreferNativePluginExecutables(priority_arguments, *configuration.original_provider, managed_host.wstring());
        Require(priority_arguments == unrelated_arguments, "unrelated native executable removed original registration");
        priority_arguments = {L"-load-resolved-plugin", original_registration,
            L"-load-resolved-plugin", other_host_registration,
            L"-load-resolved-plugin", other_path_registration,
            L"-load-resolved-plugin=" + original_registration,
            L"-load-plugin-executable", own.wstring() + L"#OwnedMacro,OtherNativeModule", L"-typecheck"};
        const std::vector<std::wstring> expected_priority{
            L"-load-resolved-plugin", other_host_registration,
            L"-load-resolved-plugin", other_path_registration,
            L"-load-plugin-executable", own.wstring() + L"#OwnedMacro,OtherNativeModule", L"-typecheck"};
        OpenFruit::MacroEngine::PreferNativePluginExecutables(priority_arguments, *configuration.original_provider, managed_host.wstring());
        Require(priority_arguments == expected_priority, "native executable priority removed user registrations or retained exact managed conflicts");
        priority_arguments = {L"-load-resolved-plugin", original_registration,
            L"-load-plugin-executable=" + own.wstring() + L"#OtherNativeModule,OwnedMacro"};
        OpenFruit::MacroEngine::PreferNativePluginExecutables(priority_arguments, *configuration.original_provider, managed_host.wstring());
        Require(priority_arguments == std::vector<std::wstring>{L"-load-plugin-executable=" + own.wstring() + L"#OtherNativeModule,OwnedMacro"},
                "equals-form native executable registration did not retain priority");
        const auto native_registration = own.wstring() + L"#OtherNativeModule,OwnedMacro";
        const std::vector<std::vector<std::wstring>> native_forms{
            {L"-load-plugin-executable", native_registration},
            {L"-load-plugin-executable=" + native_registration},
            {L"-Xfrontend", L"-load-plugin-executable", L"-Xfrontend", native_registration},
            {L"-Xfrontend", L"-load-plugin-executable=" + native_registration}};
        const std::vector<std::vector<std::wstring>> original_forms{
            {L"-load-resolved-plugin", original_registration},
            {L"-load-resolved-plugin=" + original_registration},
            {L"-Xfrontend", L"-load-resolved-plugin", L"-Xfrontend", original_registration},
            {L"-Xfrontend", L"-load-resolved-plugin=" + original_registration}};
        const std::vector<std::wstring> wrapped_user_registrations{
            L"-Xfrontend", L"-load-resolved-plugin", L"-Xfrontend", other_host_registration,
            L"-Xfrontend", L"-load-resolved-plugin=" + other_path_registration};
        for (const auto& native_form : native_forms) for (const auto& original_form : original_forms) {
            priority_arguments = {L"-module-name", L"OwnedPriorityConsumer"};
            priority_arguments.insert(priority_arguments.end(), original_form.begin(), original_form.end());
            priority_arguments.insert(priority_arguments.end(), wrapped_user_registrations.begin(), wrapped_user_registrations.end());
            priority_arguments.insert(priority_arguments.end(), native_form.begin(), native_form.end());
            priority_arguments.push_back(L"-typecheck");
            std::vector<std::wstring> expected{L"-module-name", L"OwnedPriorityConsumer"};
            expected.insert(expected.end(), wrapped_user_registrations.begin(), wrapped_user_registrations.end());
            expected.insert(expected.end(), native_form.begin(), native_form.end());
            expected.push_back(L"-typecheck");
            OpenFruit::MacroEngine::PreferNativePluginExecutables(priority_arguments, *configuration.original_provider, managed_host.wstring());
            Require(priority_arguments == expected, "driver/frontend priority left an orphan wrapper or removed user plugin arguments");
        }
        const std::vector<std::wstring> malformed_wrapper{
            L"-Xfrontend", L"-load-resolved-plugin", original_registration,
            L"-load-plugin-executable", native_registration};
        priority_arguments = malformed_wrapper;
        OpenFruit::MacroEngine::PreferNativePluginExecutables(priority_arguments, *configuration.original_provider, managed_host.wstring());
        Require(priority_arguments == malformed_wrapper, "incomplete frontend wrapper was partially rewritten");
        priority_arguments = {L"-Xfrontend", L"-load-resolved-plugin", L"-Xfrontend", original_registration,
            L"-load-plugin-executable", own.wstring() + L"#UnrelatedNativeModule"};
        const auto unmatched_wrapped = priority_arguments;
        OpenFruit::MacroEngine::PreferNativePluginExecutables(priority_arguments, *configuration.original_provider, managed_host.wstring());
        Require(priority_arguments == unmatched_wrapped, "unrelated native module removed wrapped original registration");
        fs::copy_file(own, native_library, fs::copy_options::overwrite_existing);
        HeaderMutation(native_library, true, false);
        fs::remove(managed_host);
        Require(OpenFruit::MacroEngine::ConfigureCompilerPlugins(repo.wstring(), second.wstring(), admitted.sdk.wstring(),
                configuration, configuration_error), "actual selected compiler native DLL did not retain priority");
        Require(configuration.arguments == second_arguments && configuration.environment.empty() && !configuration.original_provider,
                "all-native modules retained original host registration/environment");
        fs::remove(native_library);
        Require(OpenFruit::MacroEngine::ConfigureCompilerPlugins(repo.wstring(), second.wstring(), admitted.sdk.wstring(),
                configuration, configuration_error, {"OwnedMacro"}), "preferred source-built native module did not retain priority");
        Require(configuration.arguments == second_arguments && configuration.environment.empty() && !configuration.original_provider,
                "preferred native module was overridden by original provider");
        fs::copy_file(own, managed_host);
        check_original();
        configuration = {}; // Release admitted original file leases before fixture cleanup.
        fs::remove_all(root);
        std::cout << "Native macro provider selection and argument propagation PASS; no expansion claim.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        std::error_code ignored; fs::remove_all(root, ignored);
        return 1;
    }
}
