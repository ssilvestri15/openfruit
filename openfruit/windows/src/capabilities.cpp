#include "capabilities.hpp"
#include "tool_paths.hpp"
#include "config.hpp"
#include "sdk_catalog.hpp"
#include "darwin_macro_provider.hpp"
#include "openfruit_version.hpp"
#include "device_usbmux.hpp"

#include <windows.h>

#include <filesystem>

namespace OpenFruit {
namespace {
bool File(const std::filesystem::path& path) {
    std::error_code error;
    return !path.empty() && std::filesystem::is_regular_file(path, error) && !error;
}
// Native device operations talk to usbmuxd. iTunes installs it as the
// "Apple Mobile Device Service"; the Apple Devices app runs it as a packaged
// process instead, so a responding local endpoint also counts.
bool AppleMobileDeviceServiceInstalled() {
    const SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return false;
    const SC_HANDLE service = OpenServiceW(manager, L"Apple Mobile Device Service", SERVICE_QUERY_STATUS);
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return service != nullptr;
}
std::filesystem::path Select(const std::wstring& configured, const std::filesystem::path& discovered) {
    return configured.empty() ? discovered : std::filesystem::path(configured);
}
}
JsonValue Capabilities::Query(const std::wstring& repo_root) {
    const Config snapshot = Config::Load(L"", false);
    const std::filesystem::path root_path(repo_root);
    const auto swift = Select(snapshot.toolchain_path, ToolPaths::SwiftBin(root_path));
    const auto llvm = Select(snapshot.llvm_path, ToolPaths::LlvmBin(root_path));
    const auto sdk = Select(snapshot.sdk_path, ToolPaths::IosSdk(root_path));
    const bool swift_present = !swift.empty() && File(swift / "swiftc.exe");
    const bool clang_present = !swift.empty() && File(swift / "clang.exe");
    const bool linker_present = !llvm.empty() && File(llvm / "ld64.lld.exe");
    const bool sdk_present = SDKCatalog::HasUsableLayout(sdk);
    const auto managed_root = ToolPaths::LocalHome();
    const bool macro_host_present = File(managed_root / "bin" / "openfruit-macro-host.exe");
    const bool unicorn_present = File(managed_root / "bin" / "unicorn.dll");
    // This is metadata location only, not provider admission or runtime proof.
    // An empty/relative SDK must never cause an unrelated provider search.
    const auto provider_receipt = sdk_present && sdk.is_absolute()
        ? FindDarwinMacroProviderReceipt(managed_root, sdk) : std::filesystem::path{};
    const bool provider_receipt_present = File(provider_receipt);
    const bool signer_present = File(Select(snapshot.zsign_path, ToolPaths::Zsign(root_path)));
    DeviceUsbmuxRequest usbmux_probe;
    usbmux_probe.timeout = std::chrono::milliseconds(1000);
    const bool usbmux_service = AppleMobileDeviceServiceInstalled() ||
        DeviceUsbmux::ListDevices(usbmux_probe).status == DeviceUsbmuxStatus::Complete;
#ifdef OPENFRUIT_HAS_OPENIB_INPROCESS
    constexpr bool inprocess_openib = true;
#else
    constexpr bool inprocess_openib = false;
#endif
    auto root = JsonValue::ObjectValue();
    root.Set("schema_version", JsonValue::Number("2"));
    root.Set("engine_version", JsonValue::String(OPENFRUIT_VERSION));
    root.Set("target_platform", JsonValue::String("iOS"));
    root.Set("host_os", JsonValue::String("Windows"));
    root.Set("inspection_basis", JsonValue::String("filesystem_and_compiled_backends"));
    root.Set("tool_execution_verified", JsonValue::Boolean(false));

    auto ops = JsonValue::ObjectValue();
    auto details = JsonValue::ObjectValue();
    const auto operation = [&](const char* name, bool implemented, bool prerequisites, const char* reason) {
        const std::string status = !implemented ? "unsupported" : prerequisites ? "implemented" : "unavailable";
        ops.Set(name, JsonValue::String(status));
        auto detail = JsonValue::ObjectValue();
        detail.Set("status", JsonValue::String(status));
        detail.Set("implementation_present", JsonValue::Boolean(implemented));
        detail.Set("prerequisites_present", JsonValue::Boolean(prerequisites));
        detail.Set("reason", JsonValue::String(reason));
        detail.Set("request_validation", JsonValue::String("required"));
        details.Set(name, std::move(detail));
    };
    operation("sdk_list", true, true, "Read-only registration and layout inventory.");
    operation("sdk_select", true, true, "Selection validates the requested registered layout.");
    operation("sdk_remove", true, true, "Registration/in-use checks implemented; deletion ownership validation remains incomplete.");
    operation("sdk_download", true, true, "Authenticated Apple session and archive integrity required per request; session not inspected here.");
    operation("sdk_auto_selection", true, sdk_present, "Usable installed SDK required; acquisition requires an authenticated user session.");
    operation("project_inspect", true, true, "Requested project and settings must be validated.");
    operation("build", true, sdk_present && swift_present && clang_present && linker_present,
        "SDK and native compiler/linker prerequisites only; macro/resource compatibility and end-to-end conformance remain incomplete.");
    operation("package", true, true, "Requires valid completed build products; does not certify signing.");
    operation("sign", true, signer_present, "Legacy signer adapter; certificate/profile/bundle authorization not verified by discovery.");
    operation("deploy", true, usbmux_service, "Native usbmux/lockdown install (installation_proxy over AFC); requires Apple usbmuxd (Apple Devices or iTunes), a paired device and a signed product per request.");
    operation("devices", true, usbmux_service, "Native usbmux enumeration; requires Apple usbmuxd (Apple Devices or iTunes). Only the local daemon is probed.");
    operation("event_journal", true, true, "Storage availability checked during the requested operation.");
    operation("cache_prune", true, true, "Pruning implementation present; complete lease/scope safety validation remains incomplete.");
    operation("dependency_update", true, true, "Network/integrity and individual provider prerequisites checked per request.");
    operation("apple_browser_auth", true, true, "Interactive supported browser and user authentication required per request.");
    operation("native_darwin_plugins", true,
        macro_host_present && unicorn_present && sdk_present && provider_receipt_present,
        "Original-plugin execution path implemented; filesystem inventory only. Provider admission, dependency closure, selected plugin compatibility and actual expansion require per-request validation.");
    auto* native_plugins = details.Get("native_darwin_plugins");
    auto plugin_inputs = JsonValue::ObjectValue();
    plugin_inputs.Set("managed_macro_host", JsonValue::Boolean(macro_host_present));
    plugin_inputs.Set("unicorn", JsonValue::Boolean(unicorn_present));
    plugin_inputs.Set("selected_sdk_layout", JsonValue::Boolean(sdk_present));
    plugin_inputs.Set("provider_receipt", JsonValue::Boolean(provider_receipt_present));
    native_plugins->Set("prerequisite_inventory", std::move(plugin_inputs));
    native_plugins->Set("provider_validation", JsonValue::String("not_inspected"));
    native_plugins->Set("closure_validation", JsonValue::String("not_inspected"));
    native_plugins->Set("plugin_execution_verified", JsonValue::Boolean(false));
    operation("zero_wsl_build", false, false, "WSL paths remain reachable in production.");
    operation("valid_signed_ipa_verification", false, false, "Independent per-bundle signature/provisioning verification incomplete.");
    operation("ide_operation_adapter", false, false, "Versioned operation adapter not implemented.");
    operation("device_launch", false, false, "Launch service not implemented.");
    root.Set("operations", std::move(ops));
    root.Set("operation_details", std::move(details));
    auto tools = JsonValue::ObjectValue();
    tools.Set("swift_wmo", JsonValue::Boolean(swift_present));
    tools.Set("clang", JsonValue::Boolean(clang_present));
    tools.Set("lld_mach_o", JsonValue::Boolean(linker_present));
    tools.Set("ios_sdk_layout", JsonValue::Boolean(sdk_present));
    tools.Set("openib_compiler", JsonValue::Boolean(inprocess_openib));
    tools.Set("zsign", JsonValue::Boolean(signer_present));
    root.Set("toolchains", std::move(tools));
    return root;
}
}
