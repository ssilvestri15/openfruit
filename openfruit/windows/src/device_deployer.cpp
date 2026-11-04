#include "device_deployer.hpp"
#include "device_usbmux.hpp"
#include "device_session.hpp"
#include "win32_process.hpp"
#include "tool_paths.hpp"
#include "json_value.hpp"
#include <filesystem>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

namespace OpenFruit {

std::vector<ConnectedDevice> DeviceDeployer::ListDevices(const std::wstring& repo_root) {
    std::vector<ConnectedDevice> devices;

    // 1. Pure native usbmux discovery (zero Python dependency)
    DeviceUsbmuxRequest usbmux_req;
    usbmux_req.timeout = std::chrono::milliseconds(1500);
    auto mux_res = DeviceUsbmux::ListDevices(usbmux_req);
    if (mux_res.status == DeviceUsbmuxStatus::Complete) {
        for (const auto& dev : mux_res.devices) {
            ConnectedDevice cd;
            cd.udid = dev.udid;
            cd.name = "Apple iOS Device (" + std::to_string(dev.device_id) + ")";
            cd.connection_type = dev.connection_type.empty() ? "USB" : dev.connection_type;
            devices.push_back(std::move(cd));
        }
        return devices;
    }

    fs::path root(repo_root);
    fs::path pymobiledevice = ToolPaths::Pymobiledevice3(root);
    fs::path idevice_id = ToolPaths::FindOnPath(L"idevice_id.exe");
    if (idevice_id.empty()) {
        fs::path local_inst = ToolPaths::LocalHome() / "toolchains" / "device" / "libimobiledevice" / "idevice_id.exe";
        if (fs::exists(local_inst)) idevice_id = local_inst;
    }

    if (fs::exists(pymobiledevice)) {
        std::vector<std::wstring> args = {
            pymobiledevice.wstring(),
            L"usbmux", L"list"
        };
        std::string raw_output;
        ProcessResult res = Win32Process::Run(
            pymobiledevice.wstring(),
            args,
            L"",
            {},
            [&raw_output](const std::string& out) { raw_output += out; },
            [](const std::string&) {}
        );
        if (res.success && !raw_output.empty()) {
            if (auto json_opt = JsonValue::Parse(raw_output)) {
                if (json_opt->IsArray()) {
                    for (const auto& item : json_opt->ArrayItems()) {
                        if (item.IsObject()) {
                            std::string udid;
                            if (const auto* u = item.Get("UniqueDeviceID")) udid = u->StringValue();
                            else if (const auto* id = item.Get("Identifier")) udid = id->StringValue();

                            std::string name = "iOS Device";
                            if (const auto* n = item.Get("DeviceName")) name = n->StringValue();

                            std::string conn = "USB";
                            if (const auto* c = item.Get("ConnectionType")) conn = c->StringValue();

                            if (!udid.empty()) {
                                ConnectedDevice dev;
                                dev.udid = udid;
                                dev.name = name;
                                dev.connection_type = conn;
                                devices.push_back(std::move(dev));
                            }
                        }
                    }
                }
            }
            if (!devices.empty()) return devices;

            std::istringstream stream(raw_output);
            std::string line;
            while (std::getline(stream, line)) {
                // Trim trailing \r
                if (!line.empty() && line.back() == '\r') line.pop_back();
                // Simple parsing for UDID lines (typically 24 or 40 hex chars)
                std::istringstream ls(line);
                std::string token;
                if (ls >> token) {
                    if (token.length() >= 24 && token.find(':') == std::string::npos) {
                        ConnectedDevice dev;
                        dev.udid = token;
                        dev.connection_type = "USB";
                        std::string rest;
                        std::getline(ls, rest);
                        if (!rest.empty() && rest.front() == ' ') rest.erase(0, 1);
                        dev.name = rest.empty() ? "iOS Device" : rest;
                        devices.push_back(std::move(dev));
                    }
                }
            }
            if (!devices.empty()) return devices;
        }
    }

    if (!idevice_id.empty() && fs::exists(idevice_id)) {
        std::vector<std::wstring> args = {
            idevice_id.wstring(),
            L"-l"
        };
        std::string raw_output;
        ProcessResult res = Win32Process::Run(
            idevice_id.wstring(),
            args,
            L"",
            {},
            [&raw_output](const std::string& out) { raw_output += out; },
            [](const std::string&) {}
        );
        if (res.success && !raw_output.empty()) {
            if (auto json_opt = JsonValue::Parse(raw_output)) {
                if (json_opt->IsArray()) {
                    for (const auto& item : json_opt->ArrayItems()) {
                        if (item.IsObject()) {
                            std::string udid;
                            if (const auto* u = item.Get("UniqueDeviceID")) udid = u->StringValue();
                            else if (const auto* id = item.Get("Identifier")) udid = id->StringValue();

                            std::string name = "iOS Device";
                            if (const auto* n = item.Get("DeviceName")) name = n->StringValue();

                            std::string conn = "USB";
                            if (const auto* c = item.Get("ConnectionType")) conn = c->StringValue();

                            if (!udid.empty()) {
                                ConnectedDevice dev;
                                dev.udid = udid;
                                dev.name = name;
                                dev.connection_type = conn;
                                devices.push_back(std::move(dev));
                            }
                        }
                    }
                }
            }
            if (!devices.empty()) return devices;

            std::istringstream stream(raw_output);
            std::string line;
            while (std::getline(stream, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.length() >= 24) {
                    ConnectedDevice dev;
                    dev.udid = line;
                    dev.name = "iOS Device";
                    dev.connection_type = "USB";
                    devices.push_back(std::move(dev));
                }
            }
        }
    }

    return devices;
}

bool DeviceDeployer::Deploy(
    const std::wstring& repo_root,
    const std::wstring& signed_ipa_path,
    const std::wstring& udid
) {
    // 1. Try pure native deployment first (AFC + Installation Proxy, zero Python)
    std::string ipa_str = Win32Process::ToNarrow(signed_ipa_path);
    std::string udid_str = Win32Process::ToNarrow(udid);

    DeviceTarget target;
    target.udid = udid_str;
    target.mode = DeviceTransportMode::Usb;

    DeviceSession session(target);
    std::string native_err;
    if (session.Connect(native_err)) {
        std::string session_id;
        auto record = DeviceUsbmux::LoadPairingRecord(target.udid);
        if (record.is_valid && session.StartSession(record, session_id, native_err)) {
            std::cout << "OPENFRUIT: Connected to device via pure native usbmuxd (Session: "
                      << session_id << ")" << std::endl;
            bool ok = session.DeployIpa(ipa_str, [](int pct, const std::string& st) {
                std::cout << "\rOPENFRUIT Deploy: [" << pct << "%] " << st << std::flush;
            }, native_err);
            std::cout << std::endl;
            if (ok) {
                std::cout << "OPENFRUIT: Native application installation succeeded!" << std::endl;
                return true;
            }
            std::cerr << "OPENFRUIT: Native deployment note: " << native_err << "; trying external helper..." << std::endl;
        }
    }

    fs::path root(repo_root);
    fs::path pymobiledevice = ToolPaths::Pymobiledevice3(root);
    fs::path ideviceinstaller = ToolPaths::FindOnPath(L"ideviceinstaller.exe");
    if (ideviceinstaller.empty()) {
        fs::path local_inst = ToolPaths::LocalHome() / "toolchains" / "device" / "libimobiledevice" / "ideviceinstaller.exe";
        if (fs::exists(local_inst)) ideviceinstaller = local_inst;
    }

    if (fs::exists(pymobiledevice)) {
        std::vector<std::wstring> args = {
            pymobiledevice.wstring(),
            L"apps", L"install", L"--developer"
        };
        if (!udid.empty()) {
            args.push_back(L"--udid");
            args.push_back(udid);
        }
        args.push_back(signed_ipa_path);

        std::cout << "OPENFRUIT: Deploying to physical iOS device via pymobiledevice3..." << std::endl;
        ProcessResult res = Win32Process::Run(
            pymobiledevice.wstring(),
            args,
            L"",
            {},
            [](const std::string& out) { std::cout << out; },
            [](const std::string& err) { std::cerr << err; }
        );
        return res.success;
    }

    if (!ideviceinstaller.empty() && fs::exists(ideviceinstaller)) {
        std::vector<std::wstring> args = {
            ideviceinstaller.wstring(),
            L"--install",
            signed_ipa_path
        };
        if (!udid.empty()) {
            args.push_back(L"--udid");
            args.push_back(udid);
        }

        std::cout << "OPENFRUIT: Deploying to physical iOS device via ideviceinstaller..." << std::endl;
        ProcessResult res = Win32Process::Run(
            ideviceinstaller.wstring(),
            args,
            L"",
            {},
            [](const std::string& out) { std::cout << out; },
            [](const std::string& err) { std::cerr << err; }
        );
        return res.success;
    }

    std::cerr << "OPENFRUIT DeviceDeployer: Neither pymobiledevice3 nor ideviceinstaller found." << std::endl;
    std::cerr << "Install pymobiledevice3 or place libimobiledevice tools in %LOCALAPPDATA%\\OpenFruit\\toolchains\\device" << std::endl;
    return false;
}

} // namespace OpenFruit
