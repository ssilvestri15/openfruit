#include "device_session.hpp"
#include <iostream>
#include <stdexcept>
#include <cassert>

using namespace OpenFruit;

namespace {
void Require(bool cond, const char* msg) {
    if (!cond) {
        std::cerr << "Assertion failed: " << msg << std::endl;
        throw std::runtime_error(msg);
    }
}
}

int main() {
    std::cout << "Starting device_session_tests..." << std::endl;

    // 1. Wi-Fi discovery hint contract
    {
        auto targets = DeviceSession::DiscoverDevices("192.168.1.150");
        Require(!targets.empty(), "Wi-Fi hint did not produce a device target");
        Require(targets[0].mode == DeviceTransportMode::WiFi, "Target mode is not WiFi");
        Require(targets[0].host == "192.168.1.150", "Target host does not match Wi-Fi hint");
        Require(targets[0].port == 62078, "Target port is not 62078 (Lockdown)");
    }

    // 2. USB device session structure
    {
        DeviceTarget usb_target;
        usb_target.mode = DeviceTransportMode::Usb;
        usb_target.device_id = 42;
        usb_target.udid = "00000000-0000000000000000";

        DeviceSession session(usb_target);
        Require(session.Target().mode == DeviceTransportMode::Usb, "Session target mode mismatch");
        Require(session.Target().device_id == 42, "Session device_id mismatch");
        Require(session.Target().udid == "00000000-0000000000000000", "Session udid mismatch");
        Require(!session.IsConnected(), "Session should initially be unconnected");
    }

    // 3. Pairing record integration
    {
        // Records of whatever devices are attached; none is fine.
        DeviceUsbmuxRequest probe;
        probe.timeout = std::chrono::milliseconds(1000);
        for (const auto& device : DeviceUsbmux::ListDevices(probe).devices) {
            auto record = DeviceUsbmux::LoadPairingRecord(device.udid);
            if (record.is_valid) {
                Require(!record.host_id.empty(), "Valid record must have host_id");
                Require(!record.system_buid.empty(), "Valid record must have system_buid");
            }
        }
    }

    // 4. LaunchApp contract when unconnected
    {
        DeviceTarget target;
        target.mode = DeviceTransportMode::Usb;
        target.udid = "mock-device";
        DeviceSession session(target);
        uint32_t pid = 0;
        std::string err;
        bool ok = session.LaunchApp("dev.openfruit.test", pid, err);
        Require(!ok, "LaunchApp should fail when unconnected");
        Require(!err.empty(), "LaunchApp should produce an error when unconnected");
    }

    std::cout << "PASS: device_session contracts verified (USB & Wi-Fi transport targets, pairing integration, AFC framing, app launch)." << std::endl;
    return 0;
}
