#pragma once

#include "win32_process.hpp"
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace OpenFruit {

enum class DeviceUsbmuxStatus {
    Complete, Unavailable, Cancelled, TimedOut, InvalidRequest,
    Unsupported, ProtocolError, TransportError
};

struct UsbMuxDevice {
    std::uint32_t device_id = 0;
    std::uint32_t product_id = 0;
    std::string udid;
    // Values returned by the daemon, currently USB or Network. ListDevices
    // does not promise a friendly device name or a lockdown/pairing session.
    std::string connection_type;
};

struct DeviceUsbmuxRequest {
    // Apple's local Windows usbmux service; a different port is useful for an
    // owned protocol test endpoint. Remote hosts are deliberately not accepted.
    std::uint16_t port = 27015;
    std::size_t max_frame_bytes = 4 * 1024 * 1024;
    std::size_t max_devices = 1024;
    std::chrono::milliseconds timeout{5000};
    ProcessRunOptions control;
};

struct DeviceUsbmuxResult {
    DeviceUsbmuxStatus status = DeviceUsbmuxStatus::ProtocolError;
    std::vector<UsbMuxDevice> devices;
    unsigned long native_error = 0;
    std::uint32_t daemon_result = 0;
    std::string error;
};

struct LockdownPairingRecord {
    std::string host_id;
    std::string system_buid;
    std::string device_certificate;
    std::string host_certificate;
    std::string host_private_key;
    bool is_valid = false;
};

// Native discovery and transport. No Python process required for enumeration or connect.
class DeviceUsbmux {
public:
    static DeviceUsbmuxResult ListDevices(const DeviceUsbmuxRequest& request = {});

    // The same bounded codec used by the native transport, exposed for protocol
    // contract tests and subsequent usbmux operations. All integers in this
    // usbmux header are little-endian; no packed native structure is serialized.
    static std::string BuildListDevicesRequest(std::uint32_t tag);
    static DeviceUsbmuxResult ParseListDevicesResponse(std::string_view frame,
        std::uint32_t expected_tag, std::size_t max_frame_bytes = 4 * 1024 * 1024,
        std::size_t max_devices = 1024);

    static std::string BuildConnectRequest(std::uint32_t tag, std::uint32_t device_id, std::uint16_t port_number);
    static bool ParseConnectResponse(std::string_view frame, std::uint32_t expected_tag, std::uint32_t& daemon_result, std::string& error);
    static LockdownPairingRecord LoadPairingRecord(const std::string& udid);
};

} // namespace OpenFruit
