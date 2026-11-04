#pragma once

#include "device_usbmux.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace OpenFruit {

class DeviceTlsChannel;

enum class DeviceTransportMode {
    Usb,
    WiFi
};

struct DeviceTarget {
    DeviceTransportMode mode = DeviceTransportMode::Usb;
    std::uint32_t device_id = 0;       // usbmux device id
    std::string udid;
    std::string host = "127.0.0.1";    // IP or hostname for WiFi
    std::uint16_t port = 62078;         // Lockdown port
};

struct DeviceProperty {
    std::string key;
    std::string value;
};

class DeviceSession {
public:
    explicit DeviceSession(DeviceTarget target);
    ~DeviceSession();

    DeviceSession(const DeviceSession&) = delete;
    DeviceSession& operator=(const DeviceSession&) = delete;

    // Connect and establish lockdown session
    bool Connect(std::string& error);
    bool QueryType(std::string& out_type, std::string& error);
    bool GetValue(const std::string& key, std::string& out_value, std::string& error);
    bool GetAllValues(std::vector<DeviceProperty>& out_properties, std::string& error);
    bool StartSession(const LockdownPairingRecord& record, std::string& out_session_id, std::string& error);
    bool StartService(const std::string& service_name, std::uint16_t& out_port, bool& out_ssl, std::string& error);

    // High-level operations over USB or WiFi
    bool DeployIpa(const std::string& ipa_path,
                   const std::function<void(int percent, const std::string& status)>& progress,
                   std::string& error);

    bool StreamSyslog(const std::function<void(const std::string& line)>& on_line,
                      const std::atomic<bool>& cancellation,
                      std::string& error);

    bool CaptureScreenshot(const std::string& output_image_path, std::string& error);

    // Relays the preview agent's stream (an app built with --preview) to
    // sink, connecting through usbmux to the agent's loopback port. Waits for
    // the app and reconnects when it closes, until cancelled or sink refuses.
    bool StreamPreview(std::uint16_t port,
                       const std::function<bool(const char* data, std::size_t size)>& sink,
                       const std::atomic<bool>& cancellation,
                       std::string& error);

    bool LaunchApp(const std::string& bundle_id_or_path,
                   std::uint32_t& out_pid,
                   std::string& error);

    bool StartDebugProxy(std::uint16_t local_port,
                         const std::atomic<bool>& cancellation,
                         std::string& error);

    bool RecordScreenFrames(const std::string& output_directory,
                            std::uint32_t duration_seconds,
                            const std::atomic<bool>& cancellation,
                            std::string& error);

    const DeviceTarget& Target() const { return target_; }
    bool IsConnected() const { return is_connected_; }

    static std::vector<DeviceTarget> DiscoverDevices(const std::string& wifi_hint = "");

private:
    DeviceTarget target_;
    uintptr_t socket_ = ~0ULL; // SOCKET
    std::string session_id_;
    bool is_connected_ = false;
    LockdownPairingRecord record_;
    // Lockdown and service connections switched to TLS by the device.
    std::map<uintptr_t, std::unique_ptr<DeviceTlsChannel>> tls_;
    std::string tls_error_; // last TLS transport failure, for diagnostics

    bool EnableTls(uintptr_t sock, std::string& error);
    bool Write(uintptr_t sock, const char* data, int size);
    bool Read(uintptr_t sock, char* data, int size);

    bool SendPlist(uintptr_t sock, const std::string& xml_plist, std::string& error);
    bool ReceivePlist(uintptr_t sock, std::string& out_xml_plist, std::string& error);
    uintptr_t ConnectToServiceSocket(std::uint16_t port, std::string& error);
    void CloseSocket(uintptr_t& sock);
};

} // namespace OpenFruit
