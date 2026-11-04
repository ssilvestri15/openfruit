#include <winsock2.h>
#include <ws2tcpip.h>
#include "device_usbmux.hpp"
#include "device_tls.hpp"
#include <plist/plist.h>
#include <algorithm>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace OpenFruit;
namespace {
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void Put32(std::string& text, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) text += static_cast<char>((value >> (8 * i)) & 255);
}
std::string Frame(const std::string& dictionary, std::uint32_t tag = 1) {
    const std::string xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>" + dictionary + "</dict></plist>";
    std::string frame;
    Put32(frame, static_cast<std::uint32_t>(xml.size() + 16)); Put32(frame, 1); Put32(frame, 8); Put32(frame, tag);
    return frame + xml;
}
std::string Entry(unsigned id, const std::string& udid, const std::string& connection) {
    return "<dict><key>Properties</key><dict><key>DeviceID</key><integer>" + std::to_string(id) +
        "</integer><key>SerialNumber</key><string>" + udid + "</string><key>ConnectionType</key><string>" +
        connection + "</string><key>ProductID</key><integer>123</integer></dict></dict>";
}
void Codec() {
    const auto request = DeviceUsbmux::BuildListDevicesRequest(0x12345678);
    Require(request.size() > 16 && request[4] == 1 && request[8] == 8 &&
        static_cast<unsigned char>(request[12]) == 0x78 && static_cast<unsigned char>(request[15]) == 0x12,
        "Request did not encode the protocol's little-endian correlation header");
    plist_t plist = nullptr;
    plist_format_t format = PLIST_FORMAT_NONE;
    Require(plist_from_memory(request.data() + 16, static_cast<std::uint32_t>(request.size() - 16), &plist, &format) == PLIST_ERR_SUCCESS,
        "ListDevices request is not a property list");
    const auto message = plist_dict_get_item(plist, "MessageType");
    std::uint64_t length = 0;
    const auto type = message ? plist_get_string_ptr(message, &length) : nullptr;
    const bool correct = type && std::string_view(type, static_cast<std::size_t>(length)) == "ListDevices";
    plist_free(plist);
    Require(correct, "Wrong native usbmux request message");

    const auto empty = Frame("<key>DeviceList</key><array/>");
    const auto parsed_empty = DeviceUsbmux::ParseListDevicesResponse(empty, 1);
    Require(parsed_empty.status == DeviceUsbmuxStatus::Complete && parsed_empty.devices.empty(), "Valid empty list failed");
    const auto two = Frame("<key>DeviceList</key><array>" + Entry(7, "owned-usb", "USB") + Entry(8, "owned-network", "Network") + "</array>");
    const auto parsed = DeviceUsbmux::ParseListDevicesResponse(two, 1);
    Require(parsed.status == DeviceUsbmuxStatus::Complete && parsed.devices.size() == 2 &&
        parsed.devices[0].device_id == 7 && parsed.devices[0].udid == "owned-usb" && parsed.devices[1].connection_type == "Network",
        "Device properties did not survive native parsing");
    Require(DeviceUsbmux::ParseListDevicesResponse(two, 1, 4096, 1).status == DeviceUsbmuxStatus::ProtocolError,
        "Oversized device list ignored its explicit budget");
    const auto duplicate = Frame("<key>DeviceList</key><array>" + Entry(7, "first", "USB") + Entry(7, "second", "USB") + "</array>");
    Require(DeviceUsbmux::ParseListDevicesResponse(duplicate, 1).status == DeviceUsbmuxStatus::ProtocolError, "Duplicate daemon IDs accepted");
    Require(DeviceUsbmux::ParseListDevicesResponse(Frame("<key>DeviceList</key><array>" + Entry(7, "", "USB") + "</array>"), 1).status == DeviceUsbmuxStatus::ProtocolError,
        "Missing UDID became an invented device");
    Require(DeviceUsbmux::ParseListDevicesResponse(Frame("<key>DeviceList</key><string>not-array</string>"), 1).status == DeviceUsbmuxStatus::ProtocolError,
        "Malformed DeviceList became successful empty discovery");
    for (const unsigned code : {1u, 6u}) {
        const auto unsupported = DeviceUsbmux::ParseListDevicesResponse(Frame("<key>MessageType</key><string>Result</string><key>Number</key><integer>" + std::to_string(code) + "</integer>"), 1);
        Require(unsupported.status == DeviceUsbmuxStatus::Unsupported && unsupported.daemon_result == code && unsupported.devices.empty(),
            "Unsupported daemon command/version lost its diagnostic");
    }
    Require(DeviceUsbmux::ParseListDevicesResponse(Frame("<key>MessageType</key><string>Result</string><key>Number</key><integer>0</integer>"), 1).status == DeviceUsbmuxStatus::ProtocolError,
        "Result without DeviceList was misrepresented as complete discovery");
    Require(DeviceUsbmux::ParseListDevicesResponse(empty.substr(0, 15), 1).status == DeviceUsbmuxStatus::ProtocolError, "Truncated header accepted");
    Require(DeviceUsbmux::ParseListDevicesResponse(empty, 2).status == DeviceUsbmuxStatus::ProtocolError, "Wrong response tag accepted");
    for (const auto index : {0u, 4u, 8u}) {
        auto corrupt = empty; corrupt[index] ^= 0x20;
        Require(DeviceUsbmux::ParseListDevicesResponse(corrupt, 1).status == DeviceUsbmuxStatus::ProtocolError, "Corrupt frame header accepted");
    }
    Require(DeviceUsbmux::ParseListDevicesResponse(empty + "extra", 1).status == DeviceUsbmuxStatus::ProtocolError, "Trailing frame bytes accepted");
    Require(DeviceUsbmux::ParseListDevicesResponse(empty, 1, 15).status == DeviceUsbmuxStatus::InvalidRequest, "Invalid frame budget accepted");

    const auto conn_req = DeviceUsbmux::BuildConnectRequest(1, 42, 62078);
    Require(conn_req.size() > 16 && conn_req.find("Connect") != std::string::npos && conn_req.find("<integer>42</integer>") != std::string::npos,
        "BuildConnectRequest failed to serialize device ID and connect message");
    // usbmuxd reads PortNumber in network byte order: lockdown 62078 (0xF27E) is 0x7EF2.
    Require(conn_req.find("<key>PortNumber</key><integer>32498</integer>") != std::string::npos,
        "BuildConnectRequest did not encode a host-order port in network byte order");
    {
        // Pairing records store PEM; the TLS identity is decoded from it.
        std::string der, label;
        Require(DecodePemBlock("junk\n-----BEGIN RSA PRIVATE KEY-----\nAAEC\n-----END RSA PRIVATE KEY-----\n", der, label)
            && label == "RSA PRIVATE KEY" && der == std::string("\x00\x01\x02", 3), "PEM block decoding wrong");
        Require(!DecodePemBlock("-----BEGIN CERTIFICATE-----\nAAEC\n", der, label), "unterminated PEM accepted");
    }
    std::uint32_t daemon_res = 0;
    std::string err;
    const auto conn_ok = Frame("<key>MessageType</key><string>Result</string><key>Number</key><integer>0</integer>");
    Require(DeviceUsbmux::ParseConnectResponse(conn_ok, 1, daemon_res, err) && daemon_res == 0,
        "ParseConnectResponse failed on valid Result 0");
    const auto conn_fail = Frame("<key>MessageType</key><string>Result</string><key>Number</key><integer>3</integer>");
    Require(!DeviceUsbmux::ParseConnectResponse(conn_fail, 1, daemon_res, err) && daemon_res == 3,
        "ParseConnectResponse did not reject non-zero daemon result");
    // A syntactically valid identifier that no paired device has.
    const auto record = DeviceUsbmux::LoadPairingRecord("00000000-0000000000000000");
    Require(!record.is_valid, "pairing record found for an unpaired identifier");
}

// Owned loopback protocol fixture, never reported as a physical Apple device.
class Server {
    SOCKET listener_ = INVALID_SOCKET;
    std::jthread worker_;
public:
    std::uint16_t port = 0;
    Server(std::string response, bool stall = false, bool fragment = false) {
        listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Require(listener_ != INVALID_SOCKET, "Owned fixture could not create its socket");
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) || listen(listener_, 1)) {
            closesocket(listener_); listener_ = INVALID_SOCKET;
            throw std::runtime_error("Owned fixture could not bind its ephemeral loopback socket");
        }
        int length = sizeof(address);
        if (getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length)) {
            closesocket(listener_); listener_ = INVALID_SOCKET;
            throw std::runtime_error("Owned fixture could not identify its ephemeral port");
        }
        port = ntohs(address.sin_port);
        worker_ = std::jthread([this, response = std::move(response), stall, fragment](std::stop_token stop) {
            while (!stop.stop_requested()) {
                fd_set ready; FD_ZERO(&ready); FD_SET(listener_, &ready);
                timeval timeout{0, 20000};
                if (select(0, &ready, nullptr, nullptr, &timeout) <= 0) continue;
                const auto peer = accept(listener_, nullptr, nullptr);
                if (peer == INVALID_SOCKET) return;
                if (stall) {
                    while (!stop.stop_requested()) std::this_thread::sleep_for(std::chrono::milliseconds(2));
                } else {
                    DWORD wait = 300;
                    setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&wait), sizeof(wait));
                    char request[2048];
                    (void)recv(peer, request, sizeof(request), 0);
                    std::size_t offset = 0;
                    while (!stop.stop_requested() && offset < response.size()) {
                        const auto count = send(peer, response.data() + offset,
                            static_cast<int>(std::min<std::size_t>(fragment ? 7 : response.size(), response.size() - offset)), 0);
                        if (count <= 0) break;
                        offset += static_cast<std::size_t>(count);
                        if (fragment) std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }
                }
                shutdown(peer, SD_BOTH); closesocket(peer);
                return;
            }
        });
    }
    ~Server() {
        worker_.request_stop();
        if (worker_.joinable()) worker_.join();
        if (listener_ != INVALID_SOCKET) closesocket(listener_);
    }
};
void Transport() {
    {
        // Hold an ephemeral loopback port bound but not listening, so another
        // process cannot claim it between reservation and the refused connect.
        const auto reserved = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Require(reserved != INVALID_SOCKET, "Cannot reserve owned refused-connection endpoint");
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int length = sizeof(address);
        if (bind(reserved, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) ||
            getsockname(reserved, reinterpret_cast<sockaddr*>(&address), &length)) {
            closesocket(reserved);
            throw std::runtime_error("Cannot bind owned refused-connection endpoint");
        }
        DeviceUsbmuxRequest request; request.port = ntohs(address.sin_port);
        const auto result = DeviceUsbmux::ListDevices(request);
        closesocket(reserved);
        Require(result.status == DeviceUsbmuxStatus::Unavailable && result.native_error == WSAECONNREFUSED,
            "Refused service connection became successful empty discovery");
    }
    {
        Server server(Frame("<key>DeviceList</key><array>" + Entry(3, "owned-protocol-fixture", "USB") + "</array>"), false, true);
        DeviceUsbmuxRequest request; request.port = server.port;
        const auto result = DeviceUsbmux::ListDevices(request);
        Require(result.status == DeviceUsbmuxStatus::Complete && result.devices.size() == 1 && result.devices[0].device_id == 3,
            "Native transport did not assemble fragmented protocol header/payload");
    }
    {
        Server server({}, true);
        DeviceUsbmuxRequest request; request.port = server.port; request.timeout = std::chrono::milliseconds(45);
        const auto began = std::chrono::steady_clock::now();
        const auto result = DeviceUsbmux::ListDevices(request);
        Require(result.status == DeviceUsbmuxStatus::TimedOut && std::chrono::steady_clock::now() - began < std::chrono::seconds(2),
            "Stalled daemon escaped the bounded discovery deadline");
    }
    {
        Server server({}, true);
        DeviceUsbmuxRequest request; request.port = server.port;
        request.control.cancellation = std::make_shared<std::atomic<bool>>(false);
        std::jthread cancel([flag = request.control.cancellation] { std::this_thread::sleep_for(std::chrono::milliseconds(40)); flag->store(true); });
        Require(DeviceUsbmux::ListDevices(request).status == DeviceUsbmuxStatus::Cancelled,
            "In-flight native discovery ignored cancellation");
    }
    {
        std::string oversize; Put32(oversize, 4 * 1024 * 1024 + 1); Put32(oversize, 1); Put32(oversize, 8); Put32(oversize, 1);
        Server server(oversize);
        DeviceUsbmuxRequest request; request.port = server.port;
        Require(DeviceUsbmux::ListDevices(request).status == DeviceUsbmuxStatus::ProtocolError,
            "Untrusted frame length was not rejected before payload allocation");
    }
    {
        Server server(std::string(7, 'x'));
        DeviceUsbmuxRequest request; request.port = server.port;
        Require(DeviceUsbmux::ListDevices(request).status == DeviceUsbmuxStatus::TransportError, "Truncated socket exchange accepted");
    }
    DeviceUsbmuxRequest invalid; invalid.port = 0;
    Require(DeviceUsbmux::ListDevices(invalid).status == DeviceUsbmuxStatus::InvalidRequest, "Zero service port accepted");
    DeviceUsbmuxRequest tiny; tiny.max_frame_bytes = 16;
    Require(DeviceUsbmux::ListDevices(tiny).status == DeviceUsbmuxStatus::InvalidRequest,
        "A request unable to fit its frame was not rejected before connection");
    DeviceUsbmuxRequest cancelled; cancelled.control.cancellation = std::make_shared<std::atomic<bool>>(true);
    Require(DeviceUsbmux::ListDevices(cancelled).status == DeviceUsbmuxStatus::Cancelled, "Pre-cancelled discovery performed I/O");
    DeviceUsbmuxRequest expired; expired.control.deadline = std::chrono::steady_clock::now();
    Require(DeviceUsbmux::ListDevices(expired).status == DeviceUsbmuxStatus::TimedOut, "Expired caller deadline was ignored");
}
} // namespace
int main() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
    int status = 0;
    try {
        Codec(); Transport();
        std::cout << "PASS: native usbmux discovery codec and owned loopback transport contracts; no physical device or deployment claimed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; status = 1; }
    WSACleanup();
    return status;
}
