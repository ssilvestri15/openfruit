#include "device_session.hpp"
#include "device_tls.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <plist/plist.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

namespace OpenFruit {
namespace {

constexpr uint64_t kAfcMagic = 0x4141504C36414643ULL; // "CFA6LPAA" in little endian

#pragma pack(push, 1)
struct AfcHeader {
    uint64_t magic;
    uint64_t entire_len;
    uint64_t this_len;
    uint64_t packet_num;
    uint64_t operation;
};
#pragma pack(pop)

constexpr uint64_t AFC_OP_STATUS = 0x00000001;
[[maybe_unused]] constexpr uint64_t AFC_OP_DATA = 0x00000002;
[[maybe_unused]] constexpr uint64_t AFC_OP_READ = 0x0000000F;  // AFC_OP_FILE_READ
constexpr uint64_t AFC_OP_WRITE = 0x00000010; // AFC_OP_FILE_WRITE
constexpr uint64_t AFC_OP_MAKE_DIR = 0x00000009;
constexpr uint64_t AFC_OP_FILE_OPEN = 0x0000000D;
constexpr uint64_t AFC_OP_FILE_OPEN_RES = 0x0000000E;
constexpr uint64_t AFC_OP_FILE_CLOSE = 0x00000014;

struct WinsockInit {
    WinsockInit() {
        WSADATA data{};
        WSAStartup(MAKEWORD(2, 2), &data);
    }
    ~WinsockInit() {
        WSACleanup();
    }
};

static WinsockInit s_winsock;

bool SendAll(SOCKET sock, const char* data, int size) {
    int total = 0;
    while (total < size) {
        int sent = send(sock, data + total, size - total, 0);
        if (sent <= 0) return false;
        total += sent;
    }
    return true;
}

// A device that stops answering must fail the operation, not hang it.
void SetReceiveTimeout(SOCKET sock) {
    const DWORD milliseconds = 120000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&milliseconds), sizeof(milliseconds));
}

// Why the last plain receive stopped: peer close or a socket error/timeout.
thread_local std::string g_receive_failure;

bool RecvAll(SOCKET sock, char* data, int size) {
    int total = 0;
    while (total < size) {
        int received = recv(sock, data + total, size - total, 0);
        if (received == 0) { g_receive_failure = "device closed the connection"; return false; }
        if (received < 0) {
            const int code = WSAGetLastError();
            g_receive_failure = code == WSAETIMEDOUT ? "no reply from the device (timed out)"
                                                     : "socket error " + std::to_string(code);
            return false;
        }
        total += received;
    }
    return true;
}

} // namespace

DeviceSession::DeviceSession(DeviceTarget target)
    : target_(std::move(target)) {}

DeviceSession::~DeviceSession() {
    CloseSocket(socket_);
}

bool DeviceSession::EnableTls(uintptr_t sock, std::string& error) {
    if (record_.host_certificate.empty() || record_.host_private_key.empty()) {
        error = "Pairing record has no host certificate/key for the device's TLS session.";
        return false;
    }
    auto channel = std::make_unique<DeviceTlsChannel>();
    if (!channel->Handshake(sock, record_.host_certificate, record_.host_private_key, error)) return false;
    tls_[sock] = std::move(channel);
    return true;
}

bool DeviceSession::Write(uintptr_t sock, const char* data, int size) {
    const auto tls = tls_.find(sock);
    if (tls != tls_.end()) return tls->second->Send(data, static_cast<std::size_t>(size), tls_error_);
    return SendAll(static_cast<SOCKET>(sock), data, size);
}

bool DeviceSession::Read(uintptr_t sock, char* data, int size) {
    const auto tls = tls_.find(sock);
    if (tls != tls_.end()) return tls->second->Receive(data, static_cast<std::size_t>(size), tls_error_);
    if (RecvAll(static_cast<SOCKET>(sock), data, size)) return true;
    tls_error_ = g_receive_failure;
    return false;
}

void DeviceSession::CloseSocket(uintptr_t& sock) {
    tls_.erase(sock);
    if (sock != ~0ULL && sock != 0) {
        closesocket(static_cast<SOCKET>(sock));
        sock = ~0ULL;
    }
}

std::vector<DeviceTarget> DeviceSession::DiscoverDevices(const std::string& wifi_hint) {
    std::vector<DeviceTarget> targets;

    if (!wifi_hint.empty()) {
        DeviceTarget dt;
        dt.mode = DeviceTransportMode::WiFi;
        dt.host = wifi_hint;
        dt.port = 62078;
        dt.udid = "wifi-" + wifi_hint;
        targets.push_back(std::move(dt));
    }

    DeviceUsbmuxRequest req;
    req.timeout = std::chrono::milliseconds(1500);
    auto mux = DeviceUsbmux::ListDevices(req);
    if (mux.status == DeviceUsbmuxStatus::Complete) {
        for (const auto& d : mux.devices) {
            DeviceTarget dt;
            dt.udid = d.udid;
            dt.device_id = d.device_id;
            if (d.connection_type == "Network") {
                dt.mode = DeviceTransportMode::WiFi;
                dt.host = "127.0.0.1";
            } else {
                dt.mode = DeviceTransportMode::Usb;
            }
            targets.push_back(std::move(dt));
        }
    }

    return targets;
}

bool DeviceSession::Connect(std::string& error) {
    CloseSocket(socket_);
    is_connected_ = false;

    if (target_.mode == DeviceTransportMode::WiFi && target_.host != "127.0.0.1") {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            error = "Failed to create socket for Wi-Fi device connection.";
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target_.port ? target_.port : 62078);
        inet_pton(AF_INET, target_.host.c_str(), &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            closesocket(s);
            error = "Failed to connect to Wi-Fi device at " + target_.host + ":" + std::to_string(target_.port);
            return false;
        }
        SetReceiveTimeout(s);
        socket_ = static_cast<uintptr_t>(s);
    } else {
        // USB mode or localhost usbmux network device
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            error = "Failed to create socket for usbmuxd connection.";
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(27015);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            closesocket(s);
            error = "Cannot connect to local Apple Mobile Device service (usbmuxd port 27015).";
            return false;
        }

        if (target_.device_id == 0 && !target_.udid.empty()) {
            auto mux = DeviceUsbmux::ListDevices();
            for (const auto& d : mux.devices) {
                if (d.udid == target_.udid) {
                    target_.device_id = d.device_id;
                    break;
                }
            }
        }

        if (target_.device_id == 0) {
            closesocket(s);
            error = "Target device ID could not be resolved from usbmuxd.";
            return false;
        }

        // Send Connect request to Lockdown port 62078
        std::string req = DeviceUsbmux::BuildConnectRequest(1, target_.device_id, 62078);
        if (!SendAll(s, req.data(), static_cast<int>(req.size()))) {
            closesocket(s);
            error = "Failed to send usbmux Connect request.";
            return false;
        }

        std::array<char, 16> hdr;
        if (!RecvAll(s, hdr.data(), 16)) {
            closesocket(s);
            error = "Failed to receive usbmux Connect response header.";
            return false;
        }
        uint32_t len = *reinterpret_cast<uint32_t*>(hdr.data());
        if (len < 16 || len > 65536) {
            closesocket(s);
            error = "Invalid usbmux Connect response frame length.";
            return false;
        }
        std::string body(len - 16, '\0');
        if (!RecvAll(s, body.data(), static_cast<int>(body.size()))) {
            closesocket(s);
            error = "Failed to receive usbmux Connect response payload.";
            return false;
        }

        std::string full_frame(hdr.data(), 16);
        full_frame.append(body);
        uint32_t daemon_res = 0;
        if (!DeviceUsbmux::ParseConnectResponse(full_frame, 1, daemon_res, error) || daemon_res != 0) {
            closesocket(s);
            if (error.empty()) error = "usbmux daemon rejected connection: code " + std::to_string(daemon_res);
            return false;
        }

        SetReceiveTimeout(s);
        socket_ = static_cast<uintptr_t>(s);
    }

    is_connected_ = true;
    return true;
}

bool DeviceSession::SendPlist(uintptr_t sock, const std::string& xml_plist, std::string& error) {
    if (sock == ~0ULL) {
        error = "Socket not connected.";
        return false;
    }
    uint32_t be_len = htonl(static_cast<u_long>(xml_plist.size()));
    if (!Write(sock, reinterpret_cast<const char*>(&be_len), 4)) {
        error = "Failed to send message length header.";
        return false;
    }
    if (!Write(sock, xml_plist.data(), static_cast<int>(xml_plist.size()))) {
        error = "Failed to send message payload.";
        return false;
    }
    return true;
}

bool DeviceSession::ReceivePlist(uintptr_t sock, std::string& out_xml_plist, std::string& error) {
    if (sock == ~0ULL) {
        error = "Socket not connected.";
        return false;
    }
    uint32_t be_len = 0;
    tls_error_.clear();
    if (!Read(sock, reinterpret_cast<char*>(&be_len), 4)) {
        error = "Failed to read incoming message length header" +
            (tls_error_.empty() ? std::string(".") : ": " + tls_error_);
        return false;
    }
    uint32_t len = ntohl(be_len);
    if (len == 0 || len > 16 * 1024 * 1024) {
        error = "Incoming message length out of bounds: " + std::to_string(len);
        return false;
    }
    out_xml_plist.resize(len);
    if (!Read(sock, out_xml_plist.data(), static_cast<int>(len))) {
        error = "Failed to read incoming message payload.";
        return false;
    }
    return true;
}

bool DeviceSession::QueryType(std::string& out_type, std::string& error) {
    const std::string query =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict><key>Request</key><string>QueryType</string></dict></plist>";
    if (!SendPlist(socket_, query, error)) return false;

    std::string resp;
    if (!ReceivePlist(socket_, resp, error)) return false;

    plist_t node = nullptr;
    if (plist_from_memory(resp.data(), static_cast<uint32_t>(resp.size()), &node, nullptr) == PLIST_ERR_SUCCESS && node) {
        auto type_item = plist_dict_get_item(node, "Type");
        if (type_item && plist_get_node_type(type_item) == PLIST_STRING) {
            char* val = nullptr;
            plist_get_string_val(type_item, &val);
            if (val) {
                out_type = val;
                free(val);
            }
        }
        plist_free(node);
    }
    return !out_type.empty();
}

bool DeviceSession::GetValue(const std::string& key, std::string& out_value, std::string& error) {
    std::string req =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict><key>Request</key><string>GetValue</string><key>Key</key><string>" +
        key + "</string></dict></plist>";
    if (!SendPlist(socket_, req, error)) return false;

    std::string resp;
    if (!ReceivePlist(socket_, resp, error)) return false;

    plist_t node = nullptr;
    if (plist_from_memory(resp.data(), static_cast<uint32_t>(resp.size()), &node, nullptr) == PLIST_ERR_SUCCESS && node) {
        auto val_item = plist_dict_get_item(node, "Value");
        if (val_item && plist_get_node_type(val_item) == PLIST_STRING) {
            char* val = nullptr;
            plist_get_string_val(val_item, &val);
            if (val) {
                out_value = val;
                free(val);
            }
        }
        plist_free(node);
    }
    return true;
}

bool DeviceSession::GetAllValues(std::vector<DeviceProperty>& out_properties, std::string& error) {
    std::string req =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict><key>Request</key><string>GetValue</string></dict></plist>";
    if (!SendPlist(socket_, req, error)) return false;

    std::string resp;
    if (!ReceivePlist(socket_, resp, error)) return false;

    plist_t node = nullptr;
    if (plist_from_memory(resp.data(), static_cast<uint32_t>(resp.size()), &node, nullptr) == PLIST_ERR_SUCCESS && node) {
        auto val_item = plist_dict_get_item(node, "Value");
        if (val_item && plist_get_node_type(val_item) == PLIST_DICT) {
            plist_dict_iter it = nullptr;
            plist_dict_new_iter(val_item, &it);
            if (it) {
                char* k = nullptr;
                plist_t v = nullptr;
                while (true) {
                    plist_dict_next_item(val_item, it, &k, &v);
                    if (!k) break;
                    std::string str_val;
                    if (v && plist_get_node_type(v) == PLIST_STRING) {
                        char* sv = nullptr;
                        plist_get_string_val(v, &sv);
                        if (sv) { str_val = sv; free(sv); }
                    } else if (v && plist_get_node_type(v) == PLIST_UINT) {
                        uint64_t uv = 0;
                        plist_get_uint_val(v, &uv);
                        str_val = std::to_string(uv);
                    }
                    if (!str_val.empty()) {
                        out_properties.push_back({k, str_val});
                    }
                    free(k);
                }
                free(it);
            }
        }
        plist_free(node);
    }
    return true;
}

bool DeviceSession::StartSession(const LockdownPairingRecord& record, std::string& out_session_id, std::string& error) {
    std::string req =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict><key>Request</key><string>StartSession</string>"
        "<key>HostID</key><string>" + record.host_id + "</string>"
        "<key>SystemBUID</key><string>" + record.system_buid + "</string>"
        "</dict></plist>";
    if (!SendPlist(socket_, req, error)) return false;

    std::string resp;
    if (!ReceivePlist(socket_, resp, error)) return false;

    bool session_ssl = false;
    plist_t node = nullptr;
    if (plist_from_memory(resp.data(), static_cast<uint32_t>(resp.size()), &node, nullptr) == PLIST_ERR_SUCCESS && node) {
        auto ssl_item = plist_dict_get_item(node, "EnableSessionSSL");
        if (ssl_item && plist_get_node_type(ssl_item) == PLIST_BOOLEAN) {
            uint8_t enabled = 0;
            plist_get_bool_val(ssl_item, &enabled);
            session_ssl = enabled != 0;
        }
        auto sess_item = plist_dict_get_item(node, "SessionID");
        if (sess_item && plist_get_node_type(sess_item) == PLIST_STRING) {
            char* val = nullptr;
            plist_get_string_val(sess_item, &val);
            if (val) {
                session_id_ = val;
                out_session_id = val;
                free(val);
            }
        }
        auto err_item = plist_dict_get_item(node, "Error");
        if (err_item && plist_get_node_type(err_item) == PLIST_STRING) {
            char* err_val = nullptr;
            plist_get_string_val(err_item, &err_val);
            if (err_val) {
                error = err_val;
                free(err_val);
            }
        }
        plist_free(node);
    }
    if (session_id_.empty()) return false;
    record_ = record;
    // lockdownd continues the session over TLS with the pairing identity.
    if (session_ssl && !EnableTls(socket_, error)) {
        session_id_.clear();
        out_session_id.clear();
        return false;
    }
    return true;
}

bool DeviceSession::StartService(const std::string& service_name, std::uint16_t& out_port, bool& out_ssl, std::string& error) {
    std::string req =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict><key>Request</key><string>StartService</string>"
        "<key>Service</key><string>" + service_name + "</string>"
        "</dict></plist>";
    if (!SendPlist(socket_, req, error)) return false;

    std::string resp;
    if (!ReceivePlist(socket_, resp, error)) return false;

    out_port = 0;
    out_ssl = false;

    plist_t node = nullptr;
    if (plist_from_memory(resp.data(), static_cast<uint32_t>(resp.size()), &node, nullptr) == PLIST_ERR_SUCCESS && node) {
        auto port_item = plist_dict_get_item(node, "Port");
        if (port_item && plist_get_node_type(port_item) == PLIST_UINT) {
            uint64_t val = 0;
            plist_get_uint_val(port_item, &val);
            out_port = static_cast<uint16_t>(val);
        }
        auto ssl_item = plist_dict_get_item(node, "EnableServiceSSL");
        if (ssl_item && plist_get_node_type(ssl_item) == PLIST_BOOLEAN) {
            uint8_t bv = 0;
            plist_get_bool_val(ssl_item, &bv);
            out_ssl = (bv != 0);
        }
        auto err_item = plist_dict_get_item(node, "Error");
        if (err_item && plist_get_node_type(err_item) == PLIST_STRING) {
            char* err_val = nullptr;
            plist_get_string_val(err_item, &err_val);
            if (err_val) {
                error = err_val;
                free(err_val);
            }
        }
        plist_free(node);
    }
    return out_port > 0;
}

uintptr_t DeviceSession::ConnectToServiceSocket(std::uint16_t port, std::string& error) {
    if (target_.mode == DeviceTransportMode::WiFi && target_.host != "127.0.0.1") {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            error = "Cannot create socket for Wi-Fi service.";
            return ~0ULL;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target_.host.c_str(), &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            closesocket(s);
            error = "Cannot connect to service on Wi-Fi device port " + std::to_string(port);
            return ~0ULL;
        }
        SetReceiveTimeout(s);
        return static_cast<uintptr_t>(s);
    }

    // USB mode via usbmuxd
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        error = "Cannot create socket for usbmuxd service connection.";
        return ~0ULL;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27015);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s);
        error = "Cannot connect to usbmuxd for service connection.";
        return ~0ULL;
    }

    std::string req = DeviceUsbmux::BuildConnectRequest(2, target_.device_id, port);
    if (!SendAll(s, req.data(), static_cast<int>(req.size()))) {
        closesocket(s);
        error = "Failed to send usbmux service Connect request.";
        return ~0ULL;
    }

    std::array<char, 16> hdr;
    if (!RecvAll(s, hdr.data(), 16)) {
        closesocket(s);
        error = "Failed to read usbmux service Connect header.";
        return ~0ULL;
    }
    uint32_t len = *reinterpret_cast<uint32_t*>(hdr.data());
    std::string body(len - 16, '\0');
    if (!RecvAll(s, body.data(), static_cast<int>(body.size()))) {
        closesocket(s);
        error = "Failed to read usbmux service Connect body.";
        return ~0ULL;
    }
    std::string frame(hdr.data(), 16);
    frame.append(body);
    uint32_t daemon_res = 0;
    if (!DeviceUsbmux::ParseConnectResponse(frame, 2, daemon_res, error) || daemon_res != 0) {
        closesocket(s);
        if (error.empty()) error = "usbmux rejected service connection.";
        return ~0ULL;
    }
    SetReceiveTimeout(s);
    return static_cast<uintptr_t>(s);
}

bool DeviceSession::DeployIpa(const std::string& ipa_path,
                             const std::function<void(int percent, const std::string& status)>& progress,
                             std::string& error) {
    std::ifstream file(ipa_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        error = "Cannot open IPA file for deployment: " + ipa_path;
        return false;
    }
    const uint64_t total_file_size = static_cast<uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    if (session_id_.empty()) {
        // Services are started from an authenticated lockdown session.
        if (!is_connected_ && !Connect(error)) return false;
        const auto record = DeviceUsbmux::LoadPairingRecord(target_.udid);
        if (!record.is_valid) {
            error = "No lockdown pairing record for device " + target_.udid + "; pair it with this computer first.";
            return false;
        }
        std::string session;
        if (!StartSession(record, session, error)) {
            if (error.empty()) error = "Lockdown StartSession failed.";
            return false;
        }
    }

    if (progress) progress(5, "Connecting to Apple File Conduit (com.apple.afc)...");

    uint16_t afc_port = 0;
    bool ssl_req = false;
    if (!StartService("com.apple.afc", afc_port, ssl_req, error)) {
        return false;
    }

    uintptr_t afc_sock = ConnectToServiceSocket(afc_port, error);
    if (afc_sock == ~0ULL) return false;
    if (ssl_req && !EnableTls(afc_sock, error)) { CloseSocket(afc_sock); return false; }

    // AFC packets: this_len covers the header and the operation's own
    // arguments (path, handle); bulk data follows up to entire_len.
    uint64_t packet_number = 0;
    const auto afc = [&](uint64_t operation, const std::string& arguments, const char* data, std::size_t data_size,
                         std::string& reply, uint64_t& reply_operation) {
        AfcHeader hdr{kAfcMagic, sizeof(AfcHeader) + arguments.size() + data_size,
                      sizeof(AfcHeader) + arguments.size(), packet_number++, operation};
        if (!Write(afc_sock, reinterpret_cast<const char*>(&hdr), sizeof(hdr)) ||
            (!arguments.empty() && !Write(afc_sock, arguments.data(), static_cast<int>(arguments.size()))) ||
            (data_size && !Write(afc_sock, data, static_cast<int>(data_size)))) {
            error = "Failed to send AFC request."; return false;
        }
        AfcHeader response{};
        if (!Read(afc_sock, reinterpret_cast<char*>(&response), sizeof(response)) || response.magic != kAfcMagic ||
            response.entire_len < sizeof(AfcHeader) || response.entire_len > 64 * 1024 * 1024) {
            error = "Invalid AFC response from device."; return false;
        }
        reply.assign(static_cast<std::size_t>(response.entire_len - sizeof(AfcHeader)), '\0');
        if (!reply.empty() && !Read(afc_sock, reply.data(), static_cast<int>(reply.size()))) {
            error = "Failed to read AFC response payload."; return false;
        }
        reply_operation = response.operation;
        return true;
    };
    const auto succeeded = [&](uint64_t operation, const std::string& reply, const char* what) {
        uint64_t code = ~0ULL;
        if (operation == AFC_OP_STATUS && reply.size() >= 8) std::memcpy(&code, reply.data(), 8);
        if (code == 0) return true;
        error = std::string(what) + " failed (AFC status " + std::to_string(code) + ").";
        return false;
    };
    const auto word = [](uint64_t value) { return std::string(reinterpret_cast<const char*>(&value), 8); };
    std::string reply;
    uint64_t reply_operation = 0;

    // 1. AFC MakeDir: PublicStaging (it may already exist).
    if (!afc(AFC_OP_MAKE_DIR, std::string("PublicStaging") + '\0', nullptr, 0, reply, reply_operation)) {
        CloseSocket(afc_sock); return false;
    }

    // 2. AFC FileOpen: PublicStaging/deploy.ipa (mode 3 = write/create/truncate)
    uint64_t file_handle = 0;
    if (!afc(AFC_OP_FILE_OPEN, word(3) + "PublicStaging/deploy.ipa" + '\0', nullptr, 0, reply, reply_operation)) {
        CloseSocket(afc_sock); return false;
    }
    if (reply_operation != AFC_OP_FILE_OPEN_RES || reply.size() < 8) {
        succeeded(reply_operation, reply, "Opening the staging file on the device");
        CloseSocket(afc_sock);
        return false;
    }
    std::memcpy(&file_handle, reply.data(), 8);

    // 3. Stream IPA Chunks
    constexpr size_t kChunkSize = 256 * 1024;
    std::vector<char> buffer(kChunkSize);
    uint64_t written_total = 0;

    while (written_total < total_file_size) {
        file.read(buffer.data(), kChunkSize);
        std::streamsize bytes_read = file.gcount();
        if (bytes_read <= 0) break;
        if (!afc(AFC_OP_WRITE, word(file_handle), buffer.data(), static_cast<std::size_t>(bytes_read), reply, reply_operation) ||
            !succeeded(reply_operation, reply, "Writing the IPA to the device")) {
            CloseSocket(afc_sock);
            return false;
        }
        written_total += bytes_read;
        int pct = static_cast<int>(10 + (written_total * 45) / total_file_size);
        if (progress) progress(pct, "Transferring IPA to device staging (" + std::to_string(written_total / (1024 * 1024)) + " MB)...");
    }

    // 4. AFC FileClose
    if (!afc(AFC_OP_FILE_CLOSE, word(file_handle), nullptr, 0, reply, reply_operation) ||
        !succeeded(reply_operation, reply, "Closing the staging file")) {
        CloseSocket(afc_sock);
        return false;
    }
    CloseSocket(afc_sock);

    if (progress) progress(60, "Connecting to Installation Proxy (com.apple.mobile.installation_proxy)...");

    // 5. Connect Installation Proxy
    uint16_t inst_port = 0;
    if (!StartService("com.apple.mobile.installation_proxy", inst_port, ssl_req, error)) {
        return false;
    }

    uintptr_t inst_sock = ConnectToServiceSocket(inst_port, error);
    if (inst_sock == ~0ULL) return false;
    if (ssl_req && !EnableTls(inst_sock, error)) { CloseSocket(inst_sock); return false; }

    // 6. Send Install Command
    std::string install_cmd =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>"
        "<key>Command</key><string>Install</string>"
        "<key>ClientOptions</key><dict>"
        "<key>ApplicationType</key><string>User</string>"
        "<key>PackageType</key><string>Developer</string>"
        "</dict>"
        "<key>PackagePath</key><string>PublicStaging/deploy.ipa</string>"
        "</dict></plist>";

    if (progress) progress(61, "Requesting installation of the staged package...");
    if (!SendPlist(inst_sock, install_cmd, error)) {
        CloseSocket(inst_sock);
        return false;
    }

    // 7. Track Installation Progress
    bool complete = false;
    while (!complete) {
        std::string update_plist;
        if (!ReceivePlist(inst_sock, update_plist, error)) {
            break;
        }
        plist_t node = nullptr;
        if (plist_from_memory(update_plist.data(), static_cast<uint32_t>(update_plist.size()), &node, nullptr) != PLIST_ERR_SUCCESS || !node) {
            error = "Installation Proxy sent a status message that is not a property list.";
            break;
        }
        {
            std::string status_str = "Installing";
            auto st_item = plist_dict_get_item(node, "Status");
            if (st_item && plist_get_node_type(st_item) == PLIST_STRING) {
                char* sv = nullptr;
                plist_get_string_val(st_item, &sv);
                if (sv) { status_str = sv; free(sv); }
            }

            int pct = 60;
            auto pct_item = plist_dict_get_item(node, "PercentComplete");
            if (pct_item && plist_get_node_type(pct_item) == PLIST_UINT) {
                uint64_t uv = 0;
                plist_get_uint_val(pct_item, &uv);
                pct = 60 + static_cast<int>((uv * 40) / 100);
            }

            if (progress) progress(pct, status_str);

            if (status_str == "Complete") {
                complete = true;
            }

            auto err_item = plist_dict_get_item(node, "Error");
            if (err_item && plist_get_node_type(err_item) == PLIST_STRING) {
                char* ev = nullptr;
                plist_get_string_val(err_item, &ev);
                if (ev) { error = ev; free(ev); }
                plist_free(node);
                CloseSocket(inst_sock);
                return false;
            }
            plist_free(node);
        }
    }

    CloseSocket(inst_sock);
    if (complete && progress) progress(100, "Installation complete!");
    return complete;
}

bool DeviceSession::StreamSyslog(const std::function<void(const std::string& line)>& on_line,
                                 const std::atomic<bool>& cancellation,
                                 std::string& error) {
    uint16_t port = 0;
    bool ssl = false;
    if (!StartService("com.apple.syslog_relay", port, ssl, error)) {
        return false;
    }

    uintptr_t sock = ConnectToServiceSocket(port, error);
    if (sock == ~0ULL) return false;
    SOCKET s = static_cast<SOCKET>(sock);

    // Set non-blocking / read with timeout
    u_long non_blocking = 1;
    ioctlsocket(s, FIONBIO, &non_blocking);

    std::string current_line;
    std::array<char, 4096> buf;

    while (!cancellation.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(s, &fds);
        timeval tv{0, 100000}; // 100ms
        int res = select(0, &fds, nullptr, nullptr, &tv);
        if (res > 0) {
            int received = recv(s, buf.data(), static_cast<int>(buf.size()), 0);
            if (received <= 0) break;
            for (int i = 0; i < received; ++i) {
                char c = buf[i];
                if (c == '\n' || c == '\0') {
                    if (!current_line.empty() && current_line.back() == '\r') current_line.pop_back();
                    if (!current_line.empty() && on_line) on_line(current_line);
                    current_line.clear();
                } else {
                    current_line.push_back(c);
                }
            }
        } else if (res < 0) {
            break;
        }
    }

    CloseSocket(sock);
    return true;
}

bool DeviceSession::CaptureScreenshot(const std::string& output_image_path, std::string& error) {
    uint16_t port = 0;
    bool ssl = false;
    if (!StartService("com.apple.mobile.screenshotr", port, ssl, error)) {
        return false;
    }

    uintptr_t sock = ConnectToServiceSocket(port, error);
    if (sock == ~0ULL) return false;

    // 1. DLMessageVersionExchange
    std::string ver_msg =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><array>"
        "<string>DLMessageVersionExchange</string>"
        "<integer>100</integer>"
        "<integer>0</integer>"
        "</array></plist>";

    if (!SendPlist(sock, ver_msg, error)) {
        CloseSocket(sock);
        return false;
    }

    std::string ver_reply;
    if (!ReceivePlist(sock, ver_reply, error)) {
        CloseSocket(sock);
        return false;
    }

    // 2. Request Screenshot
    std::string shot_req =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><array>"
        "<string>DLMessageProcessMessage</string>"
        "<dict>"
        "<key>MessageType</key><string>ScreenShotRequest</string>"
        "</dict>"
        "</array></plist>";

    if (!SendPlist(sock, shot_req, error)) {
        CloseSocket(sock);
        return false;
    }

    std::string shot_resp;
    if (!ReceivePlist(sock, shot_resp, error)) {
        CloseSocket(sock);
        return false;
    }

    CloseSocket(sock);

    // Parse image data
    plist_t node = nullptr;
    bool saved = false;
    if (plist_from_memory(shot_resp.data(), static_cast<uint32_t>(shot_resp.size()), &node, nullptr) == PLIST_ERR_SUCCESS && node) {
        if (plist_get_node_type(node) == PLIST_ARRAY && plist_array_get_size(node) >= 2) {
            auto dict_item = plist_array_get_item(node, 1);
            if (dict_item && plist_get_node_type(dict_item) == PLIST_DICT) {
                auto data_item = plist_dict_get_item(dict_item, "ScreenShotData");
                if (data_item && plist_get_node_type(data_item) == PLIST_DATA) {
                    uint64_t len = 0;
                    const char* buf = plist_get_data_ptr(data_item, &len);
                    if (buf && len > 0) {
                        std::ofstream out(output_image_path, std::ios::binary);
                        if (out.is_open()) {
                            out.write(buf, static_cast<std::streamsize>(len));
                            saved = true;
                        } else {
                            error = "Cannot open destination screenshot path: " + output_image_path;
                        }
                    }
                }
            }
        }
        plist_free(node);
    }

    if (!saved && error.empty()) {
        error = "Screenshot payload did not contain valid image data.";
    }
    return saved;
}

namespace {
std::string RspChecksum(const std::string& data) {
    unsigned char sum = 0;
    for (char c : data) sum += static_cast<unsigned char>(c);
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", sum);
    return hex;
}

bool SendRspPacket(SOCKET s, const std::string& payload) {
    std::string packet = "$" + payload + "#" + RspChecksum(payload);
    return send(s, packet.data(), static_cast<int>(packet.size()), 0) == static_cast<int>(packet.size());
}

bool ReadRspPacket(SOCKET s, std::string& out_payload, int timeout_ms = 5000) {
    out_payload.clear();
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    if (select(0, &fds, nullptr, nullptr, &tv) <= 0) return false;

    char c = 0;
    // Wait for start of packet '$'
    while (recv(s, &c, 1, 0) == 1) {
        if (c == '$') break;
        if (c == '+') continue; // ACK
    }
    if (c != '$') return false;

    // Read payload until '#'
    while (recv(s, &c, 1, 0) == 1) {
        if (c == '#') break;
        out_payload.push_back(c);
        if (out_payload.size() > 65536) return false;
    }

    // Read 2 checksum bytes
    char cs[2];
    if (recv(s, cs, 2, 0) != 2) return false;
    // Send ACK
    const char ack = '+';
    send(s, &ack, 1, 0);
    return true;
}

std::string ToHex(const std::string& s) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) {
        out.push_back(hex_chars[c >> 4]);
        out.push_back(hex_chars[c & 0x0f]);
    }
    return out;
}
} // namespace

bool DeviceSession::LaunchApp(const std::string& bundle_id_or_path,
                              std::uint32_t& out_pid,
                              std::string& error) {
    out_pid = 0;
    std::string exec_target = bundle_id_or_path;

    // Optional: resolve bundle ID to container path via InstallationProxy if available
    uint16_t inst_port = 0;
    bool inst_ssl = false;
    if (StartService("com.apple.mobile.installation_proxy", inst_port, inst_ssl, error)) {
        uintptr_t inst_sock = ConnectToServiceSocket(inst_port, error);
        if (inst_sock != ~0ULL) {
            std::string lookup_cmd =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
                "<plist version=\"1.0\"><dict>"
                "<key>Command</key><string>Lookup</string>"
                "<key>ClientOptions</key><dict>"
                "<key>BundleIDs</key><array><string>" + bundle_id_or_path + "</string></array>"
                "</dict></dict></plist>";
            if (SendPlist(inst_sock, lookup_cmd, error)) {
                std::string resp_xml;
                if (ReceivePlist(inst_sock, resp_xml, error)) {
                    plist_t node = nullptr;
                    if (plist_from_memory(resp_xml.data(), static_cast<uint32_t>(resp_xml.size()), &node, nullptr) == PLIST_ERR_SUCCESS && node) {
                        auto lookup_res = plist_dict_get_item(node, "LookupResult");
                        if (lookup_res && plist_get_node_type(lookup_res) == PLIST_DICT) {
                            auto app_dict = plist_dict_get_item(lookup_res, bundle_id_or_path.c_str());
                            if (app_dict && plist_get_node_type(app_dict) == PLIST_DICT) {
                                auto path_node = plist_dict_get_item(app_dict, "Path");
                                if (path_node && plist_get_node_type(path_node) == PLIST_STRING) {
                                    char* pv = nullptr;
                                    plist_get_string_val(path_node, &pv);
                                    if (pv) {
                                        exec_target = pv;
                                        free(pv);
                                    }
                                }
                            }
                        }
                        plist_free(node);
                    }
                }
            }
            CloseSocket(inst_sock);
        }
    }

    uint16_t remote_port = 0;
    bool ssl = false;
    if (!StartService("com.apple.debugserver", remote_port, ssl, error)) {
        if (!StartService("com.apple.debugserver.DVTSecureSocketProxy", remote_port, ssl, error)) {
            return false;
        }
    }

    uintptr_t dev_sock = ConnectToServiceSocket(remote_port, error);
    if (dev_sock == ~0ULL) return false;
    SOCKET s = static_cast<SOCKET>(dev_sock);

    // Initial handshake
    const char ack = '+';
    send(s, &ack, 1, 0);

    std::string resp;
    SendRspPacket(s, "QStartNoAckMode");
    ReadRspPacket(s, resp, 2000);

    SendRspPacket(s, "QSetDisableASLR:1");
    ReadRspPacket(s, resp, 2000);

    // Set arguments via A packet: A<hex_len>,0,<hex_encoded_arg>
    std::string hex_arg = ToHex(exec_target);
    std::string a_packet = "A" + std::to_string(hex_arg.size()) + ",0," + hex_arg;
    if (!SendRspPacket(s, a_packet) || !ReadRspPacket(s, resp, 5000)) {
        CloseSocket(dev_sock);
        error = "Failed to launch process via debugserver: " + resp;
        return false;
    }

    if (resp != "OK" && !resp.starts_with("T")) {
        // Fallback: try vRun packet
        std::string vrun_packet = "vRun;" + hex_arg;
        SendRspPacket(s, vrun_packet);
        ReadRspPacket(s, resp, 5000);
    }

    // Try to parse PID from stop response Txx...pid:xxxx;
    auto pid_pos = resp.find("pid:");
    if (pid_pos != std::string::npos) {
        try {
            out_pid = static_cast<uint32_t>(std::stoul(resp.substr(pid_pos + 4), nullptr, 16));
        } catch (...) {}
    }

    // If still 0, query qC
    if (out_pid == 0) {
        SendRspPacket(s, "qC");
        if (ReadRspPacket(s, resp, 2000) && resp.starts_with("QC")) {
            auto comma = resp.find('p');
            if (comma != std::string::npos) {
                try {
                    out_pid = static_cast<uint32_t>(std::stoul(resp.substr(comma + 1), nullptr, 16));
                } catch (...) {}
            }
        }
    }

    // Detach so the app continues running on device without debugger attached
    SendRspPacket(s, "D");
    ReadRspPacket(s, resp, 2000);

    CloseSocket(dev_sock);
    return true;
}

bool DeviceSession::StartDebugProxy(std::uint16_t local_port,
                                   const std::atomic<bool>& cancellation,
                                   std::string& error) {
    uint16_t remote_port = 0;
    bool ssl = false;
    if (!StartService("com.apple.debugserver", remote_port, ssl, error)) {
        if (!StartService("com.apple.debugserver.DVTSecureSocketProxy", remote_port, ssl, error)) {
            return false;
        }
    }

    uintptr_t dev_sock = ConnectToServiceSocket(remote_port, error);
    if (dev_sock == ~0ULL) return false;
    SOCKET s_dev = static_cast<SOCKET>(dev_sock);

    // Bind local listener
    SOCKET s_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s_listen == INVALID_SOCKET) {
        CloseSocket(dev_sock);
        error = "Failed to create local listening socket for LLDB debug proxy.";
        return false;
    }

    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s_listen, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) != 0 ||
        listen(s_listen, 1) != 0) {
        closesocket(s_listen);
        CloseSocket(dev_sock);
        error = "Failed to bind and listen on 127.0.0.1:" + std::to_string(local_port);
        return false;
    }

    std::cout << "OPENFRUIT: LLDB Debug Server Proxy listening on 127.0.0.1:" << local_port
              << " (forwarding to iOS device via " << (target_.mode == DeviceTransportMode::WiFi ? "WiFi" : "USB")
              << ")..." << std::endl;
    std::cout << "Connect with: lldb -o \"gdb-remote 127.0.0.1:" << local_port << "\"" << std::endl;

    // Accept client
    u_long non_blocking = 1;
    ioctlsocket(s_listen, FIONBIO, &non_blocking);

    SOCKET s_client = INVALID_SOCKET;
    while (!cancellation.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(s_listen, &fds);
        timeval tv{0, 200000};
        if (select(0, &fds, nullptr, nullptr, &tv) > 0) {
            s_client = accept(s_listen, nullptr, nullptr);
            if (s_client != INVALID_SOCKET) break;
        }
    }
    closesocket(s_listen);

    if (s_client == INVALID_SOCKET) {
        CloseSocket(dev_sock);
        return false;
    }

    // Bidirectional forwarding
    ioctlsocket(s_client, FIONBIO, &non_blocking);
    ioctlsocket(s_dev, FIONBIO, &non_blocking);

    std::array<char, 16384> buf;
    while (!cancellation.load()) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(s_client, &read_fds);
        FD_SET(s_dev, &read_fds);

        timeval tv{0, 50000};
        int sel = select(0, &read_fds, nullptr, nullptr, &tv);
        if (sel < 0) break;
        if (sel == 0) continue;

        if (FD_ISSET(s_client, &read_fds)) {
            int received = recv(s_client, buf.data(), static_cast<int>(buf.size()), 0);
            if (received <= 0) break;
            if (!SendAll(s_dev, buf.data(), received)) break;
        }

        if (FD_ISSET(s_dev, &read_fds)) {
            int received = recv(s_dev, buf.data(), static_cast<int>(buf.size()), 0);
            if (received <= 0) break;
            if (!SendAll(s_client, buf.data(), received)) break;
        }
    }

    closesocket(s_client);
    CloseSocket(dev_sock);
    return true;
}

bool DeviceSession::StreamPreview(std::uint16_t port,
                                  const std::function<bool(const char* data, std::size_t size)>& sink,
                                  const std::atomic<bool>& cancellation,
                                  std::string& error) {
    auto waiting_since = std::chrono::steady_clock::time_point{};
    std::vector<char> buffer(256 * 1024);
    while (!cancellation.load()) {
        std::string connect_error;
        uintptr_t sock = ConnectToServiceSocket(port, connect_error);
        if (sock == ~0ULL) {
            const auto now = std::chrono::steady_clock::now();
            if (waiting_since == std::chrono::steady_clock::time_point{} || now - waiting_since > std::chrono::seconds(10)) {
                std::cerr << "OPENFRUIT preview: waiting for the app on device port " << port
                          << " (open the app built with --preview)." << std::endl;
                waiting_since = now;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        waiting_since = {};
        std::cerr << "OPENFRUIT preview: connected." << std::endl;
        // Frames arrive continuously while the app is in the foreground; a
        // backgrounded app pauses the stream, so only a long silence reconnects.
        for (;;) {
            if (cancellation.load()) { CloseSocket(sock); return true; }
            const int received = recv(static_cast<SOCKET>(sock), buffer.data(), static_cast<int>(buffer.size()), 0);
            if (received <= 0) break;
            if (!sink(buffer.data(), static_cast<std::size_t>(received))) { CloseSocket(sock); return true; }
        }
        CloseSocket(sock);
        std::cerr << "OPENFRUIT preview: stream ended; waiting for the app." << std::endl;
    }
    (void)error;
    return true;
}

bool DeviceSession::RecordScreenFrames(const std::string& output_directory,
                                      std::uint32_t duration_seconds,
                                      const std::atomic<bool>& cancellation,
                                      std::string& error) {
    if (duration_seconds == 0) duration_seconds = 10;
    const auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(duration_seconds);

    std::cout << "OPENFRUIT: Recording screen frames (" << duration_seconds << "s) to " << output_directory
              << " via " << (target_.mode == DeviceTransportMode::WiFi ? "WiFi" : "USB") << "..." << std::endl;

    uint32_t frame_index = 0;
    while (!cancellation.load() && std::chrono::steady_clock::now() < end_time) {
        char name[64];
        snprintf(name, sizeof(name), "frame_%05u.png", frame_index++);
        std::string frame_path = output_directory + "/" + name;
        std::string shot_err;
        if (CaptureScreenshot(frame_path, shot_err)) {
            std::cout << "\rCaptured: " << name << std::flush;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // ~5 fps
    }
    std::cout << "\nRecording complete (" << frame_index << " frames)." << std::endl;
    return frame_index > 0;
}

} // namespace OpenFruit
