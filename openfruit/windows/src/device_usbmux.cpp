#include <winsock2.h>
#include <ws2tcpip.h>
#include "device_usbmux.hpp"
#include <plist/plist.h>
#include <algorithm>
#include <array>
#include <limits>
#include <set>

namespace OpenFruit {
namespace {
constexpr std::size_t kHeaderBytes = 16;
constexpr std::size_t kMaximumFrame = 16 * 1024 * 1024;
constexpr std::size_t kMaximumDevices = 16384;
constexpr std::uint32_t kProtocolVersion = 1, kPlistMessage = 8;

void Append32(std::string& output, std::uint32_t value) {
    for (unsigned i = 0; i != 4; ++i) output.push_back(static_cast<char>((value >> (i * 8)) & 255));
}
std::uint32_t Read32(std::string_view input, std::size_t position) {
    std::uint32_t value = 0;
    for (unsigned i = 0; i != 4; ++i)
        value |= static_cast<std::uint32_t>(static_cast<unsigned char>(input[position + i])) << (i * 8);
    return value;
}
bool LimitsValid(std::size_t bytes, std::size_t devices) {
    return bytes >= kHeaderBytes && bytes <= kMaximumFrame && devices > 0 && devices <= kMaximumDevices;
}
DeviceUsbmuxResult Error(DeviceUsbmuxStatus status, const char* error, unsigned long native_error = 0) {
    DeviceUsbmuxResult result;
    result.status = status; result.error = error; result.native_error = native_error;
    return result;
}
struct Plist {
    plist_t value = nullptr;
    ~Plist() { if (value) plist_free(value); }
};
bool StringField(plist_t dict, const char* key, std::string& output, std::size_t maximum) {
    const auto node = plist_dict_get_item(dict, key);
    if (!node || plist_get_node_type(node) != PLIST_STRING) return false;
    std::uint64_t length = 0;
    const auto text = plist_get_string_ptr(node, &length);
    if (!text || !length || length > maximum || std::string_view(text, static_cast<std::size_t>(length)).find('\0') != std::string_view::npos)
        return false;
    output.assign(text, static_cast<std::size_t>(length));
    return true;
}
bool UIntField(plist_t dict, const char* key, std::uint32_t& output) {
    const auto node = plist_dict_get_item(dict, key);
    if (!node || plist_get_node_type(node) != PLIST_UINT) return false;
    std::uint64_t value = 0;
    plist_get_uint_val(node, &value);
    if (value > std::numeric_limits<std::uint32_t>::max()) return false;
    output = static_cast<std::uint32_t>(value);
    return true;
}
struct Winsock {
    int error = 0;
    Winsock() { WSADATA data{}; error = WSAStartup(MAKEWORD(2, 2), &data); }
    ~Winsock() { if (!error) WSACleanup(); }
};
struct Socket {
    SOCKET value = INVALID_SOCKET;
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};
class Exchange {
public:
    const DeviceUsbmuxRequest& request;
    std::chrono::steady_clock::time_point deadline;
    DeviceUsbmuxResult failure;
    explicit Exchange(const DeviceUsbmuxRequest& input) : request(input),
        deadline(std::min(input.control.deadline, std::chrono::steady_clock::now() + input.timeout)) {}

    bool Check() {
        if (request.control.cancellation && request.control.cancellation->load()) {
            failure = Error(DeviceUsbmuxStatus::Cancelled, "Device discovery cancelled."); return false;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            failure = Error(DeviceUsbmuxStatus::TimedOut, "Device discovery deadline exceeded."); return false;
        }
        return true;
    }
    bool Wait(SOCKET socket, bool writing) {
        while (Check()) {
            fd_set ready, exceptional;
            FD_ZERO(&ready); FD_SET(socket, &ready);
            FD_ZERO(&exceptional); FD_SET(socket, &exceptional);
            const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - std::chrono::steady_clock::now());
            const auto micros = std::max<std::int64_t>(0, std::min<std::int64_t>(50000, remaining.count()));
            timeval interval{0, static_cast<long>(micros)};
            const auto count = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr, &exceptional, &interval);
            if (count == SOCKET_ERROR) {
                const auto code = WSAGetLastError();
                if (code == WSAEINTR) continue;
                failure = Error(DeviceUsbmuxStatus::TransportError, "Cannot wait for the local device service.", code); return false;
            }
            if (count) return Check();
        }
        return false;
    }
    bool Transfer(SOCKET socket, char* bytes, std::size_t length, bool writing) {
        std::size_t offset = 0;
        while (offset < length && Check()) {
            const auto wanted = static_cast<int>(std::min<std::size_t>(length - offset, 65536));
            const auto count = writing ? send(socket, bytes + offset, wanted, 0) : recv(socket, bytes + offset, wanted, 0);
            if (count > 0) { offset += static_cast<std::size_t>(count); continue; }
            if (!count) {
                failure = Error(DeviceUsbmuxStatus::TransportError, "Local device service closed an incomplete exchange."); return false;
            }
            const auto code = WSAGetLastError();
            if (code == WSAEINTR) continue;
            if (code == WSAEWOULDBLOCK) { if (!Wait(socket, writing)) return false; continue; }
            failure = Error(DeviceUsbmuxStatus::TransportError, "Local device service I/O failed.", code); return false;
        }
        return offset == length && Check();
    }
};
} // namespace

std::string DeviceUsbmux::BuildListDevicesRequest(std::uint32_t tag) {
    // Independent protocol composition from the public usbmux plist contract.
    // Protocol references: libimobiledevice/libusbmuxd usbmuxd-proto.h and
    // create_plist_message / send_list_devices_packet (no implementation copied).
    static constexpr std::string_view payload =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\"><dict>"
        "<key>MessageType</key><string>ListDevices</string>"
        "<key>ClientVersionString</key><string>OPENFRUIT native</string>"
        "<key>ProgName</key><string>OPENFRUIT</string>"
        "<key>kLibUSBMuxVersion</key><integer>3</integer>"
        "</dict></plist>";
    std::string frame;
    frame.reserve(kHeaderBytes + payload.size());
    Append32(frame, static_cast<std::uint32_t>(kHeaderBytes + payload.size()));
    Append32(frame, kProtocolVersion); Append32(frame, kPlistMessage); Append32(frame, tag);
    frame.append(payload);
    return frame;
}

DeviceUsbmuxResult DeviceUsbmux::ParseListDevicesResponse(std::string_view frame,
    std::uint32_t expected_tag, std::size_t max_frame_bytes, std::size_t max_devices) {
    if (!LimitsValid(max_frame_bytes, max_devices))
        return Error(DeviceUsbmuxStatus::InvalidRequest, "Invalid device discovery limits.");
    if (frame.size() < kHeaderBytes || frame.size() > max_frame_bytes || Read32(frame, 0) != frame.size() ||
        Read32(frame, 4) != kProtocolVersion || Read32(frame, 8) != kPlistMessage || Read32(frame, 12) != expected_tag)
        return Error(DeviceUsbmuxStatus::ProtocolError, "Invalid usbmux response frame or correlation tag.");
    Plist plist;
    plist_format_t format = PLIST_FORMAT_NONE;
    const auto payload = frame.substr(kHeaderBytes);
    if (plist_from_memory(payload.data(), static_cast<std::uint32_t>(payload.size()), &plist.value, &format) != PLIST_ERR_SUCCESS ||
        !plist.value || plist_get_node_type(plist.value) != PLIST_DICT)
        return Error(DeviceUsbmuxStatus::ProtocolError, "Device service returned a malformed property list.");
    const auto list = plist_dict_get_item(plist.value, "DeviceList");
    if (!list) {
        std::string type;
        std::uint32_t code = 0;
        if (StringField(plist.value, "MessageType", type, 64) && type == "Result" && UIntField(plist.value, "Number", code)) {
            auto result = Error(code == 1 || code == 6 ? DeviceUsbmuxStatus::Unsupported : DeviceUsbmuxStatus::ProtocolError,
                "Device service did not provide a ListDevices response.");
            result.daemon_result = code;
            return result;
        }
        return Error(DeviceUsbmuxStatus::ProtocolError, "Device service response has no DeviceList.");
    }
    if (plist_get_node_type(list) != PLIST_ARRAY || plist_array_get_size(list) > max_devices)
        return Error(DeviceUsbmuxStatus::ProtocolError, "Invalid or oversized device list.");
    DeviceUsbmuxResult result;
    std::set<std::uint32_t> ids;
    for (std::uint32_t i = 0; i < plist_array_get_size(list); ++i) {
        const auto item = plist_array_get_item(list, i);
        if (!item || plist_get_node_type(item) != PLIST_DICT)
            return Error(DeviceUsbmuxStatus::ProtocolError, "Invalid device list entry.");
        const auto properties = plist_dict_get_item(item, "Properties");
        UsbMuxDevice device;
        if (!properties || plist_get_node_type(properties) != PLIST_DICT ||
            !UIntField(properties, "DeviceID", device.device_id) || !device.device_id ||
            !StringField(properties, "SerialNumber", device.udid, 256) ||
            !StringField(properties, "ConnectionType", device.connection_type, 32) ||
            (device.connection_type != "USB" && device.connection_type != "Network") ||
            !ids.insert(device.device_id).second)
            return Error(DeviceUsbmuxStatus::ProtocolError, "Invalid or duplicate device properties.");
        if (plist_dict_get_item(properties, "ProductID") && !UIntField(properties, "ProductID", device.product_id))
            return Error(DeviceUsbmuxStatus::ProtocolError, "Invalid device ProductID.");
        result.devices.push_back(std::move(device));
    }
    result.status = DeviceUsbmuxStatus::Complete;
    return result;
}

DeviceUsbmuxResult DeviceUsbmux::ListDevices(const DeviceUsbmuxRequest& request) {
    if (!request.port || !LimitsValid(request.max_frame_bytes, request.max_devices) ||
        request.timeout <= std::chrono::milliseconds::zero() || request.timeout > std::chrono::minutes(5))
        return Error(DeviceUsbmuxStatus::InvalidRequest, "Invalid local device discovery request.");
    constexpr std::uint32_t tag = 1; // One request and one response per owned connection.
    auto frame = BuildListDevicesRequest(tag);
    if (frame.size() > request.max_frame_bytes)
        return Error(DeviceUsbmuxStatus::InvalidRequest, "Device discovery frame budget is too small for the request.");
    Exchange exchange(request);
    if (!exchange.Check()) return exchange.failure;
    Winsock winsock;
    if (winsock.error) return Error(DeviceUsbmuxStatus::TransportError, "Cannot initialize Windows sockets.", winsock.error);
    Socket socket;
    socket.value = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket.value == INVALID_SOCKET)
        return Error(DeviceUsbmuxStatus::TransportError, "Cannot create local device service socket.", WSAGetLastError());
    u_long nonblocking = 1;
    if (ioctlsocket(socket.value, FIONBIO, &nonblocking))
        return Error(DeviceUsbmuxStatus::TransportError, "Cannot configure nonblocking device discovery.", WSAGetLastError());
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET; endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    endpoint.sin_port = htons(request.port);
    if (!exchange.Check()) return exchange.failure;
    if (connect(socket.value, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) == SOCKET_ERROR) {
        const auto code = WSAGetLastError();
        if (code != WSAEWOULDBLOCK && code != WSAEINPROGRESS)
            return Error(code == WSAECONNREFUSED ? DeviceUsbmuxStatus::Unavailable : DeviceUsbmuxStatus::TransportError,
                "Local usbmux service is unavailable.", code);
        if (!exchange.Wait(socket.value, true)) return exchange.failure;
        int completion = 0, length = sizeof(completion);
        if (getsockopt(socket.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&completion), &length))
            return Error(DeviceUsbmuxStatus::TransportError, "Cannot inspect local usbmux connection.", WSAGetLastError());
        if (completion)
            return Error(completion == WSAECONNREFUSED ? DeviceUsbmuxStatus::Unavailable : DeviceUsbmuxStatus::TransportError,
                "Local usbmux connection failed.", static_cast<unsigned long>(completion));
    }
    if (!exchange.Transfer(socket.value, frame.data(), frame.size(), true)) return exchange.failure;
    std::array<char, kHeaderBytes> header{};
    if (!exchange.Transfer(socket.value, header.data(), header.size(), false)) return exchange.failure;
    const auto header_view = std::string_view(header.data(), header.size());
    const auto size = Read32(header_view, 0);
    if (size < kHeaderBytes || size > request.max_frame_bytes || Read32(header_view, 4) != kProtocolVersion ||
        Read32(header_view, 8) != kPlistMessage || Read32(header_view, 12) != tag)
        return Error(DeviceUsbmuxStatus::ProtocolError, "Device service declared an invalid frame length.");
    frame.assign(header.data(), header.size());
    frame.resize(size);
    if (size > kHeaderBytes && !exchange.Transfer(socket.value, frame.data() + kHeaderBytes, size - kHeaderBytes, false))
        return exchange.failure;
    if (!exchange.Check()) return exchange.failure;
    auto result = ParseListDevicesResponse(frame, tag, request.max_frame_bytes, request.max_devices);
    if (!exchange.Check()) return exchange.failure;
    return result;
}

std::string DeviceUsbmux::BuildConnectRequest(std::uint32_t tag, std::uint32_t device_id, std::uint16_t port_number) {
    const uint16_t net_port = ((port_number & 0xFF) << 8) | ((port_number >> 8) & 0xFF);
    std::string payload =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\"><dict>"
        "<key>MessageType</key><string>Connect</string>"
        "<key>ClientVersionString</key><string>OPENFRUIT native</string>"
        "<key>ProgName</key><string>OPENFRUIT</string>"
        "<key>kLibUSBMuxVersion</key><integer>3</integer>"
        "<key>DeviceID</key><integer>" + std::to_string(device_id) + "</integer>"
        "<key>PortNumber</key><integer>" + std::to_string(net_port) + "</integer>"
        "</dict></plist>";
    std::string frame;
    frame.reserve(kHeaderBytes + payload.size());
    Append32(frame, static_cast<std::uint32_t>(kHeaderBytes + payload.size()));
    Append32(frame, kProtocolVersion);
    Append32(frame, kPlistMessage);
    Append32(frame, tag);
    frame.append(payload);
    return frame;
}

bool DeviceUsbmux::ParseConnectResponse(std::string_view frame, std::uint32_t expected_tag, std::uint32_t& daemon_result, std::string& error) {
    if (frame.size() < kHeaderBytes || Read32(frame, 0) != frame.size() ||
        Read32(frame, 4) != kProtocolVersion || Read32(frame, 8) != kPlistMessage || Read32(frame, 12) != expected_tag) {
        error = "Invalid usbmux connect frame or correlation tag.";
        return false;
    }
    Plist plist;
    plist_format_t format = PLIST_FORMAT_NONE;
    const auto payload = frame.substr(kHeaderBytes);
    if (plist_from_memory(payload.data(), static_cast<std::uint32_t>(payload.size()), &plist.value, &format) != PLIST_ERR_SUCCESS ||
        !plist.value || plist_get_node_type(plist.value) != PLIST_DICT) {
        error = "Device service returned a malformed property list.";
        return false;
    }
    std::string type;
    if (!StringField(plist.value, "MessageType", type, 64) || type != "Result") {
        error = "Expected Result message from Connect request.";
        return false;
    }
    if (!UIntField(plist.value, "Number", daemon_result)) {
        error = "Missing Number in Result response.";
        return false;
    }
    return daemon_result == 0;
}

LockdownPairingRecord DeviceUsbmux::LoadPairingRecord(const std::string& udid) {
    LockdownPairingRecord record;
    if (udid.empty()) return record;

    std::vector<std::wstring> candidate_dirs;
    // Apple's pairing records live under %ProgramData%\Apple\Lockdown.
    wchar_t program_data[MAX_PATH]{};
    const DWORD program_data_length = GetEnvironmentVariableW(L"ProgramData", program_data, MAX_PATH);
    if (program_data_length > 0 && program_data_length < MAX_PATH)
        candidate_dirs.push_back(std::wstring(program_data, program_data_length) + L"\\Apple\\Lockdown");
    wchar_t profile[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH)) {
        candidate_dirs.push_back(std::wstring(profile) + L"\\.openfruit\\lockdown");
    }
    wchar_t localapp[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", localapp, MAX_PATH)) {
        candidate_dirs.push_back(std::wstring(localapp) + L"\\Apple\\Lockdown");
    }

    std::wstring wudid(udid.begin(), udid.end());
    for (const auto& dir : candidate_dirs) {
        std::wstring path = dir + L"\\" + wudid + L".plist";
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        DWORD size = GetFileSize(hFile, nullptr);
        if (size > 0 && size < 1024 * 1024) {
            std::string content(size, '\0');
            DWORD read_bytes = 0;
            if (ReadFile(hFile, content.data(), size, &read_bytes, nullptr) && read_bytes == size) {
                Plist plist;
                plist_format_t fmt = PLIST_FORMAT_NONE;
                if (plist_from_memory(content.data(), static_cast<uint32_t>(size), &plist.value, &fmt) == PLIST_ERR_SUCCESS && plist.value) {
                    StringField(plist.value, "HostID", record.host_id, 256);
                    StringField(plist.value, "SystemBUID", record.system_buid, 256);
                    // TLS identity of the pairing: PEM bytes stored as data.
                    const auto data = [&](const char* key, std::string& output) {
                        const auto item = plist_dict_get_item(plist.value, key);
                        if (!item || plist_get_node_type(item) != PLIST_DATA) return;
                        uint64_t length = 0;
                        const char* bytes = plist_get_data_ptr(item, &length);
                        if (bytes && length < 64 * 1024) output.assign(bytes, static_cast<std::size_t>(length));
                    };
                    data("HostCertificate", record.host_certificate);
                    data("HostPrivateKey", record.host_private_key);
                    data("DeviceCertificate", record.device_certificate);
                    record.is_valid = !record.host_id.empty();
                }
            }
        }
        CloseHandle(hFile);
        if (record.is_valid) break;
    }
    return record;
}

} // namespace OpenFruit
