#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace OpenFruit {

// TLS client for lockdown and lockdown services, as libimobiledevice: the
// pairing record's host certificate and private key (PEM) authenticate the
// host; the device certificate is not validated against a public trust root.
// Uses Windows Schannel over an already connected socket.
class DeviceTlsChannel {
public:
    DeviceTlsChannel();
    ~DeviceTlsChannel();
    DeviceTlsChannel(const DeviceTlsChannel&) = delete;
    DeviceTlsChannel& operator=(const DeviceTlsChannel&) = delete;

    bool Handshake(std::uintptr_t socket, const std::string& host_certificate_pem,
                   const std::string& host_private_key_pem, std::string& error);
    bool Send(const char* data, std::size_t size, std::string& error);
    // Reads exactly size bytes of application data.
    bool Receive(char* data, std::size_t size, std::string& error);

private:
    struct State;
    std::unique_ptr<State> state_;
};

// PEM helpers exposed for contract tests.
bool DecodePemBlock(const std::string& pem, std::string& der, std::string& label);

} // namespace OpenFruit
