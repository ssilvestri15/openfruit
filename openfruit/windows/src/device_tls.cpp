#include "device_tls.hpp"

#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>

#include <atomic>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

namespace OpenFruit {

bool DecodePemBlock(const std::string& pem, std::string& der, std::string& label) {
    der.clear(); label.clear();
    const auto begin = pem.find("-----BEGIN ");
    if (begin == std::string::npos) return false;
    const auto label_end = pem.find("-----", begin + 11);
    if (label_end == std::string::npos) return false;
    label = pem.substr(begin + 11, label_end - begin - 11);
    const auto end = pem.find("-----END " + label + "-----", label_end);
    if (end == std::string::npos) return false;
    const auto block = pem.substr(begin, end + 14 + label.size() - begin);
    DWORD size = 0;
    if (!CryptStringToBinaryA(block.data(), static_cast<DWORD>(block.size()), CRYPT_STRING_BASE64HEADER,
                              nullptr, &size, nullptr, nullptr) || !size) return false;
    der.resize(size);
    if (!CryptStringToBinaryA(block.data(), static_cast<DWORD>(block.size()), CRYPT_STRING_BASE64HEADER,
                              reinterpret_cast<BYTE*>(der.data()), &size, nullptr, nullptr)) return false;
    der.resize(size);
    return true;
}

namespace {

std::string LastError(const char* what, long code) {
    char text[32];
    wsprintfA(text, "0x%08lX", static_cast<unsigned long>(code));
    return std::string(what) + " (" + text + ")";
}

// PKCS#1 or PKCS#8 RSA private key DER -> legacy CryptoAPI PRIVATEKEYBLOB.
bool RsaPrivateBlob(const std::string& der, const std::string& label, std::vector<BYTE>& blob) {
    std::string pkcs1 = der;
    if (label == "PRIVATE KEY") {
        CRYPT_PRIVATE_KEY_INFO* info = nullptr;
        DWORD size = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
                reinterpret_cast<const BYTE*>(der.data()), static_cast<DWORD>(der.size()),
                CRYPT_DECODE_ALLOC_FLAG, nullptr, &info, &size)) return false;
        pkcs1.assign(reinterpret_cast<const char*>(info->PrivateKey.pbData), info->PrivateKey.cbData);
        LocalFree(info);
    } else if (label != "RSA PRIVATE KEY") {
        return false;
    }
    BYTE* decoded = nullptr;
    DWORD size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
            reinterpret_cast<const BYTE*>(pkcs1.data()), static_cast<DWORD>(pkcs1.size()),
            CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded, &size)) return false;
    blob.assign(decoded, decoded + size);
    LocalFree(decoded);
    return true;
}

std::atomic<unsigned> g_container_counter{0};

} // namespace

struct DeviceTlsChannel::State {
    SOCKET socket = INVALID_SOCKET;
    PCCERT_CONTEXT certificate = nullptr;
    std::wstring container;          // CryptoAPI key container of the host key
    HCRYPTPROV provider = 0;
    HCRYPTKEY key = 0;
    CredHandle credentials{};
    CtxtHandle context{};
    bool have_credentials = false, have_context = false;
    SecPkgContext_StreamSizes sizes{};
    std::vector<char> incoming;   // undecrypted bytes from the socket
    std::vector<char> plaintext;  // decrypted bytes not yet returned
    std::size_t plaintext_offset = 0;

    ~State() {
        if (have_context) DeleteSecurityContext(&context);
        if (have_credentials) FreeCredentialsHandle(&credentials);
        if (certificate) CertFreeCertificateContext(certificate);
        if (key) CryptDestroyKey(key);
        if (provider) CryptReleaseContext(provider, 0);
        // The persisted container exists only for this channel.
        if (!container.empty()) {
            HCRYPTPROV removed = 0;
            CryptAcquireContextW(&removed, container.c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
        }
    }

    bool ReadMore(std::string& error) {
        char buffer[16 * 1024];
        const int received = recv(socket, buffer, sizeof(buffer), 0);
        if (received <= 0) { error = "TLS peer closed the connection."; return false; }
        incoming.insert(incoming.end(), buffer, buffer + received);
        return true;
    }
    bool SendToken(const SecBuffer& token, std::string& error) {
        if (!token.cbBuffer || !token.pvBuffer) return true;
        const char* data = static_cast<const char*>(token.pvBuffer);
        std::size_t sent = 0;
        while (sent < token.cbBuffer) {
            const int count = send(socket, data + sent, static_cast<int>(token.cbBuffer - sent), 0);
            if (count <= 0) { error = "Failed to send TLS handshake data."; return false; }
            sent += static_cast<std::size_t>(count);
        }
        return true;
    }
};

DeviceTlsChannel::DeviceTlsChannel() : state_(std::make_unique<State>()) {}
DeviceTlsChannel::~DeviceTlsChannel() = default;

bool DeviceTlsChannel::Handshake(std::uintptr_t socket, const std::string& host_certificate_pem,
                                 const std::string& host_private_key_pem, std::string& error) {
    auto& s = *state_;
    s.socket = static_cast<SOCKET>(socket);
    std::string der, label;
    if (!DecodePemBlock(host_certificate_pem, der, label) || label != "CERTIFICATE") {
        error = "Pairing record HostCertificate is not a PEM certificate."; return false;
    }
    s.certificate = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        reinterpret_cast<const BYTE*>(der.data()), static_cast<DWORD>(der.size()));
    if (!s.certificate) { error = LastError("Cannot load pairing host certificate", GetLastError()); return false; }
    std::vector<BYTE> blob;
    if (!DecodePemBlock(host_private_key_pem, der, label) || !RsaPrivateBlob(der, label, blob)) {
        error = "Pairing record HostPrivateKey is not a PEM RSA private key."; return false;
    }
    // Schannel signs with a key it opens by name: persist it in a user key
    // container (CryptoAPI, key exchange) for the duration of the channel.
    s.container = L"OPENFRUIT-device-tls-" + std::to_wstring(GetCurrentProcessId()) +
        L"-" + std::to_wstring(++g_container_counter);
    if (!CryptAcquireContextW(&s.provider, s.container.c_str(), MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
        const auto code = GetLastError();
        s.container.clear();
        error = LastError("Cannot create a key container for the pairing host key", static_cast<long>(code));
        return false;
    }
    const BOOL imported = CryptImportKey(s.provider, blob.data(), static_cast<DWORD>(blob.size()), 0, 0, &s.key);
    SecureZeroMemory(blob.data(), blob.size());
    if (!imported) { error = LastError("Cannot import pairing host key", static_cast<long>(GetLastError())); return false; }
    CRYPT_KEY_PROV_INFO provider_info{};
    provider_info.pwszContainerName = const_cast<wchar_t*>(s.container.c_str());
    provider_info.pwszProvName = const_cast<wchar_t*>(MS_ENH_RSA_AES_PROV_W);
    provider_info.dwProvType = PROV_RSA_AES;
    provider_info.dwKeySpec = AT_KEYEXCHANGE;
    if (!CertSetCertificateContextProperty(s.certificate, CERT_KEY_PROV_INFO_PROP_ID, 0, &provider_info)) {
        error = LastError("Cannot bind pairing host key to its certificate", GetLastError()); return false;
    }

    SECURITY_STATUS status = SEC_E_OK;
    SCHANNEL_CRED credential{};
    credential.dwVersion = SCHANNEL_CRED_VERSION;
    credential.cCreds = 1;
    credential.paCred = &s.certificate;
    credential.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    // The device certificate is pinned by pairing, not by a public root.
    credential.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
    TimeStamp expiry{};
    status = AcquireCredentialsHandleW(nullptr, const_cast<wchar_t*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND, nullptr,
                                       &credential, nullptr, nullptr, &s.credentials, &expiry);
    if (status != SEC_E_OK) { error = LastError("Cannot acquire TLS client credentials", status); return false; }
    s.have_credentials = true;

    constexpr DWORD request = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION | ISC_REQ_USE_SUPPLIED_CREDS;
    DWORD attributes = 0;
    bool first = true, need_data = false;
    for (;;) {
        if (!first && (need_data || s.incoming.empty()) && !s.ReadMore(error)) return false;
        SecBuffer input[2]{{static_cast<ULONG>(s.incoming.size()), SECBUFFER_TOKEN, s.incoming.data()},
                           {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc input_desc{SECBUFFER_VERSION, 2, input};
        SecBuffer output{0, SECBUFFER_TOKEN, nullptr};
        SecBufferDesc output_desc{SECBUFFER_VERSION, 1, &output};
        status = InitializeSecurityContextW(&s.credentials, first ? nullptr : &s.context, nullptr, request, 0, 0,
            first ? nullptr : &input_desc, 0, first ? &s.context : nullptr, &output_desc, &attributes, &expiry);
        if (first) s.have_context = true;
        first = false;
        if (status == SEC_E_INCOMPLETE_MESSAGE) { need_data = true; continue; }
        const bool sent = s.SendToken(output, error);
        if (output.pvBuffer) FreeContextBuffer(output.pvBuffer);
        if (!sent) return false;
        if (FAILED(status)) { error = LastError("TLS handshake with the device failed", status); return false; }
        if (input[1].BufferType == SECBUFFER_EXTRA && input[1].cbBuffer)
            s.incoming.erase(s.incoming.begin(), s.incoming.end() - input[1].cbBuffer);
        else if (status != SEC_I_INCOMPLETE_CREDENTIALS)
            s.incoming.clear();
        need_data = false;
        if (status == SEC_E_OK) break;
    }
    status = QueryContextAttributesW(&s.context, SECPKG_ATTR_STREAM_SIZES, &s.sizes);
    if (status != SEC_E_OK) { error = LastError("Cannot query TLS stream sizes", status); return false; }
    return true;
}

bool DeviceTlsChannel::Send(const char* data, std::size_t size, std::string& error) {
    auto& s = *state_;
    std::vector<char> frame;
    while (size) {
        const auto chunk = static_cast<ULONG>(std::min<std::size_t>(size, s.sizes.cbMaximumMessage));
        frame.assign(s.sizes.cbHeader + chunk + s.sizes.cbTrailer, 0);
        std::copy(data, data + chunk, frame.begin() + s.sizes.cbHeader);
        SecBuffer buffers[4]{{s.sizes.cbHeader, SECBUFFER_STREAM_HEADER, frame.data()},
                             {chunk, SECBUFFER_DATA, frame.data() + s.sizes.cbHeader},
                             {s.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, frame.data() + s.sizes.cbHeader + chunk},
                             {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, buffers};
        const auto status = EncryptMessage(&s.context, 0, &desc, 0);
        if (status != SEC_E_OK) { error = LastError("TLS encryption failed", status); return false; }
        SecBuffer token{buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer, SECBUFFER_TOKEN, frame.data()};
        if (!s.SendToken(token, error)) return false;
        data += chunk; size -= chunk;
    }
    return true;
}

bool DeviceTlsChannel::Receive(char* data, std::size_t size, std::string& error) {
    auto& s = *state_;
    while (size) {
        if (s.plaintext_offset < s.plaintext.size()) {
            const auto count = std::min(size, s.plaintext.size() - s.plaintext_offset);
            std::copy_n(s.plaintext.begin() + s.plaintext_offset, count, data);
            s.plaintext_offset += count; data += count; size -= count;
            continue;
        }
        s.plaintext.clear(); s.plaintext_offset = 0;
        if (s.incoming.empty() && !s.ReadMore(error)) return false;
        SecBuffer buffers[4]{{static_cast<ULONG>(s.incoming.size()), SECBUFFER_DATA, s.incoming.data()},
                             {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc desc{SECBUFFER_VERSION, 4, buffers};
        const auto status = DecryptMessage(&s.context, &desc, 0, nullptr);
        if (status == SEC_E_INCOMPLETE_MESSAGE) { if (!s.ReadMore(error)) return false; continue; }
        if (status == SEC_I_CONTEXT_EXPIRED) { error = "TLS peer closed the session."; return false; }
        if (status != SEC_E_OK) { error = LastError("TLS decryption failed", status); return false; }
        std::vector<char> extra;
        for (auto& buffer : buffers) {
            if (buffer.BufferType == SECBUFFER_DATA)
                s.plaintext.insert(s.plaintext.end(), static_cast<char*>(buffer.pvBuffer),
                                   static_cast<char*>(buffer.pvBuffer) + buffer.cbBuffer);
            else if (buffer.BufferType == SECBUFFER_EXTRA)
                extra.assign(s.incoming.end() - buffer.cbBuffer, s.incoming.end());
        }
        s.incoming = std::move(extra);
    }
    return true;
}

} // namespace OpenFruit
