#include <winsock2.h>
#include <ws2tcpip.h>
#include "http_transfer.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include <atomic>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
namespace fs = std::filesystem;
using namespace OpenFruit;
namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void Write(const fs::path& path, const std::string& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << bytes;
    file.close();
    Require(static_cast<bool>(file), "owned fixture write failed");
}
std::string Read(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
// The worker exits after one request or stop. Warm reuse must never contact it.
class Server {
public:
    std::atomic<unsigned> requests{0};
    explicit Server(std::string response) {
        listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Require(listener_ != INVALID_SOCKET, "owned socket failed");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        Require(!bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) &&
            !listen(listener_, 4), "owned listener failed");
        int size = sizeof(address);
        Require(!getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &size), "owned port failed");
        port_ = ntohs(address.sin_port);
        worker_ = std::jthread([this, response = std::move(response)](std::stop_token stop) {
            while (!stop.stop_requested()) {
                fd_set ready;
                FD_ZERO(&ready); FD_SET(listener_, &ready);
                timeval timeout{0, 100000};
                if (select(0, &ready, nullptr, nullptr, &timeout) <= 0) continue;
                SOCKET client = accept(listener_, nullptr, nullptr);
                if (client == INVALID_SOCKET) continue;
                DWORD limit = 1000;
                setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&limit), sizeof(limit));
                std::string request;
                char bytes[1024];
                while (request.find("\r\n\r\n") == std::string::npos && request.size() < 16384) {
                    const auto count = recv(client, bytes, sizeof(bytes), 0);
                    if (count <= 0) break;
                    request.append(bytes, count);
                }
                ++requests;
                std::size_t sent = 0;
                while (sent < response.size()) {
                    const auto count = send(client, response.data() + sent, static_cast<int>(response.size() - sent), 0);
                    if (count <= 0) break;
                    sent += count;
                }
                shutdown(client, SD_BOTH); closesocket(client);
                return;
            }
        });
    }
    ~Server() {
        worker_.request_stop();
        if (worker_.joinable()) worker_.join();
        closesocket(listener_);
    }
    std::wstring Url() const { return L"http://127.0.0.1:" + std::to_wstring(port_) + L"/owned"; }
private:
    SOCKET listener_ = INVALID_SOCKET;
    unsigned short port_ = 0;
    std::jthread worker_;
};
struct Sink : EventSink {
    bool verified_reuse = false;
    void Emit(OperationEvent event) noexcept override {
        const auto* reused = event.data.Get("reused");
        const auto* verified = event.data.Get("integrity_verified");
        if (event.kind == "task.completed" && reused && verified && reused->Bool() && verified->Bool())
            verified_reuse = true;
    }
};
}
int main() {
    WSADATA sockets{};
    if (WSAStartup(MAKEWORD(2, 2), &sockets)) return 2;
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-transfer-reuse-" + NewOperationId());
    try {
        fs::create_directories(root);
        const std::string payload = "owned verified completed download";
        const std::string rejected = "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        const std::string accepted = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(payload.size()) +
            "\r\nConnection: close\r\n\r\n" + payload;
        TransferRequest request;
        request.destination = root / "archive";
        request.expected_sha256 = Sha256(payload).value();
        request.max_bytes = payload.size();
        request.allow_loopback_http = true;
        request.reuse_verified_destination = true;
        request.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        Write(request.destination, payload);
        const auto original_time = fs::last_write_time(request.destination);
        Write(root / "archive.partial", "unrelated incomplete bytes");
        Write(root / "archive.partial.json", "unrelated resume metadata");
        auto sink = std::make_shared<Sink>();
        auto context = std::make_shared<OperationContext>(); context->sink = sink;
        OperationBinding binding(context);
        {
            Server server(rejected);
            request.url = server.Url();
            const auto result = HttpTransfer::Download(request);
            Require(result.Succeeded() && result.reused && !result.resumed && result.http_status == 0 &&
                result.bytes == payload.size() && server.requests == 0, "warm reuse contacted network or misreported");
            Require(Read(request.destination) == payload && fs::last_write_time(request.destination) == original_time,
                "warm reuse mutated final");
            Require(Read(root / "archive.partial") == "unrelated incomplete bytes" &&
                Read(root / "archive.partial.json") == "unrelated resume metadata", "warm reuse mutated resume files");
            Require(sink->verified_reuse, "reuse diagnostic missing");
        }
        {
            Server server(rejected); request.url = server.Url(); request.reuse_verified_destination = false;
            const auto result = HttpTransfer::Download(request);
            Require(result.status == TransferStatus::HttpFailure && !result.reused && server.requests == 1 &&
                Read(request.destination) == payload, "default fresh-transfer semantics changed");
            request.reuse_verified_destination = true;
        }
        {
            // Same-size corruption must never be admitted by a receipt/size shortcut.
            Write(request.destination, std::string(payload.size(), 'x'));
            Server server(accepted); request.url = server.Url();
            const auto result = HttpTransfer::Download(request);
            Require(result.Succeeded() && !result.reused && server.requests == 1 &&
                Read(request.destination) == payload, "corrupt final was reused or not repaired");
        }
        {
            Server server(rejected); request.url = server.Url(); --request.max_bytes;
            const auto result = HttpTransfer::Download(request);
            Require(!result.Succeeded() && !result.reused && server.requests == 1 &&
                Read(request.destination) == payload, "oversized final bypassed bound");
            ++request.max_bytes;
        }
        {
            Server server(accepted); request.url = server.Url(); fs::remove(request.destination);
            const auto result = HttpTransfer::Download(request);
            Require(result.Succeeded() && !result.reused && server.requests == 1 &&
                Read(request.destination) == payload, "cold opt-in transfer failed");
        }
        {
            Server server(rejected); request.url = server.Url();
            HANDLE held = CreateFileW((request.destination.wstring() + L".transfer-lock").c_str(),
                GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            Require(held != INVALID_HANDLE_VALUE, "owned transfer lock failed");
            const auto result = HttpTransfer::Download(request);
            CloseHandle(held);
            Require(result.status == TransferStatus::Busy && !result.reused && server.requests == 0,
                "reuse bypassed singleflight lock");
            CancellationSource cancel; cancel.Cancel(); request.cancellation = cancel.Token();
            Require(HttpTransfer::Download(request).status == TransferStatus::Cancelled, "cancelled reuse succeeded");
            request.cancellation = {};
            request.deadline = std::chrono::steady_clock::now();
            Require(HttpTransfer::Download(request).status == TransferStatus::TimedOut, "expired reuse succeeded");
            request.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            auto cancelled = std::make_shared<OperationContext>(); cancelled->RequestCancellation();
            {
                OperationBinding nested(cancelled);
                Require(HttpTransfer::Download(request).status == TransferStatus::Cancelled, "context cancellation bypassed");
            }
            auto expired = std::make_shared<OperationContext>();
            expired->control = std::make_shared<OperationControl>(std::chrono::steady_clock::now());
            {
                OperationBinding nested(expired);
                Require(HttpTransfer::Download(request).status == TransferStatus::TimedOut, "context deadline bypassed");
            }
            request.expected_sha256.clear();
            Require(HttpTransfer::Download(request).status == TransferStatus::InvalidRequest, "hashless reuse succeeded");
            request.expected_sha256 = Sha256(payload).value();
            request.destination = root / "directory"; fs::create_directory(request.destination);
            Require(HttpTransfer::Download(request).status == TransferStatus::IoFailure, "directory admitted as final");
            request.destination = root / "link";
            if (CreateSymbolicLinkW(request.destination.c_str(), (root / "archive").c_str(), 0x2)) {
                Require(HttpTransfer::Download(request).status == TransferStatus::IoFailure &&
                    Read(root / "archive") == payload, "reparse final admitted or target mutated");
            } else if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD) {
                std::cout << "file-symlink case unavailable without developer mode\n";
            } else {
                throw std::runtime_error("owned file symlink failed unexpectedly");
            }
            Require(server.requests == 0, "invalid/interrupted reuse contacted network");
        }
        fs::remove_all(root);
        WSACleanup();
        std::cout << "verified final-file reuse contract passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; retained owned fixture: " << root << '\n';
        WSACleanup();
        return 1;
    }
}
