#include <winsock2.h>
#include <ws2tcpip.h>
#include "http_transfer.hpp"
#include "content_hash.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <atomic>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
namespace fs = std::filesystem;
struct Reply { std::string text; bool stall = false; };
class Server {
public:
    unsigned short port = 0;
    std::vector<std::string> requests;
    explicit Server(std::vector<Reply> responses) : replies_(std::move(responses)) {
        listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(listener_, 8)) throw std::runtime_error("Owned server failed");
        int size = sizeof(address); getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &size);
        port = ntohs(address.sin_port);
        worker_ = std::jthread([this](std::stop_token stop) {
            std::size_t next = 0;
            while (!stop.stop_requested() && next < replies_.size()) {
                fd_set ready; FD_ZERO(&ready); FD_SET(listener_, &ready);
                timeval timeout{0, 100000};
                if (select(0, &ready, nullptr, nullptr, &timeout) <= 0) continue;
                SOCKET client = accept(listener_, nullptr, nullptr);
                if (client == INVALID_SOCKET) continue;
                DWORD receive_timeout = 1000;
                setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&receive_timeout), sizeof(receive_timeout));
                std::string request;
                char buffer[4096];
                while (request.find("\r\n\r\n") == std::string::npos && request.size() < 16384) {
                    const auto count = recv(client, buffer, sizeof(buffer), 0);
                    if (count <= 0) break;
                    request.append(buffer, count);
                }
                const auto headers_end = request.find("\r\n\r\n");
                const auto length_header = request.find("Content-Length: ");
                if (headers_end != std::string::npos && length_header != std::string::npos && length_header < headers_end) {
                    const auto line_end = request.find("\r\n", length_header);
                    const auto body_size = std::stoul(request.substr(length_header + 16, line_end - length_header - 16));
                    while (request.size() < headers_end + 4 + body_size && request.size() < 16384) {
                        const auto count = recv(client, buffer, sizeof(buffer), 0);
                        if (count <= 0) break;
                        request.append(buffer, count);
                    }
                }
                requests.push_back(request);
                const auto& reply = replies_[next++];
                std::size_t sent = 0;
                while (sent < reply.text.size()) {
                    const auto count = send(client, reply.text.data() + sent, static_cast<int>(reply.text.size() - sent), 0);
                    if (count <= 0) break;
                    sent += count;
                }
                if (reply.stall) std::this_thread::sleep_for(std::chrono::milliseconds(500));
                shutdown(client, SD_BOTH); closesocket(client);
            }
        });
    }
    ~Server() { if (worker_.joinable()) { worker_.request_stop(); worker_.join(); } closesocket(listener_); }
    void Finish() { worker_.join(); }
    std::wstring Url() const { return L"http://127.0.0.1:" + std::to_wstring(port) + L"/file?token=owned-url-secret"; }
private:
    SOCKET listener_ = INVALID_SOCKET;
    std::jthread worker_;
    std::vector<Reply> replies_;
};
struct Sink : OpenFruit::EventSink {
    std::vector<OpenFruit::OperationEvent> events;
    void Emit(OpenFruit::OperationEvent event) noexcept override { events.push_back(std::move(event)); }
};
std::string Read(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
int main(int argc, char** argv) {
    if (argc == 6 && std::string(argv[1]) == "--range") {
        OpenFruit::RangeTransferRequest request;
        request.url = OpenFruit::Win32Process::ToWide(argv[2]);
        request.offset = std::stoull(argv[3]); request.bytes = std::stoull(argv[4]);
        request.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(45);
        const auto first = OpenFruit::HttpTransfer::ReadRange(request);
        if (!first.Succeeded()) { std::cerr << "range status=" << static_cast<int>(first.status) << " http=" << first.http_status << '\n'; return 1; }
        request.expected_etag = first.etag; request.expected_total = first.total;
        const auto second = OpenFruit::HttpTransfer::ReadRange(request);
        if (!second.Succeeded() || second.body != first.body || second.etag != first.etag) return 1;
        std::ofstream file(fs::absolute(OpenFruit::Win32Process::ToWide(argv[5])), std::ios::binary);
        file.write(second.body.data(), second.body.size()); file.close();
        if (!file) return 1;
        std::cout << "bound_range_bytes=" << second.body.size() << " total=" << second.total
                  << " sha256=" << OpenFruit::Sha256(second.body).value_or("") << " publisher_verified=false\n";
        return 0;
    }
    if (argc == 5 && std::string(argv[1]) == "--fetch") {
        OpenFruit::TransferRequest request;
        request.url = OpenFruit::Win32Process::ToWide(argv[2]);
        request.expected_sha256 = argv[3];
        request.destination = fs::absolute(OpenFruit::Win32Process::ToWide(argv[4]));
        request.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(45);
        const auto result = OpenFruit::HttpTransfer::Download(request);
        std::cout << "success=" << result.Succeeded() << " status=" << static_cast<int>(result.status)
                  << " http=" << result.http_status << " native=" << result.native_error << " bytes=" << result.bytes << '\n';
        return result.Succeeded() ? 0 : 1;
    }
    WSADATA data{}; if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
    const auto root = fs::temp_directory_path() / ("OPENFRUIT-transfer-" + OpenFruit::NewOperationId());
    fs::create_directories(root);
    auto sink = std::make_shared<Sink>();
    auto context = std::make_shared<OpenFruit::OperationContext>(); context->sink = sink;
    OpenFruit::OperationBinding binding(context);
    const std::string payload = "owned immutable download payload";
    const auto digest = OpenFruit::Sha256(payload);
    bool passed = digest.has_value() && OpenFruit::Sha256("abc") ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    OpenFruit::TransferRequest options;
    options.destination = root / "artifact"; options.expected_sha256 = *digest;
    options.allow_loopback_http = true; options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    unsigned int cookie_calls = 0;
    options.cookie_header = [&](const auto&, const auto&) { ++cookie_calls; return L"sid=owned-cookie-secret"; };
    {
        const auto full = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(payload.size()) + "\r\nETag: \"owned-v1\"\r\nConnection: close\r\n\r\n" + payload;
        Server server({{"HTTP/1.1 302 Found\r\nLocation: /final?token=owned-url-secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"}, {full}});
        options.url = server.Url();
        const auto result = OpenFruit::HttpTransfer::Download(options);
        server.Finish();
        passed = passed && result.Succeeded() && result.bytes == payload.size() && Read(options.destination) == payload
            && server.requests.size() == 2 && cookie_calls == 0 && !fs::exists(options.destination.wstring() + L".partial");
    }
    const auto previous = Read(options.destination);
    {
        Server server({{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncorrupt"}});
        options.url = server.Url();
        passed = passed && OpenFruit::HttpTransfer::Download(options).status == OpenFruit::TransferStatus::IntegrityFailure
            && Read(options.destination) == previous;
    }
    {
        fs::remove(options.destination);
        Server server({{"HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(payload.size()) + "\r\nETag: \"owned-v1\"\r\nConnection: close\r\n\r\n" + payload.substr(0, 8)},
            {"HTTP/1.1 206 Partial Content\r\nContent-Length: " + std::to_string(payload.size() - 8) + "\r\nContent-Range: bytes 8-" + std::to_string(payload.size() - 1) + "/" + std::to_string(payload.size()) + "\r\nConnection: close\r\n\r\n" + payload.substr(8)}});
        options.url = server.Url();
        const auto interrupted = OpenFruit::HttpTransfer::Download(options);
        const auto resumed = OpenFruit::HttpTransfer::Download(options);
        server.Finish();
        passed = passed && interrupted.status == OpenFruit::TransferStatus::NetworkFailure && resumed.Succeeded()
            && resumed.resumed && Read(options.destination) == payload && server.requests.size() == 2
            && server.requests[1].find("Range: bytes=8-") != std::string::npos;
    }
    {
        const std::string replacement = "owned replacement after locked publication";
        Server server({{"HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(replacement.size()) +
            "\r\nConnection: close\r\n\r\n" + replacement}});
        options.url = server.Url(); options.expected_sha256 = *OpenFruit::Sha256(replacement);
        HANDLE reader = CreateFileW(options.destination.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const auto blocked = OpenFruit::HttpTransfer::Download(options);
        passed = passed && reader != INVALID_HANDLE_VALUE && blocked.status == OpenFruit::TransferStatus::IoFailure
            && Read(options.destination) == payload;
        if (reader != INVALID_HANDLE_VALUE) CloseHandle(reader);
        const auto published = OpenFruit::HttpTransfer::Download(options);
        server.Finish();
        passed = passed && published.Succeeded() && published.resumed && Read(options.destination) == replacement
            && server.requests.size() == 1; // The completed partial is verified and published without another request.
        options.expected_sha256 = *digest;
        { std::ofstream restore(options.destination, std::ios::binary); restore << payload; }
    }
    {
        Server server({{"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\nConnection: close\r\n\r\n", true}});
        options.url = server.Url();
        OpenFruit::CancellationSource cancel; options.cancellation = cancel.Token();
        std::jthread trigger([&] { std::this_thread::sleep_for(std::chrono::milliseconds(100)); cancel.Cancel(); });
        const auto start = std::chrono::steady_clock::now();
        const auto result = OpenFruit::HttpTransfer::Download(options);
        passed = passed && result.status == OpenFruit::TransferStatus::Cancelled
            && std::chrono::steady_clock::now() - start < std::chrono::seconds(2) && Read(options.destination) == payload;
        options.cancellation = {};
    }
    {
        Server server({{"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\nConnection: close\r\n\r\n", true}});
        options.url = server.Url(); options.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
        passed = passed && OpenFruit::HttpTransfer::Download(options).status == OpenFruit::TransferStatus::TimedOut;
    }
    options.url = L"http://untrusted.example.invalid/file";
    passed = passed && OpenFruit::HttpTransfer::Download(options).status == OpenFruit::TransferStatus::InvalidRequest;
    {
        const std::string response = R"({"downloads":[],"secret":"owned-response-secret"})";
        Server server({{"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\n"
            "Set-Cookie: token=owned-response-cookie; Domain=apple.com; Path=/; Secure; HttpOnly; Max-Age=3600\r\n"
            "Set-Cookie: scoped=owned-scoped-response-cookie; Path=/services-account; Secure\r\nContent-Length: " +
            std::to_string(response.size()) + "\r\nConnection: close\r\n\r\n" + response}});
        OpenFruit::JsonPostRequest post;
        post.url = server.Url(); post.allow_loopback_http = true;
        post.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        post.cookie_header = [&](const auto&, const auto&) { ++cookie_calls; return L"sid=owned-cookie-secret"; };
        const auto result = OpenFruit::HttpTransfer::PostJson(post);
        server.Finish();
        passed = passed && result.Succeeded() && result.body == response && result.set_cookie_headers.size() == 2 &&
            result.set_cookie_headers[0].find(L"owned-response-cookie") != std::wstring::npos &&
            result.set_cookie_headers[1].find(L"owned-scoped-response-cookie") != std::wstring::npos &&
            server.requests.size() == 1
            && server.requests[0].starts_with("POST /file?token=owned-url-secret HTTP/1.1")
            && server.requests[0].find("\r\n\r\n{}") != std::string::npos && cookie_calls == 0;
    }
    {
        const char bytes[] = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x0a\xab\x56\xca\xcf\x56\xb2\x2a\x29\x2a\x4d\xad\x05\x00\x90\x5f\xd4\xa7\x0b\x00\x00\x00";
        const std::string compressed(bytes, sizeof(bytes) - 1);
        Server server({{"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: " +
            std::to_string(compressed.size()) + "\r\nConnection: close\r\n\r\n" + compressed}});
        OpenFruit::JsonPostRequest post; post.url = server.Url(); post.allow_loopback_http = true;
        const auto result = OpenFruit::HttpTransfer::PostJson(post);
        server.Finish();
        passed = passed && result.Succeeded() && result.body == "{\"ok\":true}";
    }
    {
        const char bytes[] = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x0a\x73\x74\x1c\x05\xa3\x60\x14\x38\x0e\x73\x00\x00\x01\x2e\xa0\x51\xe8\x03\x00\x00";
        const std::string compressed(bytes, sizeof(bytes) - 1);
        Server server({{"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: " +
            std::to_string(compressed.size()) + "\r\nConnection: close\r\n\r\n" + compressed}});
        OpenFruit::JsonPostRequest post; post.url = server.Url(); post.allow_loopback_http = true; post.max_bytes = 100;
        const auto result = OpenFruit::HttpTransfer::PostJson(post);
        server.Finish();
        passed = passed && result.status == OpenFruit::TransferStatus::InvalidRequest && result.body.empty();
    }
    {
        Server server({{"HTTP/1.1 302 Found\r\nLocation: https://untrusted.example.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"}});
        OpenFruit::JsonPostRequest post; post.url = server.Url(); post.allow_loopback_http = true;
        const auto result = OpenFruit::HttpTransfer::PostJson(post);
        passed = passed && result.status == OpenFruit::TransferStatus::HttpFailure && result.body.empty();
    }
    {
        Server server({{"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345"}});
        OpenFruit::JsonPostRequest post; post.url = server.Url(); post.allow_loopback_http = true; post.max_bytes = 4;
        const auto result = OpenFruit::HttpTransfer::PostJson(post);
        passed = passed && result.status == OpenFruit::TransferStatus::HttpFailure && result.body.empty();
    }
    {
        Server server({{"HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(payload.size()) +
            "\r\nConnection: close\r\n\r\n" + payload}});
        OpenFruit::StagedTransferRequest stage;
        stage.url = server.Url(); stage.staging_directory = root / "staging";
        stage.expected_bytes = payload.size(); stage.allow_loopback_http = true;
        stage.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        stage.cookie_header = [&](const auto&, const auto&) { ++cookie_calls; return L"sid=owned-cookie-secret"; };
        const auto result = OpenFruit::HttpTransfer::Stage(stage);
        server.Finish();
        passed = passed && result.Succeeded() && result.transfer.bytes == payload.size() &&
            result.path.parent_path() == stage.staging_directory && Read(result.path) == payload &&
            result.path.string().find("owned-url-secret") == std::string::npos && cookie_calls == 0;
    }
    {
        Server server({{"HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(payload.size()) +
            "\r\nETag: \"stage-v1\"\r\nConnection: close\r\n\r\n" + payload.substr(0, 8)},
            {"HTTP/1.1 206 Partial Content\r\nContent-Length: " + std::to_string(payload.size() - 8) +
             "\r\nContent-Range: bytes 8-" + std::to_string(payload.size() - 1) + "/" +
             std::to_string(payload.size()) + "\r\nConnection: close\r\n\r\n" + payload.substr(8)}});
        OpenFruit::StagedTransferRequest stage;
        stage.url = server.Url(); stage.staging_directory = root / "staging";
        stage.expected_bytes = payload.size(); stage.allow_loopback_http = true;
        const auto interrupted = OpenFruit::HttpTransfer::Stage(stage);
        const auto identity = OpenFruit::Sha256(OpenFruit::Win32Process::ToNarrow(stage.url));
        const auto record = identity ? stage.staging_directory / (*identity + ".download.partial.json") : fs::path{};
        const bool private_record = identity && fs::exists(record) &&
            Read(record).find("owned-url-secret") == std::string::npos &&
            Read(record).find("owned-cookie-secret") == std::string::npos;
        const auto resumed = OpenFruit::HttpTransfer::Stage(stage);
        server.Finish();
        passed = passed && private_record && interrupted.transfer.status == OpenFruit::TransferStatus::NetworkFailure &&
            resumed.Succeeded() && resumed.transfer.resumed && Read(resumed.path) == payload &&
            server.requests.size() == 2 && server.requests[1].find("Range: bytes=8-") != std::string::npos;
    }
    {
        Server server({{"HTTP/1.1 302 Found\r\nLocation: /other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"}});
        OpenFruit::StagedTransferRequest stage;
        stage.url = server.Url(); stage.staging_directory = root / "staging";
        stage.expected_bytes = payload.size(); stage.allow_loopback_http = true;
        const auto result = OpenFruit::HttpTransfer::Stage(stage);
        passed = passed && result.transfer.status == OpenFruit::TransferStatus::HttpFailure && result.path.empty();
    }
    {
        Server server({{"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncorrupt!"}});
        OpenFruit::StagedTransferRequest stage;
        stage.url = server.Url(); stage.staging_directory = root / "staging";
        stage.expected_bytes = payload.size(); stage.allow_loopback_http = true;
        const auto result = OpenFruit::HttpTransfer::Stage(stage);
        passed = passed && result.transfer.status == OpenFruit::TransferStatus::InvalidRequest && result.path.empty();
    }
    {
        OpenFruit::RangeTransferRequest range;
        range.offset = 5000000000ULL; range.bytes = 4; range.allow_loopback_http = true;
        range.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        const std::string prefix = "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 5000000000-5000000003/6000000000\r\n";
        Server server({{prefix + "ETag: \"range-v1\"\r\nConnection: close\r\n\r\nABCD"},
                       {prefix + "ETag: \"range-v1\"\r\nConnection: close\r\n\r\nABCD"}});
        range.url = server.Url();
        const auto first = OpenFruit::HttpTransfer::ReadRange(range);
        range.expected_total = first.total; range.expected_etag = first.etag;
        const auto second = OpenFruit::HttpTransfer::ReadRange(range);
        server.Finish();
        passed = passed && first.Succeeded() && second.Succeeded() && first.body == "ABCD" && second.body == first.body &&
            first.total == 6000000000ULL && first.etag == L"\"range-v1\"" && server.requests.size() == 2 &&
            server.requests[0].find("Range: bytes=5000000000-5000000003") != std::string::npos &&
            server.requests[1].find("If-Match: \"range-v1\"") != std::string::npos &&
            server.requests[1].find("Accept-Encoding: identity") != std::string::npos &&
            server.requests[1].find("Cookie:") == std::string::npos;
    }
    for (const std::string reply : {
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nETag: \"range-v1\"\r\nConnection: close\r\n\r\nABCD",
        "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 8-11/16\r\nETag: \"changed\"\r\nConnection: close\r\n\r\nABCD",
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 8-11/16\r\nETag: W/\"range-v1\"\r\nConnection: close\r\n\r\nABCD",
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 8-11/16\r\nConnection: close\r\n\r\nABCD",
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 8-11/17\r\nETag: \"range-v1\"\r\nConnection: close\r\n\r\nABCD",
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 7-10/16\r\nETag: \"range-v1\"\r\nConnection: close\r\n\r\nABCD",
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 8-11/16\r\nETag: \"range-v1\"\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\nABCD",
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\nContent-Range: bytes 8-11/16\r\nETag: \"range-v1\"\r\nConnection: close\r\n\r\nABC",
        "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 8-11/16\r\nETag: \"range-v1\"\r\nConnection: close\r\n\r\nAB"}) {
        Server server({{reply}});
        OpenFruit::RangeTransferRequest range;
        range.url = server.Url(); range.allow_loopback_http = true; range.offset = 8; range.bytes = 4;
        range.expected_total = 16; range.expected_etag = L"\"range-v1\"";
        range.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        const auto result = OpenFruit::HttpTransfer::ReadRange(range);
        server.Finish();
        passed = passed && !result.Succeeded() && result.body.empty() && result.etag.empty() && result.total == 0 && server.requests.size() == 1;
    }
    {
        OpenFruit::RangeTransferRequest range;
        range.url = L"https://example.com/fixture"; range.offset = UINT64_MAX; range.bytes = 2;
        passed = passed && OpenFruit::HttpTransfer::ReadRange(range).status == OpenFruit::TransferStatus::InvalidRequest;
        range.offset = 0; range.bytes = 4; range.expected_etag = L"\"v1\"\r\nInjected: bad";
        passed = passed && OpenFruit::HttpTransfer::ReadRange(range).status == OpenFruit::TransferStatus::InvalidRequest;
        range.expected_etag.clear(); range.deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        passed = passed && OpenFruit::HttpTransfer::ReadRange(range).status == OpenFruit::TransferStatus::TimedOut;
    }
    {
        Server server({{"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 0-3/16\r\nETag: \"range-v1\"\r\nConnection: close\r\n\r\nA", true}});
        OpenFruit::CancellationSource cancel;
        OpenFruit::RangeTransferRequest range;
        range.url = server.Url(); range.allow_loopback_http = true; range.bytes = 4; range.cancellation = cancel.Token();
        std::jthread trigger([&] { std::this_thread::sleep_for(std::chrono::milliseconds(100)); cancel.Cancel(); });
        const auto result = OpenFruit::HttpTransfer::ReadRange(range);
        passed = passed && result.status == OpenFruit::TransferStatus::Cancelled && result.body.empty() && result.total == 0;
    }
    {
        Server server({{"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 0-3/16\r\nETag: \"range-context\"\r\nConnection: close\r\n\r\nA", true}});
        OpenFruit::RangeTransferRequest range;range.url=server.Url();range.allow_loopback_http=true;range.bytes=4;
        std::jthread trigger([&]{std::this_thread::sleep_for(std::chrono::milliseconds(100));context->RequestCancellation();});
        const auto interrupted=OpenFruit::HttpTransfer::ReadRange(range);trigger.join();
        passed=passed&&interrupted.status==OpenFruit::TransferStatus::Cancelled&&interrupted.body.empty();
        context->control=std::make_shared<OpenFruit::OperationControl>();
    }

    {
        const std::string public_bytes("owned-key-response\0original",27);
        Server server({{"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nSet-Cookie: ignored=owned-cookie-secret\r\nContent-Length: 27\r\nConnection: close\r\n\r\n"+public_bytes}});
        OpenFruit::JsonPostRequest request;request.url=server.Url();request.allow_loopback_http=true;request.max_bytes=64;
        const auto result=OpenFruit::HttpTransfer::GetBytes(request);server.Finish();
        passed=passed&&result.Succeeded()&&result.body==public_bytes&&result.set_cookie_headers.empty()&&server.requests.size()==1&&server.requests[0].starts_with("GET ")&&server.requests[0].find("Accept-Encoding: identity")!=std::string::npos&&server.requests[0].find("Cookie:")==std::string::npos;
    }
    for(const std::string reply:{
        "HTTP/1.1 302 Found\r\nLocation: /redirect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\nConnection: close\r\n\r\nABCD",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nABCDE",
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nAB",
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nABCDE"}){
        Server server({{reply}});OpenFruit::JsonPostRequest request;request.url=server.Url();request.allow_loopback_http=true;request.max_bytes=4;
        const auto result=OpenFruit::HttpTransfer::GetBytes(request);server.Finish();passed=passed&&!result.Succeeded()&&result.body.empty()&&server.requests.size()==1;
        if(result.http_status==302)passed=passed&&result.redirect_url==L"/redirect";
    }
    {
        Server server({{"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nA",true}});
        OpenFruit::JsonPostRequest request;request.url=server.Url();request.allow_loopback_http=true;request.deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(100);
        const auto result=OpenFruit::HttpTransfer::GetBytes(request);passed=passed&&result.status==OpenFruit::TransferStatus::TimedOut&&result.body.empty();
    }
    {
        OpenFruit::JsonPostRequest request;request.url=L"https://example.invalid/owned";request.cookie_header=[](const auto&,const auto&){return L"secret";};
        passed=passed&&OpenFruit::HttpTransfer::GetBytes(request).status==OpenFruit::TransferStatus::InvalidRequest;
    }
    bool cancelled_event = false, progress_event = false, unverified_stage_event = false;
    for (const auto& event : sink->events) {
        const auto text = event.data.Serialize();
        passed = passed && text.find("owned-url-secret") == std::string::npos &&
            text.find("owned-cookie-secret") == std::string::npos &&
            text.find("owned-response-secret") == std::string::npos &&
            text.find("owned-response-cookie") == std::string::npos &&
            text.find("owned-key-response") == std::string::npos;
        if (event.kind == "task.completed" && event.data.GetString("state") == "cancelled") cancelled_event = true;
        if (event.kind == "task.completed" && event.data.GetString("status") == "succeeded" &&
            event.data.Get("integrity_verified") && !event.data.Get("integrity_verified")->Bool(true))
            unverified_stage_event = true;
        if (event.kind == "task.progress" && event.data.GetString("basis") == "bytes") progress_event = true;
    }
    passed = passed && cancelled_event && progress_event && unverified_stage_event &&
        !OpenFruit::Sha256File(root / "missing").has_value();
    fs::remove_all(root); // Unique owned fixture only.
    WSACleanup();
    if (!passed) std::cerr << "Native transfer integrity/resume/cancellation contract failed.\n";
    return passed ? 0 : 1;
}
