#pragma once

#include "application_service.hpp"

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>

namespace OpenFruit {

struct OperationAdapterOptions {
    // Bare local name, never a remote server or complete pipe path.
    std::wstring pipe_name;
    std::size_t max_frame_bytes = 1024 * 1024;
    std::size_t max_json_depth = 32;
    std::size_t max_queued_builds = 8;
    std::size_t max_retained_operations = 64;
    std::size_t max_event_count = 256;
    std::size_t max_event_bytes = 1024 * 1024;
    std::chrono::milliseconds io_timeout{5000};
};

// Local, current-user RPC host. A single native worker invokes the same
// ApplicationService as the CLI. Disconnection never cancels an operation.
// Replay is bounded and retained only for this server lifetime; the existing
// event journal remains the durable diagnostic record, not a second build log.
class OperationAdapter {
public:
    explicit OperationAdapter(BuildContext host_snapshot,
        OperationAdapterOptions options = {});
    ~OperationAdapter();
    OperationAdapter(const OperationAdapter&) = delete;
    OperationAdapter& operator=(const OperationAdapter&) = delete;
    bool Start(std::string& error);
    // Transport I/O is cancellable. Joining a legacy in-process build remains
    // cooperative; no claim of a hard bounded Stop for noncooperating work.
    void Stop();
    bool IsRunning() const noexcept;
    std::wstring PipeName() const;
    std::string LastError() const;
    JsonValue HandleRequest(const JsonValue& request);

    // Same framed transport used by IDE clients: uint32 little-endian length,
    // followed by bounded UTF-8 JSON v1. One request/response per connection.
    static bool Call(const std::wstring& pipe_name, const JsonValue& request,
        JsonValue& response, std::string& error,
        std::chrono::milliseconds timeout = std::chrono::seconds(10),
        std::size_t max_frame_bytes = 1024 * 1024);
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace OpenFruit
