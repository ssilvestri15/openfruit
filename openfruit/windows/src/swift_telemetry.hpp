#pragma once

#include "operation_events.hpp"
#include "process_diagnostics.hpp"

#include <functional>
#include <map>
#include <string>

namespace OpenFruit {

// Swift driver's stderr protocol: decimal byte count, newline, JSON payload.
// Arbitrary JSON in diagnostic text is never interpreted as telemetry.
class SwiftTelemetryParser {
public:
    using RecordCallback = std::function<void(const JsonValue&)>;
    using TextCallback = std::function<void(const std::string&)>;
    SwiftTelemetryParser(RecordCallback record, TextCallback text);
    void Consume(const std::string& chunk);
    void Finish();
private:
    void Drain();
    RecordCallback record_;
    TextCallback text_;
    std::string pending_;
    std::string header_;
    std::size_t expected_ = 0;
    bool pending_cr_ = false;
    static constexpr std::size_t kMaximumRecord = 16 * 1024 * 1024;
    static constexpr std::size_t kMaximumText = 64 * 1024;
};

class SwiftCompilerTelemetry {
public:
    SwiftCompilerTelemetry(OperationContextPtr context, SwiftTelemetryParser::TextCallback text);
    void Consume(const std::string& chunk) { parser_.Consume(chunk); }
    void Finish();
private:
    void Record(const JsonValue& value);
    void Progress(const std::string& kind, const JsonValue& event, const JsonValue& job, int pid);
    OperationContextPtr context_;
    SwiftTelemetryParser::TextCallback text_;
    ProcessDiagnostics diagnostics_;
    std::map<int, JsonValue> active_;
    // Human-readable job progress for the build log (the journal keeps events).
    std::map<int, std::uint64_t> started_ticks_;
    std::size_t finished_jobs_ = 0, failed_jobs_ = 0, skipped_jobs_ = 0;
    SwiftTelemetryParser parser_;
};

} // namespace OpenFruit
