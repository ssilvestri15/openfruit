#pragma once

#include "operation_events.hpp"

namespace OpenFruit {

// Deliberately narrow command allowlist: do not log shell bodies, response-file
// contents, arbitrary environment values or authentication arguments.
JsonValue DescribeCommand(const std::wstring& executable,
                          const std::vector<std::wstring>& arguments,
                          const std::wstring& working_directory);
std::string RedactDiagnosticText(std::string text);
void RedactEventData(JsonValue& value);

// One instance per output stream; pipe readers feed complete diagnostics even
// when UTF-8 and lines are split across arbitrary ReadFile chunks.
class ProcessDiagnostics {
public:
    ProcessDiagnostics(OperationContextPtr context, const std::wstring& working_directory,
                       std::vector<std::string> sensitive_values = {});
    void Feed(const std::string& chunk);
    void Finish();
    std::size_t StackFrameCount() const noexcept { return stack_frame_count_; }
private:
    void Line(std::string line);
    void FinishStack();
    OperationContextPtr context_;
    std::filesystem::path working_directory_;
    std::vector<std::string> sensitive_values_;
    std::string pending_;
    std::string previous_diagnostic_;
    bool discarding_line_ = false;
    std::string stack_trace_id_;
    std::size_t stack_frame_count_ = 0;
    std::size_t trace_frame_count_ = 0;
    bool trace_truncated_ = false;
};

std::vector<std::string> SensitiveCommandValues(const std::vector<std::wstring>& arguments);

} // namespace OpenFruit
