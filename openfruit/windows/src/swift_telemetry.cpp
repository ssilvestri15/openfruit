#include "swift_telemetry.hpp"
#include "win32_process.hpp"

#include <algorithm>
#include <charconv>
#include <psapi.h>

namespace OpenFruit {

SwiftTelemetryParser::SwiftTelemetryParser(RecordCallback record, TextCallback text)
    : record_(std::move(record)), text_(std::move(text)) {}

void SwiftTelemetryParser::Consume(const std::string& chunk) {
    // Slice large reads so malformed text and declared payload sizes cannot
    // cause unbounded accumulation; the consumer always keeps draining.
    for (std::size_t offset = 0; offset < chunk.size(); offset += 4096) {
        // The Windows Swift driver announces the JSON size before the CRT
        // expands LF to CRLF on stderr. Normalize those transport newlines,
        // including a CR/LF split between reads, before applying byte counts.
        const auto end = std::min(chunk.size(), offset + 4096);
        for (std::size_t i = offset; i < end; ++i) {
            const char byte = chunk[i];
            if (pending_cr_) {
                if (byte != '\n') pending_.push_back('\r');
                pending_cr_ = false;
            }
            if (byte == '\r') pending_cr_ = true;
            else pending_.push_back(byte);
        }
        Drain();
    }
}

void SwiftTelemetryParser::Drain() {
    for (;;) {
        if (expected_) {
            if (pending_.size() < expected_) return;
            const auto payload = pending_.substr(0, expected_);
            pending_.erase(0, expected_);
            expected_ = 0;
            const auto value = JsonValue::Parse(payload);
            if (value && value->IsObject() && !value->GetString("kind").empty()) record_(*value);
            else text_(header_ + payload);
            header_.clear();
            continue;
        }
        const auto newline = pending_.find('\n');
        if (newline == std::string::npos) {
            if (pending_.size() >= kMaximumText) { text_(pending_); pending_.clear(); }
            return;
        }
        const auto line = pending_.substr(0, newline + 1);
        auto length = line.substr(0, line.size() - 1);
        if (!length.empty() && length.back() == '\r') length.pop_back();
        std::size_t bytes = 0;
        const auto conversion = std::from_chars(length.data(), length.data() + length.size(), bytes);
        pending_.erase(0, newline + 1);
        if (!length.empty() && conversion.ec == std::errc{} &&
            conversion.ptr == length.data() + length.size() && bytes && bytes <= kMaximumRecord) {
            expected_ = bytes;
            header_ = line;
        } else text_(line);
    }
}

void SwiftTelemetryParser::Finish() {
    if (pending_cr_) { pending_.push_back('\r'); pending_cr_ = false; }
    Drain();
    if (!header_.empty() || !pending_.empty()) text_(header_ + pending_);
    header_.clear(); pending_.clear(); expected_ = 0;
}

SwiftCompilerTelemetry::SwiftCompilerTelemetry(OperationContextPtr context, SwiftTelemetryParser::TextCallback text)
    : context_(std::move(context)), text_(std::move(text)), diagnostics_(context_, L""),
      parser_([this](const JsonValue& value) { Record(value); }, [this](const std::string& plain) {
          diagnostics_.Feed(plain);
          text_(plain);
      }) {}

void SwiftCompilerTelemetry::Record(const JsonValue& value) {
    const auto kind = value.GetString("kind");
    if (kind != "began" && kind != "finished" && kind != "signalled" && kind != "skipped") return;
    const auto pid_value = value.Get("pid");
    const int pid = pid_value ? pid_value->Int(0) : 0;
    auto data = JsonValue::ObjectValue();
    data.Set("pid", JsonValue::Number(std::to_string(pid)));
    data.Set("basis", JsonValue::String("observed_compiler_job"));
    data.Set("phase", JsonValue::String(value.GetString("name")));
    if (kind == "began" && pid > 0) active_.insert_or_assign(pid, value);
    const auto found = active_.find(pid);
    const auto inputs = value.Get("inputs") ? value.Get("inputs") :
        (found == active_.end() ? nullptr : found->second.Get("inputs"));
    if (inputs) data.Set("inputs", *inputs);
    if (const auto outputs = value.Get("outputs")) data.Set("outputs", *outputs);
    if (const auto status = value.Get("exit-status")) data.Set("exit_code", *status);
    if (const auto signal = value.Get("signal")) data.Set("signal", *signal);
    data.Set("process_sample_status", JsonValue::String("unavailable"));
    // Only a PID emitted for this driver's job may be sampled. Never scan
    // unrelated swift processes or select a process merely by its name.
    if (kind == "began" && pid > 0) {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
        if (process) {
            PROCESS_MEMORY_COUNTERS counters{};
            if (GetProcessMemoryInfo(process, &counters, sizeof(counters))) {
                data.Set("working_set_bytes", JsonValue::Number(std::to_string(counters.WorkingSetSize)));
                data.Set("process_sample_status", JsonValue::String("available"));
            }
            FILETIME created{}, ended{}, kernel{}, user{};
            if (GetProcessTimes(process, &created, &ended, &kernel, &user)) {
                ULARGE_INTEGER k{}, u{};
                k.LowPart = kernel.dwLowDateTime; k.HighPart = kernel.dwHighDateTime;
                u.LowPart = user.dwLowDateTime; u.HighPart = user.dwHighDateTime;
                data.Set("cpu_100ns", JsonValue::Number(std::to_string(k.QuadPart + u.QuadPart)));
            }
            data.Set("sample_tick_ms", JsonValue::Number(std::to_string(GetTickCount64())));
            CloseHandle(process);
        }
    }
    if (context_) context_->Emit("compiler." + kind, std::move(data), kind == "signalled" ? "error" : "info");
    Progress(kind, value, found == active_.end() ? value : found->second, pid);
    const auto output = value.GetString("output");
    if (!output.empty()) { diagnostics_.Feed(output); text_(output); }
    if (kind == "finished" || kind == "signalled") active_.erase(pid);
}

void SwiftCompilerTelemetry::Progress(const std::string& kind, const JsonValue& event, const JsonValue& job, int pid) {
    if (kind == "skipped") { ++skipped_jobs_; return; }
    std::size_t files = 0; std::string names;
    if (const auto* inputs = job.Get("inputs"); inputs && inputs->IsArray()) {
        for (const auto& input : inputs->ArrayItems()) {
            if (!input.IsString()) continue;
            const auto& path = input.StringValue();
            if (++files > 2) continue;
            const auto slash = path.find_last_of("/\\");
            names += (names.empty() ? "" : ", ") + (slash == std::string::npos ? path : path.substr(slash + 1));
        }
    }
    if (files > 2) names += ", +" + std::to_string(files - 2);
    std::string line = "OPENFRUIT Swift job: ";
    if (kind == "began") {
        started_ticks_[pid] = GetTickCount64();
        line += "started " + job.GetString("name") + " (" + std::to_string(files) + " file(s): " + names + ")";
    } else {
        kind == "signalled" ? ++failed_jobs_ : ++finished_jobs_;
        const auto exit_value = event.Get("exit-status");
        const auto exit_code = exit_value ? exit_value->Int(0) : 0;
        if (exit_code != 0) { --finished_jobs_; ++failed_jobs_; }
        std::string seconds;
        if (const auto started = started_ticks_.find(pid); started != started_ticks_.end()) {
            seconds = " in " + std::to_string((GetTickCount64() - started->second) / 1000) + "s";
            started_ticks_.erase(started);
        }
        line += (kind == "signalled" || exit_code != 0 ? "FAILED " : "finished ") + job.GetString("name") +
                " (" + std::to_string(files) + " file(s): " + names + ")" + seconds;
    }
    line += " [done " + std::to_string(finished_jobs_) + ", failed " + std::to_string(failed_jobs_) +
            ", running " + std::to_string(started_ticks_.size()) + "]\n";
    text_(line);
}

void SwiftCompilerTelemetry::Finish() {
    if (skipped_jobs_) text_("OPENFRUIT Swift job: " + std::to_string(skipped_jobs_) + " job(s) up to date (skipped)\n");
    parser_.Finish();
    diagnostics_.Finish();
    if (!active_.empty() && context_) {
        auto data = JsonValue::ObjectValue();
        data.Set("unterminated_jobs", JsonValue::Number(std::to_string(active_.size())));
        context_->Emit("compiler.telemetry_incomplete", std::move(data), "warning");
    }
    active_.clear();
}

} // namespace OpenFruit
