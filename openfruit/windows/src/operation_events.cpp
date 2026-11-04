#include "operation_events.hpp"
#include "process_diagnostics.hpp"
#include "win32_process.hpp"

#include <algorithm>
#include <atomic>
#include <bcrypt.h>
#include <iostream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace OpenFruit {
namespace {
thread_local OperationContextPtr current_context;
}

std::string NewOperationId() {
    unsigned char bytes[16]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("Unable to allocate a unique operation identity");
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    for (unsigned char byte : bytes) {
        id.push_back(digits[byte >> 4]);
        id.push_back(digits[byte & 15]);
    }
    return id;
}

OperationContextPtr CurrentOperationContext() noexcept { return current_context; }

bool OperationContext::CancellationRequested() const noexcept {
    return control && control->cancellation_requested.load();
}
bool OperationContext::DeadlineExceeded() const noexcept {
    return control && std::chrono::steady_clock::now() >= control->deadline;
}
void OperationContext::RequestCancellation() const noexcept {
    if (control && !control->cancellation_requested.exchange(true)) Emit("operation.cancelling");
}

CompositeEventSink::CompositeEventSink(std::vector<std::shared_ptr<EventSink>> sinks)
    : sinks_(std::move(sinks)) {}

void CompositeEventSink::Emit(OperationEvent event) noexcept {
    for (const auto& sink : sinks_) {
        if (!sink) continue;
        try { sink->Emit(event); } catch (...) {}
    }
}

void OperationContext::Emit(std::string kind, JsonValue data, std::string severity) const noexcept {
    if (!sink) return;
    try {
        sink->Emit({std::move(kind), std::move(severity), build_id, span_id, {}, std::move(data)});
    } catch (...) {
        // Observability must not replace the underlying build result.
    }
}

OperationBinding::OperationBinding(OperationContextPtr context) noexcept
    : previous_(std::move(current_context)) { current_context = std::move(context); }
OperationBinding::~OperationBinding() { current_context = std::move(previous_); }

OperationSpan::OperationSpan(std::string name, JsonValue metadata, std::function<bool()> outcome)
    : name_(std::move(name)), started_(std::chrono::steady_clock::now()), outcome_(std::move(outcome)) {
    const auto parent = CurrentOperationContext();
    if (!parent) return;
    auto child = std::make_shared<OperationContext>(*parent);
    parent_id_ = parent->span_id;
    child->span_id = NewOperationId();
    context_ = std::move(child);
    binding_ = std::make_unique<OperationBinding>(context_);
    metadata.Set("name", JsonValue::String(name_));
    if (context_->sink) context_->sink->Emit({"task.started", "info", context_->build_id,
                                            context_->span_id, parent_id_, std::move(metadata)});
}

OperationSpan::~OperationSpan() {
    if (!context_ || completed_) return;
    try {
        const bool success = outcome_ ? outcome_() : succeeded_;
        Complete(JsonValue::ObjectValue(), success);
    } catch (...) {
        context_->Emit("observability.error", JsonValue::ObjectValue(), "error");
    }
}

void OperationSpan::Complete(JsonValue result, bool success) {
    if (!success && context_ && context_->DeadlineExceeded()) result.Set("failure_reason", JsonValue::String("deadline_exceeded"));
    Complete(std::move(result), success ? OperationOutcome::Succeeded :
        context_ && context_->CancellationRequested() ? OperationOutcome::Cancelled : OperationOutcome::Failed);
}
void OperationSpan::Complete(JsonValue result, OperationOutcome outcome) {
    if (!context_ || completed_) return;
    completed_ = true;
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_).count();
    result.Set("name", JsonValue::String(name_));
    result.Set("state", JsonValue::String(outcome == OperationOutcome::Succeeded ? "succeeded" :
        outcome == OperationOutcome::Cancelled ? "cancelled" : "failed"));
    result.Set("duration_ms", JsonValue::Number(std::to_string(elapsed)));
    if (context_->sink) context_->sink->Emit({"task.completed", outcome == OperationOutcome::Failed ? "error" : "info", context_->build_id,
                                            context_->span_id, parent_id_, std::move(result)});
    binding_.reset();
}

StageProgress::StageProgress(std::vector<std::string> stages)
    : context_(CurrentOperationContext()), stages_(std::move(stages)) { Publish("running"); }

StageProgress::~StageProgress() {
    if (!finished_) {
        try { Finished(false); } catch (...) {}
    }
}

void StageProgress::Started(const std::string& stage) {
    active_ = stage;
    Publish("running");
}

void StageProgress::Completed(const std::string& stage) {
    if (std::find(stages_.begin(), stages_.end(), stage) == stages_.end()) return;
    if (std::find(completed_.begin(), completed_.end(), stage) == completed_.end()) {
        completed_.push_back(stage);
    }
    active_.clear();
    Publish("running");
}

void StageProgress::Finished(bool success) {
    finished_ = true;
    Publish(success && completed_.size() == stages_.size() ? "succeeded" :
        context_ && context_->CancellationRequested() ? "cancelled" : "failed");
}

void StageProgress::Publish(const std::string& state) {
    if (!context_) return;
    auto data = JsonValue::ObjectValue();
    data.Set("basis", JsonValue::String("stage_units"));
    data.Set("plan_revision", JsonValue::Number("1"));
    data.Set("state", JsonValue::String(state));
    data.Set("active_stage", JsonValue::String(active_));
    data.Set("completed_units", JsonValue::Number(std::to_string(completed_.size())));
    data.Set("planned_units", JsonValue::Number(std::to_string(stages_.size())));
    const unsigned percent = stages_.empty() ? 0 : static_cast<unsigned>(100 * completed_.size() / stages_.size());
    data.Set("percent", JsonValue::Number(std::to_string(state == "succeeded" ? 100 : std::min(99u, percent))));
    data.Set("is_time_estimate", JsonValue::Boolean(false));
    context_->Emit("build.progress", std::move(data));
}

JsonValue StringArray(const std::vector<std::wstring>& values) {
    auto result = JsonValue::ArrayValue();
    for (const auto& value : values) result.ArrayItems().push_back(JsonValue::String(Win32Process::ToNarrow(value)));
    return result;
}

JsonStreamSink::JsonStreamSink(std::ostream& stream)
    : stream_(stream) {}

JsonValue EventEnvelopeBuilder::Build(OperationEvent event) {
    if (sequence_ == std::numeric_limits<std::uint64_t>::max()) throw std::overflow_error("Event producer sequence exhausted");
    SYSTEMTIME now{}; GetSystemTime(&now);
    std::ostringstream timestamp;
    timestamp << std::setfill('0') << std::setw(4) << now.wYear << '-'
        << std::setw(2) << now.wMonth << '-' << std::setw(2) << now.wDay << 'T'
        << std::setw(2) << now.wHour << ':' << std::setw(2) << now.wMinute << ':'
        << std::setw(2) << now.wSecond << '.' << std::setw(3) << now.wMilliseconds << 'Z';
    auto envelope = JsonValue::ObjectValue();
    envelope.Set("schema_version", JsonValue::Number("1"));
    envelope.Set("timestamp", JsonValue::String(timestamp.str()));
    envelope.Set("producer_id", JsonValue::String(producer_id_));
    envelope.Set("producer_sequence", JsonValue::Number(std::to_string(++sequence_)));
    envelope.Set("process_id", JsonValue::Number(std::to_string(GetCurrentProcessId())));
    envelope.Set("thread_id", JsonValue::Number(std::to_string(GetCurrentThreadId())));
    envelope.Set("kind", JsonValue::String(event.kind));
    envelope.Set("severity", JsonValue::String(event.severity));
    envelope.Set("build_id", JsonValue::String(event.build_id));
    envelope.Set("span_id", JsonValue::String(event.span_id));
    envelope.Set("parent_span_id", JsonValue::String(event.parent_span_id));
    RedactEventData(event.data);
    envelope.Set("data", std::move(event.data));
    return envelope;
}

void JsonStreamSink::Emit(OperationEvent event) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        stream_ << envelope_.Build(std::move(event)).Serialize(false) << "\n" << std::flush;
    } catch (...) {}
}

} // namespace OpenFruit
