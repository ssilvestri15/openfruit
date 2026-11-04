#pragma once

#include "json_value.hpp"

#include <chrono>
#include <cstdint>
#include <atomic>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace OpenFruit {

// Shared native contract. Sinks format/persist events; build services never
// depend on a console, an IDE, or the journal implementation.
struct OperationEvent {
    std::string kind;
    std::string severity = "info";
    std::string build_id;
    std::string span_id;
    std::string parent_span_id;
    JsonValue data = JsonValue::ObjectValue();
};

class EventSink {
public:
    virtual ~EventSink() = default;
    virtual void Emit(OperationEvent event) noexcept = 0;
};

class CompositeEventSink final : public EventSink {
public:
    explicit CompositeEventSink(std::vector<std::shared_ptr<EventSink>> sinks);
    void Emit(OperationEvent event) noexcept override;
private:
    std::vector<std::shared_ptr<EventSink>> sinks_;
};

struct OperationControl {
    explicit OperationControl(std::chrono::steady_clock::time_point limit = std::chrono::steady_clock::time_point::max())
        : deadline(limit) {}
    std::atomic<bool> cancellation_requested{false};
    const std::chrono::steady_clock::time_point deadline;
};

struct OperationContext {
    std::shared_ptr<EventSink> sink;
    std::string build_id;
    std::string span_id;
    std::filesystem::path journal_directory;
    std::shared_ptr<OperationControl> control = std::make_shared<OperationControl>();
    bool CancellationRequested() const noexcept;
    bool DeadlineExceeded() const noexcept;
    void RequestCancellation() const noexcept;
    void Emit(std::string kind, JsonValue data = JsonValue::ObjectValue(),
              std::string severity = "info") const noexcept;
};

using OperationContextPtr = std::shared_ptr<const OperationContext>;
OperationContextPtr CurrentOperationContext() noexcept;
std::string NewOperationId();

// Bind explicitly in each worker. No process-global mutable build context.
class OperationBinding {
public:
    explicit OperationBinding(OperationContextPtr context) noexcept;
    ~OperationBinding();
    OperationBinding(const OperationBinding&) = delete;
    OperationBinding& operator=(const OperationBinding&) = delete;
private:
    OperationContextPtr previous_;
};

enum class OperationOutcome { Succeeded, Failed, Cancelled };
class OperationSpan {
public:
    OperationSpan(std::string name, JsonValue metadata = JsonValue::ObjectValue(),
                  std::function<bool()> outcome = {});
    ~OperationSpan();
    void Succeed() noexcept { succeeded_ = true; }
    void Complete(JsonValue result, bool success);
    void Complete(JsonValue result, OperationOutcome outcome);
    OperationContextPtr Context() const noexcept { return context_; }
    OperationSpan(const OperationSpan&) = delete;
    OperationSpan& operator=(const OperationSpan&) = delete;
private:
    std::string name_;
    std::string parent_id_;
    OperationContextPtr context_;
    std::unique_ptr<OperationBinding> binding_;
    std::chrono::steady_clock::time_point started_;
    std::function<bool()> outcome_;
    bool succeeded_ = false;
    bool completed_ = false;
};

// Explicit stage-unit progress: this is not an elapsed-time estimate.
class StageProgress {
public:
    explicit StageProgress(std::vector<std::string> stages);
    ~StageProgress();
    void Started(const std::string& stage);
    void Completed(const std::string& stage);
    void Finished(bool success);
private:
    void Publish(const std::string& state);
    OperationContextPtr context_;
    std::vector<std::string> stages_;
    std::vector<std::string> completed_;
    std::string active_;
    bool finished_ = false;
};

JsonValue StringArray(const std::vector<std::wstring>& values);

// Common transport schema for live JSON and persisted/replayed events.
// A producer belongs to one sink instance; callers serialize Build with their
// transport lock, so sequence order matches admitted/written record order.
class EventEnvelopeBuilder {
public:
    JsonValue Build(OperationEvent event);
private:
    std::string producer_id_ = NewOperationId();
    std::uint64_t sequence_ = 0;
};

class JsonStreamSink final : public EventSink {
public:
    explicit JsonStreamSink(std::ostream& stream);
    void Emit(OperationEvent event) noexcept override;
private:
    std::ostream& stream_;
    std::mutex mutex_;
    EventEnvelopeBuilder envelope_;
};

} // namespace OpenFruit
