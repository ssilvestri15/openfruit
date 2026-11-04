#pragma once
#include "operation_events.hpp"
namespace OpenFruit {
// One CLI console boundary per process. The OS callback only changes the
// shared atomic control and wakes a worker; sinks run outside the callback.
// No console attachment/allocation or handler changes in unrelated processes.
class ConsoleCancellation {
public:
    explicit ConsoleCancellation(OperationContextPtr context);
    ~ConsoleCancellation();
    ConsoleCancellation(const ConsoleCancellation&) = delete;
    ConsoleCancellation& operator=(const ConsoleCancellation&) = delete;
    void Finish() noexcept;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
