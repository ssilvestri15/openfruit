#pragma once
#include "darwin_thread_context.hpp"
#include <optional>
#include <vector>

namespace OpenFruit {
// Serial queue for the existing task/engine. Deadlines use the caller's monotonic
// clock. Kernel lock ownership, QoS policy and workqueue upcalls are separate.
class DarwinThreadRunQueue {
public:
    explicit DarwinThreadRunQueue(std::uint64_t exclusive_clear_pc=0):exclusive_clear_pc_(exclusive_clear_pc){}
    DarwinThreadRunQueue(const DarwinThreadRunQueue&)=delete;
    DarwinThreadRunQueue& operator=(const DarwinThreadRunQueue&)=delete;
    enum class State { Runnable, Running, Waiting, Terminated };
    enum class WakeReason { None, Signaled, TimedOut, Cancelled };
    struct Entry {
        std::uint64_t id=0;
        DarwinThreadContext* context=nullptr; // task owns lifetime until termination
        State state=State::Runnable;
        WakeReason wake_reason=WakeReason::None;
        std::uint64_t order=0,wait_key=0;
        std::optional<std::uint64_t> deadline;
        std::uint32_t suspend_count=0; // independent of a kernel wait/deadline
        int effective_priority=31; // owner resolves QoS/caps; default ordinary base priority
        int base_priority=31;
        bool timeshare=true,queued_at_head=false;
        std::uint32_t sched_usage=0;
        std::uint8_t pri_shift=127; // XNU INT8_MAX: no contention penalty
        std::uint64_t wake_generation=0; // one event, independent of persistent wake_reason
    };
private:
    std::uint64_t exclusive_clear_pc_=0,last_dispatched_=0,exclusive_clears_=0;
    uc_engine* engine_=nullptr; // borrowed; queue never migrates between tasks
    std::vector<Entry> entries_;
    std::uint64_t running_=0,next_order_=1,dispatches_=0;
    Entry* Find(std::uint64_t) noexcept;
    std::uint64_t Order();
    void MakeRunnable(Entry&,WakeReason);
    static void RecomputePriority(Entry&) noexcept;
public:
    std::uint64_t ExclusiveClearPC() const noexcept{return exclusive_clear_pc_;}
    std::uint64_t ExclusiveClears() const noexcept{return exclusive_clears_;}
    bool Admit(std::uint64_t,DarwinThreadContext&,bool initially_suspended=false);
    // Applies a policy base priority at the next dispatch boundary. Timeshare
    // decay consumes only usage/shift supplied by the actual accounting owner.
    bool SetEffectivePriority(std::uint64_t,int) noexcept;
    bool SetTimeshare(std::uint64_t,bool) noexcept;
    // XNU macOS priority.c: fixed uses base; timeshare uses
    // clamp(base-(sched_usage>>pri_shift),0,95), or no decay for shift127.
    // Owner must supply measured CPU usage in its calibrated absolute units and
    // the derived scheduler bucket shift. No fabricated per-dispatch penalty.
    bool UpdateTimeshareUsage(std::uint64_t,std::uint32_t,std::uint8_t) noexcept;
    // Pinned XNU defaults: 5/8 aging table and sched_decay_penalty1. Calibration
    // accepts the final unscaled EWMA bucket load, never raw runnable count.
    // Caller owns the real clock,125ms tick,15ms load EWMA and QoS buckets.
    static std::uint32_t AgeTimeshareUsage(std::uint32_t,std::uint32_t ticks) noexcept;
    static bool CalibrateTimeshareShift(std::uint64_t tick_interval,
        std::uint32_t ewma_bucket_load,std::uint8_t& output) noexcept;
    uc_err Suspend(uc_engine*,std::uint64_t);
    bool Resume(std::uint64_t);
    uc_err Dispatch(uc_engine*,std::uint64_t now,std::uint64_t& selected);
    uc_err YieldCurrent(uc_engine*);
    // Both fixed and timeshare rotate after quantum expiry. Involuntary
    // preemption with quantum remaining requeues at its priority's head.
    // Voluntary YieldCurrent always relinquishes the quantum and joins tail.
    uc_err PreemptCurrent(uc_engine*,bool quantum_expired);
    uc_err Block(uc_engine*,std::uint64_t wait_key,std::optional<std::uint64_t> deadline);
    std::size_t Wake(std::uint64_t wait_key,std::size_t maximum);
    std::size_t Expire(std::uint64_t now);
    bool CancelWait(std::uint64_t);
    bool Terminate(std::uint64_t);
    const Entry* Lookup(std::uint64_t) const noexcept;
    std::size_t Size() const noexcept{return entries_.size();}
    std::uint64_t Running() const noexcept{return running_;}
    std::uint64_t Dispatches() const noexcept{return dispatches_;}
};
}
