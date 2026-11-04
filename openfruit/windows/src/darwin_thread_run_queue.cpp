#include "darwin_thread_run_queue.hpp"
#include <limits>
#include <stdexcept>
#include <algorithm>
#include <array>

namespace OpenFruit {
DarwinThreadRunQueue::Entry* DarwinThreadRunQueue::Find(std::uint64_t id) noexcept {
    for(auto& entry:entries_)if(entry.id==id)return &entry;return nullptr;
}
const DarwinThreadRunQueue::Entry* DarwinThreadRunQueue::Lookup(std::uint64_t id) const noexcept {
    for(const auto& entry:entries_)if(entry.id==id)return &entry;return nullptr;
}
std::uint64_t DarwinThreadRunQueue::Order(){
    if(next_order_==std::numeric_limits<std::uint64_t>::max())throw std::runtime_error("Guest run queue ordering exhausted");
    return next_order_++;
}
void DarwinThreadRunQueue::MakeRunnable(Entry& entry,WakeReason reason){
    const bool awakened=entry.state==State::Waiting&&reason!=WakeReason::None;
    if(awakened&&entry.wake_generation==UINT64_MAX)throw std::runtime_error("Guest wake generation exhausted");
    const auto order=Order();entry.order=order;entry.state=State::Runnable;
    if(awakened)++entry.wake_generation;
    entry.wake_reason=reason;entry.wait_key=0;entry.deadline.reset();entry.queued_at_head=false;
}
bool DarwinThreadRunQueue::Admit(std::uint64_t id,DarwinThreadContext& context,bool suspended){
    if(!id||Find(id)||!context.Saved()||(engine_&&context.BoundEngine()!=engine_))return false;
    for(const auto& entry:entries_)if(entry.context==&context||(entry.context&&!exclusive_clear_pc_))return false;
    entries_.push_back({id,&context,State::Runnable,WakeReason::None,Order(),0,{},suspended?1u:0u});
    engine_=context.BoundEngine();return true;
}
bool DarwinThreadRunQueue::SetEffectivePriority(std::uint64_t id,int priority) noexcept {
    auto* entry=Find(id);
    if(!entry||entry->state==State::Terminated||priority<0||priority>127)return false;
    entry->base_priority=priority;RecomputePriority(*entry);return true;
}
void DarwinThreadRunQueue::RecomputePriority(Entry& entry) noexcept {
    if(!entry.timeshare){entry.effective_priority=entry.base_priority;return;}
    const auto penalty=entry.pri_shift==127?0u:entry.sched_usage>>entry.pri_shift;
    entry.effective_priority=int(std::clamp<std::int64_t>(std::int64_t(entry.base_priority)-penalty,0,95));
}
bool DarwinThreadRunQueue::SetTimeshare(std::uint64_t id,bool timeshare) noexcept {
    auto* entry=Find(id);if(!entry||entry->state==State::Terminated)return false;
    // thread_policy.c reinserts a queued mode update at its priority's tail.
    if(entry->state==State::Runnable){
        if(next_order_==std::numeric_limits<std::uint64_t>::max())return false;
        entry->order=next_order_++;entry->queued_at_head=false;
    }
    entry->timeshare=timeshare;RecomputePriority(*entry);return true;
}
bool DarwinThreadRunQueue::UpdateTimeshareUsage(std::uint64_t id,std::uint32_t usage,std::uint8_t shift) noexcept {
    auto* entry=Find(id);
    if(!entry||entry->state==State::Terminated||(shift>31&&shift!=127))return false;
    entry->sched_usage=usage;entry->pri_shift=shift;RecomputePriority(*entry);return true;
}
std::uint32_t DarwinThreadRunQueue::AgeTimeshareUsage(std::uint32_t usage,std::uint32_t ticks) noexcept {
    // priority.c:sched_decay_shifts; preserve the original shift rounding.
    static constexpr std::array<std::array<int,2>,32> shifts{{
        {1,1},{1,3},{1,-3},{2,-7},{3,5},{3,-5},{4,-8},{5,7},
        {5,-7},{6,-10},{7,10},{7,-9},{8,-11},{9,12},{9,-11},{10,-13},
        {11,14},{11,-13},{12,-15},{13,17},{13,-15},{14,-17},{15,19},{16,18},
        {16,-19},{17,22},{18,20},{18,-20},{19,26},{20,22},{20,-22},{21,-27}}};
    if(!ticks)return usage;if(ticks>=shifts.size())return 0;
    const auto first=usage>>shifts[ticks][0];const auto second=shifts[ticks][1];
    return second>0?first+(usage>>second):first-(usage>>-second);
}
bool DarwinThreadRunQueue::CalibrateTimeshareShift(std::uint64_t tick_interval,
    std::uint32_t load,std::uint8_t& output) noexcept {
    if(!tick_interval||tick_interval>UINT64_MAX/5||load>127)return false;
    // sched_prim.c:sched_timeshare_init / load_shift_init and
    // sched_average.c:compute_averages, default sched_decay_penalty1.
    auto interval=(tick_interval*5)/3;std::uint32_t fixed=0;
    while(interval>31){interval>>=1;++fixed;}
    if(!load){output=127;return true;}
    std::uint32_t load_shift=0;for(auto level=load;level>1;level>>=1)++load_shift;
    output=fixed>=load_shift&&fixed-load_shift<=31?std::uint8_t(fixed-load_shift):127;
    return true;
}
uc_err DarwinThreadRunQueue::Suspend(uc_engine* engine,std::uint64_t id){
    auto* entry=Find(id);
    if(!engine||engine!=engine_||!entry||entry->state==State::Terminated||entry->suspend_count==UINT32_MAX)return UC_ERR_ARG;
    if(entry->state==State::Running){
        const auto error=entry->context->Capture(engine);if(error!=UC_ERR_OK)return error;
        MakeRunnable(*entry,entry->wake_reason);running_=0;
    }
    ++entry->suspend_count;return UC_ERR_OK;
}
bool DarwinThreadRunQueue::Resume(std::uint64_t id){
    auto* entry=Find(id);if(!entry||entry->state==State::Terminated||!entry->suspend_count)return false;
    if(entry->suspend_count==1&&entry->state==State::Runnable){entry->order=Order();entry->queued_at_head=false;}
    --entry->suspend_count;return true;
}
uc_err DarwinThreadRunQueue::Dispatch(uc_engine* engine,std::uint64_t now,std::uint64_t& selected){
    selected=0;if(!engine||running_||(engine_&&engine!=engine_))return UC_ERR_ARG;Expire(now);
    Entry* next=nullptr;for(auto& entry:entries_)if(entry.state==State::Runnable&&!entry.suspend_count&&(!next
        ||entry.effective_priority>next->effective_priority
        ||(entry.effective_priority==next->effective_priority
            &&(entry.queued_at_head!=next->queued_at_head?entry.queued_at_head:
                entry.queued_at_head?entry.order>next->order:entry.order<next->order))))next=&entry;
    if(!next)return UC_ERR_OK;
    if(last_dispatched_&&last_dispatched_!=next->id&&!exclusive_clear_pc_)return UC_ERR_ARG;
    auto error=next->context->Restore(engine);if(error!=UC_ERR_OK)return error;
    if(last_dispatched_!=next->id&&exclusive_clear_pc_){
        error=DarwinThreadContext::ClearExclusiveMonitor(engine,exclusive_clear_pc_);if(error!=UC_ERR_OK)return error;
        ++exclusive_clears_;
    }
    last_dispatched_=next->id;next->state=State::Running;next->queued_at_head=false;
    running_=selected=next->id;++dispatches_;return UC_ERR_OK;
}
uc_err DarwinThreadRunQueue::YieldCurrent(uc_engine* engine){
    auto* entry=Find(running_);if(!entry||entry->state!=State::Running)return UC_ERR_ARG;
    const auto error=entry->context->Capture(engine);if(error!=UC_ERR_OK)return error;
    const auto reason=entry->wake_reason;MakeRunnable(*entry,reason);running_=0;return UC_ERR_OK;
}
uc_err DarwinThreadRunQueue::PreemptCurrent(uc_engine* engine,bool quantum_expired){
    auto* entry=Find(running_);if(!entry||entry->state!=State::Running)return UC_ERR_ARG;
    const auto error=entry->context->Capture(engine);if(error!=UC_ERR_OK)return error;
    const auto reason=entry->wake_reason;MakeRunnable(*entry,reason);
    entry->queued_at_head=!quantum_expired;running_=0;return UC_ERR_OK;
}
uc_err DarwinThreadRunQueue::Block(uc_engine* engine,std::uint64_t key,std::optional<std::uint64_t> deadline){
    auto* entry=Find(running_);if(!entry||entry->state!=State::Running||!key)return UC_ERR_ARG;
    const auto error=entry->context->Capture(engine);if(error!=UC_ERR_OK)return error;
    const auto order=Order();entry->order=order;entry->state=State::Waiting;
    entry->wake_reason=WakeReason::None;entry->wait_key=key;entry->deadline=deadline;running_=0;return UC_ERR_OK;
}
std::size_t DarwinThreadRunQueue::Wake(std::uint64_t key,std::size_t maximum){
    if(!key)return 0;std::size_t count=0;
    while(count<maximum){
        Entry* next=nullptr;for(auto& entry:entries_)if(entry.state==State::Waiting&&entry.wait_key==key&&(!next||entry.order<next->order))next=&entry;
        if(!next)break;MakeRunnable(*next,WakeReason::Signaled);++count;
    }
    return count;
}
std::size_t DarwinThreadRunQueue::Expire(std::uint64_t now){
    std::size_t count=0;for(auto& entry:entries_)if(entry.state==State::Waiting&&entry.deadline&&*entry.deadline<=now){MakeRunnable(entry,WakeReason::TimedOut);++count;}return count;
}
bool DarwinThreadRunQueue::CancelWait(std::uint64_t id){
    auto* entry=Find(id);if(!entry||entry->state!=State::Waiting)return false;
    MakeRunnable(*entry,WakeReason::Cancelled);return true;
}
bool DarwinThreadRunQueue::Terminate(std::uint64_t id){
    auto* entry=Find(id);if(!entry||entry->state==State::Terminated)return false;
    if(running_==id)running_=0;entry->state=State::Terminated;entry->wake_reason=WakeReason::None;
    entry->wait_key=0;entry->deadline.reset();entry->suspend_count=0;entry->context=nullptr;return true;
}
}
