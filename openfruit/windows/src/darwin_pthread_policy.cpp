#include "darwin_pthread_policy.hpp"
#include "darwin_thread_run_queue.hpp"
namespace OpenFruit {
namespace {
constexpr std::uint64_t qos_mask=0x3f00,override_mask=0x3fc000;
constexpr std::uint64_t sched_flag=0x20000000,manager_flag=0x02000000;
constexpr std::uint64_t override_flag=0x00800000,cooperative_flag=0x08000000;
bool HasOverride(std::uint64_t priority) noexcept {
    return !(priority&(sched_flag|manager_flag))&&(priority&override_flag)&&(priority&override_mask);
}
}
bool DecodeDarwinPthreadQos(std::uint64_t priority,DarwinPthreadQos& output) noexcept {
    if(priority&(sched_flag|manager_flag))return false;
    auto bits=(priority&qos_mask)>>8;if(!bits)return false;
    std::uint8_t tier=1;while(!(bits&1)){++tier;bits>>=1;}
    // Defined signed-byte conversion without implementation-defined narrowing.
    const auto byte=static_cast<int>(priority&0xff);
    const auto relative=(byte>=128?byte-256:byte)+1;
    if(relative>0||relative< -15)return false;
    output={tier,relative};return true;
}
bool EncodeDarwinPthreadQos(DarwinPthreadQos qos,std::uint32_t& output) noexcept {
    if(!qos.tier||qos.tier>6||qos.relative_priority>0||qos.relative_priority< -15)return false;
    output=(1u<<(8+qos.tier-1))|static_cast<std::uint8_t>(qos.relative_priority-1);return true;
}
bool ResolveDarwinPthreadBasePriority(DarwinPthreadQos qos,int& output) noexcept {
    if(!qos.tier||qos.tier>6||qos.relative_priority>0||qos.relative_priority< -15)return false;
    // osfmk/kern/thread_policy.c thread_qos_scaled_relative_priority and
    // osfmk/kern/sched.h: maintenance/background share (0,4].
    constexpr int upper[]{0,4,4,20,31,37,46};
    const auto lower=qos.tier<=2?0:upper[qos.tier-1];
    output=upper[qos.tier]-((upper[qos.tier]-lower)*(-qos.relative_priority)/16);
    return true;
}
bool DarwinPthreadRunQueuePolicyProvider::Ready() const noexcept {
    const auto* entry=queue_.Lookup(thread_id_);
    return entry&&entry->state!=DarwinThreadRunQueue::State::Terminated
        &&entry->context&&entry->context->Saved();
}
int DarwinPthreadRunQueuePolicyProvider::ApplyQos(DarwinPthreadQos qos) noexcept {
    int priority=0;
    if(!ResolveDarwinPthreadBasePriority(qos,priority))return 4; // KERN_INVALID_ARGUMENT
    if(!Ready())return 37; // KERN_TERMINATED: no live admitted context
    // The existing dispatch boundary consumes this priority, including waiting
    // and suspended peers once eligible. No detached metadata-only success.
    return queue_.SetEffectivePriority(thread_id_,priority)?0:4;
}
int DarwinPthreadRunQueuePolicyProvider::Apply(void* owner,DarwinPthreadQos qos) noexcept {
    return static_cast<DarwinPthreadRunQueuePolicyProvider*>(owner)->ApplyQos(qos);
}
DarwinPthreadPolicyOperations DarwinPthreadRunQueuePolicyProvider::Operations() noexcept {
    return {this,Apply,nullptr,nullptr};
}
int ApplyDarwinPthreadSetSelf(DarwinPthreadPolicyState& state,std::uint64_t priority,
    std::uint32_t voucher,std::uint32_t flags,DarwinPthreadPolicyKind kind,
    const DarwinPthreadPolicyOperations& operations) noexcept {
    // XNU f6217f8 bsd/pthread/pthread_workqueue.c:bsdthread_set_self.
    constexpr auto known=DarwinSetSelfQos|DarwinSetSelfVoucher|DarwinSetSelfFixedPriority|
        DarwinSetSelfTimeshare|DarwinSetSelfUnbind|DarwinSetSelfQosOverride;
    if(flags&~known)return 45;
    int unbind_error=0,qos_error=0,voucher_error=0,fixed_error=0;
    const auto workqueue=kind!=DarwinPthreadPolicyKind::Ordinary;
    const auto ordinary_workqueue=kind==DarwinPthreadPolicyKind::OrdinaryWorkqueue;
    if(flags&DarwinSetSelfUnbind)unbind_error=ordinary_workqueue?37:workqueue?45:22;
    if(flags&(DarwinSetSelfQos|DarwinSetSelfQosOverride)){
        DarwinPthreadQos qos;
        if(!(flags&DarwinSetSelfQos)||!DecodeDarwinPthreadQos(priority,qos))qos_error=22;
        else if(flags&DarwinSetSelfQosOverride){
            if(!HasOverride(priority)||!(priority&cooperative_flag))qos_error=22;
        }else if(HasOverride(priority))qos_error=22;
        if(!qos_error){
            if(kind==DarwinPthreadPolicyKind::WorkqueueUnsupported)qos_error=45;
            // An ordinary worker cannot transition into the cooperative pool,
            // including a syntactically valid cooperative override request.
            else if(ordinary_workqueue&&(priority&cooperative_flag))qos_error=22;
            else if(!workqueue&&!state.qos.tier)qos_error=1;
            else if(!operations.owner)qos_error=45;
            else {
                if(ordinary_workqueue){
                    if(!operations.update_workqueue)qos_error=45;
                    else if(operations.update_workqueue(operations.owner,qos,
                        (priority&0x80000000u)!=0)!=0)qos_error=22;
                }
                // Valid override encoding on an ordinary non-workqueue thread
                // does not redistribute any workqueue override. XNU still
                // applies the requested ordinary QoS through thread policy.
                if(!qos_error){
                    if(!operations.apply_qos)qos_error=45;
                    else if(operations.apply_qos(operations.owner,qos)!=0)qos_error=22;
                    else state.qos=qos;
                }
            }
        }
    }
    if(flags&DarwinSetSelfVoucher){
        if(!operations.owner||!operations.apply_voucher)voucher_error=45;
        else if(operations.apply_voucher(operations.owner,voucher)!=0)voucher_error=2;
        else state.voucher=voucher;
    }
    // A QoS error suppresses fixed/timeshare, but does not suppress voucher.
    if(!qos_error&&(flags&(DarwinSetSelfFixedPriority|DarwinSetSelfTimeshare))){
        if(workqueue)fixed_error=45;
        else if(!operations.owner||!operations.apply_timeshare)fixed_error=45;
        else {
            // Source gives FIXED precedence when both bits are present.
            const bool timeshare=!(flags&DarwinSetSelfFixedPriority);
            if(operations.apply_timeshare(operations.owner,timeshare)!=0)fixed_error=22;
            else state.timeshare=timeshare;
        }
    }
    if(qos_error&&voucher_error)return 94;
    if(unbind_error)return unbind_error;if(qos_error)return qos_error;
    if(voucher_error)return voucher_error;return fixed_error;
}
int ApplyDarwinBsdthreadCtl(DarwinPthreadPolicyState& state,std::uint32_t command,
    std::uint64_t arg1,std::uint64_t arg2,std::uint64_t arg3,
    DarwinPthreadPolicyKind kind,const DarwinPthreadPolicyOperations& operations) noexcept {
    switch(command){
    case 0x100:return ApplyDarwinPthreadSetSelf(state,arg1,static_cast<std::uint32_t>(arg2),
        static_cast<std::uint32_t>(arg3),kind,operations);
    case 0x10:case 0x401:case 0x402:return 45; // source-discontinued commands
    case 0x80:case 0x800:if(arg3)return 22;return 45;
    case 0x1000:if(arg2||arg3)return 22;return 45;
    case 0x40:case 0x200:case 0x400:case 0x2000:case 0x4000:return 45;
    default:return 22;
    }
}
}
