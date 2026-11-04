#pragma once
#include <cstdint>
namespace OpenFruit {
class DarwinThreadRunQueue;
struct DarwinPthreadQos {std::uint8_t tier=0;int relative_priority=0;bool operator==(const DarwinPthreadQos&) const=default;};
// Pinned XNU priority_private.h: tiers maintenance1..interactive6, legacy/default4.
// Zero is unspecified. Invalid decode/encode leaves the output untouched.
bool DecodeDarwinPthreadQos(std::uint64_t priority,DarwinPthreadQos&) noexcept;
bool EncodeDarwinPthreadQos(DarwinPthreadQos,std::uint32_t&) noexcept;
// XNU f6217f8 ordinary QoS band scaling, before task caps, importance,
// overrides and CPU-usage decay. Does not establish a full scheduling provider.
bool ResolveDarwinPthreadBasePriority(DarwinPthreadQos,int&) noexcept;
struct DarwinPthreadPolicyState {
    DarwinPthreadQos qos{};
    bool timeshare=true;
    std::uint32_t voucher=0;
};
// OrdinaryWorkqueue is a non-bound ordinary constrained/overcommit worker.
// Cooperative, kevent-bound, manager and above-UI workers need other providers.
enum class DarwinPthreadPolicyKind { Ordinary, OrdinaryWorkqueue, WorkqueueUnsupported };
struct DarwinPthreadPolicyOperations {
    void* owner=nullptr;
    // Each requested stage requires a real owner provider. Providers return
    // Mach kern_return_t: 0 success, nonzero failure. The owner must implement
    // real scheduling/voucher effects; this module does not establish them.
    int (*apply_qos)(void*,DarwinPthreadQos) noexcept=nullptr;
    int (*apply_voucher)(void*,std::uint32_t) noexcept=nullptr;
    int (*apply_timeshare)(void*,bool) noexcept=nullptr;
    // Ordinary workqueue owner must update real requested QoS, overcommit type,
    // admission accounting and pending-request redrive before CPU policy.
    // This stage precedes apply_qos. A later policy failure does not roll back
    // its effects, matching XNU's bucket-before-thread_policy_set ordering.
    int (*update_workqueue)(void*,DarwinPthreadQos,bool overcommit) noexcept=nullptr;
};
// Ordinary guest CPU priority provider for the existing serial task queue.
// The queue and thread context must outlive this binding. It can also prepare
// an admitted, suspended peer; the syscall owner must enforce SET_SELF identity.
// No voucher, fixed/timeshare transition, task cap, override or I/O QoS is
// established by this CPU-only provider. Those callbacks remain absent.
class DarwinPthreadRunQueuePolicyProvider {
    DarwinThreadRunQueue& queue_;
    std::uint64_t thread_id_;
    static int Apply(void*,DarwinPthreadQos) noexcept;
public:
    DarwinPthreadRunQueuePolicyProvider(DarwinThreadRunQueue& queue,std::uint64_t id) noexcept
        :queue_(queue),thread_id_(id){}
    bool Ready() const noexcept;
    int ApplyQos(DarwinPthreadQos) noexcept; // Mach kern_return_t, not BSD errno
    DarwinPthreadPolicyOperations Operations() noexcept;
};
inline constexpr std::uint32_t DarwinSetSelfQos=0x01,DarwinSetSelfVoucher=0x02;
inline constexpr std::uint32_t DarwinSetSelfFixedPriority=0x04,DarwinSetSelfTimeshare=0x08;
inline constexpr std::uint32_t DarwinSetSelfUnbind=0x10,DarwinSetSelfQosOverride=0x40;
// Independent source stages may apply before another stage fails. The return
// preserves XNU error precedence, including EBADMSG for QoS+voucher failure.
// No capability bits or kernel scheduling equivalence are implied.
int ApplyDarwinPthreadSetSelf(DarwinPthreadPolicyState&,std::uint64_t priority,
    std::uint32_t voucher,std::uint32_t flags,DarwinPthreadPolicyKind,
    const DarwinPthreadPolicyOperations&) noexcept;
// Bounded ordinary SET_SELF command primitive, not syscall registration. Other
// live commands are explicitly unsupported; source-discontinued/unknown command
// errors and reserved arguments are preserved.
int ApplyDarwinBsdthreadCtl(DarwinPthreadPolicyState&,std::uint32_t command,
    std::uint64_t arg1,std::uint64_t arg2,std::uint64_t arg3,
    DarwinPthreadPolicyKind,const DarwinPthreadPolicyOperations&) noexcept;
}
