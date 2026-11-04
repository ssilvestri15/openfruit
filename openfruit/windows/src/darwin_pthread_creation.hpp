#pragma once
#include "darwin_pthread_registration.hpp"
#include <array>
#include <cstdint>

namespace OpenFruit {
inline constexpr std::uint32_t DarwinPthreadStartCustom=0x01000000;
inline constexpr std::uint32_t DarwinPthreadStartSetSched=0x02000000;
inline constexpr std::uint32_t DarwinPthreadStartQosClass=0x08000000;
inline constexpr std::uint32_t DarwinPthreadStartTsdBaseSet=0x10000000;
inline constexpr std::uint32_t DarwinPthreadStartSuspended=0x20000000;
struct DarwinPthreadCreateRequest {
    std::uint64_t user_func=0,user_arg=0,user_stack=0,user_pthread=0;
    // Actual task map limit and allocated thread port, supplied by the owner.
    std::uint64_t user_address_max=0;
    std::uint32_t thread_port=0,flags=0;
};
struct DarwinPthreadCreationState {
    std::array<std::uint32_t,68> arm64_words{};
    std::uint64_t tsd_base=0,mach_self_address=0,mach_self_value=0;
    bool initially_suspended=false,mach_self_copyout=false;
};
// Pure preparation of the supported CUSTOM ARM64 creation ABI. Success does
// not allocate/register/resume a thread or perform copyout. Main must validate
// mappings, perform checked copyout of the real port, then publish/resume the
// context. Failure cleanup retires owned objects; it does not promise rollback
// of guest bytes already copied out (XNU preserves those on later resume error).
// SETSCHED/QOS and other unsupported flags return Darwin ENOTSUP, never success.
// Output is untouched on error; registration must be the existing decoder output.
// thread_start must be the owning task's converted registered
// entry, not the raw PAC-bearing bsdthread_register argument. XNU's syscall
// shim converts that argument before storing it, retaining authentication poison;
// this producer performs no authentication or pointer masking. SP/X4 and arguments retain
// their supplied bits, including unaligned SP, exactly as _bsdthread_create.
int PrepareDarwinPthreadCreationArm64(bool registered,std::uint64_t thread_start,
    const DarwinPthreadRegistrationInput&,const DarwinPthreadCreateRequest&,
    DarwinPthreadCreationState&) noexcept;

inline constexpr std::uint32_t DarwinWorkqueueOvercommit=0x00010000;
inline constexpr std::uint32_t DarwinWorkqueueReuse=0x00020000;
inline constexpr std::uint32_t DarwinWorkqueueNewSpi=0x00040000;
inline constexpr std::uint32_t DarwinWorkqueueKevent=0x00080000;
inline constexpr std::uint32_t DarwinWorkqueueEventManager=0x00100000;
inline constexpr std::uint32_t DarwinWorkqueueWorkloop=0x00400000;
// kern_support.c WQ_KEVENT_LIST_LEN: events delivered below the stack top.
inline constexpr std::uint32_t DarwinWorkqueueKeventListLength=16;
inline constexpr std::uint32_t DarwinWorkqueueTsdBaseSet=0x00200000;
inline constexpr std::uint32_t DarwinWorkqueuePriorityQos=0x00004000;
struct DarwinWorkqueueUpcallRequest {
    std::uint64_t self=0,stack_bottom=0,user_address_max=0,actual_tsd_base=0;
    std::uint32_t thread_port=0,flags=0;
    std::uint8_t qos_tier=0; // XNU thread_qos_t maintenance1..interactive6
    // KEVENT upcalls: the owner copied kevent_count events to kevent_list,
    // which is also the entry stack top (no kevent data buffer is used).
    // WORKLOOP upcalls also carry the kqueue id in the 8 bytes below the list;
    // the stack top is then that slot aligned down to 16 bytes.
    std::uint64_t kevent_list=0;
    std::uint32_t kevent_count=0;
    bool first_use=true;
    // Owner confirms the first-use TSD has actually been installed; this pure
    // producer cannot perform machine_thread_set_tsd_base or prove mappings.
    bool first_use_tsd_installed=false;
};
struct DarwinWorkqueueUpcallState {
    std::array<std::uint32_t,68> arm64_words{};
    std::uint64_t tsd_base=0;
    bool first_use=false;
};
// Caller precondition results, deliberately not XNU syscall errno values.
enum class DarwinWorkqueuePreparationStatus {
    Ready,Unregistered,InvalidEntrypoint,InvalidPort,InvalidAddress,
    UnsupportedFlags,InconsistentLifecycle,InvalidQos,TsdNotPrepared
};
// libpthread 42d026df5b07825070f60134b980a1ec2552dfee:
// kern/kern_support.c:workq_set_register_state/workq_setup_thread. Registration
// owns an authenticated workqueue_start. Supports ordinary QoS upcalls and
// kqworkq KEVENT/EVENT_MANAGER and WORKLOOP delivery of an owner-copied event
// list; no cooperative/exit delivery, allocation, admission, copyout,
// scheduling or capability publication. Owner supplies real stack/port/TSD,
// validates mappings/port rights and performs the actual context transition.
// First use requires installed self+tsd_offset and emits TSD_BASE_SET. Reuse
// retains actual_tsd_base and emits REUSE; its word array describes only the
// GPR entry ABI, not a complete replacement of the saved CPU context. In
// particular InitializeArm64 resets FP/NEON and is not a reuse implementation.
// No MACH_THREAD_SELF copyout occurs in this workqueue kernel path: original
// libpthread initializes that slot. Failed preparation leaves output untouched.
DarwinWorkqueuePreparationStatus PrepareDarwinWorkqueueUpcallArm64(
    const DarwinPthreadRegistrationState&,const DarwinWorkqueueUpcallRequest&,
    DarwinWorkqueueUpcallState&) noexcept;
}
