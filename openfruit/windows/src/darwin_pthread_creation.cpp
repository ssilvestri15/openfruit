#include "darwin_pthread_creation.hpp"
#include <limits>

namespace OpenFruit {
int PrepareDarwinPthreadCreationArm64(bool registered,std::uint64_t start,
    const DarwinPthreadRegistrationInput& registration,const DarwinPthreadCreateRequest& request,
    DarwinPthreadCreationState& output) noexcept {
    // libpthread 42d026d kern/kern_support.c:_bsdthread_create. Port allocation
    // is owned by Main; this pure producer cannot establish its lifetime.
    if(!registered)return 22;
    if(!request.thread_port||request.thread_port==UINT32_MAX)return 24;
    if(!(request.flags&DarwinPthreadStartCustom))return 22;
    constexpr auto supported=DarwinPthreadStartCustom|DarwinPthreadStartSuspended;
    if(request.flags&~supported)return 45;
    if(registration.mach_thread_self_offset>registration.max_tsd_offset)return 22;
    DarwinPthreadCreationState state;
    state.initially_suspended=(request.flags&DarwinPthreadStartSuspended)!=0;
    auto flags=request.flags&~DarwinPthreadStartSuspended;
    if(registration.tsd_offset){
        if(request.user_pthread>UINT64_MAX-registration.tsd_offset)return 14;
        const auto address=request.user_pthread+registration.tsd_offset;
        // XNU f6217f8 osfmk/arm64/pcb.c: machine_thread_set_tsd_base accepts
        // unaligned values and clamps those beyond vm_map_max to zero.
        state.tsd_base=address>request.user_address_max?0:address;
        flags|=DarwinPthreadStartTsdBaseSet;
        if(registration.mach_thread_self_offset){
            if(address>UINT64_MAX-registration.mach_thread_self_offset)return 14;
            state.mach_self_address=address+registration.mach_thread_self_offset;
            if(state.mach_self_address>UINT64_MAX-7)return 14;
            state.mach_self_value=request.thread_port;
            state.mach_self_copyout=true;
        }
    }
    const auto put=[&](std::size_t at,std::uint64_t value){
        state.arm64_words[at]=static_cast<std::uint32_t>(value);
        state.arm64_words[at+1]=static_cast<std::uint32_t>(value>>32);
    };
    put(0,request.user_pthread);put(2,request.thread_port);put(4,request.user_func);
    put(6,request.user_arg);put(8,request.user_stack);put(10,flags);
    put(62,request.user_stack);put(64,start);
    // Fresh user state has zero NZCV and opaque flags. Privileged CPSR/default
    // SSBS bits are outside the existing InitializeArm64 supported user scope.
    output=state;return 0;
}

DarwinWorkqueuePreparationStatus PrepareDarwinWorkqueueUpcallArm64(
    const DarwinPthreadRegistrationState& registration,
    const DarwinWorkqueueUpcallRequest& request,DarwinWorkqueueUpcallState& output) noexcept {
    using Status=DarwinWorkqueuePreparationStatus;
    if(!registration.registered)return Status::Unregistered;
    if(!registration.workqueue_start||(registration.workqueue_start&3)
        ||registration.workqueue_start>request.user_address_max)return Status::InvalidEntrypoint;
    if(!request.thread_port||request.thread_port==UINT32_MAX)return Status::InvalidPort;
    constexpr auto supported=DarwinWorkqueueOvercommit|DarwinWorkqueueReuse|DarwinWorkqueueKevent
        |DarwinWorkqueueEventManager|DarwinWorkqueueWorkloop;
    if(request.flags&~supported)return Status::UnsupportedFlags;
    const auto kevent=(request.flags&DarwinWorkqueueKevent)!=0;
    const auto workloop=(request.flags&DarwinWorkqueueWorkloop)!=0;
    if(!kevent&&(request.flags&(DarwinWorkqueueEventManager|DarwinWorkqueueWorkloop)||request.kevent_list||request.kevent_count))
        return Status::UnsupportedFlags;
    if(workloop&&(request.flags&DarwinWorkqueueEventManager))return Status::UnsupportedFlags;
    const auto reuse=(request.flags&DarwinWorkqueueReuse)!=0;
    if(request.first_use==reuse||(!request.first_use&&request.first_use_tsd_installed))
        return Status::InconsistentLifecycle;
    if(request.qos_tier<1||request.qos_tier>6)return Status::InvalidQos;
    const auto stack_top=request.self&~std::uint64_t{15};
    // workq_setup_thread: the list sits directly below the pthread stack top.
    const auto kevent_list=stack_top-std::uint64_t{DarwinWorkqueueKeventListLength}*64;
    if(kevent&&(request.kevent_list!=kevent_list||request.kevent_count>DarwinWorkqueueKeventListLength))
        return Status::InvalidAddress;
    // workq_thread_set_top_addr aligns the entry stack below the id slot.
    const auto entry_top=workloop?(kevent_list-8)&~std::uint64_t{15}:kevent?kevent_list:stack_top;
    if(!request.self||!request.stack_bottom||request.stack_bottom>=entry_top
        ||request.self>request.user_address_max||registration.pthread_bytes<=0
        ||static_cast<std::uint64_t>(registration.pthread_bytes-1)>request.user_address_max-request.self)
        return Status::InvalidAddress;
    auto flags=request.flags|DarwinWorkqueueNewSpi|DarwinWorkqueuePriorityQos|request.qos_tier;
    if(request.first_use){
        const auto offset=registration.input.tsd_offset;
        // This bounded provider requires usable TSD rather than pretending the
        // original guest can run without it (pthread.c:_pthread_wqthread_setup).
        if(!offset||offset>=static_cast<std::uint32_t>(registration.pthread_bytes)
            ||request.self>UINT64_MAX-offset||!request.first_use_tsd_installed
            ||request.actual_tsd_base!=request.self+offset
            ||request.actual_tsd_base>request.user_address_max)return Status::TsdNotPrepared;
        flags|=DarwinWorkqueueTsdBaseSet;
    }else if(!request.actual_tsd_base||request.actual_tsd_base>request.user_address_max){
        return Status::TsdNotPrepared;
    }
    DarwinWorkqueueUpcallState state;
    state.tsd_base=request.actual_tsd_base;state.first_use=request.first_use;
    const auto put=[&](std::size_t at,std::uint64_t value){
        state.arm64_words[at]=static_cast<std::uint32_t>(value);
        state.arm64_words[at+1]=static_cast<std::uint32_t>(value>>32);
    };
    put(0,request.self);put(2,request.thread_port);put(4,request.stack_bottom);
    put(8,flags);put(62,entry_top);put(64,registration.workqueue_start);
    if(kevent){put(6,kevent_list);put(10,request.kevent_count);}
    output=state;return Status::Ready;
}
}
