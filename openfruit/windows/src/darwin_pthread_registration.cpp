#include "darwin_pthread_registration.hpp"
#include <algorithm>

namespace OpenFruit {
namespace {
std::uint64_t Read(std::span<const std::uint8_t> bytes,std::size_t at,unsigned width){
    std::uint64_t value=0;for(unsigned n=0;n<width;++n)value|=std::uint64_t(bytes[at+n])<<(8*n);return value;
}
void Put(std::span<std::uint8_t> bytes,std::size_t at,std::uint64_t value,unsigned width){
    for(unsigned n=0;n<width;++n)bytes[at+n]=static_cast<std::uint8_t>(value>>(8*n));
}
}
int DecodeDarwinPthreadRegistration(std::int32_t pthread_bytes,bool has_data,
    std::uint64_t data_size,std::span<const std::uint8_t> copyin,
    std::uint64_t legacy_dispatch_offset,DarwinPthreadRegistrationInput& output) noexcept {
    output={};if(pthread_bytes<0||pthread_bytes>DarwinMaximumPthreadBytes)return 22;
    DarwinPthreadRegistrationInput value;
    if(has_data){
        if(data_size<8)return 22;
        value.copied_bytes=static_cast<std::size_t>(std::min<std::uint64_t>(data_size,DarwinPthreadRegistrationBytes));
        if(copyin.size()<value.copied_bytes)return 14;
        std::copy_n(copyin.begin(),value.copied_bytes,value.normalized_data.begin());
        value.input_version=Read(value.normalized_data,0,8);
        if(value.input_version!=data_size)return 22;
        value.unknown_tail_bytes=data_size-value.copied_bytes;
        value.dispatch_queue_offset=Read(value.normalized_data,8,8);
        value.tsd_offset=static_cast<std::uint32_t>(Read(value.normalized_data,24,4));
        value.return_to_kernel_offset=static_cast<std::uint32_t>(Read(value.normalized_data,28,4));
        value.mach_thread_self_offset=static_cast<std::uint32_t>(Read(value.normalized_data,32,4));
        value.joinable_offset_bits=static_cast<std::uint32_t>(Read(value.normalized_data,48,4));
        value.wq_quantum_expiry_offset=static_cast<std::uint32_t>(Read(value.normalized_data,52,4));
    }else value.dispatch_queue_offset=legacy_dispatch_offset;
    // ARM64 TSD slots are 8 bytes. XNU clamps unavailable offsets to zero;
    // alignment of individual offsets is not required by this ABI.
    const auto size=static_cast<std::uint32_t>(pthread_bytes);
    if(size>=8&&value.tsd_offset<=size-8)value.max_tsd_offset=size-value.tsd_offset-8;
    else value.tsd_offset=0;
    if(value.dispatch_queue_offset>value.max_tsd_offset)value.dispatch_queue_offset=0;
    if(value.return_to_kernel_offset>value.max_tsd_offset)value.return_to_kernel_offset=0;
    if(value.mach_thread_self_offset>value.max_tsd_offset)value.mach_thread_self_offset=0;
    if(value.wq_quantum_expiry_offset>value.max_tsd_offset)value.wq_quantum_expiry_offset=0;
    Put(value.normalized_data,8,value.dispatch_queue_offset,8);Put(value.normalized_data,24,value.tsd_offset,4);
    Put(value.normalized_data,28,value.return_to_kernel_offset,4);Put(value.normalized_data,32,value.mach_thread_self_offset,4);
    Put(value.normalized_data,52,value.wq_quantum_expiry_offset,4);
    output=value;return 0;
}
int EncodeDarwinPthreadRegistration(const DarwinPthreadRegistrationInput& input,
    const DarwinPthreadRegistrationOutput& output,
    std::span<std::uint8_t> copyout) noexcept {
    if(input.copied_bytes>DarwinPthreadRegistrationBytes||output.version!=DarwinPthreadRegistrationBytes)return 22;
    if(copyout.size()<input.copied_bytes)return 14;
    auto data=input.normalized_data;
    Put(data,0,output.version,8);
    Put(data,16,output.main_qos,8);
    Put(data,36,output.stack_addr_hint,8);
    Put(data,44,output.mutex_default_policy,4);
    std::copy_n(data.begin(),input.copied_bytes,copyout.begin());
    return 0;
}
int CommitDarwinPthreadRegistration(DarwinPthreadRegistrationState& state,
    const DarwinPthreadRegistrationInput& input,std::int32_t pthread_bytes,
    std::uint64_t thread_start,std::uint64_t workqueue_start,std::uint64_t stack_addr_hint) noexcept {
    if(pthread_bytes<0||pthread_bytes>DarwinMaximumPthreadBytes)return 22;
    state.stack_addr_hint=stack_addr_hint;
    if(state.registered)return 22;
    state.thread_start=thread_start;state.workqueue_start=workqueue_start;
    state.pthread_bytes=pthread_bytes;state.input=input;state.registered=true;
    return 0;
}
std::size_t DarwinWorkqueueDispatchCopyinBytes(std::uint64_t data_size) noexcept {
    // A negative signed affinity becomes a very large unsigned long in XNU's
    // MIN(sizeof(cfg), (unsigned long)arg2); all such inputs copy 24 bytes.
    const auto size_bits=static_cast<std::uint32_t>(data_size);
    return size_bits&0x80000000u?DarwinWorkqueueDispatchConfigurationBytes:
        std::min<std::size_t>(size_bits,DarwinWorkqueueDispatchConfigurationBytes);
}
int DecodeDarwinWorkqueueDispatchConfiguration(std::uint64_t data_size,
    std::span<const std::uint8_t> copyin,DarwinWorkqueueDispatchConfiguration& output) noexcept {
    const auto count=DarwinWorkqueueDispatchCopyinBytes(data_size);
    if(copyin.size()<count)return 14; // copyin EFAULT precedes version/flags
    std::array<std::uint8_t,DarwinWorkqueueDispatchConfigurationBytes> data{};
    std::copy_n(copyin.begin(),count,data.begin());
    DarwinWorkqueueDispatchConfiguration value;
    value.version=static_cast<std::uint32_t>(Read(data,0,4));
    value.flags=static_cast<std::uint32_t>(Read(data,4,4));
    if(value.flags||value.version<1)return 45; // ENOTSUP
    value.serialno_offset=Read(data,8,8);
    value.has_label=value.version>=2;
    if(value.has_label)value.label_offset=Read(data,16,8);
    value.copied_bytes=count;
    output=value;return 0;
}
int DecodeDarwinWorkqueueRequest(std::uint32_t operation,bool workqueue_open,
    std::uint64_t count,std::uint64_t priority,DarwinWorkqueueRequest& output) noexcept {
    if(operation!=0x20&&operation!=0x30)return 22;
    const auto reqcount=static_cast<std::uint32_t>(count);
    const auto pp=static_cast<std::uint32_t>(priority);
    // _pthread_priority_thread_qos returns ffs of the valid QoS mask, unless
    // SCHED_PRI or EVENT_MANAGER encodes a different kind of priority.
    auto bits=(pp&0x3f00u)>>8;
    if(!workqueue_open||!reqcount||reqcount>65535||!bits||(pp&0x22000000u))return 22;
    std::uint8_t qos=1;
    while(!(bits&1u)){++qos;bits>>=1;}
    const bool overcommit=(pp&0x80000000u)!=0;
    if(operation==0x30){
        if(reqcount>1)return 45; // source checks count before conflicting type
        if(overcommit)return 22;
        return 45; // no cooperative provider
    }
    output={reqcount,qos,overcommit};return 0;
}
}
