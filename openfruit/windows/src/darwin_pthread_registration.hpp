#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace OpenFruit {
// Published libpthread packed registration ABI; later inputs may append fields.
inline constexpr std::size_t DarwinPthreadRegistrationBytes=56;
inline constexpr std::int32_t DarwinMaximumPthreadBytes=65536;
struct DarwinPthreadRegistrationInput {
    std::uint64_t input_version=0,unknown_tail_bytes=0,dispatch_queue_offset=0;
    std::uint32_t tsd_offset=0,return_to_kernel_offset=0,mach_thread_self_offset=0;
    std::uint32_t joinable_offset_bits=0,wq_quantum_expiry_offset=0,max_tsd_offset=0;
    std::size_t copied_bytes=0;
    std::array<std::uint8_t,DarwinPthreadRegistrationBytes> normalized_data{};
};
// Decode/normalize copy-in only. This neither registers a thread nor supplies
// copy-out metadata, feature bits, scheduling or TSD storage.
int DecodeDarwinPthreadRegistration(std::int32_t pthread_bytes,bool has_data,
    std::uint64_t data_size,std::span<const std::uint8_t> copyin,
    std::uint64_t legacy_dispatch_offset,DarwinPthreadRegistrationInput&) noexcept;

struct DarwinPthreadRegistrationOutput {
    std::uint64_t version=DarwinPthreadRegistrationBytes;
    std::uint64_t main_qos=0; // _pthread_unspecified_priority(); owner supplies actual policy
    std::uint64_t stack_addr_hint=0;
    std::uint32_t mutex_default_policy=0; // owner supplies its implemented mutex policy
};

inline constexpr std::uint32_t DarwinPthreadFeatureDispatchFunc    = 0x01;
inline constexpr std::uint32_t DarwinPthreadFeatureFinePrio        = 0x02;
inline constexpr std::uint32_t DarwinPthreadFeatureBsdthreadCtl    = 0x04;
inline constexpr std::uint32_t DarwinPthreadFeatureSetSelf         = 0x08;
inline constexpr std::uint32_t DarwinPthreadFeatureQosMaintenance  = 0x10;
inline constexpr std::uint32_t DarwinPthreadFeatureKevent          = 0x40;
inline constexpr std::uint32_t DarwinPthreadFeatureWorkloop        = 0x80;
inline constexpr std::uint32_t DarwinPthreadFeatureQosDefault      = 0x40000000;
// ABI bit names above describe Apple capabilities, not implemented providers.
// No scheduling/voucher/ulock provider is established by this codec.
inline constexpr std::uint32_t DarwinPthreadSupportedFeatures = 0;

// Encodes outgoing registration copyout data according to the XNU wire format.
// Encodes only input.copied_bytes (the negotiated min(data_size, 56) prefix),
// preserves all other destination bytes, and performs no copy for legacy input.
// Caller must derive QoS/stack hint/mutex policy from actual owner providers;
// this helper does not commit registration or establish any feature capability.
int EncodeDarwinPthreadRegistration(const DarwinPthreadRegistrationInput& input,
    const DarwinPthreadRegistrationOutput& output,
    std::span<std::uint8_t> copyout) noexcept;

// Task-owned registration, separate from the feature set returned to libpthread.
// The caller supplies successfully decoded input and task-converted entrypoints.
// Conversion may retain authentication poison; publication does not certify PAC.
// This transition performs no guest copyout and promises no workqueue capability.
struct DarwinPthreadRegistrationState {
    bool registered=false;
    std::int32_t pthread_bytes=0;
    std::uint64_t thread_start=0,workqueue_start=0,stack_addr_hint=0;
    DarwinPthreadRegistrationInput input{};
};
// libpthread kern/kern_support.c:_bsdthread_register resets the stack hint before
// checking duplicate registration. Publication precedes policy lookup/copyout;
// subsequent copyout failure does not undo it. Invalid size has no side effects.
int CommitDarwinPthreadRegistration(DarwinPthreadRegistrationState&,
    const DarwinPthreadRegistrationInput&,std::int32_t pthread_bytes,
    std::uint64_t converted_thread_start,std::uint64_t converted_workqueue_start,
    std::uint64_t stack_addr_hint) noexcept;

// XNU f6217f8 bsd/pthread/workqueue_syscalls.h / pthread_workqueue.c.
// BSD 368 WQOPS_SETUP_DISPATCH copies a zero-extended 24-byte kernel prefix.
// data_size is the raw affinity argument: its low signed 32 bits are converted
// to unsigned long before MIN, so a negative affinity requests the full prefix.
// Caller enforces task registration and supplies the readable guest copy-in.
// A version-1 update must preserve the owner's existing label offset.
inline constexpr std::size_t DarwinWorkqueueDispatchConfigurationBytes=24;
struct DarwinWorkqueueDispatchConfiguration {
    std::uint32_t version=0,flags=0;
    std::uint64_t serialno_offset=0,label_offset=0;
    std::size_t copied_bytes=0;
    bool has_label=false;
    bool operator==(const DarwinWorkqueueDispatchConfiguration&) const=default;
};
std::size_t DarwinWorkqueueDispatchCopyinBytes(std::uint64_t data_size) noexcept;
int DecodeDarwinWorkqueueDispatchConfiguration(std::uint64_t data_size,
    std::span<const std::uint8_t> copyin,DarwinWorkqueueDispatchConfiguration&) noexcept;

struct DarwinWorkqueueRequest {
    std::uint32_t count=0;
    std::uint8_t qos_tier=0;
    bool overcommit=false;
    bool operator==(const DarwinWorkqueueRequest&) const=default;
};
// Decode WQOPS_QUEUE_REQTHREADS (0x20). count/priority use their low int32 ABI
// bits. Unlike ordinary SET_SELF, this operation ignores relative priority and
// uses only the QoS tier and overcommit flag. Cooperative 0x30 is unsupported,
// retaining source error precedence for invalid count/QoS/overcommit mixtures.
// Both decoders leave output untouched on error; neither admits a worker,
// supplies a scheduler, or publishes any pthread capability.
int DecodeDarwinWorkqueueRequest(std::uint32_t operation,bool workqueue_open,
    std::uint64_t count,std::uint64_t priority,DarwinWorkqueueRequest&) noexcept;
}
