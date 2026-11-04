#pragma once
#include <unicorn/unicorn.h>
#include <cstdint>
#include <span>

namespace OpenFruit {
// Requires CPU-only context mode (the native engine's Unicorn default); memory
// snapshots are not thread state. Bound to the task's existing engine, with
// shared guest mappings. Destroy contexts before closing the owning engine.
class DarwinThreadContext {
    uc_engine* engine_=nullptr;
    uc_context* context_=nullptr;
    bool saved_=false;
    std::uint64_t captures_=0;
public:
    DarwinThreadContext()=default;
    ~DarwinThreadContext();
    DarwinThreadContext(const DarwinThreadContext&)=delete;
    DarwinThreadContext& operator=(const DarwinThreadContext&)=delete;
    // Initialize a fresh saved context from the existing ARM_THREAD_STATE64 wire
    // words; retain process keys, reset NEON/FP, set actual TSD base and the
    // owner's modeled CPU identity. TPIDR_EL0 is Darwin CPU info, not inherited
    // user TLS. Default0 represents the existing single modeled CPU.
    // Preserves the live creator CPU on return; temporarily uses its complete
    // floating-point backend to prepare a snapshot. Call while the engine is
    // quiescent, outside emulation callbacks. CPU mappings remain task-shared.
    uc_err InitializeArm64(uc_engine*,std::span<const std::uint32_t>,std::uint64_t tsd_base,
        std::uint64_t cpu_identity=0) noexcept;
    // Reuse a saved ARM64 worker, following XNU thread_set_wq_state64: replace
    // its GPR/PC/SP and reset modeled user CPSR, without reinitializing FP/NEON,
    // TLS, modeled CPU identity or PAC keys. This bounded backend admits only
    // zero CPSR/opaque input words; hardware-dependent SSBS is not modeled.
    // Same-engine, quiescent/outside-callback contract as InitializeArm64.
    // Preserves the live creator and publishes the replacement only on success.
    uc_err SetWorkqueueStateArm64(uc_engine*,std::span<const std::uint32_t>) noexcept;
    uc_err Capture(uc_engine*) noexcept;
    uc_err Restore(uc_engine*) const noexcept;
    // Execute the task-owned CLREX service instruction and preserve guest PC.
    static uc_err ClearExclusiveMonitor(uc_engine*,std::uint64_t instruction_pc) noexcept;
    bool Saved() const noexcept {return saved_;}
    uc_engine* BoundEngine() const noexcept {return engine_;}
    std::uint64_t Captures() const noexcept {return captures_;}
};
}
