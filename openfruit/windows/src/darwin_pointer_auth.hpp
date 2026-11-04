#pragma once
#include <unicorn/unicorn.h>
#include <cstdint>
#include <array>

namespace OpenFruit {
// Same-task function-key authentication, discriminator zero. Must run outside
// uc_emu_start/callbacks at task-owned AUTIA X0,X1 and PACIA X0,X1 instructions.
// Preserves the entire creator CPU context. Never strips PAC or publishes an
// output after failure. With task IA disabled, returns the unmodified input;
// that identity operation does not validate a signature. Never changes IB.
// This is not registration or capability publication.
uc_err AuthenticateDarwinFunctionPointer(uc_engine*,std::uint64_t authenticate_pc,
    std::uint64_t sign_pc,std::uint64_t input,std::uint64_t& output) noexcept;
// XNU BSD366 shim conversion of the two user function pointers. NOJOP returns
// the identical pair. Enabled-JOP uses the existing non-FPAC AUT backend.
// Key A / discriminator0 retains poison; conversion
// success does not certify either signature. A poisoned pointer faults only
// when consumed. Preserves complete creator CPU and output on backend failure.
uc_err ConvertDarwinFunctionPointersFromUser(uc_engine*,std::uint64_t authenticate_pc,
    const std::array<std::uint64_t,2>& input,std::array<std::uint64_t,2>& output) noexcept;
// XNU same-task ARM_THREAD_STATE64 conversion, creation TSSF_NONE. NOJOP
// preserves every pointer bit and emits representation NO_PTRAUTH flags=1;
// the context consumer must consume those flags separately from guest PSTATE.
// Uses task-owned AUTIA/AUTDA/XPACI, preserves creator CPU, and retains actual
// architectural authentication poison for the eventual guest consumer to fault.
// No PC/SP mapping/alignment precheck; this is not generic set-state/signals.
uc_err ConvertDarwinThreadStateArm64(uc_engine*,std::uint64_t auth_code_pc,
    std::uint64_t auth_data_pc,std::uint64_t strip_code_pc,
    const std::array<std::uint32_t,68>& input,std::array<std::uint32_t,68>& output) noexcept;
}
