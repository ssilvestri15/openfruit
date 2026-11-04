#pragma once
#include <array>
#include <cstdint>
#include <limits>
#include <vector>

namespace OpenFruit {
// Ordinary guest processes are never the kernel (0) or system init (1).
// IDs are unique across live native engines, remain positive pid_t values,
// and are not recycled by this runtime. This does not create an init process.
std::uint32_t AllocateDarwinProcessId();
// Task-lifetime identity, independent of the PID. XNU assigns p_idversion on
// process creation and retains it for an exec-copy (kern_fork.c, forkproc).
// Allocate once per new guest process, not per thread, query or exec. This
// runtime never recycles a generation; exhaustion fails instead of wrapping.
std::uint32_t AllocateDarwinProcessGeneration();
// Snapshot of the launcher's effective Windows token in the same SID realm
// used by stat64. Guest credential mutation/set-ID transitions are unavailable.
struct DarwinProcessCredentials {
    std::uint32_t uid=0,gid=0;
    std::vector<std::uint32_t> groups;
};
int CaptureDarwinProcessCredentials(DarwinProcessCredentials&);
// Source-defined non-login audit session (bsd/bsm/audit.h and audit_session.c).
// A Windows token is not a Darwin audit login session. Guest login/session
// mutation is not implemented; Main retains this snapshot for the task lifetime.
struct DarwinProcessAuditSession {
    std::uint32_t auid=std::numeric_limits<std::uint32_t>::max(),asid=0;
};
using DarwinSecurityToken=std::array<std::uint32_t,2>;
using DarwinAuditToken=std::array<std::uint32_t,8>;
// XNU kern_prot.c: set_security_token / proc_calc_audit_token. Real and effective
// credentials coincide in the immutable guest credential model. Returned values
// own their words and cannot change when another task or host token changes.
DarwinSecurityToken BuildDarwinSecurityToken(const DarwinProcessCredentials&) noexcept;
DarwinAuditToken BuildDarwinAuditToken(const DarwinProcessCredentials&,
    std::uint32_t pid,std::uint32_t generation,
    const DarwinProcessAuditSession& session={}) noexcept;
}
