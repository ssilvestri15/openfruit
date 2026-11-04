# Darwin subsystem coordination

Main maintains the global catalog, dependencies, file ownership, shared interfaces,
ledger, crash diagnosis and native integration. Specialists use native Codex
subagents. The project TOML roles follow the
[official custom-agent format](https://learn.chatgpt.com/docs/agent-configuration/subagents).
Roles inherit session model and permissions. Project files do not raise the host's
actual concurrency limit: this session has Main plus three simultaneous workers.

The authoritative ownership manifest is `DARWIN_SUBSYSTEM_OWNERS.json`.
`darwin_arm64.cpp` is shared runtime glue with a single Main writer; no concurrent
worker edits are allowed. The present IPC/task state lives there, so IPC changes
are submitted as precise integration proposals until a necessary module boundary
is explicitly assigned. Objective-C and Swift execute in original guest libraries:
missing host dependencies must be identified before any bridge implementation.
No surrogate runtime, extra loader, or broad speculative extraction is permitted.

## Dependency scheduling

1. pthread lifecycle/TLS/synchronization, VM lifetimes and IPC/port contracts form
   the first workgroup. Cross-references are runtime prerequisites, not a promise
   that any entire subsystem can finish independently.
2. VFS audits run against those mappings and native descriptors; Objective-C and
   Swift/transport specialists identify original initialization/transport host
   contracts using dependency/reachability evidence rather than all imported names.
3. Main resolves cyclic IPC/thread ownership at existing task interfaces and
   assigns bounded batches. Declaration/catalog enumeration alone never creates
   an implementation obligation for guest-provided exports.

Main assigns exact contract IDs, scope, writable files, expected test target and
upstream evidence at dispatch. A specialist reports cross-owner dependencies
before implementing that portion. Results use `DARWIN_AGENT_RESULT.schema.json`;
ledger updates are proposals carrying exact scope and artifacts, merged only by
Main after tests and original-path classification. No two writers edit the ledger.
Agent result artifacts go under the user diagnostic root, never in source.

## Build and integration protocol

Only Main configures, builds, installs or invokes CTest in the shared native build
tree. Workers may prepare tests, and request a module test run; Main runs it and
returns the concrete log/hash. An isolated build is permitted only when Main
explicitly assigns its output directory. Tests that use Windows/Unicorn must use
the existing native dependency chain. No Python or shell simulation establishes
runtime semantic correctness.

For each completed bounded group Main reviews changes, integrates existing native
interfaces, executes ABI/behavior/error tests and relevant integration consumers,
records candidate SHA256, installs through the native build, and probes the original
Apple binary. Unsupported behavior stays an explicit failure. Original single-
thread startup cannot prove peer lifecycle or full plugin execution. Main refreshes
the existing ledger/progress webpage without rebinding historical proofs.

## Error attribution

Errors include stop reason, signed selector/domain, candidate/probe hash, localized
contract IDs, owner candidates and evidence confidence. Static selector ownership
is a routing hint; crash PC, memory fault or terminal BSD abort is not necessarily
the root cause. Main reviews earliest causal failure and joins exact native static
sites/traces before assigning correction. Unknown selector/indirect transfers stay
unknown. Shared ABI/clock/loader failures belong to Main until a narrower contract
is proven. Main sends the responsible native subagent a follow-up task with the
reproduction and evidence; a JSON routing report never launches agents itself.

Completion is limited to the exact assigned and tested scope. Unit tests do not
prove original plugin startup or the whole architecture. Final quality review
remains required only after the full architecture objective is achieved.

## First integrated workgroup

The 2026-10-10 workgroup ran all six native roles. Main accepted scoped VM,
BSD, IPC and pthread preparation changes after 56 native tests and 34 diagnostic
tests passed. The installed original probe retained its honest pthread capability
stop. Objective-C and Swift delivered dependency/source audits; their original
initialization and handshake are still missing. Six schema-validated result files,
failed attempts, candidate/source hashes and original proofs are retained in the
user diagnostic `darwin-subsystems-20261010` directory. The source ledger holds
reviewed scopes; accepted proof artifacts stay outside Git. Routing is projected
into the existing progress JSON/page, not a new runtime or agent launcher.

Next assignment is the complete pthread registration capability dependency group;
VFS pipe/dup semantics are the source-backed transport group that can proceed once
Main freezes its existing module interface. Cross-owner waits/port allocation are
reviewed by Main before implementation. No feature mask is published merely
because a preparation helper or isolated owned test succeeds.

## Macro-runtime workflow (2026-10-11)

The native macro path complements the full architecture plan; its bounded scope is defined in
`docs/OBJECTIVE.md`. Main (Codex) coordinates native Codex subagents.
The six Darwin roles above are recreated with identical instructions and
ownership; three roles are added for the new independent activities:

| Activity | Role | Writable scope (unless Main assigns more) |
|---|---|---|
| 1. Macro Dependency Audit | `macro_audit` | `docs/MACRO_COMPATIBILITY_INVENTORY.json`, `docs/MACRO_COMPATIBILITY.md`, diagnostic root |
| 2. Native Windows Macro Host | `windows_macro_host` | `native/macro-host/**`, `openfruit/windows/src/macro_engine.*`, its tests, diagnostic root |
| 3. Apple Darwin Runtime (MVMR closure) | the six `darwin_*` roles, led by `darwin_swift_transport` for closure analysis | existing ownership |
| 4. Build Integration | `build_integration` | diagnostic root measurements; source edits only by Main assignment |

Every role must prove its subsystem without launching the whole
`swift-plugin-server` (contract harness, owned guest ARM64 consumers, real
compiler-plugin protocol tests). The original Apple probe is a periodic
integration check, not the discovery mechanism. Main compares the Windows-native
and Darwin paths through reproducible experiments, never hypotheses. No new
generic Darwin syscall is implemented without a demonstrated macro requirement.

Crash routing reports carry: contract, observed error, diagnostic evidence,
probable owner, dependencies. The stop point is distinguished from the root
cause. Progress uses the four contract levels (catalogued / implemented / tested
/ verified-on-Apple) with explicit denominators.
