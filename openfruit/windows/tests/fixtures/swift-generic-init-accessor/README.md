# Generic init accessor compiler probe

This owned Swift language fixture reduces the SIL verification failure observed
while compiling original RealmSwift under SDK 27. It uses no Apple SDK, imports,
macros, Realm code or OPENFRUIT compiler proxy. It never replaces a macro in an
application build.

Run the selected compiler with `-emit-silgen Probe.swift -o <owned-output.sil>`.
Keep SIL verification enabled. Compiler/stdlib SDK matching is a prerequisite;
a failure to import a mismatched Windows standard library does not test this bug.

Observed baseline: Windows Swift 6.4-dev, commit `bd6612707e478cc`, exits with
`0xC000001D` and `SIL verification failed: wrong argument type of initializer or
setter`. The optional closure argument's substituted generic signature gains
`_NativeClass` in the superclass-constrained initializer, while the accessor
signature does not.

The separate owned native project using the original Apple `State` macro also
reproduces this fingerprint. The pure language fixture isolates compiler lowering;
it does not prove target ABI correctness or full application compatibility.
Evidence: user diagnostics `architecture-completion/20261020-generic-state-sil/`.

| Original Windows compiler | Verification mode | Observed result |
|---|---|---|
| 6.4-dev `bd6612707e478cc` | Default | Same SIL failure, `0xC000001D` |
| 6.3.3, matching Windows SDK | Explicit `-Xfrontend -sil-verify-all` | Same SIL failure, `0x80000003` |
| 6.4.1 release, matching registered Windows SDK | Default | Same SIL failure, `0xC000001D` |
| 6.4.1 release, matching registered Windows SDK | Explicit `-Xfrontend -sil-verify-all` | Same SIL failure, `0xC000001D` |
| 6.4.4-dev `21c4f776d5fd89c`, official October 17 release-branch snapshot, host SDK 6.4.1 | Default | Same SIL failure, `0xC000001D` |
| 6.5-dev `f62414fd1d17227`, official October 17 main snapshot, its original paired host SDK/runtime | Default | Same SIL failure, `0xC000001D` |

The initial 6.3.3 and 6.4.1 attempts inherited a mismatched/deleted Windows SDK
from the parent process and failed before SIL generation. They are not compiler
bug comparisons. The valid host-only probes use the corresponding installed
Windows standard library; this is not a manual Apple target propagation fix.

The 6.4.1 default-mode evidence is
`pure-init-accessor-641-default-result.json`, with separate stdout/stderr logs.
It rules out the additional verifier flag as the cause of this reproduction.
No fixed compiler version is established. Do not add this known external failure
as a required passing native CTest or weaken verification to make it pass.

Additional controls on 6.4.1: the unchanged fixture passes `-typecheck`; a separate
owned control that removes the superclass-constrained generic initializer passes
SIL generation. The control is diagnostic evidence, never a source rewrite for an
upstream build. `compiler-trigger-controls.json` records both commands and hashes.

The 6.5 initial attempt failed to launch without its paired SxS runtime, then
rejected the older Windows standard library. Neither counts as a SIL comparison.
After original runtime assemblies and the paired SDK were extracted without
executing the installer, `pure-init-accessor-main-paired-result.json` records the
actual same verifier failure. Runtime assemblies used an isolated private SxS
layout; no system registration or production toolchain selection changed.

Snapshot signatures were valid Apple signatures and extracted package/container
digests matched their authenticated bundle manifests. Neither snapshot was adopted.
Both temporary download/expanded trees were removed after confirming no live
snapshot processes; logs, manifests, hashes and results remain in the evidence
case. Installed CLI and Swift 6.4.1 hashes are unchanged by that bounded cleanup.
See [the prepared upstream report](BUG_REPORT.md); it has not been published.
