# Draft: SIL init accessor mismatch under a generic superclass constraint

This is an unpublished report prepared from an OPENFRUIT-owned standalone
language reduction. No third-party or Apple SDK source is needed.

## Reproduction

Use [Probe.swift](Probe.swift) with a Windows standard library matching the
selected compiler:

```text
swiftc -typecheck Probe.swift
swiftc -emit-silgen Probe.swift -o Probe.sil
```

The first command succeeds on Swift 6.4.1. The second terminates in the SIL
verifier with its default checks enabled. No special feature or verification
flags, imports, macro plugins, package manager or Apple SDK are involved.

```text
SIL verification failed: wrong argument type of initializer or setter
```

The value passed to `assign_or_init #OwnedAccessor.value` has an optional closure
whose substituted generic signature includes `_NativeClass`; the initializer and
setter closure signatures do not include that requirement. The surrounding
initializer constrains `Value` to `OwnedProjection<Root>`. A separate owned control
without that superclass-constrained generic initializer generates SIL normally.

Expected: successful SIL generation, with the assignment value and accessor
arguments lowered to compatible types.

Observed on original Windows compilers with assertions:

- Swift 6.4-dev `bd6612707e478cc`, default verification.
- Swift 6.3.3 with its matching SDK, explicit `-Xfrontend -sil-verify-all`.
- Swift 6.4.1 release, default and explicit verification.
- Swift 6.4.4-dev `21c4f776d5fd89c`, October 17 release-branch snapshot, default verification; the installed 6.4.1 Windows standard library was accepted for this test.
- Swift 6.5-dev `f62414fd1d17227`, October 17 main snapshot, with its original paired SDK and runtime, default verification.

The 6.4/6.5 observations terminate with `0xC000001D`; 6.3.3 with explicit
verification terminates with `0x80000003`. Windows exception codes alone are not
the causal fingerprint; the verifier diagnostic and mismatched SIL signatures are.

Original snapshot installers were acquired from the links on
[Swift.org's Windows installation page](https://www.swift.org/install/windows/).
Signatures and extracted component hashes were verified. No compiler sources or
binaries were patched, and verification was never disabled.

The local diagnostic case `20261020-generic-state-sil` retains complete stderr,
compiler identities, source hashes and environment details. The real application
failure also traverses an original Apple `State` macro, but this standalone case
establishes a language-lowering failure independently of that macro path.
