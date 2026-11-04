# Mutable subscript reads inside a captured parameter-pack expansion

OPENFRUIT-owned compiler capability fixture, independent of any upstream package,
SDK, Foundation or macro implementation. It reproduces the SILGen lvalue assert
seen while compiling a real package in Swiftfin's dependency graph.

Build in the matching Windows Swift host SDK/runtime environment:

```
swiftc -swift-version 5 PackLValue.swift main.swift -o PackLValue.exe
PackLValue.exe
```

Verified 2026-10-29:

- Official Windows Swift 6.4.1+Asserts: C++ assert in SILGenExpr.cpp:7609,
  `l-values must be emitted with emitLValue` (exit 0xC000001D).
- Official Windows Swift 6.4.1+NoAsserts: compile and runtime PASS. Runtime checks
  cover heterogeneous values, reads after mutating the backing keys, nested
  function captures and an empty pack.
- Swift 6 language mode and disabling SIL opaque values did not fix the Asserts
  compiler; official Windows 6.3.3+Asserts also reproduced the failure. These were
  controlled diagnostics, not production configuration changes.

The same integrity-verified Swift 6.4.1 installer contains both variants. Adding
its NoAsserts component does not require compiler rebuilding or binary patches.
This fixture is supporting compiler evidence; the real native Swiftfin build
remains the authoritative application validation.
