# OPENFRUIT — Project Objective

## Product vision

OPENFRUIT aims to provide an **Xcode-compatible iOS build environment that runs natively on Windows**.

A developer should be able to take a normal upstream iOS repository and, as far as technically possible, use the flow:

```text
git clone <upstream-repository>
OPENFRUIT build <project>
```

with OPENFRUIT handling:

```text
repository/project discovery
→ Xcode/workspace/SwiftPM interpretation
→ build-setting evaluation
→ dependency resolution
→ build graph construction
→ Swift / Objective-C / C / C++ compilation
→ Xcode build phases
→ resource processing
→ Mach-O link
→ app/framework/extension assembly
→ provisioning/signing
→ IPA
→ install / launch / debug
```

The upstream project must not need to be designed for Windows.

## Fundamental compatibility principle

OPENFRUIT implements general ecosystem semantics, never project-specific compatibility hacks.

Forbidden as compatibility mechanisms:

- modifying application sources;
- modifying package/dependency sources;
- modifying Apple sources or macros;
- dependency forks maintained only for OPENFRUIT;
- application-name conditionals;
- package-name conditionals;
- OPENFRUIT-only per-project configuration required for one upstream application.

Reference applications are regression suites for the compatibility layer.

## Reference matrix

The first major compatibility matrix is:

```text
CampUS
IceCubesApp
Swiftfin
Nextcloud
```

The current intermediate application gate is a valid signed IPA. Install/launch/debug remain part of the final product objective.

## Architecture boundary

The public product entrypoint is the native Windows CLI under `%LOCALAPPDATA%\OPENFRUIT\bin\OPENFRUIT.exe`.

Persistent SDK/toolchain installation belongs under `%LOCALAPPDATA%\OPENFRUIT`; user configuration and user-scoped mutable state belong under `%USERPROFILE%\.OPENFRUIT`.

Repository-local `.tools` is not part of the current architecture.

The repository itself should contain source, tests, controlled fixtures, compatibility metadata, documentation and build scripts — not downloaded SDKs/toolchains, user credentials, mutable dependency caches or generated application/build state.

## Xcode semantic goals

OPENFRUIT should reproduce the relevant behavior of Xcode rather than merely make selected applications compile. In particular it must preserve the distinction and propagation of:

- Base SDK;
- Deployment Target;
- selected configuration;
- target architecture;
- `.pbxproj` settings;
- `.xcconfig` inheritance;
- schemes/targets;
- SwiftPM dependency/product relationships;
- binary framework/XCFramework selection;
- framework/library/header search paths;
- generated modules/resources;
- build phases;
- code signing/provisioning.

Compatibility fixes must repair these generic contracts at the correct owning layer.

## Native Windows macro execution path (2026-10-11)

The full architecture plan and original Apple binary gates remain required.
The native macro path contributes to a **fully
Windows-native iOS build without WSL**, supporting as many Swift macros of the
ecosystem as possible: Apple SDK macros, custom project macros, third-party
compiler plugins and, where possible, precompiled macOS (Mach-O) plugins.
Nextcloud is a validation project, not the limit of compatibility.

Guiding question:

> What is the minimum set of Apple components that must really execute to
> support the largest possible set of Swift macros?

The answer is the **Minimum Viable Macro Runtime (MVMR)**: minimize Darwin
dependence without needlessly sacrificing general compatibility.

Execution preference for every compiler plugin, in order:

1. **Windows-native macro host** — plugin built from source with the exact
   Windows Swift/SwiftSyntax compatible with the selected toolchain and served
   through the real compiler-plugin protocol to `swift-frontend`.
2. **Darwin Compatibility Host** — original Mach-O plugin executed by the
   existing OPENFRUIT runtime (Mach-O loader, original dyld, ipsw, Unicorn
   ARM64, PAC, pthread/TLS, scheduler, Mach IPC, VM) only when (1) is not
   technically possible (e.g. closed-source Apple plugins).
3. **Unsupported** — explicit, diagnosed failure. Never a substitute expansion.

The Darwin runtime is preserved and extended in a targeted way; it is not
abandoned or rewritten, and new generic syscalls are implemented only when a
concrete macro-compatibility requirement (or its prerequisite) is shown.

### Macro compatibility inventory

Each analyzed macro/plugin records: package and version, implementation module,
Swift and SwiftSyntax versions, host dependencies, source availability,
possible execution mode (Windows-native / Darwin Compatibility Host / not yet
supported), residual Darwin contracts, status and proof. Compatibility is
proven only by real expansions, not by compilation or plugin startup. The
inventory grows over time and never claims completeness it does not have.

### Contract progress levels (AnyPS5 model)

Every Darwin contract carries four independent levels, never conflated with
dispatcher registration:

| Level | Condition |
|---|---|
| 1. Catalogued | The contract exists in the analyzed Apple version |
| 2. Implemented | OPENFRUIT contains a real implementation, not a stub |
| 3. Tested | A targeted suite passes with reproducible evidence |
| 4. Verified on Apple | Exercised correctly on the observed original Apple path |

The progress page shows separately: Darwin contract coverage, Swift macro
compatibility, compiler-plugin compatibility, Swift-version support, Windows
macro host progress, Darwin Compatibility Host progress and fully-native iOS
pipeline status. Every percentage has an explicit denominator; catalogue
coverage is never presented as global Darwin completion.

### Success criteria

1. First milestone: at least one real Swift macro expanded correctly on Windows
   without WSL (native path, or Darwin runtime when required).
2. Extend to the main macro categories (freestanding expression/declaration,
   attached peer/member/memberAttribute/accessor/extension/body/preamble).
3. Verify real third-party compiler plugins.
4. Progressively support more packages and Swift versions.
5. Execute original Mach-O plugins when no native path exists and the Darwin
   runtime allows it.
6. Integrate both paths in the OPENFRUIT C++ pipeline.
7. A reproducible iOS build entirely on Windows, without WSL.

Nextcloud success is an important end-to-end proof but does not exhaust the
general compatibility objective.
