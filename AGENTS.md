# AGENTS.md — OPENFRUIT

## Authority

This file defines the non-negotiable operating rules for work on OPENFRUIT.

Read, in order:

1. `AGENTS.md`
2. `docs/OBJECTIVE.md`
3. `docs/DIAGNOSTIC_PROTOCOL.md`
4. `docs/CURRENT_CHECKPOINT.md`
5. `docs/CLEAN_START.md`

The repository is the source of truth. Historical chats and logs are context only and must never override the current repository state or these files.

## Mission

OPENFRUIT is an Xcode-compatible iOS build environment for Windows.

The intended product flow is:

```text
git clone <upstream-repository>
OPENFRUIT build <project>
```

OPENFRUIT must build real upstream iOS projects without project-specific patches or modifications to upstream sources.

Core principle:

> OPENFRUIT adapts the build environment to the project.
> The project is never adapted to OPENFRUIT.

A project-specific workaround that succeeds is still an architectural failure.

## Product entrypoint

The authoritative runtime entrypoint is the native CLI:

```text
%LOCALAPPDATA%\OPENFRUIT\bin\OPENFRUIT.exe
```

`OPENFRUIT.ps1` may exist only as a thin argument-forwarding launcher to that executable. It must not contain a second build/bootstrap implementation.

Repository-local `.tools` is not part of the current architecture and must not be recreated or used by production/runtime code.

Do not implement a parallel OPENFRUIT build engine in PowerShell, Python, shell scripts, tests or compatibility helpers.

Support scripts may bootstrap, diagnose or validate the native implementation only.

## Managed state layout

Persistent installation/toolchain state belongs under:

```text
%LOCALAPPDATA%\OPENFRUIT
```

Typical managed areas include:

```text
%LOCALAPPDATA%\OPENFRUIT\bin
%LOCALAPPDATA%\OPENFRUIT\sdk
%LOCALAPPDATA%\OPENFRUIT\toolchains
%LOCALAPPDATA%\OPENFRUIT\cache
```

User configuration, credentials and user-scoped mutable state belong under:

```text
%USERPROFILE%\.OPENFRUIT
```

Do not put secrets in the repository or in clear-text generated diagnostic artifacts.

## Upstream integrity

Never modify upstream content in order to make a project build.

This includes:

* application source code;
* upstream package/dependency source code;
* dependency manifests;
* `Package.swift`;
* upstream `.xcodeproj` / `project.pbxproj`;
* upstream `.xcconfig`;
* vendored upstream libraries;
* Apple source code;
* Apple SDK contents;
* Apple framework/module metadata;
* Apple macros;
* upstream macros;
* upstream compiler plugins;
* generated upstream source.

Do not patch, rewrite, normalize or regenerate upstream files merely because OPENFRUIT cannot currently consume them.

If an upstream construct fails, fix the missing OPENFRUIT/Xcode-compatible semantic instead.

## Universal fixes only

Never introduce production behavior keyed to the identity of a specific:

* application;
* repository;
* target;
* package;
* dependency;
* framework;
* library;
* macro;
* compiler plugin.

Forbidden examples:

```cpp
if (projectName == "Nextcloud") { ... }
if (projectName == "Swiftfin") { ... }
if (targetName == "VLCUI") { ... }
if (packageName == "Firebase") { ... }
if (frameworkName == "MobileVLCKit") { ... }
if (macroName == "SomeMacro") { ... }
```

A fix is acceptable only if it implements general ecosystem semantics such as:

* Xcode;
* Swift;
* SwiftPM;
* Clang;
* CocoaPods;
* Carthage;
* XCFrameworks;
* Apple SDK/toolchain behavior;
* compiler-plugin/macro infrastructure;
* packaging/signing;
* Windows filesystem compatibility;
* another general supported build-system contract.

Real applications, packages and frameworks are regression suites for the compatibility layer, not special cases.

Their names may appear in tests, fixtures, documentation, diagnostics and logs.

Their identities must not control production behavior.

## No custom macro/plugin substitutes

Never create, replace, emulate, intercept or inject a custom macro or compiler plugin as a workaround for failure of an upstream macro/plugin.

Forbidden:

```text
upstream macro fails
→ create an OPENFRUIT macro that generates equivalent code
```

Forbidden:

```text
upstream plugin cannot execute
→ detect that plugin/package
→ manually generate its expected output
```

Forbidden:

```text
known macro/package
→ bypass original plugin execution
→ substitute OPENFRUIT-owned generated source
```

Required approach:

```text
original upstream macro/plugin fails
→ identify the missing compiler / host / runtime / IPC / build semantic
→ implement that semantic generically
→ run the original upstream macro/plugin unchanged
```

OPENFRUIT may provide generic macro/plugin infrastructure, host bridges, compatibility providers and protocol implementations.

It must not provide project- or macro-specific substitutes for upstream behavior.

Mock macros/plugins are permitted only inside isolated OPENFRUIT-owned tests when testing generic infrastructure. They must never replace an upstream component in an application build.

## Current application gate

Until changed in `docs/CURRENT_CHECKPOINT.md`, the application pipeline is:

```text
clean upstream repository
→ project discovery
→ dependency resolution
→ package build
→ Swift / Objective-C / C / C++ compilation
→ resource processing
→ link
→ bundle assembly
→ signing
→ valid signed IPA
```

Install and launch remain part of the final product objective but are temporarily outside the current diagnostic gate.

The exact currently permitted diagnostic step is defined by `docs/CURRENT_CHECKPOINT.md`.

Do not advance further in the pipeline merely because a downstream build can be attempted.

## Build-setting semantics

For every application:

* derive settings from `.pbxproj`, `.xcconfig`, schemes and selected configuration;
* derive dependency information from authoritative package/build metadata;
* keep Base SDK and Deployment Target separate;
* do not derive SDK/toolchain selection from `Info.plist`;
* preserve Swift/Objective-C runtime availability semantics;
* select XCFramework slices from platform/architecture metadata rather than names;
* propagate framework/header/library/module search paths through the real build graph;
* use preview Swift only when a preview/beta SDK actually requires it.

During one diagnosis, freeze:

* application commit;
* target/scheme;
* configuration;
* Base SDK;
* Deployment Target;
* Swift toolchain;
* architecture;
* provider configuration;
* macro/plugin concurrency.

Do not change multiple independent variables merely to make an error disappear.

## Incremental diagnostic workflow

Use the real application build as the primary integration loop:

1. run or resume the current application build;
2. stop at the first new causal failure;
3. record its stable symptom and best-supported causal hypothesis;
4. inspect the owning OPENFRUIT/Xcode-compatible contract;
5. implement only a generic fix;
6. rebuild the native `OPENFRUIT.exe`;
7. resume the same application build, reusing valid completed artifacts;
8. repeat until the application gate passes;
9. run the established reference applications as regression checks.

Warm caches and previously completed target products may be reused during this
development loop. Do not invalidate expensive unrelated work merely to obtain
a formal negative control.

Create a smaller OPENFRUIT-owned harness only when the real failure is ambiguous,
dangerous to iterate on, prohibitively slow to reach, or cannot be localized
from the production build. Baseline FAIL and repeated clean-cache PASS runs are
optional diagnostic tools, not mandatory gates.

Do not rerun the full application while the same unchanged failure remains
unexplained. After a candidate fix, however, resuming the real application
build is the normal validation path.

Stop at the first causal failure and do not fix downstream symptoms while an
earlier contract is still broken.

## Diagnostic overrides are not fixes

Manual flags, paths, copied artifacts, environment variables or injected values may be used only in a separate controlled experiment to prove causality.

They are not acceptable as the implementation.

For example:

```text
manual -F makes import succeed
```

may prove that framework-search-path propagation is missing.

It does not prove OPENFRUIT is fixed.

If OPENFRUIT is responsible for a value, the final implementation must derive and propagate it automatically from authoritative metadata.

This includes, where applicable:

* `-F`;
* `-I`;
* `-L`;
* SDK paths;
* module paths;
* plugin paths;
* target triples;
* deployment targets;
* framework products;
* XCFramework slice selection;
* linker inputs;
* generated build settings.

## Regression-test rule

A regression test is invalid if it manually injects, hardcodes, pre-resolves, pre-copies or overrides a value that the real OPENFRUIT pipeline must derive or propagate.

Examples include manual `-F` paths, SDK paths, generated module maps, dependency products, target triples, build settings, package outputs or resources when those values are part of the behavior under test.

When a focused regression harness is warranted, prefer demonstrating baseline
FAIL and candidate PASS. A second clean-cache PASS is required only when the
failure itself is cache-sensitive or the user explicitly requests release-grade
proof.

A handcrafted compiler command may be useful for causal diagnosis but is not a production-path regression proof.

## Validation levels for cross-component fixes

When a failure crosses component boundaries, use the applicable levels needed
to localize it:

```text
1. Contract test
2. Propagation test
3. Original-path reproduction test
4. Failing-module/target test
5. Full-application gate
```

A component-only pass is supporting evidence. The originally failing real path
remains the authoritative validation.

Use this progression when a focused harness is needed:

```text
contract
→ propagation
→ isolated module/target
→ integration
→ full application
```

## Cache rules

Iterative application builds may reuse a warm invocation cache and completed
target products when their correctness dimensions still match the current
build.

Cache identity must include the dimensions that affect correctness, including:

* compiler/toolchain identity;
* Base SDK;
* target/deployment target where relevant;
* configuration;
* architecture.

Do not reuse artifacts known to be corrupt, produced under incompatible build
dimensions, or belonging to the contract currently being tested.

Immutable downloads may be reused only when integrity-verified and when reuse does not bypass the behavior under test.

The originally failing target must actually be rebuilt after its owning inputs
or implementation change. Unrelated successful targets may remain warm.

Use a clean/versioned cache for a final release-grade validation when requested,
or when cache behavior is itself implicated in the failure.

## Candidate identity

Record the SHA-256 of each native candidate used for a meaningful application
iteration. Preserving a separate baseline binary is optional unless a focused
baseline comparison is required for the current diagnosis.

## Macro/plugin provider

Keep macro/plugin concurrency at:

```text
N = 2
```

unless a controlled benchmark demonstrates another value is stable and better and the checkpoint is updated accordingly.

WSL/Darling or another compatibility provider may be used only where a Darwin/Unix dependency genuinely requires it.

Main orchestration remains Windows-native.

A compatibility provider must implement generic required semantics. It must not become a place for project-, package-, macro- or plugin-specific behavior.

## Upstream cleanliness

Before a full application gate, the upstream application checkout must be clean:

```text
git status --porcelain
```

Never silently modify upstream source to make a build pass.

Do not leave diagnostic edits, generated replacements or manifest changes in the upstream checkout between gates.

## Generated state

Generated state is not source.

Do not commit accidental:

```text
.tools/
build/
.build/
root.json
logs
editor backup files
credentials
certificates
provisioning profiles
diagnostic caches
```

Do not hide an architectural regression merely by adding its output path to `.gitignore`.

If an unexpected generated path appears, determine which component created it and why.

`.tools` is intentionally not ignored so that its accidental recreation is visible.

## Git discipline

The committed clean native-v4 baseline is the recovery point.

Work incrementally from it.

Create local commits whenever a meaningful unit of diagnostic or
implementation progress has been completed and validated. Keep each commit
focused on that progress, and do not include unrelated pre-existing worktree
changes.

Do not use destructive repository-wide operations such as:

```text
git reset --hard
git clean -fdx
```

unless explicitly requested by the user with full knowledge of their effect.

A diagnostic implementation should modify the minimum OPENFRUIT-owned surface necessary to test the current causal hypothesis.

Do not mix unrelated cleanup, refactoring or speculative fixes into the same candidate.

## Checkpoint discipline

Rewrite `docs/CURRENT_CHECKPOINT.md` whenever the active causal failure materially changes.

Keep it short and reproducible rather than appending project history.

Record as applicable:

* symptom/fingerprint;
* current causal hypothesis;
* frozen environment;
* baseline hash;
* candidate hash;
* contract-test result;
* propagation-test result;
* original-path reproduction result;
* failing-module result;
* full-app result;
* valid/invalid caches;
* next permitted gate.

Do not describe already completed work as a future step.

## Stop conditions

Stop expanding scope when:

* the first causal failure has been identified;
* the requested gate has been completed;
* a candidate still requires validation;
* proceeding would require modifying upstream content;
* the proposed implementation would require a project/package-specific special case;
* the proposed implementation would replace or emulate an upstream macro/plugin;
* the test would require manually injecting the value whose propagation is under test.

Report the causal finding and smallest permitted next experiment instead.

## Native Darwin subsystem agents

For authorized Darwin work, use the native Codex subsystem roles in `.codex/agents/`
and the ownership/integration protocol in `docs/DARWIN_MULTI_AGENT.md`.
`docs/DARWIN_SUBSYSTEM_OWNERS.json` assigns modules and ledger contracts;
`docs/DARWIN_AGENT_RESULT.schema.json` defines compact result and error artifacts.
Main owns shared runtime glue, catalog, ledger, CMake, diagnostic checkpoint,
candidate installation, global tests and original Apple probes. Workers propose
ledger updates and shared-file changes to Main; they never edit them concurrently.
Respect the actual session concurrency limit; schedule roles in waves as needed.
Do not launch simulated agents or competing builds in the same output directory.
New module files and cross-owner interfaces require Main assignment before edits.
All existing integrity, honest capability, evidence and whole-objective rules apply.

## Definition of fixed

A failure is not fixed merely because:

* a helper passes;
* a handcrafted compiler command succeeds;
* a module works with manually supplied flags;
* an upstream file was modified;
* a custom macro/plugin reproduces expected generated code;
* a special-case branch makes one application compile;
* the symptom disappears under another SDK/toolchain;
* a warm cache succeeds.

It is fixed only when the original causal path passes through the real OPENFRUIT
pipeline under the frozen build dimensions, using a generic OPENFRUIT-owned
implementation and without modifying or substituting upstream behavior. Warm
unrelated artifacts do not invalidate that result when the formerly failing
target was rebuilt.
