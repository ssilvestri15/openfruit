# OPENFRUIT — Diagnostic Protocol

## 0. Freeze the environment

Before diagnosing a failure, record:

```text
application
commit
target/scheme
configuration
architecture
base_sdk
deployment_target
swift_toolchain
candidate_hash
baseline_hash
jobs
macro_plugin_jobs
cache_schema/cache_root
```

Do not change these values during one diagnosis unless evidence shows one of them is itself the bug. If a material variable changes, start a new checkpoint.

## 1. First causal failure

Identify the earliest failure that actually blocks progress. Ignore repeated diagnostics from parallel jobs, downstream consequences, warnings and failures OPENFRUIT already recovered from.

Record both:

### Symptom fingerprint

A stable description of what was observed.

### Causal fingerprint

The currently proven or best-supported broken producer/consumer contract.

Do not confuse the symptom with proof of root cause.

## 2. Choose the validation path

Prefer the real application or target path that exposed the failure. Reuse
valid completed targets and caches during iterative development.

Use a smaller harness when the production failure is ambiguous, dangerous,
prohibitively slow to reach, or cannot otherwise be localized. The harness must
still cross the original production contract.

A test is invalid if it manually supplies the exact value OPENFRUIT is expected to derive or propagate.

For example, if the bug is framework-search-path propagation, manually passing `-F` is not a valid regression test.

## 3. Optional baseline negative control

Use a baseline/reference implementation when the causal claim needs an explicit
negative control or when cache-sensitive behavior is being investigated.

If the baseline passes, the harness does not prove the candidate fix.

## 4. Candidate verification

After a generic fix, rebuild the native CLI and resume the originally failing
real target. The formerly failing target must be rebuilt; unrelated completed
targets may remain warm. Repeat with a clean cache only when cache behavior is
part of the failure or release-grade proof is explicitly requested.

## 5. Propagation gate

For a cross-component fix, verify that the producer's result reaches the real consumer automatically.

Do not stop at a helper/unit-level pass.

## 6. Failing module/target gate

Build the originally failing module/target through the real OPENFRUIT path.

After this passes, resume the full application build from its valid completed
artifacts.

## 7. Full application gate

Use a pristine upstream checkout. A warm cache is permitted for iterative
application progress; use a clean/versioned cache when requested for final
release-grade validation or when cache correctness is in question.

The current global application gate is:

```text
SIGNED IPA
```

## 8. Cache policy

Persistent managed installation under `%LOCALAPPDATA%\OPENFRUIT` is not itself diagnostic state.

Diagnostic/application invocation caches must be isolated and versioned. Failed or uncertain caches must not be reused as proof.

Repository-local `.tools` must not be used or recreated.

## 9. Checkpoint update

When the first causal failure changes, rewrite `docs/CURRENT_CHECKPOINT.md` with the new reproducible state. Historical logs belong elsewhere; do not turn the checkpoint into an append-only diary.

For native Darwin runtime work, also retain a `runtime report-progress` snapshot
from the existing static inventory, original probe/command identity and scoped
contract ledger. Attach tested-candidate evidence, preserve previous snapshots and
compare contract changes and verification regressions. Do not equate registered
handlers, import symbols, mapped images or instruction counts with complete runtime
coverage. The total contract count remains unknown; no global percentage is valid.
See [DARWIN_RUNTIME_PROGRESS.md](DARWIN_RUNTIME_PROGRESS.md).
