# CURRENT CHECKPOINT

## State — 2026-11-04

Application gate (clean upstream → valid signed IPA) PASS, iOS only (watchOS
and visionOS targets/assets are out of scope by user decision):

| Application | Upstream | Selection | Result |
| --- | --- | --- | --- |
| Delta | `rileytestut/Delta` 8d76891 | `Delta.xcworkspace --scheme Delta`, Debug, SDK 27.2 | signed IPA; installs, runs, alternate icons work |
| VLC | `videolan/vlc-ios` ace696892 | `VLC.xcworkspace --scheme VLC-iOS-no-watch`, Debug, SDK 27.2, iOS 15.0 | signed IPA; installs and launches |
| Swiftfin | 024a6f1 | `Swiftfin.xcodeproj --scheme Swiftfin`, Debug, SDK 27.2, iOS 18.6 | signed IPA on 2026-11-04 (328 s warm) with its Icon Composer primary and alternate icons (`1daef03`); before it, .icon documents were not compiled (copied as loose files) |
| CampUS | — | clean-install run | signed IPA (`--rebind-bundle-id`) |
| Nextcloud | `nextcloud/ios` 184cf38893 | `Nextcloud.xcodeproj --scheme Nextcloud`, Debug, SDK 27.2, iOS 17.0 | signed IPA after a from-scratch install (cold 41 min, warm 3 min); `verify`: no integrity issue |

Common frozen dimensions: arm64, Swift 6.4.1 NoAsserts (selected automatically
from the original ToolchainInfo.plist), native macro provider N=2 with a warm
broker pool, `--rebind-bundle-id` for the development profile.

Device (outside the formal gate, user-requested): iPhone18,3, iOS 27.0.1.
`openfruit device install` installs natively (lockdown/service TLS, AFC,
installation_proxy) without pymobiledevice3.

Installed candidate (`1daef03`, 98 native tests):
`3780fcf6ada9639126140f7c6d97f1ff2b01d06b55103fb6aa02cce36913d59b`.
Regression on 2026-11-04, signed IPA each, upstream checkouts clean: CampUS
985 s and Delta 1786 s (cold, earlier candidate); VLC 290 s and Delta 1360 s
on `ed7f35d4` (`68f1fdb` plus the since-removed manifest runner); Swiftfin
328 s on the installed candidate. VLC had
regressed with compilation caching: its Swift 4 VLC-ShareExtension imported
the SDK Clang modules through Swift 4 API notes under explicit modules;
`68f1fdb` applies swift-build's rule (no explicit modules or caching below
Swift 5 or with C++ interop). Runtimes for a new deployment target reuse the
authenticated originals of an earlier one (`19fffde`: 160 s -> 0.5 s).
Since the Nextcloud gate: missing bundle resources fail like Xcode
(`795ff21`); package contexts are keyed only by code that runs inside a
compile (`589862c`); warm builds reuse file digests, skip rereading
unchanged source views, project checkouts concurrently and skip SwiftPM
only when its inputs are unchanged (`934650b`..`714b750`). Nextcloud warm
build: 39 s (was 287 s): no receipt rewrites or Git metadata churn
(`0490306`), no Swift driver for an up-to-date target (`38e838f`), no
linker for an up-to-date link (`-dependency_info`, `cfbe26d`), concurrent
source view inventory (`b3916a9`, `d4bd0ff`: toolstate 28 s -> 9 s), the
official dependency graph reused while its inputs are unchanged
(`cee9d30`; the first two builds after an OpenFruit update still query it),
a regex-free SDK import scan (`fde9e15`), and signature-slack and IPA
writing that read each byte once at most (`38de1b4`, `51336de`).
An edit to one shared Swift file recompiles that file and relinks only the
targets whose object changed; the checkout stays clean. Unsigned embedded
frameworks are sealed through the signing junction again (`029311c`).
Remaining warm cost: SwiftPM workspace verification ~15 s (toolstate
inventory and verification ~9 s, checkouts ~3 s), resources and embedding
~9 s, two zsign passes ~4 s. `console_cancellation_tests` fails only when
ctest is started from the Git Bash tool (console attachment); it passes
from PowerShell. A failed
SwiftPM run is no longer accepted from old products (`779fd87`). Pruning of superseded package contexts
(`df15d04`) has not yet run on a build that supersedes one.

The inherited manifest runner (committed as `c4f9ba6`) is removed again: it
only appended a fixed `-context` when SwiftPM passed none, and SwiftPM
6.2/6.3/main always pass `-context` after `-handle` when they run a compiled
manifest, so the injected value never took effect. It stays on branch
`wip/manifest-runner`.

## Next permitted gate

Regression of Nextcloud, CampUS, Delta and VLC on the installed `1daef03`
candidate (Swiftfin passed on it), then device install/launch.

## Open findings

- The GitHub release run of `0.1.0-dev` failed 8 native tests (the runner's
  TEMP is the 8.3 name `C:\Users\RUNNER~1`); fixed in `4b57f81` (long paths
  in source view copies), `4206d69` (SDK cleanup deleted a registered
  quarantine spelled through an alias) and `4f8c6e3` (test fixtures and
  skips). With a managed Swift installed, four tests still fail when TEMP is
  a junction (`swiftpm_source_workspace`, `swift_host_environment`,
  `cache_read_operations`; junctions are refused by design, an 8.3 name is
  not a junction) or about 46 characters long (`swiftpm_manifest_integrity`,
  `swiftpm_source_workspace`, `swift_host_environment`). On a machine without
  Swift they skip; the long-path cases are not diagnosed yet.
- One Swiftfin emit-module run failed with "failed to receive result from
  plugin" on loadPluginLibrary; not reproduced since. On recurrence inspect
  `diagnostics/macro-runtime/sessions.jsonl` and `workers.log` before changing
  the provider.
- Cold or changed macro expansions run sequentially at ~200 ms each under
  emulation; the commpage MEM_READ hooks cost ~20% but carry the timebase
  update and unsupported-field checks.
- `Internal Error: DecodingError ... unexpected end of file` (~3 per frontend)
  is the project's pinned swift-syntax decoding a benign zero-length
  end-of-session frame; a relay would intercept upstream plugins, so not done.
- The package context key covers the compile-time link closure (1695
  inputs). Warm adoption reuses a completed context with equal dimensions;
  SwiftPM then rebuilds only what its own incremental state finds changed.
- Compilation caching is on for application and package Swift modules
  (`ea93b6d`, `451aaca`): explicit modules and a shared CAS, each Swift
  driver scanning in a module cache of its own (shared scanning caches made
  SDK modules appear as conflicting variants). Nextcloud: clean app rebuild
  175 s instead of 634 s; all package Swift modules rebuilt explicitly in
  765 s. Not for Clang: `-fdepscan` aborts with implicit modules
  (`-fmodules`, which SwiftPM passes). Prefix maps do not work for Swift
  inputs with this toolchain on Windows (the frontend opens the remapped
  path), so CAS reuse needs an unchanged build location.
- The first build after a SwiftPM run rehashes the ~37k artifact files that
  SwiftPM rewrote (about 60 s); later builds do not.
- Nextcloud launch needs the app group `group.it.twsweb.Crypto-Cloud`
  (Brand/NCBrand.swift), which only Nextcloud's team can provision; with
  another team the app aborts in Realm. The build gate is unaffected.
- Nextcloud's seven app extensions are stripped at signing: the single
  development profile (`dev.openios.hello`) does not authorize their IDs.
- There is no separate `sign` command (it was listed in the help without an
  implementation and is removed); signing runs inside `build`.
- Package resources other than `.xcstrings` that SwiftPM leaves unhandled
  (for example CodeScanner's `Assets.xcassets`) are not yet built.
- Delta's Harmony submodule `Misc.` directory checks out as `Misc` on Windows
  (submodule reports modified); it does not affect the build.
- Unmodeled Darwin kernel paths stop the macro runtime with a named reason
  (unsupported kevent filter, workloop command, kqueue fd); none is hit by the
  reference applications.

## Valid state

Keep valid downloads, resolver state and warm caches; native cache identity
(triple, SDK + SDKSettings hash, configuration, Swift version, frontend
SHA-256) selects compatible execution products. Do not rewrite upstream
package or application sources.

Notes: tools run inside the Claude desktop app see a virtualized
%LOCALAPPDATA%; installs and builds for validation must run from a real
terminal. History of how each gate was reached lives in the commit log.
