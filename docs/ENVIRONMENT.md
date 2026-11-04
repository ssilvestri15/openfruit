# Environment variables

OPENFRUIT is configured by `%USERPROFILE%\.OPENFRUIT\config.toml` and
`openfruit config`. The variables below override or tune it; most users need
none of them. Variables in the last section are set by OPENFRUIT for its own
child processes and must not be set by hand.

## Location overrides

Each one replaces a path OPENFRUIT otherwise derives. `config.cpp` exports the
configured values under the same names to child processes.

| Variable | Overrides |
| --- | --- |
| `OPENFRUIT_HOME` | managed installation root (default `%LOCALAPPDATA%\OPENFRUIT`) |
| `OPENFRUIT_USER_STATE` | user state root (default `%USERPROFILE%\.OPENFRUIT`) |
| `OPENFRUIT_CACHE_ROOT` | cache root (default `<home>\cache`) |
| `OPENFRUIT_ROOT` | OPENFRUIT source checkout used by `system_info` |
| `OPENFRUIT_IOS_SDK` | iPhoneOS SDK directory |
| `OPENFRUIT_XCODE_PATH` | Xcode archive/installation used for SDK and runtime extraction |
| `OPENFRUIT_SWIFT_BIN` | Swift toolchain `usr\bin` (otherwise selected from the SDK; NoAsserts preferred) |
| `OPENFRUIT_LLVM_BIN` | LLVM `bin` (clang, lld, llvm tools) |
| `OPENFRUIT_LD64` | Mach-O linker used by package builds |
| `OPENFRUIT_APPLE_LINKER` | Apple-compatible linker the compiler proxy forwards to |
| `OPENFRUIT_ZSIGN` | zsign executable used for signing |
| `OPENFRUIT_PYMOBILEDEVICE3` | pymobiledevice3 used by `openfruit deploy` (`openfruit device install` is native) |
| `OPENFRUIT_IPSW` | ipsw tool |
| `OPENFRUIT_DARLING_TOOLS` | Darling tools directory for the compatibility provider |
| `OPENFRUIT_WSL_DISTRO` | WSL distribution used by the compatibility provider |

## Tuning and diagnostics

| Variable | Effect |
| --- | --- |
| `OPENFRUIT_MACRO_POOL_SIZE` | warm original macro servers per broker (default 4) |
| `OPENFRUIT_MACRO_BROKER_IDLE_SECONDS` | idle time before a persistent broker exits (default 900) |
| `OPENFRUIT_MACRO_PREWARM=0` | do not pre-warm the macro broker before a build |
| `OPENFRUIT_MACRO_EXPANSION_CACHE=0` | disable the original-expansion response cache |
| `OPENFRUIT_MACRO_TRACE_DIR` | directory for macro bridge request traces |
| `OPENFRUIT_APPLE_PLUGIN_SERVER_POOL_SIZE` | macro bridge plugin servers (default 2, 1–8) |
| `OPENFRUIT_APPLE_PLUGIN_SERVER_QUEUE_TIMEOUT_MS` | wait for a free plugin server (default 600000) |
| `OPENFRUIT_APPLE_PLUGIN_SERVER_RESPONSE_TIMEOUT_MS` | wait for a plugin response (default 120000) |
| `OPENFRUIT_APPLE_PLUGIN_SERVER_RETRIES` | plugin request attempts (default 3, 1–8) |
| `OPENFRUIT_DISABLE_APPLE_PLUGIN_SERVER=1` | macro bridge loads plugins without the Apple plugin server |
| `OPENFRUIT_COMPILER_PROXY_TRACE=1` | compiler proxy reports the compatibility decisions it makes (header modules, include roots) |
| `OPENFRUIT_APPLE_HOST_PROBE_PAUSE` | Apple plugin host pauses 60 s at start (debugger attach) |

## Internal (set by OPENFRUIT)

These carry the build context from the orchestrator to the compiler proxy,
SwiftPM, macro hosts and build-phase scripts. Their values are derived from
the build; setting them manually is a diagnostic override, not a fix.

- Event journal: `OPENFRUIT_EVENT_DIRECTORY`, `OPENFRUIT_EVENT_BUILD_ID`,
  `OPENFRUIT_EVENT_PARENT_SPAN`.
- Compiler proxy: `OPENFRUIT_COMPILER_PROXY_REAL`,
  `OPENFRUIT_COMPILER_PROXY_IDENTITY`, `OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL`,
  `OPENFRUIT_SWIFT_MANIFEST_SDK`, `OPENFRUIT_SWIFT_TARGET_PROXY_REAL`,
  `OPENFRUIT_COMPILER_SYMLINK_MAP`, `OPENFRUIT_COMPILER_STRING_MACROS`,
  `OPENFRUIT_COMPILER_OBJC_STRING_MACROS`,
  `OPENFRUIT_SWIFT_IMPORT_RECOVERY_ROOT`, `OPENFRUIT_SWIFT_IMPORT_RECOVERY_GRAPH`.
- Compatibility-provider fallback (cleared on the native package path):
  `OPENFRUIT_SWIFT_FALLBACK_BIN`, `_PREBUILT`, `_MODULE_CACHE`, `_SDK`,
  `_RESOURCE_DIR`, `_PLUGIN_SERVER`, `OPENFRUIT_USE_APPLE_PLUGIN_SERVER`.
- Macro runtime: `OPENFRUIT_DARWIN_MACRO_PROVIDER`,
  `OPENFRUIT_DARWIN_MACRO_MODULES`, `OPENFRUIT_MACRO_HOST_ROLE`,
  `OPENFRUIT_MACRO_BROKER_PIPE`, `OPENFRUIT_MACRO_BROKER_SCOPE`,
  `OPENFRUIT_DARLING_BUNDLE`, `OPENFRUIT_DARLING_PREFIX`,
  `OPENFRUIT_OWNED_PROVIDER_LOG`.
- Host tools for build phases: `OPENFRUIT_HOST_SWIFT_BIN`,
  `OPENFRUIT_HOST_SWIFT_RUNTIME`, `OPENFRUIT_HOST_SDKROOT`.
- Migration: `OPENFRUIT_LEGACY_SDK_PATH` (SDK path persisted by an older
  configuration).

`OPENFRUIT_HAS_OPENIB_INPROCESS` is a compile definition, not an environment
variable; the `OPENFRUIT_APPLE_*_HOST_*` / `*_READY` names are protocol
markers printed by the plugin hosts.
