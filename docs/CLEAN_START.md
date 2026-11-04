# OPENFRUIT — Clean Start Procedure

This procedure clears generated/diagnostic state while preserving source and the managed OPENFRUIT installation.

See [Storage layout and retention](STORAGE_LAYOUT.md) for the roles of `c`, `w`,
managed cache categories, toolchain versions and the current native prune limits.

## Repository state to remove

Generated build scratch is not source:

```text
<repo>\build
```

The current native build script can regenerate it. Keep it ignored by Git.

Generated repository-tree snapshots such as a temporary root `root.json` should also be removed rather than committed.

Repository-local `.tools` is obsolete. A clean source tree must not contain or recreate it.

## User-scoped diagnostic state

Old diagnostic caches may be removed when starting a new controlled run:

```text
%USERPROFILE%\.OPENFRUIT\c\v5
%USERPROFILE%\.OPENFRUIT\cache
```

Do not delete configuration, credentials or secrets merely to start a diagnostic cycle.

## Managed installation to preserve

Do not delete the managed installation root:

```text
%LOCALAPPDATA%\OPENFRUIT
```

It contains the installed CLI, SDKs, toolchains and other managed infrastructure.

Do not clear `%LOCALAPPDATA%\OPENFRUIT\cache` as a whole. It also contains
installed Darwin provider payloads and paired XIP archives still required by
target-runtime acquisition. Its name does not imply that every entry is disposable.
Invalidate only a classified, unreferenced category or artifact, after checking
its consumers. Preserve `bin`, `sdk` and `toolchains` during generic cleanup.

The native `cache prune` command currently prunes participating entries under
the user-state `c/v/r2-*` execution contexts only. Resolver workspaces and legacy
execution formats remain protected because old consumers use different locking.
Entries without the existing per-entry consumer lease marker are preserved, as
are entries currently leased. Managed cache categories are
protected until category-specific reference and consumer-lifetime policies exist.
Reported deleted byte lengths are logical; hard links and compression can make
physical recovery different. This is a safety boundary, not complete automatic
retention for every cache namespace.

## Source paths to preserve

Preserve source and controlled fixtures, including:

```text
AGENTS.md
docs
OPENFRUIT\windows\src
OPENFRUIT\windows\tests
native
openib
```

Legacy material listed at the end of `.gitignore` stays on disk but is not
published.

Classify remaining scripts individually before removal. Do not delete a provider/bridge implementation merely because an old PowerShell bootstrap path was retired.

## Never use destructive Git cleanup blindly

Do not blindly run:

```powershell
git reset --hard
git clean -fdx
```

Especially before the first repository baseline commit, untracked files are not recoverable through Git.

## Clean-baseline sequence

1. remove repository `build\`;
2. remove temporary tree/log snapshots such as root `root.json`;
3. verify `.tools` is absent;
4. verify source-of-truth docs are present;
5. review `.gitignore`;
6. run `OPENFRUIT\windows\build.ps1 -Configuration Release` once from the clean source tree;
7. confirm the build does not recreate `.tools`;
8. remove `build\` again if the baseline commit should contain source only;
9. run `git status --short`;
10. create the first baseline commit.
