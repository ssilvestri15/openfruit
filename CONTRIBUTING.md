# Contributing to OPENFRUIT

Thank you for helping. Before you start, read `AGENTS.md`: it defines the
rules every change must follow. In short:

- OPENFRUIT adapts the build environment to the project; never modify an
  upstream project, package, Apple SDK or macro to make a build pass.
- Fixes must implement general Xcode, Swift, SwiftPM, Clang or Apple
  toolchain semantics, never behaviour keyed to a specific app, package,
  framework or macro.
- Never replace or emulate an upstream macro or compiler plugin.
- Keep each change focused and covered by a test where it is practical.

## Building and testing

```powershell
.\openfruit\windows\build.ps1 -WithTests
```

## License and Contributor License Agreement

OPENFRUIT is licensed under GPL-2.0-or-later (see `LICENSE`). Contributions
are accepted only under the [Contributor License Agreement](CLA.md), which
lets the maintainer keep the project's licensing options open while
guaranteeing that released versions stay available as free software.

To accept it, put this line in your pull request description:

    I have read and agree to the OPENFRUIT Contributor License Agreement, version 1.0.

and sign off each commit with `git commit -s`.

Do not submit code you did not write unless its license is compatible with
GPL-2.0-or-later and you identify it in the pull request.
