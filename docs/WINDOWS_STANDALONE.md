# Windows standalone package

The binary ZIP is produced from the native CMake install rules:

```powershell
cmake --build <native-build-directory> --config Release
cpack --config <native-build-directory>/CPackConfig.cmake -C Release
```

Extract it outside the source repository and run `bin/OPENFRUIT.exe --help`.
Managed SDKs, toolchains and user configuration keep their existing locations:
`%LOCALAPPDATA%/OPENFRUIT` and `%USERPROFILE%/.OPENFRUIT`.

The ZIP does not distribute Apple SDKs, private signing credentials, provisioning
profiles, project sources or mutable build caches. Use the normal bootstrap and
SDK acquisition commands for those inputs. The package itself does not install,
sign or deploy an application.

This is the packaging entry point for wave M8. Relocation and application-matrix
results are recorded separately in `POST_FUNCTIONAL_WAVES.md`; producing an archive
alone does not complete the release gate.
