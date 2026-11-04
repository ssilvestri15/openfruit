$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $Root "build"
cmake --build $Build --config Release
if ($LASTEXITCODE -ne 0) { throw "OpenIB build failed with exit code $LASTEXITCODE" }
ctest --test-dir $Build -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "OpenIB tests failed with exit code $LASTEXITCODE" }
