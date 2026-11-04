$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $Root "build"
if (-not (Get-Command ninja -ErrorAction SilentlyContinue)) {
    throw "OpenIB requires Ninja on Windows"
}
cmake --fresh -S $Root -B $Build -G "Ninja Multi-Config" -DOPENIB_BUILD_TESTS=ON
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed with exit code $LASTEXITCODE" }
cmake --build $Build --config Release
if ($LASTEXITCODE -ne 0) { throw "OpenIB build failed with exit code $LASTEXITCODE" }
Write-Host "Built: $Build\Release\openib.exe"
