param(
    [string]$BuildDirectory = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
    $BuildDirectory = Join-Path $root "build-xcconfig-anchor-probe"
}

cmake -S $root -B $BuildDirectory `
    -DOPENFRUIT_BUILD_XCCONFIG_ANCHOR_PROBE=ON
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build $BuildDirectory --config Release `
    --target xcode_xcconfig_anchor_probe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$probe = Join-Path $BuildDirectory "Release\xcode_xcconfig_anchor_probe.exe"
if (-not (Test-Path -LiteralPath $probe)) {
    $probe = Join-Path $BuildDirectory "xcode_xcconfig_anchor_probe.exe"
}

$fixture = Join-Path $PSScriptRoot "fixtures\xcconfig-anchor"
& $probe $fixture
exit $LASTEXITCODE
