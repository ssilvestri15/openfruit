param(
    [string]$BuildDirectory = "",
    [string]$CacheRoot = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
    $BuildDirectory = Join-Path $root "build-carthage-binary-probe"
}
if ([string]::IsNullOrWhiteSpace($CacheRoot)) {
    $CacheRoot = Join-Path $BuildDirectory "cache"
}

cmake -S $root -B $BuildDirectory `
    -DOPENFRUIT_BUILD_CARTHAGE_BINARY_PROBE=ON
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cmake --build $BuildDirectory --config Release --target carthage_binary_probe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$fixture = Join-Path $BuildDirectory "fixture"
$payload = Join-Path $fixture "payload\Demo.xcframework"
$framework = Join-Path $payload "ios-arm64\Demo.framework"
New-Item -ItemType Directory -Force -Path (Join-Path $framework "Modules") | Out-Null
Set-Content -LiteralPath (Join-Path $payload "Info.plist") -Encoding utf8 -Value `
    '<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundlePackageType</key><string>XFWK</string></dict></plist>'
Set-Content -LiteralPath (Join-Path $framework "Modules\module.modulemap") -Encoding utf8 -Value `
    'framework module Demo { header "Demo.h" export * }'
Set-Content -LiteralPath (Join-Path $framework "Demo.h") -Encoding utf8 -Value `
    '#define OPENFRUIT_CARTHAGE_PROBE 1'

$archive = Join-Path $fixture "Demo-1.0.0.tar.xz"
tar.exe -cJf $archive -C (Join-Path $fixture "payload") .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$metadata = Join-Path $fixture "Demo.json"
@{ "1.0.0" = $archive } | ConvertTo-Json | Set-Content -LiteralPath $metadata -Encoding utf8
Set-Content -LiteralPath (Join-Path $fixture "Cartfile") -Encoding utf8 -Value `
    ('binary "{0}" == 1.0.0' -f $metadata)

$env:OPENFRUIT_CACHE_ROOT = [System.IO.Path]::GetFullPath($CacheRoot)
$probe = Join-Path $BuildDirectory "Release\carthage_binary_probe.exe"
if (-not (Test-Path -LiteralPath $probe)) {
    $probe = Join-Path $BuildDirectory "carthage_binary_probe.exe"
}
& $probe $fixture
exit $LASTEXITCODE
