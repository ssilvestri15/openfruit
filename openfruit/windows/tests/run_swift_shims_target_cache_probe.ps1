[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LinuxSwiftc,
    [Parameter(Mandatory=$true)][string]$SdkPath,
    [Parameter(Mandatory=$true)][string]$PrebuiltModules,
    [Parameter(Mandatory=$true)][string]$ResourceDir,
    [Parameter(Mandatory=$true)][string]$CachePath,
    [string[]]$Targets = @('arm64-apple-ios18.6', 'arm64-apple-ios13.0')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $CachePath) {
    throw "Probe cache must not already exist: $CachePath"
}

function ConvertTo-WslPath {
    param([Parameter(Mandatory=$true)][string]$Path)
    $absolute = [IO.Path]::GetFullPath($Path)
    return '/mnt/' + $absolute.Substring(0, 1).ToLowerInvariant() +
        $absolute.Substring(2).Replace('\', '/')
}

$sdk = (Resolve-Path -LiteralPath $SdkPath).Path
$prebuilt = (Resolve-Path -LiteralPath $PrebuiltModules).Path
$resource = (Resolve-Path -LiteralPath $ResourceDir).Path
$probe = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'swift_shims_import_probe.swift')).Path
$cache = [IO.Path]::GetFullPath($CachePath)
New-Item -ItemType Directory -Path $cache -Force | Out-Null

$sdkWsl = ConvertTo-WslPath $sdk
$prebuiltWsl = ConvertTo-WslPath $prebuilt
$resourceWsl = ConvertTo-WslPath $resource
$probeWsl = ConvertTo-WslPath $probe
$cacheWsl = ConvertTo-WslPath $cache
$results = [Collections.Generic.List[object]]::new()

foreach ($target in $Targets) {
    & wsl.exe -d Ubuntu -- $LinuxSwiftc -typecheck $probeWsl `
        -parse-stdlib -Xfrontend -enable-objc-interop `
        -target $target -sdk $sdkWsl -I $prebuiltWsl `
        -resource-dir $resourceWsl -module-cache-path $cacheWsl `
        -Xcc "-fmodule-map-file=$sdkWsl/usr/lib/swift/shims/module.modulemap" `
        -no-color-diagnostics
    $exitCode = $LASTEXITCODE
    $results.Add([pscustomobject]@{ Target = $target; ExitCode = $exitCode })
    if ($exitCode -ne 0) {
        $results | ConvertTo-Json
        exit $exitCode
    }
}

$pcmFiles = @(Get-ChildItem -LiteralPath $cache -Recurse -Filter 'SwiftShims-*.pcm')
[pscustomobject]@{
    Passed = $true
    Results = $results
    SwiftShimsPcmCount = $pcmFiles.Count
    Cache = $cache
} | ConvertTo-Json -Depth 4
