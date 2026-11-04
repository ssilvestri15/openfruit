[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackagePath,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$ScratchPath,
    [Parameter(Mandatory=$true)][string]$SourceToolset,
    [Parameter(Mandatory=$true)][string]$CompilerProxy,
    [Parameter(Mandatory=$true)][string]$SwiftBin,
    [Parameter(Mandatory=$true)][string]$HostSdk,
    [Parameter(Mandatory=$true)][string]$FallbackRoot,
    [Parameter(Mandatory=$true)][string]$LinuxSwiftc,
    [string[]]$FrameworkSearchPath = @(),
    [string]$Triple = 'arm64-apple-ios18.6',
    [ValidateSet('debug','release')][string]$Configuration = 'debug',
    [ValidateRange(1,32)][int]$Jobs = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $ScratchPath) {
    throw "Checkpoint scratch must not already exist: $ScratchPath"
}

$package = (Resolve-Path -LiteralPath $PackagePath).Path
$sourceToolsetPath = (Resolve-Path -LiteralPath $SourceToolset).Path
$proxy = (Resolve-Path -LiteralPath $CompilerProxy).Path
$swiftRoot = (Resolve-Path -LiteralPath $SwiftBin).Path
$hostSdkPath = (Resolve-Path -LiteralPath $HostSdk).Path
$fallback = (Resolve-Path -LiteralPath $FallbackRoot).Path
$scratch = [IO.Path]::GetFullPath($ScratchPath)
$checkpointToolchain = Join-Path $scratch 'OPENFRUIT-checkpoint-toolchain'
New-Item -ItemType Directory -Force -Path $checkpointToolchain | Out-Null

Copy-Item -LiteralPath $proxy -Destination (Join-Path $checkpointToolchain 'swiftc.exe')
Copy-Item -LiteralPath $proxy -Destination (Join-Path $checkpointToolchain 'clang.exe')
Copy-Item -LiteralPath $proxy -Destination (Join-Path $checkpointToolchain 'clang++.exe')

function Remove-ForcedTargetPair {
    param([object[]]$Options)
    $result = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $Options.Count; $index++) {
        if ([string]$Options[$index] -eq '-target' -and $index + 1 -lt $Options.Count) {
            $index++
            continue
        }
        $result.Add([string]$Options[$index])
    }
    return @($result)
}

$toolset = Get-Content -LiteralPath $sourceToolsetPath -Raw | ConvertFrom-Json
$toolset.rootPath = $checkpointToolchain
$toolset.swiftCompiler.path = Join-Path $checkpointToolchain 'swiftc.exe'
$toolset.cCompiler.path = Join-Path $checkpointToolchain 'clang.exe'
$toolset.cxxCompiler.path = Join-Path $checkpointToolchain 'clang++.exe'
$toolset.swiftCompiler.extraCLIOptions = Remove-ForcedTargetPair @($toolset.swiftCompiler.extraCLIOptions)
$toolset.cCompiler.extraCLIOptions = Remove-ForcedTargetPair @($toolset.cCompiler.extraCLIOptions)
$toolset.cxxCompiler.extraCLIOptions = Remove-ForcedTargetPair @($toolset.cxxCompiler.extraCLIOptions)
foreach ($frameworkPath in $FrameworkSearchPath) {
    $absoluteFrameworkPath = [IO.Path]::GetFullPath($frameworkPath)
    if (-not (Test-Path -LiteralPath $absoluteFrameworkPath -PathType Container)) {
        throw "Framework search path does not exist: $absoluteFrameworkPath"
    }
    $toolset.swiftCompiler.extraCLIOptions += @('-F', $absoluteFrameworkPath)
    $toolset.cCompiler.extraCLIOptions += @('-F', $absoluteFrameworkPath)
    $toolset.cxxCompiler.extraCLIOptions += @('-F', $absoluteFrameworkPath)
}
$toolsetPath = Join-Path $scratch 'OPENFRUIT-checkpoint-toolset.json'
$toolset | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $toolsetPath -Encoding utf8NoBOM

function ConvertTo-WslPath {
    param([Parameter(Mandatory=$true)][string]$Path)
    $absolute = [IO.Path]::GetFullPath($Path)
    return '/mnt/' + $absolute.Substring(0, 1).ToLowerInvariant() + $absolute.Substring(2).Replace('\', '/')
}

$realSwiftc = Join-Path $swiftRoot 'swiftc.exe'
$realClang = Join-Path $swiftRoot 'clang-real.exe'
if (-not (Test-Path -LiteralPath $realClang)) { $realClang = Join-Path $swiftRoot 'clang.exe' }
$swift = Join-Path $swiftRoot 'swift.exe'
$env:SDKROOT = $hostSdkPath
$env:SWIFT_EXEC_MANIFEST = $proxy
$env:OPENFRUIT_SWIFT_MANIFEST_PROXY_REAL = $realSwiftc
$env:OPENFRUIT_SWIFT_MANIFEST_SDK = $hostSdkPath
$env:OPENFRUIT_SWIFT_TARGET_PROXY_REAL = $realSwiftc
$env:OPENFRUIT_COMPILER_PROXY_REAL = $realClang
$env:OPENFRUIT_SWIFT_FALLBACK_BIN = $LinuxSwiftc
$env:OPENFRUIT_SWIFT_FALLBACK_PREBUILT = ConvertTo-WslPath (Join-Path $fallback 'prebuilt')
$env:OPENFRUIT_SWIFT_FALLBACK_MODULE_CACHE = ConvertTo-WslPath (Join-Path $scratch 'fallback-module-cache')
$sdkOption = @($toolset.swiftCompiler.extraCLIOptions)
$sdkIndex = [Array]::IndexOf($sdkOption, '-sdk')
if ($sdkIndex -lt 0) { throw 'Apple SDK missing from toolset.' }
$env:OPENFRUIT_SWIFT_FALLBACK_SDK = ConvertTo-WslPath ([string]$sdkOption[$sdkIndex + 1])
$env:OPENFRUIT_SWIFT_FALLBACK_RESOURCE_DIR = ConvertTo-WslPath (Join-Path $fallback 'target-resource-v1')

& $swift build --package-path $package --scratch-path $scratch `
    --cache-path (Join-Path $scratch 'shared-cache') --manifest-cache local `
    --build-system native `
    --jobs $Jobs --configuration $Configuration --triple $Triple --toolchain $swiftRoot `
    --toolset $toolsetPath --disable-index-store -Xswiftc -j1 --target $Target
$exitCode = $LASTEXITCODE

[pscustomobject]@{
    Passed = $exitCode -eq 0
    ExitCode = $exitCode
    Package = $package
    Target = $Target
    Triple = $Triple
    Scratch = $scratch
    Toolset = $toolsetPath
} | ConvertTo-Json
exit $exitCode
