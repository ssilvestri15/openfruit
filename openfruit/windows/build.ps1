[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')]
    [string]$Configuration = 'Release',
    [ValidateRange(0, 256)]
    [int]$Jobs = 0,
    [switch]$CoreOnly,
    [switch]$SkipInstall,
    [switch]$WithTests,
    # Release version from the tag: X.Y.Z, or X.Y.Z-dev for a prerelease.
    [ValidatePattern('^$|^[0-9]+\.[0-9]+\.[0-9]+(-dev)?$')]
    [string]$Version = '',
    [string]$BuildDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$windowsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $windowsRoot '..\..')).Path
$buildRoot = if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
    Join-Path $repoRoot ('build\OPENFRUIT-native\' + $Configuration.ToLowerInvariant())
} else {
    [IO.Path]::GetFullPath($BuildDirectory)
}
$managedRoot = if (-not [string]::IsNullOrWhiteSpace($env:OPENFRUIT_HOME)) {
    [IO.Path]::GetFullPath($env:OPENFRUIT_HOME)
} elseif (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    Join-Path $env:LOCALAPPDATA 'OPENFRUIT'
} else {
    throw 'LOCALAPPDATA or OPENFRUIT_HOME is required for the managed installation.'
}
if ($Jobs -le 0) { $Jobs = [Math]::Max(1, [Environment]::ProcessorCount) }

$clang = Get-Command clang-cl.exe -ErrorAction SilentlyContinue
if ($null -eq $clang) { throw 'clang-cl.exe is required to build the native engine.' }
foreach ($toolName in @('cmake.exe', 'ninja.exe')) {
    if ($null -eq (Get-Command $toolName -ErrorAction SilentlyContinue)) {
        throw "$toolName is required to build the native engine."
    }
}

# CMake/Ninja owns source selection, header dependencies, compilation and linking.
# This script only configures/builds/installs those native targets. Resource
# backends are managed dependencies; never patch an upstream checkout here.
$previousEnvironment = [Environment]::GetEnvironmentVariables()
try {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw 'Visual Studio C++ Build Tools are required (vswhere.exe was not found).'
    }
    $vsInstall = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ([string]::IsNullOrWhiteSpace($vsInstall)) {
        throw 'Visual Studio C++ Build Tools were not found.'
    }
    Import-Module (Join-Path $vsInstall 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
    Enter-VsDevShell -VsInstallPath $vsInstall -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
    # Native tools report failure through exit codes, checked below. Under
    # Windows PowerShell 5.1 with redirected output, 'Stop' would turn any
    # stderr line (for example a CMake deprecation warning) into a fatal error.
    $ErrorActionPreference = 'Continue'

    $openibEnabled = if ($CoreOnly) { 'OFF' } else { 'ON' }
    $testsEnabled = if ($WithTests) { 'ON' } else { 'OFF' }
    $configureArgs = @(
        '-S', $windowsRoot, '-B', $buildRoot, '-G', 'Ninja',
        "-DCMAKE_CXX_COMPILER=$($clang.Source)",
        "-DCMAKE_C_COMPILER=$($clang.Source)",
        "-DCMAKE_BUILD_TYPE=$Configuration",
        "-DBUILD_TESTING=$testsEnabled",
        "-DOPENFRUIT_BUILD_OPENIB=$openibEnabled",
        "-DOPENIB_BUILD_TESTS=$testsEnabled",
        # Always passed, so a previous release version never lingers in the cache.
        "-DOPENFRUIT_RELEASE_VERSION=$Version"
    )
    & cmake.exe @configureArgs
    if ($LASTEXITCODE -ne 0) { throw 'Native CMake configuration failed.' }
    & cmake.exe --build $buildRoot --parallel $Jobs
    if ($LASTEXITCODE -ne 0) { throw 'Native engine build failed.' }
    if ($WithTests) {
        & ctest.exe --test-dir $buildRoot --output-on-failure
        if ($LASTEXITCODE -ne 0) { throw 'Native tests failed.' }
    }
    if (-not $SkipInstall) {
        # A persistent macro broker (and its workers) runs the installed host
        # image; stop those processes so the image can be replaced.
        $installedHost = [IO.Path]::GetFullPath((Join-Path $managedRoot 'bin\openfruit-macro-host.exe'))
        $hosts = @(Get-Process -Name 'openfruit-macro-host' -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -and [string]::Equals([IO.Path]::GetFullPath($_.Path), $installedHost, [StringComparison]::OrdinalIgnoreCase) })
        if ($hosts.Count -gt 0) {
            $hosts | Stop-Process -Force -ErrorAction SilentlyContinue
            $hosts | Wait-Process -Timeout 30 -ErrorAction SilentlyContinue
        }
        & cmake.exe --install $buildRoot --prefix $managedRoot
        if ($LASTEXITCODE -ne 0) { throw 'Managed native installation failed.' }
    }
    $candidate = Join-Path $buildRoot 'openfruit.exe'
    $candidateHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
    [pscustomobject]@{
        Passed = $true
        Configuration = $Configuration
        Jobs = $Jobs
        Executable = $candidate
        ManagedExecutable = if ($SkipInstall) { $null } else { Join-Path $managedRoot 'bin\openfruit.exe' }
        SHA256 = $candidateHash
        Bytes = (Get-Item -LiteralPath $candidate).Length
    } | ConvertTo-Json
} finally {
    foreach ($name in [Environment]::GetEnvironmentVariables().Keys) {
        if (-not $previousEnvironment.Contains($name)) {
            # A null value can leave a present-but-empty native variable on
            # current .NET. LLVM treats empty VC discovery paths as configured.
            # Restore absence explicitly, rather than changing its semantics.
            Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
        }
    }
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
}
