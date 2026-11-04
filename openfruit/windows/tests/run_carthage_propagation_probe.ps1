param(
    [Parameter(Mandatory = $true)]
    [string]$Probe,
    [Parameter(Mandatory = $true)]
    [string]$DiagnosticRoot,
    [Parameter(Mandatory = $true)]
    [string]$CacheRoot
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$fixtureSource = Join-Path $PSScriptRoot "fixtures\carthage-propagation"
$packageSource = Join-Path $PSScriptRoot "fixtures\carthage-propagation-dependency"
$fixture = Join-Path $DiagnosticRoot "fixture"
$packageRepository = Join-Path $DiagnosticRoot "package-repository"
$projectBundle = Join-Path $fixture "CarthageGraphProbe.xcodeproj"

foreach ($path in @($DiagnosticRoot, $CacheRoot, $fixture, $packageRepository)) {
    if (Test-Path -LiteralPath $path) {
        throw "Diagnostic path must not already exist: $path"
    }
}

New-Item -ItemType Directory -Path $DiagnosticRoot | Out-Null
Copy-Item -LiteralPath $fixtureSource -Destination $fixture -Recurse
Copy-Item -LiteralPath $packageSource -Destination $packageRepository -Recurse
Move-Item -LiteralPath (Join-Path $fixture "Probe.xcodeproj") -Destination $projectBundle

git -C $packageRepository init --quiet
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git -C $packageRepository config user.name "OPENFRUIT Diagnostic"
git -C $packageRepository config user.email "diagnostic@OPENFRUIT.invalid"
git -C $packageRepository add Package.swift Sources
git -C $packageRepository commit --quiet -m "OPENFRUIT propagation fixture"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git -C $packageRepository tag 1.1.4
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$projectFile = Join-Path $projectBundle "project.pbxproj"
$packageUrl = ([System.Uri]::new(
    [System.IO.Path]::GetFullPath($packageRepository) +
    [System.IO.Path]::DirectorySeparatorChar)).AbsoluteUri
$projectText = (Get-Content -LiteralPath $projectFile -Raw).Replace(
    "__OPENFRUIT_PROPAGATION_PACKAGE_URL__",
    $packageUrl)
Set-Content -LiteralPath $projectFile -Value $projectText -Encoding utf8NoBOM

$env:OPENFRUIT_CACHE_ROOT = [System.IO.Path]::GetFullPath($CacheRoot)
& $Probe $repoRoot $projectBundle
exit $LASTEXITCODE
