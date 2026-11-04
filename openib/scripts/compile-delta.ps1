param(
    [string]$OpenIB = "$PSScriptRoot\..\build\Release\openib.exe",
    [string]$Delta = "$PSScriptRoot\..\tests\fixtures\delta",
    [string]$Out = "$PSScriptRoot\..\out\delta"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$storyboards = @("LaunchScreen", "GamesDatabase", "Main", "PauseMenu", "Settings")
foreach ($name in $storyboards) {
    & $OpenIB analyze "$Delta\$name.storyboard"
    & $OpenIB compile "$Delta\$name.storyboard" -o "$Out\$name.storyboardc"
}
$syncResultsSource = Join-Path (Split-Path -Parent $Delta) 'Syncing\SyncResultsViewController.storyboard'
if (-not (Test-Path -LiteralPath $syncResultsSource -PathType Leaf)) {
    $syncResultsSource = Join-Path $Delta 'SyncResultsViewController.storyboard'
}
if (Test-Path -LiteralPath $syncResultsSource -PathType Leaf) {
    & $OpenIB analyze $syncResultsSource
    & $OpenIB compile $syncResultsSource -o "$Out\SyncResultsViewController.storyboardc"
}
& $OpenIB compile "$Delta\PausePresentationControllerContentView.xib" -o "$Out\PausePresentationControllerContentView.nib"
