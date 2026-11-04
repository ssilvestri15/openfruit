param(
    [Parameter(Mandatory=$true)][string]$DeltaApp,
    [string]$Generated = "$PSScriptRoot\..\out\delta"
)
$ErrorActionPreference = "Stop"
$base = Join-Path $DeltaApp "Base.lproj"
New-Item -ItemType Directory -Force -Path $base | Out-Null
foreach ($name in @("LaunchScreen","GamesDatabase","Main","PauseMenu","Settings")) {
    $src = Join-Path $Generated "$name.storyboardc"
    $dst = Join-Path $base "$name.storyboardc"
    if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
    Copy-Item $src $dst -Recurse -Force
}
Copy-Item "$Generated\PausePresentationControllerContentView.nib" "$base\PausePresentationControllerContentView.nib" -Force
Write-Warning "Re-sign Delta.app after this operation. Do not reuse the official IPA _CodeSignature."
