param(
    [Parameter(Mandatory=$true)][string]$OfficialApp,
    [string]$OpenIB = "$PSScriptRoot\..\build\Release\openib.exe",
    [string]$Out = "$PSScriptRoot\..\out\official-dumps"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
Get-ChildItem $OfficialApp -Recurse -Filter *.nib | ForEach-Object {
    $relative = $_.FullName.Substring($OfficialApp.Length).TrimStart('\') -replace '[\\/:*?"<>|]', '_'
    & $OpenIB dump $_.FullName | Out-File (Join-Path $Out "$relative.txt") -Encoding utf8
}
Write-Host "NIB dumps written to $Out"
