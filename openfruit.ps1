[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Forward only. The native CLI owns the standard managed installation and
# user-state/cache locations; invoking this launcher must not select a fork.
$managedRoot = if ([string]::IsNullOrWhiteSpace($env:OPENFRUIT_HOME)) {
    Join-Path $env:LOCALAPPDATA 'OPENFRUIT'
} else {
    $env:OPENFRUIT_HOME
}
$openfruit = Join-Path $managedRoot 'bin\openfruit.exe'

if (-not (Test-Path -LiteralPath $openfruit -PathType Leaf)) {
    throw "OpenFruit non installato: $openfruit`nCompilare prima con .\openfruit\windows\build.ps1"
}

& $openfruit @Arguments
exit $LASTEXITCODE
