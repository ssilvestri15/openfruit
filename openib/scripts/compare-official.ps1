param(
    [Parameter(Mandatory=$true)][string]$OfficialApp,
    [string]$Generated = "$PSScriptRoot\..\out\delta",
    [string]$OpenIB = "$PSScriptRoot\..\build\Release\openib.exe"
)
$ErrorActionPreference = "Stop"

$storyboards = [ordered]@{
    LaunchScreen = 'Base.lproj'
    GamesDatabase = 'Base.lproj'
    Main = 'Base.lproj'
    PauseMenu = 'Base.lproj'
    Settings = 'Base.lproj'
    SyncResultsViewController = '.'
}

function ConvertTo-Hashtable($obj) {
    if ($obj -is [System.Management.Automation.PSCustomObject]) {
        $ht = [ordered]@{}
        foreach ($prop in $obj.PSObject.Properties) { $ht[$prop.Name] = ConvertTo-Hashtable $prop.Value }
        return $ht
    }
    if ($obj -is [System.Collections.IList]) {
        return @($obj | ForEach-Object { ConvertTo-Hashtable $_ })
    }
    return $obj
}
$results = [System.Collections.Generic.List[object]]::new()
$plistFailures = [System.Collections.Generic.List[string]]::new()

function Test-PlistValueEqual($left, $right) {
    if ($left -is [System.Collections.IDictionary] -and $right -is [System.Collections.IDictionary]) {
        if ($left.Count -ne $right.Count) { return $false }
        foreach ($key in $left.Keys) {
            if (-not $right.Contains($key) -or -not (Test-PlistValueEqual $left[$key] $right[$key])) { return $false }
        }
        return $true
    }
    if ($left -is [System.Collections.IList] -and $right -is [System.Collections.IList]) {
        if ($left.Count -ne $right.Count) { return $false }
        for ($i = 0; $i -lt $left.Count; $i++) {
            if (-not (Test-PlistValueEqual $left[$i] $right[$i])) { return $false }
        }
        return $true
    }
    return [object]::Equals($left, $right)
}

foreach ($entry in $storyboards.GetEnumerator()) {
    $name = $entry.Key
    $officialResources = Join-Path $OfficialApp $entry.Value
    $officialDirectory = Join-Path $officialResources "$name.storyboardc"
    $generatedDirectory = Join-Path $Generated "$name.storyboardc"
    if (-not (Test-Path -LiteralPath $officialDirectory -PathType Container)) {
        throw "Official storyboard directory is missing: $officialDirectory"
    }
    $officialPlist = Join-Path $officialDirectory 'Info.plist'
    $generatedPlist = Join-Path $generatedDirectory 'Info.plist'
    if (-not (Test-Path -LiteralPath $generatedPlist -PathType Leaf)) {
        $plistFailures.Add("$name`: generated Info.plist is missing")
    } else {
        $officialJson = & plutil -convert json -o - $officialPlist
        if ($LASTEXITCODE -ne 0) { throw "Unable to parse official Info.plist: $officialPlist" }
        $generatedJson = & plutil -convert json -o - $generatedPlist
        if ($LASTEXITCODE -ne 0) { throw "Unable to parse generated Info.plist: $generatedPlist" }
        $officialData = ConvertTo-Hashtable ($officialJson | ConvertFrom-Json)
        $generatedData = ConvertTo-Hashtable ($generatedJson | ConvertFrom-Json)
        if (-not (Test-PlistValueEqual $officialData $generatedData)) {
            $plistFailures.Add("$name`: Info.plist differs")
        }
    }
    $officialNibs = @(Get-ChildItem -LiteralPath $officialDirectory -Filter '*.nib' -File)
    $generatedNibs = if (Test-Path -LiteralPath $generatedDirectory -PathType Container) {
        @(Get-ChildItem -LiteralPath $generatedDirectory -Filter '*.nib' -File)
    } else { @() }
    $officialNames = @($officialNibs | ForEach-Object Name)
    $generatedNames = @($generatedNibs | ForEach-Object Name)
    foreach ($missing in $officialNames | Where-Object { $_ -notin $generatedNames }) {
        $results.Add([pscustomobject]@{ Source = $name; NIB = $missing; Status = 'MISSING'; Differences = $null })
    }
    foreach ($extra in $generatedNames | Where-Object { $_ -notin $officialNames }) {
        $results.Add([pscustomobject]@{ Source = $name; NIB = $extra; Status = 'EXTRA'; Differences = $null })
    }
    foreach ($nib in $officialNibs | Where-Object { $_.Name -in $generatedNames }) {
        $generatedNib = Join-Path $generatedDirectory $nib.Name
        $diff = (& $OpenIB diff $generatedNib $nib.FullName 2>&1 | Out-String)
        $matched = [regex]::Match($diff, 'Differences: (\d+)')
        $results.Add([pscustomobject]@{
            Source = $name
            NIB = $nib.Name
            Status = if ($LASTEXITCODE -eq 0) { 'PASS' } else { 'FAIL' }
            Differences = if ($LASTEXITCODE -eq 0) { 0 } elseif ($matched.Success) { [int]$matched.Groups[1].Value } else { $null }
        })
    }
}

$xibName = 'PausePresentationControllerContentView.nib'
$officialXib = Join-Path (Join-Path $OfficialApp 'Base.lproj') $xibName
$generatedXib = Join-Path $Generated $xibName
if ((Test-Path -LiteralPath $officialXib -PathType Leaf) -and (Test-Path -LiteralPath $generatedXib -PathType Leaf)) {
    $diff = (& $OpenIB diff $generatedXib $officialXib 2>&1 | Out-String)
    $matched = [regex]::Match($diff, 'Differences: (\d+)')
    $results.Add([pscustomobject]@{
        Source = 'XIB'
        NIB = $xibName
        Status = if ($LASTEXITCODE -eq 0) { 'PASS' } else { 'FAIL' }
        Differences = if ($LASTEXITCODE -eq 0) { 0 } elseif ($matched.Success) { [int]$matched.Groups[1].Value } else { $null }
    })
} else {
    $results.Add([pscustomobject]@{ Source = 'XIB'; NIB = $xibName; Status = 'MISSING'; Differences = $null })
}

$results | Sort-Object Status, Differences, Source, NIB | Format-Table -AutoSize
$passed = @($results | Where-Object Status -eq 'PASS').Count
$failed = @($results | Where-Object Status -eq 'FAIL').Count
$missing = @($results | Where-Object Status -eq 'MISSING').Count
$extra = @($results | Where-Object Status -eq 'EXTRA').Count
Write-Host "PASS=$passed FAIL=$failed MISSING=$missing EXTRA=$extra TOTAL=$($results.Count)"
Write-Host "PLIST_PASS=$($storyboards.Count - $plistFailures.Count) PLIST_FAIL=$($plistFailures.Count)"
foreach ($failure in $plistFailures) { Write-Host $failure }
if ($failed -or $missing -or $extra -or $plistFailures.Count) { exit 1 }
