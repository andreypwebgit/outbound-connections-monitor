param(
    [string]$Tag = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$cargoText = Get-Content -Raw (Join-Path $repoRoot "src-tauri\Cargo.toml")
$cargoMatch = [regex]::Match($cargoText, '(?m)^version\s*=\s*"([^"]+)"')
if (-not $cargoMatch.Success) {
    throw "No se pudo leer la version de src-tauri/Cargo.toml."
}

$cargoVersion = $cargoMatch.Groups[1].Value
$tauriVersion = (Get-Content -Raw (Join-Path $repoRoot "src-tauri\tauri.conf.json") | ConvertFrom-Json -AsHashtable)["version"]
$packageVersion = (Get-Content -Raw (Join-Path $repoRoot "package.json") | ConvertFrom-Json -AsHashtable)["version"]
$lockVersion = (Get-Content -Raw (Join-Path $repoRoot "package-lock.json") | ConvertFrom-Json -AsHashtable)["version"]

$versions = [ordered]@{
    "src-tauri/Cargo.toml" = $cargoVersion
    "src-tauri/tauri.conf.json" = $tauriVersion
    "package.json" = $packageVersion
    "package-lock.json" = $lockVersion
}

$mismatches = $versions.GetEnumerator() | Where-Object { $_.Value -ne $cargoVersion }
if ($mismatches) {
    $details = ($versions.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", "
    throw "Las versiones no estan sincronizadas: $details"
}

if ($Tag) {
    $tagVersion = $Tag.TrimStart("v")
    if ($tagVersion -ne $cargoVersion) {
        throw "El tag $Tag no coincide con la version $cargoVersion."
    }
}

Write-Output "Version validada: $cargoVersion"
