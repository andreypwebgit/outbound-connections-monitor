param(
    [string]$Tag = "",
    [switch]$RequireSigningConfiguration
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

if ($RequireSigningConfiguration) {
    $required = @(
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "AZURE_SUBSCRIPTION_ID",
        "ARTIFACT_SIGNING_ENDPOINT",
        "ARTIFACT_SIGNING_ACCOUNT",
        "ARTIFACT_SIGNING_CERTIFICATE_PROFILE"
    )
    $missing = $required | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) }
    if ($missing.Count -gt 0) {
        throw "Falta configuracion de firma: $($missing -join ', ')."
    }
}

Write-Output "Version validada: $cargoVersion"
if ($RequireSigningConfiguration) {
    Write-Output "Configuracion de Artifact Signing presente."
}
