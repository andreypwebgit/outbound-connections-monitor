param(
    [Parameter(Mandatory = $true)]
    [string]$Directory,
    [string]$OutputName = "checksums.txt"
)

$ErrorActionPreference = "Stop"
$resolved = (Resolve-Path -LiteralPath $Directory).Path
$outputPath = Join-Path $resolved $OutputName
$files = Get-ChildItem -LiteralPath $resolved -File |
    Where-Object { $_.Name -ne $OutputName } |
    Sort-Object Name

if ($files.Count -eq 0) {
    throw "No hay artefactos para generar checksums en $resolved."
}

$lines = foreach ($file in $files) {
    "{0}  {1}" -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $file.Name
}
$lines | Set-Content -LiteralPath $outputPath -Encoding utf8
Get-Content -LiteralPath $outputPath
