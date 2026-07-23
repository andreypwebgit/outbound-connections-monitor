param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths
)

$ErrorActionPreference = "Stop"
$files = foreach ($path in $Paths) {
    Get-Item -LiteralPath $path -ErrorAction Stop
}

if ($files.Count -eq 0) {
    throw "No se recibieron artefactos para verificar."
}

foreach ($file in $files) {
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Firma no valida en $($file.Name): $($signature.Status) - $($signature.StatusMessage)"
    }
    if (-not $signature.SignerCertificate) {
        throw "El artefacto $($file.Name) no expone certificado firmante."
    }
    Write-Output ("Firma valida: {0} | {1}" -f $file.Name, $signature.SignerCertificate.Subject)
}
