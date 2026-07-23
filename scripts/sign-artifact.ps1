param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

$ErrorActionPreference = "Stop"

$target = (Resolve-Path -LiteralPath $Path).Path
$dlib = [Environment]::GetEnvironmentVariable("ARTIFACT_SIGNING_DLIB_PATH")
$metadata = [Environment]::GetEnvironmentVariable("ARTIFACT_SIGNING_METADATA_PATH")

if ([string]::IsNullOrWhiteSpace($dlib) -or -not (Test-Path -LiteralPath $dlib -PathType Leaf)) {
    throw "ARTIFACT_SIGNING_DLIB_PATH no apunta a un archivo valido."
}
if ([string]::IsNullOrWhiteSpace($metadata) -or -not (Test-Path -LiteralPath $metadata -PathType Leaf)) {
    throw "ARTIFACT_SIGNING_METADATA_PATH no apunta a un archivo valido."
}

$sdkRoots = @(
    (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"),
    (Join-Path $env:ProgramFiles "Windows Kits\10\bin")
) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }

$signTool = $sdkRoots |
    ForEach-Object { Get-ChildItem -LiteralPath $_ -Directory } |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1

if (-not $signTool) {
    throw "No se encontro signtool.exe x64 en el Windows SDK."
}

& $signTool sign /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 `
    /dlib $dlib /dmdf $metadata $target
if ($LASTEXITCODE -ne 0) {
    throw "SignTool fallo con exit code $LASTEXITCODE."
}

$signature = Get-AuthenticodeSignature -LiteralPath $target
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "La firma recien aplicada no es valida: $($signature.Status)."
}

Write-Output "Artefacto firmado y verificado: $([IO.Path]::GetFileName($target))"
