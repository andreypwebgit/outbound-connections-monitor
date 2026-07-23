$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Assert-Contains {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,
        [Parameter(Mandatory = $true)]
        [string]$Fragment,
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if (-not $Text.Contains($Fragment)) {
        throw "$Context no contiene el fragmento obligatorio: $Fragment"
    }
}

function Assert-DoesNotContain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,
        [Parameter(Mandatory = $true)]
        [string]$Fragment,
        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ($Text.Contains($Fragment)) {
        throw "$Context conserva una configuracion prohibida: $Fragment"
    }
}

$package = Get-Content -Raw (Join-Path $repoRoot "package.json") | ConvertFrom-Json
$validTag = "v$($package.version)"
& (Join-Path $PSScriptRoot "validate-release.ps1") -Tag $validTag | Out-Null

$invalidTag = if ($validTag -eq "v0.0.0") { "v0.0.1" } else { "v0.0.0" }
$invalidTagRejected = $false
try {
    & (Join-Path $PSScriptRoot "validate-release.ps1") -Tag $invalidTag | Out-Null
}
catch {
    $invalidTagRejected = $true
}
if (-not $invalidTagRejected) {
    throw "validate-release.ps1 acepto un tag que no coincide con los manifiestos."
}

$workflowPath = Join-Path $repoRoot ".github\workflows\release.yml"
$workflow = Get-Content -Raw $workflowPath
$requiredWorkflowFragments = @(
    "npx tauri build --ci",
    "scripts\generate-checksums.ps1",
    "anchore/sbom-action@",
    "actions/attest@",
    "softprops/action-gh-release@",
    "no están firmados con Authenticode"
)
foreach ($fragment in $requiredWorkflowFragments) {
    Assert-Contains -Text $workflow -Fragment $fragment -Context "release.yml"
}

$forbiddenWorkflowFragments = @(
    "azure/login@",
    "ARTIFACT_SIGNING_",
    "AZURE_CLIENT_ID",
    "signCommand",
    "verify-signatures.ps1",
    "environment: release"
)
foreach ($fragment in $forbiddenWorkflowFragments) {
    Assert-DoesNotContain -Text $workflow -Fragment $fragment -Context "release.yml"
}

$removedScripts = @(
    "scripts\sign-artifact.ps1",
    "scripts\verify-signatures.ps1"
)
foreach ($relativePath in $removedScripts) {
    if (Test-Path -LiteralPath (Join-Path $repoRoot $relativePath)) {
        throw "El script de firma retirado sigue presente: $relativePath"
    }
}

$readme = Get-Content -Raw (Join-Path $repoRoot "README.md")
$security = Get-Content -Raw (Join-Path $repoRoot "SECURITY.md")
$distribution = Get-Content -Raw (Join-Path $repoRoot "docs\build-and-distribution.md")
Assert-Contains -Text $readme -Fragment "no están firmados" -Context "README.md"
Assert-Contains -Text $security -Fragment "Authenticode-signed" -Context "SECURITY.md"
Assert-Contains -Text $distribution -Fragment "no están firmados con Authenticode" -Context "docs/build-and-distribution.md"

Write-Output "Politica de release unsigned validada: version, workflow, artefactos y documentacion."
