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

$codeqlPath = Join-Path $repoRoot ".github\workflows\codeql.yml"
if (-not (Test-Path -LiteralPath $codeqlPath)) {
    throw "Falta .github/workflows/codeql.yml."
}

$codeql = Get-Content -Raw $codeqlPath
$requiredCodeqlFragments = @(
    "name: CodeQL",
    "pull_request:",
    "push:",
    "schedule:",
    "workflow_dispatch:",
    "contents: read",
    "security-events: write",
    "javascript-typescript",
    "rust",
    "build-mode: none",
    "github/codeql-action/init@",
    "github/codeql-action/analyze@"
)
foreach ($fragment in $requiredCodeqlFragments) {
    Assert-Contains -Text $codeql -Fragment $fragment -Context "codeql.yml"
}

if ($codeql.Contains("pull_request_target:")) {
    throw "codeql.yml no debe ejecutar codigo de PR con pull_request_target."
}

$workflowPaths = Get-ChildItem -LiteralPath (Join-Path $repoRoot ".github\workflows") -Filter "*.yml"
foreach ($workflowPath in $workflowPaths) {
    $usesMatches = Select-String -LiteralPath $workflowPath.FullName -Pattern '^\s*uses:\s*(?<action>[^\s#]+)'
    foreach ($usesMatch in $usesMatches) {
        $action = $usesMatch.Matches[0].Groups["action"].Value
        if ($action.StartsWith("./")) {
            continue
        }

        if ($action -notmatch '@[0-9a-f]{40}$') {
            throw "$($workflowPath.Name) contiene una accion sin fijar por SHA completa: $action"
        }
    }
}

$ci = Get-Content -Raw (Join-Path $repoRoot ".github\workflows\ci.yml")
Assert-Contains -Text $ci -Fragment "name: Build & test (Windows)" -Context "ci.yml"
Assert-Contains -Text $ci -Fragment ".\scripts\test-github-hardening.ps1" -Context "ci.yml"

$dependabot = Get-Content -Raw (Join-Path $repoRoot ".github\dependabot.yml")
foreach ($ecosystem in @("github-actions", "cargo", "npm")) {
    Assert-Contains -Text $dependabot -Fragment "package-ecosystem: $ecosystem" -Context "dependabot.yml"
}

Write-Output "Hardening de GitHub validado: CodeQL, acciones fijadas, CI estable y cobertura Dependabot."
