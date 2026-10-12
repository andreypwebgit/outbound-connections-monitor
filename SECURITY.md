# Security Policy

## Supported versions

Security fixes are provided for the latest published `1.x` release. Older
`0.x` builds are unsupported after the publication of v1.0.0.

## Reporting a vulnerability

Do not disclose exploitable details in a public issue. Use GitHub's private
vulnerability reporting flow for this repository:

`Security` → `Advisories` → `Report a vulnerability`.

Include the affected version, Windows version, reproduction steps, expected
impact and any relevant logs with secrets or personal data removed.

## Scope and product boundaries

OCM is an on-demand, local connection analyzer. It is not an antivirus, EDR,
IDS, firewall or continuous monitor. Reports about missing continuous
monitoring, packet capture or automatic blocking are therefore outside the
security scope unless they demonstrate that the documented behavior is being
misrepresented or bypassed.

## Release integrity

Official v1 releases are published only by `.github/workflows/release.yml` from
an exact `vX.Y.Z` tag. The workflow:

- validates tag and manifest versions;
- runs formatting, Clippy and the complete Rust suite;
- states explicitly that the executable, MSI and NSIS are not
  Authenticode-signed and may trigger Windows publisher or SmartScreen
  warnings;
- publishes SHA-256 checksums and an SPDX SBOM;
- generates a GitHub artifact attestation tied to the source commit.

If any of these gates fails, the release must not be treated as official.

## Repository security controls

Changes to `main` go through a pull request and must pass the Windows build and
test job plus CodeQL analysis for Rust and JavaScript/TypeScript. The only
exception is the repository's deploy keys: since 2026-10-12, by the owner's
decision, the `main` ruleset lets them push directly. That path is used only by
the maintainer's own tooling, never force-pushes, and its pushes still run the
same checks, which are reviewed after every push. The repository also enables:

- Dependabot alerts and automatic security update pull requests;
- scheduled version update pull requests for GitHub Actions, Cargo and npm;
- secret scanning and push protection;
- GitHub rules that reject branch deletion, force-pushes and merges with
  unresolved review threads or failing required checks (deploy keys excepted,
  as described above).

GitHub Actions are pinned to complete commit SHAs. Dependabot proposes their
updates as reviewable pull requests; no dependency update is merged
automatically.
