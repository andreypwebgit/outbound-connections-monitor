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
- signs the executable, MSI and NSIS artifacts with Microsoft Artifact Signing;
- verifies Authenticode signatures before publication;
- publishes SHA-256 checksums and an SPDX SBOM;
- generates a GitHub artifact attestation tied to the source commit.

If any of these gates fails, the release must not be treated as official.
