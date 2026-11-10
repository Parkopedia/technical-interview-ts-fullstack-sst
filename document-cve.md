# Residual CVEs (no fix available in current parents)

Last reviewed: 2026-11-10

Scanned with `trivy fs --scanners vuln --include-dev-deps .` and `npm audit`.
After the 2026-11-10 dependency update, **no HIGH or CRITICAL vulnerabilities
remain**. The findings below are MEDIUM/LOW. They are not suppressed (there
is no `.trivyignore`). They are listed here because the current direct
dependencies give no non-breaking way to fix them.

All three are in **dev/build tooling only** (`sst` CLI and `aws-cdk-lib`). None
of them is bundled into the deployed Lambda functions, whose only runtime
dependency is `stripe`.

| ID | Severity | Package (installed) | Fixed in | Dependency path | Why it is not fixed |
|---|---|---|---|---|---|
| [CVE-2026-118764](https://avd.aquasec.com/nvd/cve-2026-118764) (npm: [GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249)) | MEDIUM | `minimatch` 10.2.6 | 11.0.1 | `aws-cdk-lib@2.275.0` → bundled `minimatch` | `minimatch` is a **bundled dependency** of `aws-cdk-lib` (`inBundle: true`), so npm `overrides` cannot replace it. `aws-cdk-lib` 2.275.0 is the latest release and still bundles 10.2.6. `npm audit fix --force` would *downgrade* to `aws-cdk-lib@2.239.0`, which is a breaking change. Remove this entry when a newer `aws-cdk-lib` bundles `minimatch` ≥ 11.0.1. |
| [CVE-2026-41907](https://avd.aquasec.com/nvd/cve-2026-41907) (npm: [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq)) | MEDIUM | `uuid` 8.0.0 | 11.1.1 / 12.0.1 / 13.0.1 | `sst@3.19.3` → `aws-sdk@2.1692.0` (exact pin) → `uuid@8.0.0` (exact pin) | Every `sst` 3.x release (3.19.3 is the latest) pins `aws-sdk@2.1692.0`, which pins `uuid@8.0.0`. The fix needs a forced **three-major** bump (8 → 11+) underneath the unmaintained AWS SDK v2, which was never tested against it. That was judged out of scope for a MEDIUM finding in this HIGH-remediation change. `npm audit fix --force` would install `sst@4.x`, a major framework upgrade. Resolve it when the project moves to `sst` 4.x. |
| [GHSA-j965-2qgj-vjmq](https://github.com/advisories/GHSA-j965-2qgj-vjmq) | LOW | `aws-sdk` 2.1692.0 | none (no patched v2 release) | `sst@3.19.3` → `aws-sdk@2.1692.0` | AWS SDK for JavaScript v2 is end-of-support and there is no fixed version. The advisory asks callers to validate the `region` parameter. This project does not call `aws-sdk` v2 directly: it is used internally by the `sst` CLI with region values from the developer's own config. Resolve it when the project moves to `sst` 4.x, which drops `aws-sdk` v2. |

## Out of scope: misconfiguration findings inside `node_modules`

When `trivy fs --scanners misconfig .` runs on a checkout **with
`node_modules` installed**, it reports HIGH misconfigurations (DS-0002, DS-0015,
DS-0019, KSV-0014, KSV-0118, AWS-0095). They come from third-party files shipped
inside `aws-cdk-lib` / `@aws-cdk/asset-*`: asset-layer Dockerfiles, the EKS
neuron device-plugin addon YAML, and CloudFormation snapshot templates. None of
these are repository files, none are deployed by this app, and none appear when
the repository itself is scanned (`--skip-dirs '**/node_modules'`, or a CI
checkout without `node_modules`).
