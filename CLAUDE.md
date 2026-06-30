## Security

This repository has a security audit at [`docs/security-audit.md`](docs/security-audit.md).

This audit covers design-time architectural security — STRIDE analysis, OWASP Top 10
assessment, dependency review, and supply chain integrity. It complements CI-based
tools (CodeQL, Trivy, GitHub Advanced Security) which cover build-time code scanning
and known CVEs.

**MUST consult this file when:**
- Making changes that affect the security architecture (auth, trust boundaries, data flow)
- Adding, removing, or upgrading dependencies
- Introducing new endpoints, services, or external integrations
- Reviewing code that touches authentication, authorization, or data handling
- Making infrastructure or deployment changes that affect the attack surface

**MUST re-run `/security-audit` when changes affect the security posture.** The audit
is a living document — the Risk Register tracks findings with ROAM status and must be
kept current. CI tools catch code-level bugs; this audit catches architectural gaps.
