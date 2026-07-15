# Security Audit — ts-fullstack-sst

Generated: 2026-06-30
Agent: security-audit v2.0.0

## Project Profile

- **Stack**: TypeScript (ESM, `"type": "module"`), Node.js 20.x (`.nvmrc` = `lts/*`). Bundled & deployed with SST v3 (3.19.0) on top of AWS CDK (`aws-cdk-lib` 2.132.1, `constructs` 10.3.0).
- **Architecture**: Serverless monorepo (npm workspaces — root + `packages/functions`; a `pnpm-workspace.yaml` is also present). A single AWS Lambda handler sits behind an API Gateway V2 HTTP API. No frontend, no BFF, no background workers.
- **Auth mechanism**: **None detected.** The only API Gateway V2 route is declared without an authorizer (`sst.aws.ApiGatewayV2` route in `sst.config.ts` has no `auth`/JWT/Lambda authorizer). The endpoint is fully public.
- **Data stores**: No databases, caches, or file storage in this repository. Customer data lives in **Stripe** (external system of record).
- **External integrations**: **Stripe** (`stripe` ^14.23.0) — customer search + billing portal session creation. AWS (Lambda, API Gateway V2, Secrets/SSM via SST `Resource`).
- **Deployment**: AWS serverless, region `eu-central-1`, AWS profile `technical-interviews`. Provisioned by SST/Pulumi. No containers, no Kubernetes, no Terraform.
- **Existing security controls**: Stripe API key stored as an SST `Secret` (`STRIPE_KEY`) rather than hardcoded — secret is injected at runtime via `Resource.STRIPE_KEY.value` and linked to the route handler. `package-lock.json` committed with `integrity` hashes (lockfileVersion 3). `.gitignore` excludes `.sst`, `node_modules`, env files.
- **Primary attack surface**: The single unauthenticated public HTTP endpoint `GET /drivers/{driverId}/get-customer-portal-url` (`packages/functions/src/get-customer-portal-url.ts`). It accepts an attacker-controlled `driverId` path parameter, interpolates it into a Stripe search query, and — when a match is found — returns a Stripe **billing portal URL** for that customer. This is the dominant risk concentration: no authentication, attacker-controlled query input, and a sensitive capability (billing portal access) behind it.

---

## STRIDE Analysis

### Step 1: Components

| # | Component | Description |
|---|-----------|-------------|
| C1 | External caller (Internet client) | Any unauthenticated HTTP client; no identity is established. |
| C2 | API Gateway V2 HTTP API (`Api`) | Public ingress; route defined in `sst.config.ts` with no authorizer, throttling, or access logging configured. |
| C3 | Lambda handler `get-customer-portal-url` | `packages/functions/src/get-customer-portal-url.ts`; reads `driverId`, queries Stripe, returns billing portal URL. Holds the `STRIPE_KEY` secret. |
| C4 | Stripe API (external) | Customer search + billing portal session creation. Trust boundary to a third-party SaaS. |
| C5 | `STRIPE_KEY` secret (SST Secret / SSM) | Credential injected into the Lambda at runtime via `Resource.STRIPE_KEY.value`. |

### Step 2: STRIDE Analysis Table

| Component | Threat Category | Threat Description | Risk (H/M/L) | Existing Mitigation | Recommended Action |
|-----------|----------------|-------------------|---------------|--------------------|--------------------|
| C2 API Gateway route | **S**poofing | Route has no authorizer (`sst.config.ts` defines `GET /drivers/{driverId}/...` with no JWT/Lambda authorizer). Any caller can act as any "driver" — there is no identity to verify, so a request for `driverId=X` is indistinguishable from the real owner of X. | **H** | None — endpoint is public. | Add an authorizer (JWT/Cognito or Lambda authorizer) and verify the caller is authorised for the requested `driverId`. |
| C3 Lambda handler | **T**ampering | `driverId` is string-interpolated directly into the Stripe search query: `` query: `metadata['ppDriverId']:'${driverId}'` `` (`get-customer-portal-url.ts:11-13`). A crafted `driverId` containing a quote/operator can alter the query semantics (Stripe Search Query injection — CWE-74 / CWE-943), potentially matching unintended customers. | **H** | None — raw interpolation. | Validate/whitelist `driverId` (e.g. strict regex/UUID) and escape single quotes before building the query; treat the search string as untrusted input. |
| C2/C3 Request path | **R**epudiation | No application logging or API Gateway access logging is configured. There is no audit trail tying a billing-portal-URL issuance to a request/source IP/time, so actions cannot be attributed or disputed after the fact. | **M** | None detected. | Enable API Gateway access logs and structured Lambda logging (request id, source IP, `driverId`, outcome); ship to CloudWatch with retention. |
| C3 Response / C4 Stripe | **I**nfo Disclosure | The unauthenticated endpoint returns a Stripe **billing portal URL** for any `driverId` that resolves to a customer (BOLA/IDOR). Anyone who can guess/enumerate a `driverId` gains a link into that customer's billing portal. Additionally, the 404 body `No customer found with driverId ${driverId}` (`get-customer-portal-url.ts:18-20`) confirms existence/non-existence, enabling enumeration. | **H** | None. | Require authentication + per-resource authorization before issuing portal URLs; return a generic 404/403 that does not reveal existence; consider short-lived, single-use links. |
| C2 API Gateway / C4 Stripe | **D**enial of Service | No throttling/rate limiting is set on the route. Each request triggers a Stripe `customers.search` + `billingPortal.sessions.create` call. An attacker can flood the endpoint to exhaust Stripe rate limits, drive Lambda/Stripe cost amplification, and degrade availability. | **H** | API Gateway default account-level throttling only (not route-specific or tuned). | Configure route/stage throttling and burst limits; add WAF/rate-based rules; consider caching/short-circuit for unknown drivers. |
| C3 Lambda / C5 Secret | **E**levation of Privilege | The Lambda holds the `STRIPE_KEY` secret which carries broad Stripe API capability. Because there is no authorization layer, any anonymous caller effectively exercises a privileged Stripe operation (creating billing portal sessions) through the function. The handler also creates the session for `customers.data[0]` without confirming the match belongs to the caller. | **H** | Secret stored as SST Secret (not hardcoded); linked only to this handler. | Scope the Stripe key to the minimum capability (restricted key); gate the privileged operation behind authorization; validate the matched customer against the authenticated principal. |
| C3 Response | **I**nfo Disclosure | Driver/customer **enumeration** via differential responses (200 with URL vs 404 with explicit message) lets an attacker map valid `driverId` values. | **M** | None. | Normalise responses for the unauthenticated case; rate-limit; require auth. |
| C5 Secret handling | **T**ampering / Spoofing | If the Stripe key were ever logged or leaked (no logging today, but no explicit redaction policy), it could be reused to impersonate the application against Stripe. | **L** | Secret injected at runtime, not in source/`.gitignore` covers env files. | Add a redaction/logging policy; rotate keys periodically; use restricted keys. |

### Step 3: Priority Summary (highest risk first)

1. **Unauthenticated endpoint (Spoofing / A01 / A07)** — no authorizer on the only route; any caller impersonates any driver. *Fix: add authorizer + per-`driverId` authorization.*
2. **BOLA/IDOR billing-portal-URL disclosure (Info Disclosure / A01)** — anonymous access to any customer's billing portal link. *Fix: authenticate + authorize per resource.*
3. **Stripe Search Query injection (Tampering / A03)** — raw `driverId` interpolation into the search query. *Fix: validate + escape input.*
4. **Privileged Stripe operation exposed without authz (Elevation of Privilege)** — anonymous callers drive privileged Stripe calls. *Fix: scope key + gate behind authz.*
5. **No rate limiting (Denial of Service + cost amplification)** — each call hits Stripe. *Fix: route throttling + WAF.*
6. **Customer enumeration via differential 404 (Info Disclosure)** — explicit "no customer found" message. *Fix: generic responses.*
7. **No logging/audit trail (Repudiation / A09)** — actions cannot be attributed. *Fix: access + structured logging.*
8. **Vulnerable transitive dependency `qs` (A06)** — moderate DoS advisory (see Phase 4). *Fix: update `stripe`/lockfile.*
9. **`.npmrc ignore-scripts` absent (Supply chain / A08)** — lifecycle scripts run on install. *Fix: add `.npmrc` with `ignore-scripts=true`.*

---

## OWASP Top 10 Assessment

| Category | Relevance | Risk | Findings |
|----------|-----------|------|----------|
| A01: Broken Access Control | HIGH | **H** | No access control anywhere. The only route lacks an authorizer and the handler performs no per-resource authorization, so any caller can request a billing portal URL for any `driverId` — textbook BOLA/IDOR. (`sst.config.ts:29-31`, `get-customer-portal-url.ts`) |
| A02: Cryptographic Failures | LOW | **L** | No app-managed crypto or PII at rest in this repo (Stripe holds the data). `return_url` is the static `https://example.com/account` (HTTPS). TLS is provided by API Gateway/Stripe. Low residual risk. |
| A03: Injection | HIGH | **H** | Stripe Search Query injection: `driverId` is interpolated unescaped into `` `metadata['ppDriverId']:'${driverId}'` `` (`get-customer-portal-url.ts:11-13`). CWE-74 / CWE-943. No SQL/NoSQL/OS command injection (no such sinks present). |
| A04: Insecure Design | HIGH | **H** | The design exposes a sensitive capability (issue billing portal link) on an anonymous endpoint keyed only by a guessable identifier, with no threat-model-driven controls (no authn, no authz, no rate limit, no logging). The insecurity is architectural, not a single bug. |
| A05: Security Misconfiguration | MED | **M** | Route configured without authorizer, throttling, or access logging. README documents an unauthenticated `curl` as the intended usage, implying this is the current expected configuration. No security headers configured (limited relevance for a JSON API). |
| A06: Vulnerable & Outdated Components | MED | **M** | `npm audit` reports 1 moderate production advisory: `qs` (GHSA-q8mj-m7cp-5q26, CWE-476 DoS) pulled transitively via `stripe`. Dev/build tree (`aws-cdk-lib`, `sst`, `hono`, `minimatch`, etc.) has further advisories but is not shipped in the Lambda runtime. See Phase 4. |
| A07: Identification & Authentication Failures | HIGH | **H** | There is no authentication mechanism at all. Anonymous identity is implicitly accepted for a sensitive operation. |
| A08: Software & Data Integrity Failures | MED | **M** | Lockfile is committed with `integrity` hashes (good). However, `.npmrc` does not set `ignore-scripts=true`, so dependency lifecycle scripts can execute on install (CI/dev integrity exposure). No CI workflows present to assess artifact-signing/provenance. |
| A09: Security Logging & Monitoring Failures | HIGH | **H** | No application logging, no API Gateway access logging, no alerting. Attacks (enumeration, abuse) would be invisible and unattributable. |
| A10: Server-Side Request Forgery (SSRF) | LOW | **L** | No user-controlled URL is fetched server-side. `return_url` is a hardcoded constant, and outbound calls go only to the Stripe SDK. Low risk. |

---

## Dependency Security Review

**Audit tool run:** `npm audit` (npm 10.9.8, Node v20.20.2) — executed successfully (network available).

**Production dependency tree** (`npm audit --omit=dev`): **1 moderate, 0 high, 0 critical** (25 prod dependencies).

| Package | Severity | Advisory | CWE | Path | Notes |
|---------|----------|----------|-----|------|-------|
| `qs` (6.11.1–6.15.1) | Moderate | [GHSA-q8mj-m7cp-5q26](https://github.com/advisories/GHSA-q8mj-m7cp-5q26) | CWE-476 | transitive via `stripe` | Remotely-triggerable DoS in `qs.stringify` with `encodeValuesOnly`. `fixAvailable: true` — bump `stripe`/regenerate lockfile. |

**Full tree incl. dev/build** (`npm audit`): **12 total — 6 high, 6 moderate, 0 critical** (250 total deps; prod 25, dev 226). High-severity advisories are confined to the dev/build/tooling tree and are **not bundled into the Lambda runtime**: `@modelcontextprotocol/sdk` ([GHSA-8r9q-7v3j-jr4g](https://github.com/advisories/GHSA-8r9q-7v3j-jr4g)), `aws-cdk-lib` ([GHSA-v4mq-x674-ff73](https://github.com/advisories/GHSA-v4mq-x674-ff73)), `hono` ([GHSA-92vj-g62v-jqhh](https://github.com/advisories/GHSA-92vj-g62v-jqhh)), `minimatch` ([GHSA-3ppc-4f35-3m26](https://github.com/advisories/GHSA-3ppc-4f35-3m26)), `opencontrol`, `sst`. Moderate: `ajv`, `aws-sdk`, `brace-expansion`, `qs`, `uuid`, `yaml`. These ship with SST/CDK tooling; track and upgrade with the SST version.

**Supply-chain / maintenance notes:**
- Direct production dependency surface is small (`stripe` only) — low direct attack surface.
- `stripe` is a well-maintained, single-vendor SDK; primary transitive risk is `qs` above.
- No `postinstall`/`preinstall`/`prepare` lifecycle scripts in either `package.json` (checked) — good.
- Transitive depth is dominated by the SST/CDK build toolchain (dev only), not the runtime.

**Recommendation:** Regenerate `package-lock.json` after bumping `stripe` to clear the `qs` advisory; periodically upgrade SST/CDK to clear dev-tree highs; run `npm audit --omit=dev` in CI as a gate (no CI is present today).

---

## Supply Chain Integrity

Static checks against the detected stack (npm only — `detect-stacks.sh` reports `npm`; no Docker/Python/Maven/Gradle/.NET/Go, no `.github/workflows/`, no Terraform, no pre-commit config).

| Area | Check | Result |
|------|-------|--------|
| CI/CD pinning | `.github/workflows/` present? | **N/A** — no CI workflows in repo. (No Actions to pin, no `pull_request_target`, no permission grants to assess.) |
| npm install scripts | `.npmrc` sets `ignore-scripts=true`? | **HIGH — absent.** No `.npmrc` exists, so dependency lifecycle scripts are permitted to run on `npm install`. Per Phase 5 npm rule this is flagged HIGH. *Recommend adding `.npmrc` with `ignore-scripts=true`.* |
| npm lifecycle scripts | Project's own `package.json` lifecycle scripts | None (`scripts` are `dev/build/deploy/remove/console/typecheck/test` — no install hooks). Good. |
| Lockfile integrity | `package-lock.json` committed with `integrity` | **OK** — committed, lockfileVersion 3, 211 `integrity` entries present. |
| Container images | `Dockerfile` present? | **N/A** — no Dockerfile / `.dockerignore`. |
| Infrastructure as Code | `*.tf` present? | **N/A** — no Terraform; infra defined via SST/CDK in TypeScript. |
| Build scripts & hooks | `curl|sh` / `wget|sh` in Makefile/`*.sh`; pre-commit `rev` pinning | **N/A** — no Makefile, no `*.sh`, no `.pre-commit-config.yaml`. |
| Dependency confusion | Public-before-private registry ordering | **N/A** — no `.npmrc`/registry config; default public registry only, no private scoped registry configured. |

---

## Build Artifact Protection

The artifact protection script (`protect-artifact.sh`) was run from the repo root. Detected stack: **npm only** (no Docker/Python/Maven/Gradle/.NET/Go). Actions taken:

| Action | Target | Result |
|--------|--------|--------|
| Add `export-ignore` rule | `.gitattributes` (created) | **ADDED** — `docs/security-audit.md export-ignore` excludes the audit from `git archive` outputs. |
| Exclude from npm package (root) | `.npmignore` (created) | **ADDED** — `docs/security-audit.md`. Script flagged `RISK_REGISTER: MEDIUM` because the package uses a `.npmignore` denylist rather than a `files` allowlist (see #11). |
| Exclude from npm package (functions) | `packages/functions/.npmignore` (created) | **ADDED** — `docs/security-audit.md`. Script flagged `RISK_REGISTER: MEDIUM` for the same reason (see #12). |

**Outstanding warnings:** The script's standard footer notes that items marked `WARNING`/`ACTION NEEDED` would require manual changes — none were emitted for this repo (the only excluder invoked was npm, which auto-edited `.npmignore`). The two `RISK_REGISTER: MEDIUM` findings (denylist vs allowlist) are recorded as separate rows #11 and #12 below. Recommendation per script output: replace each `.npmignore` denylist with a `"files"` allowlist in the corresponding `package.json` (e.g. `"files": ["dist/", "lib/", "README.md", "LICENSE"]`) so audit/internal files are excluded by default.

---

## Summary

### Critical Findings (immediate action needed)
- **Unauthenticated access to billing portal URLs (Broken Access Control / BOLA).** The single public route has no authorizer and the handler performs no per-resource authorization, so anyone can obtain a Stripe billing portal link for any `driverId` (#1, #3). This is the combination of A01 + A07 and is the most urgent issue.

### High-Risk Findings (address in next sprint)
- **Stripe Search Query injection** via unescaped `driverId` interpolation (#2).
- **Elevation of privilege** — anonymous callers drive a privileged Stripe operation (#6).
- **No rate limiting / throttling** → DoS and Stripe cost amplification (#5).
- **`.npmrc ignore-scripts` absent** → install-time supply-chain exposure (#9).

### Medium-Risk Findings (track and plan)
- **No logging / audit trail** (Repudiation, A09) (#4).
- **Customer/driver enumeration** via differential 404 message (#7).
- **Vulnerable transitive dependency `qs`** (moderate DoS, fix available) (#8).
- **npm denylist (`.npmignore`) instead of `files` allowlist** in each package (#11, #12 — added in Phase 6).

### Positive Findings (things done well)
- Stripe API key is stored as an **SST Secret** and injected at runtime — not hardcoded, and env files are gitignored.
- `package-lock.json` is committed with `integrity` hashes (reproducible installs).
- No dependency **lifecycle install scripts** in the project's own manifests.
- Small **direct production dependency** surface (`stripe` only).
- `return_url` is a fixed constant (no SSRF via user-controlled redirect).

---

## Risk Register

Track the status of each finding using ROAM. New findings start as **Open** — a pre-triage state indicating the finding has not yet been assigned a ROAM status:
- **Open** — not yet triaged; default state for new findings
- **Resolved** — fixed, no longer a risk
- **Owned** — assigned to a person/team, mitigation in progress
- **Accepted** — risk acknowledged, decision made not to mitigate (requires sign-off)
- **Mitigated** — controls in place that reduce the risk to acceptable level

| ID | Severity | Finding | ROAM Status | Owner | Decided By | Decision Date | Review Date | Notes |
|----|----------|---------|-------------|-------|------------|---------------|-------------|-------|
| 1 | Critical | No authorizer on `GET /drivers/{driverId}/get-customer-portal-url` (`sst.config.ts:29-31`); anonymous callers can request any driver's billing portal URL — Broken Access Control / BOLA (A01, A07). | Open | — | — | — | — | — |
| 2 | High | Stripe Search Query injection: `driverId` interpolated unescaped into `metadata['ppDriverId']:'${driverId}'` (`get-customer-portal-url.ts:11-13`). CWE-74 / CWE-943 (A03). | Open | — | — | — | — | — |
| 3 | High | Information disclosure: unauthenticated endpoint returns a Stripe billing portal URL for any resolvable `driverId` (IDOR) (`get-customer-portal-url.ts:25-35`). | Open | — | — | — | — | — |
| 4 | Medium | No application or API Gateway access logging configured — actions cannot be attributed (Repudiation, A09). | Open | — | — | — | — | — |
| 5 | High | No route-level rate limiting/throttling; each request hits Stripe → DoS and cost amplification (DoS). | Open | — | — | — | — | — |
| 6 | High | Elevation of privilege: Lambda holds broad-capability `STRIPE_KEY`; absent authorization lets anonymous callers drive privileged Stripe operations (`get-customer-portal-url.ts:5-7,25-28`). | Open | — | — | — | — | — |
| 7 | Medium | Customer/driver enumeration via differential 404 message `No customer found with driverId ${driverId}` (`get-customer-portal-url.ts:18-20`). | Open | — | — | — | — | — |
| 8 | Medium | Vulnerable transitive dependency `qs` (6.11.1–6.15.1) via `stripe` — DoS, GHSA-q8mj-m7cp-5q26, CWE-476; fix available (A06). | Open | — | — | — | — | — |
| 9 | High | `.npmrc` with `ignore-scripts=true` absent — dependency lifecycle scripts may run on install (supply chain, A08). | Open | — | — | — | — | — |
| 10 | Low | `return_url` hardcoded to `https://example.com/account` (`get-customer-portal-url.ts:27`) — placeholder, not a production destination (A02, low). | Open | — | — | — | — | — |
| 11 | Medium | Root package (`.`) uses a `.npmignore` denylist to exclude the audit; a `"files"` allowlist in `package.json` is recommended (safer publish posture). Flagged by `protect-artifact.sh` (Phase 6). | Open | — | — | — | — | — |
| 12 | Medium | `packages/functions` uses a `.npmignore` denylist to exclude the audit; a `"files"` allowlist in `package.json` is recommended. Flagged by `protect-artifact.sh` (Phase 6). | Open | — | — | — | — | — |

## Revision History
| Date | Trigger | Key Changes |
|------|---------|-------------|
| 2026-06-30 | Initial audit | Full security audit created (STRIDE, OWASP Top 10, dependency review via `npm audit`, supply chain integrity, build artifact protection). |
