# Security Audit — ts-fullstack-sst

Generated: 2026-10-07
Agent: security-audit v2.0.0

## Project Profile

- **Stack**: TypeScript (ESM, `"type": "module"`), Node.js LTS (`.nvmrc` = `lts/*`; v24 as of 2026-11-10). Bundled & deployed with SST v3 (3.19.3) on top of AWS CDK (`aws-cdk-lib` 2.275.0, `constructs` 10.8.1). Versions updated 2026-11-10.
- **Architecture**: Serverless monorepo (npm workspaces — root + `packages/functions`; npm is the only package manager — `pnpm-workspace.yaml`/`pnpm-lock.yaml` were removed in 4b4350d). A single AWS Lambda handler sits behind an API Gateway V2 HTTP API. No frontend, no BFF, no background workers.
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
| A06: Vulnerable & Outdated Components | MED | **M** | `npm audit` reports 1 moderate production advisory: `qs` (GHSA-q8mj-m7cp-5q26, CWE-476 DoS) pulled transitively via `stripe`. Dev/build tree (`aws-cdk-lib`, `sst`, `hono`, `minimatch`, etc.) has further advisories but is not shipped in the Lambda runtime. See Phase 4. **2026-11-10:** the production tree is clean (`npm audit --omit=dev`: 0), and there are no high/critical findings in the dev tree. 3 MEDIUM/LOW residuals remain, see `document-cve.md`. |
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

**Update 2026-10-07: Critical/High transitive CVE remediation (Risk Register #13).**
> **Historical (superseded 2026-11-10):** the pnpm files described below (`pnpm-lock.yaml`, `pnpm-workspace.yaml`) were removed from the repository in 4b4350d. Only `package-lock.json` and the npm `"overrides"` in `package.json` remain. See *Update 2026-11-10*.
- **Two lockfiles were committed at the time**: `package-lock.json` (npm) and `pnpm-lock.yaml` (pnpm v9 lockfile, `pnpm-workspace.yaml`). pnpm does **not** read npm's `"overrides"` in `package.json`. Earlier npm-only overrides (`hono`, `@modelcontextprotocol/sdk`) therefore never reached `pnpm-lock.yaml`, and advisories in packages present in both lockfiles were reported twice.
- Fixed 8 CVEs (10 alerts) in the dev/build tree. None ship in the Lambda bundle (the `stripe`-only runtime):

| CVE | Advisory | Package | Severity | Was → Now | Path |
|-----|----------|---------|----------|-----------|------|
| CVE-2025-62610 | [GHSA-m732-5p4w-x69g](https://github.com/advisories/GHSA-m732-5p4w-x69g) | `hono` | High | 4.7.4 → 4.12.25 (pnpm) | `sst` → `opencontrol@0.0.6` |
| CVE-2026-22817 | [GHSA-f67f-6cw9-8mq4](https://github.com/advisories/GHSA-f67f-6cw9-8mq4) | `hono` | High | 4.7.4 → 4.12.25 (pnpm) | `sst` → `opencontrol@0.0.6` |
| CVE-2026-22818 | [GHSA-3vhc-576x-3qv4](https://github.com/advisories/GHSA-3vhc-576x-3qv4) | `hono` | High | 4.7.4 → 4.12.25 (pnpm) | `sst` → `opencontrol@0.0.6` |
| CVE-2026-29045 | [GHSA-q5qw-h33p-qvwr](https://github.com/advisories/GHSA-q5qw-h33p-qvwr) | `hono` | High | 4.7.4 → 4.12.25 (pnpm) | `sst` → `opencontrol@0.0.6` |
| CVE-2026-54290 | [GHSA-88fw-hqm2-52qc](https://github.com/advisories/GHSA-88fw-hqm2-52qc) | `hono` | High | 4.7.4 → 4.12.25 (pnpm) | `sst` → `opencontrol@0.0.6` |
| CVE-2025-66414 | [GHSA-w48q-cv73-mx4w](https://github.com/advisories/GHSA-w48q-cv73-mx4w) | `@modelcontextprotocol/sdk` | High | 1.6.1 → 1.29.0 (pnpm) | `sst` → `opencontrol@0.0.6` |
| CVE-2026-90711 | [GHSA-jqcg-44mw-7w3h](https://github.com/advisories/GHSA-jqcg-44mw-7w3h) | `proxy-addr` | Critical | 2.0.7 → 2.0.8 (both) | `opencontrol` → `@modelcontextprotocol/sdk` → `express@5.2.1` |
| CVE-2026-93749 | [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q) | `source-map-js` | High | 1.2.1 → 1.2.2 (both) | `vitest` → `vite` → `postcss` (test toolchain) |

- **Method**: every `sst` 3.x release pins `opencontrol@0.0.6`, which pins `hono@4.7.4` and `@modelcontextprotocol/sdk@1.6.1`, and `express@5.2.1` (the latest) still allows `proxy-addr@2.0.7`. No fixed parent exists within the current major. The fix therefore uses CVE-commented `overrides:` in `pnpm-workspace.yaml`, mirroring the existing npm overrides. On the npm side, `proxy-addr` and `source-map-js` got an in-range lockfile update (`npm update`); no new npm overrides were needed. A compatibility pin `opencontrol>zod: 3.25.76` is also required, because `@modelcontextprotocol/sdk@1.29.0` imports `zod/v4` (peer `^3.25 || ^4.0`).
- **Known limitation**: `opencontrol@0.0.6` wraps the SDK's request schemas in a zod-3 `z.union`. That is incompatible with every patched SDK (>= 1.24, zod-v4 schemas), so its MCP handler returns HTTP 500 (`option._parseSync is not a function`) under both lockfiles. The same was already true of the npm tree before this change. This app never imports `opencontrol` or uses `sst.aws.OpenControl`, so it has no functional impact.
- **Audit after remediation**: `pnpm audit` went from 1 critical / 8 high / 36 moderate / 4 low to 0 critical / 1 high / 11 moderate / 2 low. `npm audit` went from 1 critical / 6 high / 10 moderate to 0 critical / 5 high / 10 moderate. The prod-only trees are `pnpm audit --prod` with no vulnerabilities and `npm audit --omit=dev` with 1 moderate (`qs`). The remaining advisories are tracked as Risk Register #14.

**Update 2026-11-10: High CVE alert remediation and package update (Risk Register #15).**
- **Scope**: fixes the HIGH alerts CVE-2026-104850, CVE-2026-111767 (`@modelcontextprotocol/sdk`) and CVE-2026-112942 (`vite`), plus every other HIGH reported by `trivy fs --scanners vuln --include-dev-deps` (Trivy 0.75.0) and `npm audit`. All of them are in the dev/build/test tree. None ship in the Lambda bundle (the `stripe`-only runtime).
- **Single package manager**: the pnpm files were removed in 4b4350d. npm `"overrides"` in the root `package.json` are now the **only** override mechanism, and `package-lock.json` is the only lockfile.
- Fixed HIGH findings:

| CVE / ID | Advisory | Package | Severity | Was → Now | Path |
|----------|----------|---------|----------|-----------|------|
| CVE-2026-104850 | [GHSA-6qxp-vccf-f47h](https://github.com/advisories/GHSA-6qxp-vccf-f47h) | `@modelcontextprotocol/sdk` | High | 1.29.0 → 1.32.2 | `sst` → `opencontrol@0.0.6` (override) |
| CVE-2026-111767 | [GHSA-22jm-h49p-29qw](https://github.com/advisories/GHSA-22jm-h49p-29qw) | `@modelcontextprotocol/sdk` | High | 1.29.0 → 1.32.2 | `sst` → `opencontrol@0.0.6` (override) |
| CVE-2026-111768 | [GHSA-46jr-4wx8-v453](https://github.com/advisories/GHSA-46jr-4wx8-v453) | `@modelcontextprotocol/sdk` | High | 1.29.0 → 1.32.2 | `sst` → `opencontrol@0.0.6` (override) |
| — | [GHSA-f897-62hf-6gxq](https://github.com/advisories/GHSA-f897-62hf-6gxq) | `@modelcontextprotocol/sdk` | High | 1.29.0 → 1.32.2 | `sst` → `opencontrol@0.0.6` (override) |
| CVE-2026-112942 | [GHSA-587h-7wmj-h5pm](https://github.com/advisories/GHSA-587h-7wmj-h5pm) | `vite` | High | 8.1.5 → 8.3.7 | `vitest` / `@vitest/mocker` (test toolchain) |
| CVE-2026-14257 | [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg) | `brace-expansion` (bundled) | High | 5.0.7 → 5.0.12 | `aws-cdk-lib` bundle |
| CVE-2026-69152 | [GHSA-rgw5-rvv9-x895](https://github.com/advisories/GHSA-rgw5-rvv9-x895) | `brace-expansion` (bundled) | High | 5.0.7 → 5.0.12 | `aws-cdk-lib` bundle |
| CVE-2026-102276 | [GHSA-6j4f-fj2g-mc7p](https://github.com/advisories/GHSA-6j4f-fj2g-mc7p) | `brace-expansion` (bundled) | High | 5.0.7 → 5.0.12 | `aws-cdk-lib` bundle |
| CVE-2026-102278 | [GHSA-qhr7-859c-m2p7](https://github.com/advisories/GHSA-qhr7-859c-m2p7) | `brace-expansion` (bundled) | High | 5.0.7 → 5.0.12 | `aws-cdk-lib` bundle |
| CVE-2026-111181 | [GHSA-27r3-jxmh-p828](https://github.com/advisories/GHSA-27r3-jxmh-p828) | `body-parser` | High | 2.3.0 → 2.4.0 | `@modelcontextprotocol/sdk` → `express` |
| CVE-2026-67213 | [GHSA-2v37-7h3g-55p8](https://github.com/advisories/GHSA-2v37-7h3g-55p8) | `nanoid` | High | 3.3.16 → 3.3.20 | `vite` → `postcss` |
| — | [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) | `zod` (+ `zod-to-json-schema`) | High (npm audit only) | 3.24.2 → 4.6.7 (`zod-to-json-schema` 3.24.3 → 3.25.2) | `sst` → `opencontrol@0.0.6` (scoped override) |

- **Also cleared** (MEDIUM/LOW, 39 → 3): `hono` 4.12.25 → 4.13.17 (12 findings), `fast-uri` 3.1.7 → 3.1.9 (5), `ip-address` 10.3.1 → 10.7.6 (5), `qs` 6.15.3 → 6.17.1 (3, **runtime** via `stripe` — see #8), `vite` (4 more), `@vitest/mocker`/`vitest` 4.1.10 → 4.1.12 (3), `@modelcontextprotocol/sdk` (2 more: CVE-2026-111769, CVE-2026-111771), `brace-expansion` (1 more: CVE-2026-102277), `@hono/node-server` 1.19.17 → 2.1.6 (1).
- **Method**:
  - Direct dev dependencies bumped: `sst` 3.19.0 → 3.19.3 (latest 3.x), `aws-cdk-lib` 2.262.1 → 2.275.0 (latest; bundles `brace-expansion` 5.0.12, and bundled deps cannot be overridden), `constructs` 10.5.0 → 10.8.1, `vitest` `^4.1.0` → `^4.1.12`.
  - npm `overrides` bumped: `@modelcontextprotocol/sdk` 1.29.0 → 1.32.2, `hono` 4.12.25 → 4.13.17, `fast-uri` 3.1.7 → 3.1.9. Added a scoped override `opencontrol > zod 4.6.7 / zod-to-json-schema 3.25.2`.
  - Ran `npm install` + `npm update` for in-range transitive updates (`vite`, `body-parser`, `nanoid`, `qs`, `ip-address`, …).
  - The regenerated lockfile now also lists every platform `@rolldown/binding-*` package. Before, only `darwin-arm64` was recorded, so `vitest` could not start on Linux.
- **Override rationale** (dated 2026-11-10; `package.json` is JSON and cannot carry comments):
  - Every `sst` 3.x release (through 3.19.3) depends on `opencontrol@0.0.6`, which pins `@modelcontextprotocol/sdk@1.6.1`, `hono@4.7.4`, `zod@3.24.2` and `zod-to-json-schema@3.24.3`. No 3.x parent fixes them, and `fast-uri` is reached via the sdk's `ajv`.
  - There is no patched `zod` 3.x for GHSA-mrhx-c7xc-m3w5 (fixed in 4.6.6), which is why the `opencontrol` zod override crosses a major version.
  - **Remove these overrides once the project moves to `sst` 4.x.** `sst@4.17.2` no longer depends on `opencontrol` or `aws-sdk` v2.
- **`opencontrol` compatibility**: as noted on 2026-10-07, `opencontrol@0.0.6`'s MCP handler was already broken with any patched SDK (`option._parseSync is not a function`: its zod-3 `z.union` wraps the SDK's zod-4 schemas).
  - With the zod-4 override, a smoke test of `createMcp()` shows `initialize` and `tools/call` work again. `tools/list` returns an empty `inputSchema`, because `zod-to-json-schema` only understands zod-v3 internals.
  - This app never imports `opencontrol` or uses `sst.aws.OpenControl`, so there is no functional impact.
- **Verification**:
  - `packages/functions` `tsc --noEmit`: OK.
  - `vitest run --passWithNoTests`: OK. It previously failed on the missing rolldown binding.
  - Root `npm run typecheck`: OK after `sst install` generated `.sst/platform`.
  - `npm ci`: clean.
- **Audit after remediation**:
  - Trivy (dev deps included) went from 11 high / 34 medium / 5 low to 0 high / 2 medium / 1 low.
  - `npm audit` went from 9 high / 12 moderate to 0 high / 4 moderate / 1 low.
  - `npm audit --omit=dev` went from 1 moderate (`qs`) to **0**.
  - The residuals are documented in [`document-cve.md`](../document-cve.md) and tracked as #14.

---

## Supply Chain Integrity

Static checks against the detected stack (npm only — `detect-stacks.sh` reports `npm`; no Docker/Python/Maven/Gradle/.NET/Go, no `.github/workflows/`, no Terraform, no pre-commit config).

| Area | Check | Result |
|------|-------|--------|
| CI/CD pinning | `.github/workflows/` present? | **N/A** — no CI workflows in repo. (No Actions to pin, no `pull_request_target`, no permission grants to assess.) |
| npm install scripts | `.npmrc` sets `ignore-scripts=true`? | **HIGH — absent.** No `.npmrc` exists, so dependency lifecycle scripts are permitted to run on `npm install`. Per Phase 5 npm rule this is flagged HIGH. *Recommend adding `.npmrc` with `ignore-scripts=true`.* |
| npm lifecycle scripts | Project's own `package.json` lifecycle scripts | None (`scripts` are `dev/build/deploy/remove/console/typecheck/test` — no install hooks). Good. |
| Lockfile integrity | `package-lock.json` committed with `integrity` | **OK** — committed, lockfileVersion 3, 211 `integrity` entries present. |
| Lockfile integrity (pnpm) | `pnpm-lock.yaml` committed with `integrity` | **N/A — removed (historical).** The 2026-10-07 dual-lockfile caveat no longer applies: `pnpm-lock.yaml` and `pnpm-workspace.yaml` were removed in 4b4350d. npm is the only package manager, and security overrides live only in `"overrides"` in the root `package.json` (2026-11-10). |
| npm `overrides` | Transitive pins for CVE remediation | **OK, temporary** (2026-11-10). Overrides: `@modelcontextprotocol/sdk` 1.32.2, `hono` 4.13.17, `fast-uri` 3.1.9, and `opencontrol` > `zod` 4.6.7 / `zod-to-json-schema` 3.25.2. They exist because `sst` 3.x pins `opencontrol@0.0.6`. Remove them once the project moves to `sst` 4.x (see #15). |
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
- ~~**Vulnerable transitive dependency `qs`** (moderate DoS, fix available) (#8).~~ Resolved 2026-11-10 (`qs` 6.17.1).
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
| 8 | Medium | Vulnerable transitive dependency `qs` (6.11.1–6.15.1) via `stripe` — DoS, GHSA-q8mj-m7cp-5q26, CWE-476; fix available (A06). | Resolved | — | — | 2026-11-10 | — | In-range lockfile update to `qs` 6.17.1 (`stripe` 14.25.0). This also clears the later `qs` advisories CVE-2026-82417, CVE-2026-82562 and CVE-2026-110816. `npm audit --omit=dev` now reports 0 vulnerabilities. |
| 9 | High | `.npmrc` with `ignore-scripts=true` absent — dependency lifecycle scripts may run on install (supply chain, A08). | Open | — | — | — | — | — |
| 10 | Low | `return_url` hardcoded to `https://example.com/account` (`get-customer-portal-url.ts:27`) — placeholder, not a production destination (A02, low). | Open | — | — | — | — | — |
| 11 | Medium | Root package (`.`) uses a `.npmignore` denylist to exclude the audit; a `"files"` allowlist in `package.json` is recommended (safer publish posture). Flagged by `protect-artifact.sh` (Phase 6). | Open | — | — | — | — | — |
| 12 | Medium | `packages/functions` uses a `.npmignore` denylist to exclude the audit; a `"files"` allowlist in `package.json` is recommended. Flagged by `protect-artifact.sh` (Phase 6). | Open | — | — | — | — | — |
| 13 | High | Critical/High CVEs in transitive dev/build deps `hono` (CVE-2025-62610, CVE-2026-22817, CVE-2026-22818, CVE-2026-29045, CVE-2026-54290), `@modelcontextprotocol/sdk` (CVE-2025-66414), `proxy-addr` (CVE-2026-90711, critical) and `source-map-js` (CVE-2026-93749), across `package-lock.json` and `pnpm-lock.yaml` (A06). | Resolved | — | — | 2026-10-07 | — | Fixed by `pnpm-workspace.yaml` overrides (`hono` 4.12.25, `@modelcontextprotocol/sdk` 1.29.0, `proxy-addr` 2.0.8, `source-map-js` 1.2.2, compat pin `opencontrol>zod` 3.25.76) plus an in-range `npm update` of `proxy-addr` and `source-map-js` in `package-lock.json`. No first-party use of hono JWT/JWK/CORS, `trust proxy` or MCP HTTP transports. `opencontrol@0.0.6` (unused) cannot handle MCP requests with any patched SDK. *(Historical: the pnpm files were later removed in 4b4350d, and the npm overrides were superseded by #15.)* |
| 14 | Medium | Remaining dev/build-tree advisories after #13: `@modelcontextprotocol/sdk` CVE-2026-104850 / GHSA-6qxp-vccf-f47h (high, needs >= 1.31.0); `hono` moderates/lows needing >= 4.12.27 / 4.12.34 / 4.13.5 / 4.13.7; `uuid`, `aws-sdk` (via `sst`); npm-only `fast-uri` 3.1.7 (GHSA-hrr3-gc8f-f4qj, needs 3.1.8), `ip-address`, `nanoid`, `brace-expansion`, `vitest`; dual npm/pnpm lockfiles that need duplicated overrides (A06/A08). | Open | — | — | — | — | Out of scope for the 2026-10-07 Critical/High remediation. Prod-only trees: pnpm has no advisories; npm has `qs` only (#8). **2026-11-10 update — mostly resolved by #15.** Fixed: sdk, `hono`, `fast-uri`, `ip-address`, `nanoid`, `brace-expansion`, `vitest`. The dual-lockfile issue is gone because the pnpm files were removed. **Still open (MEDIUM/LOW, no non-breaking fix):** `minimatch` 10.2.6 bundled in `aws-cdk-lib` 2.275.0 (CVE-2026-118764 / GHSA-g3hv-75wg-m249, needs 11.0.1; bundled, so it can't be overridden); `uuid` 8.0.0 via `sst` → `aws-sdk@2.1692.0` exact pins (CVE-2026-41907 / GHSA-w5hq-g745-h8pq); `aws-sdk` v2 GHSA-j965-2qgj-vjmq (LOW, no patched release). All three are documented in `document-cve.md`. The `uuid`/`aws-sdk` items are expected to go away with `sst` 4.x. |
| 15 | High | HIGH CVEs in transitive dev/build/test deps: `@modelcontextprotocol/sdk` 1.29.0 (CVE-2026-104850, CVE-2026-111767, CVE-2026-111768, GHSA-f897-62hf-6gxq), `vite` 8.1.5 (CVE-2026-112942), `brace-expansion` 5.0.7 bundled in `aws-cdk-lib` (CVE-2026-14257, CVE-2026-69152, CVE-2026-102276, CVE-2026-102278), `body-parser` 2.3.0 (CVE-2026-111181), `nanoid` 3.3.16 (CVE-2026-67213), `zod` 3.24.2 via `opencontrol` (GHSA-mrhx-c7xc-m3w5, npm audit) (A06). | Resolved | — | — | 2026-11-10 | — | Fixed by: npm override bumps (sdk 1.32.2, `hono` 4.13.17, `fast-uri` 3.1.9); a new scoped override (`opencontrol` > `zod` 4.6.7 / `zod-to-json-schema` 3.25.2); `aws-cdk-lib` 2.275.0 (bundles `brace-expansion` 5.0.12); `sst` 3.19.3; `constructs` 10.8.1; `vitest` ^4.1.12; and an in-range `npm update` (`vite` 8.3.7, `body-parser` 2.4.0, `nanoid` 3.3.20). Trivy `--include-dev-deps` and `npm audit` both report 0 high/critical. The overrides exist because `sst` 3.x → `opencontrol@0.0.6` pins old versions. Remove them when moving to `sst` 4.x. |

## Revision History
| Date | Trigger | Key Changes |
|------|---------|-------------|
| 2026-06-30 | Initial audit | Full security audit created (STRIDE, OWASP Top 10, dependency review via `npm audit`, supply chain integrity, build artifact protection). |
| 2026-10-07 | Critical/High CVE alert remediation (manual update; the `/security-audit` skill was not available in this environment) | Dependency review: documented the dual npm/pnpm lockfiles and the remediation of 8 CVEs (hono ×5, `@modelcontextprotocol/sdk`, `proxy-addr`, `source-map-js`). Supply chain: added a `pnpm-lock.yaml` row (pnpm >= 10 needed for workspace overrides). Risk Register: added #13 (Resolved) and #14 (Open, remaining advisories). |
| 2026-11-10 | High CVE alert remediation (CVE-2026-104850, CVE-2026-111767, CVE-2026-112942) and package update. Manual update: the `/security-audit` skill was not available in this environment (only `trivy` and `security-review`). | Project profile: updated the stack versions (`sst` 3.19.3, `aws-cdk-lib` 2.275.0, `constructs` 10.8.1) and noted that npm is the only package manager. Dependency review: added *Update 2026-11-10* (12 HIGH findings fixed, method, override rationale, audit before/after) and marked the 2026-10-07 dual-lockfile text as historical. Supply chain: marked the pnpm row removed and added an npm `overrides` row. Risk Register: #8 → Resolved, #14 updated (3 MEDIUM/LOW residuals remain, see `document-cve.md`), added #15 (Resolved). |
