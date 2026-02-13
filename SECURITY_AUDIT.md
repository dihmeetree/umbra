# Security Audit Report — Statera Protocol

**Date:** 2026-02-13
**Scope:** Full codebase security review of the Statera Protocol monorepo
**Application:** Privacy-preserving, over-collateralized stablecoin protocol on Midnight blockchain

---

## Executive Summary

This audit covers the entire Statera Protocol codebase including smart contracts (Compact language), backend services (Node.js/Express/Hono), frontend (React/Vite), CLI tools, oracle services, Rust cryptography crates, and CI/CD infrastructure. **27 findings** were identified across critical, high, medium, and low severities.

| Severity | Count |
|----------|-------|
| Critical | 5     |
| High     | 7     |
| Medium   | 10    |
| Low      | 5     |

---

## Critical Severity

### C-01: Hardcoded Admin Secret Keys

**Files:**
- `packages/oracle-server/src/oracle.ts:47`
- `packages/oracle-server/src/game.ts:75`

**Description:** Admin secret keys used for cryptographic operations are hardcoded as trivial, predictable constants:

```typescript
// oracle.ts:47
const adminSecretKey = 12345678901234567890n

// game.ts:75
const adminSecretKey = 98765432109876543210n
```

These keys are used to derive admin public keys via `ecMulGenerator()` and are passed as constructor arguments to smart contract simulators. Any attacker who reads the source can derive the admin public key and forge authorized operations.

**Impact:** Complete compromise of oracle and game admin functionality. An attacker can manipulate oracle prices, forge attestations, and control game state.

**Recommendation:** Generate admin keys from a cryptographically secure random source or derive them from a securely stored seed. Load secrets from environment variables, never hardcode them.

---

### C-02: Server-Side Request Forgery (SSRF) via User-Controlled Prover URL

**Files:**
- `packages/oracle-server/src/index.ts:69`
- `packages/oracle-server/src/index.ts:88`

**Description:** The oracle server accepts a `proverUrl` parameter directly from user input (query string and POST body) and makes HTTP requests to it without any validation:

```typescript
// GET endpoint - line 69
const proverUrl = c.req.query('proverUrl') || 'http://localhost:8080'

// POST endpoint - line 88
const body = await c.req.json<{ proverUrl?: string }>()
const proverUrl = body.proverUrl || 'http://localhost:8080'
```

The URL is passed directly to `fetchVerifiedBitcoinPrice()` which creates a `ProverClient` and makes HTTP requests to the attacker-controlled URL.

**Impact:** An attacker can:
- Scan internal network services
- Access cloud metadata endpoints (e.g., `http://169.254.169.254/`)
- Exfiltrate data from internal services
- Perform port scanning

**Recommendation:** Validate the prover URL against an allowlist of trusted prover endpoints. At minimum, reject private/internal IP ranges and enforce HTTPS.

---

### C-03: Unrestricted CORS on Liquidation Server

**File:** `packages/server/src/server.ts:12`

**Description:** The Express server uses `cors()` with no configuration, which allows requests from any origin:

```typescript
app.use(cors())
```

This means any website can make authenticated cross-origin requests to the liquidation endpoint.

**Impact:** Any malicious website a user visits can trigger liquidation requests against the server. Combined with the lack of authentication (see C-04), this allows unauthenticated cross-origin liquidation of any position.

**Recommendation:** Configure CORS with an explicit origin allowlist:
```typescript
app.use(cors({ origin: ['https://your-domain.com'], methods: ['POST'] }))
```

---

### C-04: No Authentication or Authorization on Any API Endpoint

**Files:**
- `packages/server/src/routes/liquidation_route.ts:11` — `POST /api/v1/liquidate`
- `packages/oracle-server/src/index.ts:27` — `POST /api/oracle/init`
- `packages/oracle-server/src/index.ts:67-101` — `GET/POST /api/oracle/price`
- `packages/oracle-server/src/index.ts:106` — `POST /api/game/init`
- `packages/oracle-server/src/index.ts:161` — `POST /api/game/resolve`

**Description:** Every API endpoint across all services is publicly accessible with no authentication, authorization, or API key requirement. Sensitive operations like liquidation execution, oracle initialization, and game state manipulation require no credentials.

```typescript
// liquidation_route.ts:11 — no auth middleware
router.post('/liquidate', async (req: Request, res: Response) => {
  // Directly processes request
})
```

**Impact:** Anyone can:
- Liquidate arbitrary positions via `POST /api/v1/liquidate`
- Re-initialize the oracle, resetting its state via `POST /api/oracle/init`
- Manipulate game outcomes via `POST /api/game/resolve`

**Recommendation:** Implement authentication middleware (API keys, JWT tokens, or wallet-based signature verification) on all sensitive endpoints. Add authorization checks to ensure callers have permission for the requested operation.

---

### C-05: Wallet Seed Logged in Plaintext

**File:** `packages/server/lib/utils/wallet.ts:346`

**Description:** The wallet mnemonic seed (the master private key for the liquidation bot wallet) is logged in plaintext:

```typescript
logger.info(`Your wallet seed is: ${seed}`)
```

This occurs in the `buildWalletAndWaitForFunds` function, which is called during server initialization.

**Impact:** Anyone with access to log files, log aggregation systems, or console output can obtain the wallet's master private key and drain all funds.

**Recommendation:** Remove this log statement entirely. Never log private key material under any circumstances.

---

## High Severity

### H-01: No Input Validation on Liquidation Endpoint

**File:** `packages/server/src/controllers/liquidator.ts:13`

**Description:** The liquidation handler destructures request body fields with no validation:

```typescript
const { id, debt, collateral_amount } = req.body
```

There is no check that:
- Fields exist and are the correct type
- `debt` and `collateral_amount` are positive numbers
- `id` corresponds to an actual on-chain position
- Numeric values are within valid ranges

**Impact:** Invalid input can cause unexpected behavior, application crashes, or manipulation of the liquidation logic.

**Recommendation:** Add input validation using a schema validation library (e.g., `zod`, `joi`, or `io-ts` which is already a dependency). Validate types, ranges, and format of all user-supplied data.

---

### H-02: Hardcoded Proof Server IPs over Unencrypted HTTP

**File:** `packages/ui/src/lib/walletProofServerSetup.ts:1-4`

**Description:** Production proof server addresses are hardcoded with unencrypted HTTP:

```typescript
export const proof_servers = [
  'http://13.53.62.251:6300/',
  'http://51.20.55.91:6300/'
]
```

**Impact:**
- Traffic to/from proof servers is unencrypted and vulnerable to man-in-the-middle attacks
- IP addresses of infrastructure are exposed in source code
- Server changes require code redeployment

**Recommendation:** Use HTTPS for all proof server communication. Move server addresses to environment variables (`VITE_PROOF_SERVER_URLS`). Do not commit infrastructure IP addresses to source control.

---

### H-03: Unvalidated JSON Deserialization with `any` Types

**Files:**
- `packages/oracle-server/src/index.ts:165-166`
- `packages/server/lib/utils/wallet.ts:253`

**Description:** The game resolution endpoint uses `any` types for attestation data, bypassing all TypeScript safety:

```typescript
const body = await c.req.json<{
  prediction: 'up' | 'down'
  startAttestation: any  // No runtime validation
  endAttestation: any    // No runtime validation
}>()
```

Fields from the unvalidated body are then used in `BigInt()` constructors (lines 179-210), `Buffer.from()`, and passed to the contract simulator. Malformed input will cause unhandled runtime exceptions.

Similarly, wallet state is deserialized without validation:
```typescript
const stateObject = JSON.parse(serializedState) // wallet.ts:253
```

**Impact:** Type confusion, unhandled exceptions causing service crashes, potential manipulation of contract state through crafted payloads.

**Recommendation:** Define strict runtime validation schemas for all parsed JSON. Use `io-ts` (already in dependencies) or `zod` to validate structure, types, and value ranges before processing.

---

### H-04: Missing Rate Limiting on All Endpoints

**Files:**
- `packages/server/src/server.ts`
- `packages/oracle-server/src/index.ts`

**Description:** No rate limiting is configured on any endpoint. The liquidation endpoint, oracle initialization, and price fetching endpoints can all be called without restriction.

**Impact:** Denial of service through request flooding. Resource exhaustion. Potential financial impact if liquidation or oracle endpoints are abused at scale.

**Recommendation:** Add rate limiting middleware. For Express, use `express-rate-limit`. For Hono, use `hono/rate-limiter` or similar. Apply stricter limits to sensitive endpoints (liquidation, oracle init).

---

### H-05: Unsafe `as string` Type Assertions on Environment Variables

**File:** `packages/server/lib/config/wallet-config.ts:1-6`

**Description:** Environment variables are cast with `as string` without checking if they're defined:

```typescript
export const walletConfig = {
  proofServerUri: process.env.PROOF_SERVER_URI as string,
  indexerUri: process.env.INDEXER_URI as string,
  indexerWsUri: process.env.INDEXER_WS_URI as string,
  nodeUri: process.env.NODE_URI as string
}
```

If any variable is undefined, the value will be `undefined` cast to `string` at the type level, but remain `undefined` at runtime. This silences TypeScript errors while allowing runtime failures.

**Impact:** Silent misconfiguration leading to connections to `undefined` URIs, potential crashes, or default/fallback behavior that may be insecure.

**Recommendation:** Validate all required environment variables at startup and fail fast with a clear error message if any are missing.

---

### H-06: No CSRF Protection

**Files:**
- `packages/server/src/server.ts`
- `packages/oracle-server/src/index.ts`

**Description:** Neither the Express nor Hono server implements CSRF protection. Combined with the permissive CORS configuration (C-03), any website can forge requests to the backend.

**Impact:** Cross-site request forgery attacks can trigger liquidations or manipulate oracle state from any website the user visits.

**Recommendation:** Implement CSRF tokens for state-changing endpoints, or use strict same-origin CORS policies combined with authentication tokens in custom headers.

---

### H-07: Production Build Not Minified

**File:** `packages/ui/vite.config.ts:14`

**Description:** The Vite build configuration explicitly disables minification:

```typescript
build: {
  target: 'esnext',
  minify: false
}
```

**Impact:** Production JavaScript bundles contain unminified source code, exposing internal logic, variable names, API endpoints, and making reverse engineering trivial. Also increases bundle size.

**Recommendation:** Enable minification for production builds: `minify: 'esbuild'` or `minify: true`.

---

## Medium Severity

### M-01: Debug Logging of Sensitive Data in Production Code

**Files:**
- `packages/server/lib/utils/utils.ts:15-21`
- `packages/server/lib/utils/utils.ts:9` (nonce bytes logged)

**Description:** Debug `console.log` statements output byte arrays and nonce values:

```typescript
console.log('Converting array:', Array.from(array).map(b => b.toString(16).padStart(2, '0')).join(''))
console.log('Array length:', array.length)
```

And nonce bytes are logged via pino:
```typescript
logger?.info({ nonceBytes: Array.from(newBytes) }, 'Random nonce bytes')
```

**Impact:** Sensitive cryptographic material (nonces, byte arrays used for UUIDs/identifiers) can leak to log outputs.

**Recommendation:** Remove debug logging of byte arrays. Use appropriate log levels (debug/trace) gated behind environment checks. Never log cryptographic nonces.

---

### M-02: Deprecated `substr()` Method Usage

**File:** `packages/server/lib/utils/utils.ts:72`

**Description:** Uses the deprecated `String.prototype.substr()`:

```typescript
bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
```

**Impact:** May behave unexpectedly in future JavaScript engine versions.

**Recommendation:** Replace with `hex.substring(i, i + 2)` or `hex.slice(i, i + 2)`.

---

### M-03: Hardcoded Localhost CORS Origins

**File:** `packages/oracle-server/src/index.ts:15-19`

**Description:** CORS is configured with hardcoded localhost origins only:

```typescript
cors({
  origin: ['http://localhost:3001', 'http://localhost:3000'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
})
```

**Impact:** Will not work in production without modification, likely leading developers to weaken CORS to `*` as a quick fix.

**Recommendation:** Use environment variables for allowed origins with safe defaults.

---

### M-04: Silent Error Swallowing

**File:** `packages/ui/src/lib/client-side-liquidation-bot.ts:98`

**Description:** Exception caught and completely ignored:

```typescript
} catch (error) {}
```

**Impact:** Liquidation status check failures are silently swallowed, hiding critical monitoring failures from users.

**Recommendation:** At minimum, log the error. Implement proper error handling that notifies the user of monitoring failures.

---

### M-05: Mongoose Schema Validation Issues

**File:** `packages/server/src/models/tx-broadcast.ts:14-36`

**Description:** The Mongoose schema uses `require` instead of `required` (a common typo that Mongoose silently ignores):

```typescript
user: { type: String, require: true },     // Should be "required"
onchain_event: { type: OnchainEvent, require: true },
```

Additionally, no field-level validators (min/max length, pattern matching) are defined.

**Impact:** The `require: true` validation is silently not enforced. Documents can be created with missing `user` and `onchain_event` fields.

**Recommendation:** Fix `require` → `required`. Add appropriate validators for each field.

---

### M-06: Docker Image Uses `alpine:latest` Tag

**File:** `packages/cli/Dockerfile:8`

**Description:**

```dockerfile
FROM alpine:latest AS downloader
```

**Impact:** Non-reproducible builds. The base image can change between builds, introducing untested or vulnerable packages.

**Recommendation:** Pin to a specific Alpine version: `FROM alpine:3.19`.

---

### M-07: Docker Container Runs as Root

**File:** `packages/cli/Dockerfile`

**Description:** No `USER` directive is present in the Dockerfile. The container runs all processes as root.

**Impact:** If the container is compromised, the attacker has root access to the container filesystem and any mounted volumes.

**Recommendation:** Create a non-root user and switch to it before running services:
```dockerfile
RUN adduser -D appuser
USER appuser
```

---

### M-08: No Price Validation on Oracle/Game Endpoints

**Files:**
- `packages/oracle-server/src/index.ts:189,209`
- `packages/oracle-server/src/game.ts:154`

**Description:** Price values from user input are converted to `BigInt` without validation:

```typescript
priceCents: BigInt(Math.round(body.startAttestation.price * 100))
```

No checks for:
- Negative prices
- Zero prices
- Extremely large prices
- NaN/Infinity values

**Impact:** Invalid prices could cause incorrect liquidations, game manipulation, or arithmetic overflow in contract operations.

**Recommendation:** Validate that prices are positive finite numbers within reasonable bounds before processing.

---

### M-09: Missing `.dockerignore` File

**Description:** No `.dockerignore` file exists in the repository.

**Impact:** Docker build context may include `.git`, `node_modules`, `.env` files, and other sensitive or unnecessarily large files, increasing build time and potentially leaking secrets into image layers.

**Recommendation:** Create a `.dockerignore` file excluding `.git`, `node_modules`, `.env*`, `*.pem`, logs, and build artifacts.

---

### M-10: CI Pipeline Executes Unverified Remote Script

**File:** `.github/workflows/ci.yml:34`

**Description:** The CI pipeline downloads and executes a shell script from the internet:

```yaml
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/midnightntwrk/compact/releases/latest/download/compact-installer.sh | sh
```

While HTTPS and TLS 1.2 are enforced, there is no checksum or signature verification of the script before execution.

**Impact:** If the upstream repository or GitHub release is compromised, malicious code will execute in the CI environment with full access to repository secrets.

**Recommendation:** Pin the installer to a specific release version and verify its SHA-256 checksum before execution.

---

## Low Severity

### L-01: Unused Dependencies Increase Attack Surface

**File:** `packages/server/package.json`

**Description:** `mongodb`, `mongoose`, and `socket.io` are declared as dependencies but the server never connects to MongoDB and doesn't use Socket.io.

**Impact:** Larger dependency tree with more potential supply-chain vulnerabilities.

**Recommendation:** Remove unused dependencies.

---

### L-02: No Dependency Vulnerability Scanning in CI

**File:** `.github/workflows/ci.yml`

**Description:** The CI pipeline runs build, typecheck, and lint but does not run `yarn audit` or any SAST/dependency scanning tool.

**Impact:** Known vulnerable dependencies may be deployed without detection.

**Recommendation:** Add `yarn audit` or integrate a tool like Snyk/Dependabot into the CI pipeline.

---

### L-03: No `.env.example` File

**Description:** Required environment variables are scattered across multiple source files with no centralized documentation.

**Impact:** Developers may misconfigure the application, leading to insecure defaults or runtime errors.

**Recommendation:** Create `.env.example` documenting all required variables with placeholder values.

---

### L-04: Inconsistent WebSocket Library Versions

**Files:**
- Root `package.json`: `ws@^8.18.1`
- `packages/api/package.json`: `ws@8.17.1`
- `packages/cli/package.json`: `ws@^8.14.2`

**Impact:** Security patches may not be applied consistently across packages.

**Recommendation:** Align all packages to the same `ws` version using Yarn's `resolutions` field.

---

### L-05: Browser Polyfills for Node.js Crypto Modules

**File:** `packages/ui/vite.config.ts:23`

**Description:** The frontend aliases `crypto` to `crypto-browserify`:

```typescript
crypto: 'crypto-browserify',
```

**Impact:** `crypto-browserify` may have weaker or less-audited implementations compared to native Web Crypto API.

**Recommendation:** Where possible, use the native Web Crypto API (`window.crypto.subtle`) instead of browserified polyfills.

---

## Remediation Priority Matrix

### Immediate Action Required (Critical)

| ID | Finding | Effort |
|----|---------|--------|
| C-01 | Replace hardcoded admin secret keys with secure key derivation | Low |
| C-02 | Implement URL allowlist for prover endpoints | Low |
| C-03 | Configure CORS with explicit origin allowlist | Low |
| C-04 | Add authentication middleware to all endpoints | Medium |
| C-05 | Remove wallet seed logging | Low |

### Short-Term (High)

| ID | Finding | Effort |
|----|---------|--------|
| H-01 | Add input validation to liquidation endpoint | Low |
| H-02 | Move proof server URLs to env vars, enforce HTTPS | Low |
| H-03 | Add runtime validation for JSON payloads | Medium |
| H-04 | Add rate limiting middleware | Low |
| H-05 | Validate env vars at startup | Low |
| H-06 | Implement CSRF protection | Medium |
| H-07 | Enable production minification | Low |

### Medium-Term

| ID | Finding | Effort |
|----|---------|--------|
| M-01 | Remove debug logging | Low |
| M-02 | Replace deprecated `substr()` | Low |
| M-03 | Externalize CORS config | Low |
| M-04 | Fix silent error swallowing | Low |
| M-05 | Fix Mongoose schema (`require` → `required`) | Low |
| M-06 | Pin Docker base image version | Low |
| M-07 | Add non-root user to Docker | Low |
| M-08 | Add price validation | Low |
| M-09 | Create `.dockerignore` | Low |
| M-10 | Verify CI installer checksum | Medium |

### Backlog (Low)

| ID | Finding | Effort |
|----|---------|--------|
| L-01 | Remove unused dependencies | Low |
| L-02 | Add dependency scanning to CI | Low |
| L-03 | Create `.env.example` | Low |
| L-04 | Align `ws` versions | Low |
| L-05 | Evaluate native Web Crypto API usage | Medium |
