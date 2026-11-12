# Security roadmap — Immich ASVS 5.0.0 L1/L2 remediation

Derived from [`ASVS-5.0.0-L1-L2-assessment-immich.md`](./ASVS-5.0.0-L1-L2-assessment-immich.md) (see the [assessment JSON](./ASVS-5.0.0-L1-L2-assessment-immich.json) for the underlying data and evidence references).

Of the 253 assessed requirements: 90 fully implemented, 79 partially, 37 not implemented, 47 not applicable. 49 implemented controls have no test coverage. Themes below are ordered by descending risk exposure: L1 gaps outrank L2 (ASVS Level 1 is the baseline), `Implemented: no` outranks `partial`, and untested controls add verification risk on top.

## 1. Anti-automation & credential attacks — highest exposure

The internet-facing login has no protection against brute force or credential stuffing.

- **V6.3.1** (L1, not implemented): no rate limiting, lockout or throttling on authentication endpoints. Only a constant-time dummy bcrypt compare prevents user-enumeration timing.
- **V2.4.1** (L2): no anti-automation controls on any endpoint (login, upload, search).
- **V6.2.4 / V6.2.12** (L1/L2): no common-password or breached-password (HIBP-style) screening at registration or password change.
- **V6.1.1 / V6.1.2** (L1/L2): anti-automation controls and context-specific word lists are not documented.

Proposed work: per-IP/per-account throttling or lockout on auth and costly endpoints; breached-password check on registration and password change; document the controls.

## 2. Upload hardening

- **V5.2.1** (L1, not implemented): multer is configured without file size limits and the JSON body limit does not apply to multipart uploads — no server-side upload size cap exists.
- **V5.2.2** (L1, partial): only extensions are checked at upload; content is validated later during processing, not by magic bytes.
- **V1.3.4** (L2, partial): SVG uploads accepted and served inline without sanitization.
- **V5.4.3** (L2): no malware/antivirus scanning of uploads.

Proposed work: multer `limits` per upload type; magic-byte validation at upload; serve SVG originals with `Content-Disposition: attachment` or sanitize; document the malware-scan decision (accept risk or integrate a scanner).

## 3. Session lifecycle management

Sessions never expire and are not bounded.

- **V7.3.1 / V7.3.2** (L2, not implemented): no inactivity timeout, no absolute maximum session lifetime (cookie maxAge is 400 days, session rows persist until logout).
- **V7.1.1 – V7.1.3** (L2): session lifetimes, concurrent-session limits and SSO lifetime coordination are not documented (there is no limit).
- **V7.5.1** (L2): sensitive account changes (email update) do not require re-authentication or the current password.
- **V7.2.4 / V7.4.2 / V7.4.3** (L2, partial): re-login does not terminate previous sessions; disabling a user does not kill sessions; password-change session invalidation is opt-in.
- **V7.4.5** (L2, partial): no admin endpoint to revoke an individual user's sessions.

Proposed work: configurable inactivity + absolute session timeouts; require current password for email/password changes; terminate other sessions on password change and user disablement; admin session-revocation endpoint.

## 4. Browser & client hardening — quick wins

Mostly configuration-level changes.

- **V3.3.3** (L2, not implemented): no `__Host-` cookie prefixes.
- **V3.4.1** (L1, partial): HSTS sent with helmet's default 180-day max-age, no `includeSubDomains`; ASVS requires ≥ 1 year.
- **V3.4.3 / V3.4.6** (L2, partial): CSP lacks `frame-ancestors` (only obsolete `X-Frame-Options` protects) and uses `base-uri 'self'` instead of `'none'`.
- **V4.4.2** (L2, not implemented): WebSocket handshake does not validate the Origin header.
- **V3.2.2** (L1, partial): the admin-configured login-page message is rendered as raw HTML via Svelte `{@html}`; sanitize it or render as text.
- **V3.3.1 / V3.3.4** (L1/L2, partial): `Secure` flag depends on request protocol; session token also returned in the login response body.

Proposed work: `__Host-` prefixes + explicit HSTS policy in `helmet.json`; CSP `frame-ancestors 'none'`, `base-uri 'none'`; Origin allowlist in the socket.io adapter; text-render the login page message.

## 5. Verification debt — add tests for existing controls

49 implemented controls have no test coverage (assessment `Tested: no` despite `Implemented: yes`). Highest-value additions:

- **V9.1.1 / V9.1.2**: JWT signature verification and the HS256 algorithm allowlist (workflow execution tokens) — no tests exist for either.
- **V10.5.3 / V10.5.4**: OIDC issuer and audience validation — no mismatch tests exist.
- **V3.4.4 / V3.4.5**: `X-Content-Type-Options: nosniff` and Referrer-Policy headers — no assertions.
- **V1.3.11**: mail header-injection safety (zod `toEmail` + nodemailer structured messages).
- **V7.6.2, V6.5.3/4, V6.2.9/10, V13.4.4, V16.2.4, V16.3.4**: session creation consent, CSPRNG token generation, password length ceiling absence, TRACE rejection, log format, error logging.

These require no product change — only regression tests — and they convert unverified claims into enforced behavior.

## 6. Documentation & governance — unblocks many L2 verdicts at once

Several chapters fail wholesale on missing documentation rather than missing code:

- **V8.1.1 / V8.1.2**: authorization documentation (function-level and field-level rules exist only in code).
- **V11.1.1 / V11.1.2**: cryptographic key-management policy and crypto inventory.
- **V14.1.1 / V14.1.2 / V14.2.4**: sensitive-data classification and per-class protection requirements.
- **V16.1.1 / V16.3.2 / V16.3.3**: logging inventory; failed-authorization logging; defined security-event list.
- **V2.1.1 / V2.1.2 / V2.1.3**: input-validation, cross-field and business-limit documentation.
- **V15.1.1 / V15.1.2**: risk-based dependency remediation time frames and SBOM (renovate exists, no policy/inventory).

Proposed work: a `docs/docs/developer/security/` section covering the above; wire failed-authorization logging into the auth guard; enable a dependency-scanning/SBOM workflow.

## 7. Transport & internal TLS — deployment-level

- **V12.1.1 / V12.2.1 / V12.2.2** (L1, partial): TLS protocol/cipher policy and certificates are entirely reverse-proxy concerns; the app listens on plain HTTP. Document hardening requirements (TLS 1.2+, HSTS) as deployment prerequisites.
- **V12.3.1 – V12.3.4** (L2): internal traffic (Postgres, Redis, ML service) is unencrypted on the container network by default; DB `sslmode` exists but is not enforced.
- **V13.2.4 / V13.2.5** (L2): no outbound destination allowlist for admin-configured URLs (ML endpoint, map tiles, OAuth issuer).

Proposed work: document the TLS threat model for internal networks; add optional internal TLS/mTLS configuration; an admin-configurable outbound allowlist.

## Suggested sequencing

1. **Sprint 1 (config/quick wins):** theme 4 + multer limits from theme 2 — small diffs, immediate hardening.
2. **Sprint 2 (anti-automation):** theme 1 — the largest single risk reduction.
3. **Sprint 3 (sessions):** theme 3 — user-visible behavior changes, needs design decisions (timeout values).
4. **Continuous:** theme 5 test additions alongside each change.
5. **Sprint 4 (governance):** theme 6 documentation — mostly writing, unlocks ~20 L2 verdicts.
6. **Sprint 5 (transport):** theme 7 — coordinated with deployment/docs.
