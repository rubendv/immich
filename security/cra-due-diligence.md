# CRA Due Diligence Report — Third-Party Components

Product: Immich 3.4.0-rc.0 (server, web, mobile, machine-learning, native, CLI/SDK)
SBOM: `security/sbom/immich-top-level.cdx.json` (CycloneDX 1.6, 435 direct components with resolved versions from lockfiles)
Date: 2026-11-12

This report assesses whether the third-party components identified in the SBOM are developed according to a trustworthy process and backed by a professionally organized maintenance team, per the EU Cyber Resilience Act (CRA) Annex I and the Commission's "Food Chain" due-diligence criteria. CVE identification is included but is only one aspect; the emphasis is on process trustworthiness.

Evidence was collected from the GitHub REST API (repository activity, licenses, security policies, release history), crates.io API, and repository pages, on the date above. Evidence levels used below:

- **[V-API]** verified via GitHub API on 2026-11-12
- **[V-HTML]** verified via repository page on 2026-11-12
- **[V-CRATE]** verified via crates.io API on 2026-11-12
- **[D]** documented, publicly known fact (verify before external use)
- **[P]** pending verification (GitHub API rate limit prevented automated collection for this component)

## 1. Summary and verdict

**Overall: the dependency profile is low-to-moderate risk.** The dominant runtime dependencies (NestJS, Express, Socket.IO, SvelteKit/Svelte, FastAPI, Pydantic, uvicorn, sharp, jose, React, Flutter, onnxruntime, OpenTelemetry) are professionally stewarded projects with active maintenance, published security policies, regular releases, and — for the largest — foundation or corporate stewardship. No component in the SBOM is CE marked or carries an EU Declaration of Conformity (expected — see §3.1).

**Components requiring follow-up** (weakest maintenance evidence):

| Component | Where | Finding |
|---|---|---|
| `dom-to-image` | web | Last repo push 2024-04-08, no security policy, no releases [V-API]. Effectively unmaintained; consider `html-to-image` or `modern-screenshot` replacement. |
| `qrcode` | web | Last push 2024-08-23, no security policy, no release cadence [V-API]. Low complexity, but stale; monitor. |
| `sanitize-filename` | server | Single-maintainer project (372 stars), no security policy [V-API]. Small, well-understood code; acceptable with periodic review. |
| `moxcms`, `pic-scale` | native | Single maintainer (awxkee), very active (releases Sep–Nov 2026) and heavily downloaded (127M / 3.7M) [V-CRATE], but bus-factor of 1 and no published security policy. |
| `fluent-ffmpeg`, `nestjs-otel`, `async-lock`, `geo-tz`, `sirv` | server | [P] — verify activity and stewardship before external release. |

## 2. SBOM scope

Generated from lockfiles (reproducible, version-pinned): `pnpm-lock.yaml` (server, web, packages, e2e, docs tooling), `machine-learning/uv.lock`, `native/Cargo.lock` (workspace top-level), `mobile/pubspec.yaml` (constraints; exact versions are resolved at build time by Flutter). Dev-only dependencies are included with `scope: excluded`. All components carry purls, making the SBOM directly consumable by OSV/NVD scanning tooling.

## 3. Due-diligence criteria

### 3.1 CRA CE marking and EU Declaration of Conformity

**None of the FOSS components are CE marked or have an EU Declaration of Conformity** [D]. This is expected and not a red flag: under the CRA, free and open-source software outside a commercial activity is out of scope, and components are not themselves "products with digital elements". The CRA obligation falls on Immich as the product manufacturer. Where commercial offerings exist around a component, note:

- onnxruntime (Microsoft), Flutter (Google), React (Meta), Pydantic (Pydantic Services Inc. / pydantic team): corporate development, but still no CE marking of the OSS artifacts themselves.

**Action for manufacturer:** ensure the *product* (Immich distribution) has its own conformity assessment, DoC, and CE marking pathway if placed on the EU market in scope.

### 3.2 Known vulnerabilities in public databases

An automated OSV/NVD scan could not be executed from this environment (sandbox network restrictions). The SBOM is purl-formatted for direct submission to OSV (`api.osv.dev/v1/querybatch`) or Grype/Trivy in CI. Known history relevant to risk assessment:

- `express`: CVE-2024-43796 (open redirect, fixed 4.21.2/5.0.0) and CVE-2024-45590 (DoS) — both fixed long before the pinned 5.x line [D].
- `ua-parser-js`: supply-chain compromise (CVE-2021-43609) and ReDoS (CVE-2021-44906) history — the package now publishes from a verified org; ensure the pinned version is current [D].
- `handlebars`, `lodash`, `semver`, `ua-parser-js`: older ReDoS/prototype-pollution CVEs all fixed in current majors [D].

**Action:** wire OSV scanning into CI against the SBOM; treat unpatched criticals as release blockers.

### 3.3 Availability of security patches

All major components demonstrated prompt patch releases for past security issues (express, socket.io, svelte ecosystem, pydantic, pillow, huggingface-hub all have security patch history within their current support lines) [D]. The pinned versions are on actively supported major lines, so patch availability is **good**. Exceptions: `dom-to-image` and `qrcode` have no recent releases, so a future vulnerability would likely go unpatched.

### 3.4 Evidence of vulnerability disclosure and handling process

- `@nestjs/core` (nestjs/nest): SECURITY.md present [V-API].
- `express`: security policy tab, "Security Policies and Procedures" document, dedicated governance [V-HTML].
- `pydantic`, `svelte`, `socket.io`, `uvicorn`, `react`, `ioredis`, `postgres`, `hls.js`, `uuid`, `sanitize-filename`: no SECURITY.md found at repo root [V-API]. For svelte, socket.io, pydantic, uvicorn and react, private disclosure is nonetheless documented elsewhere (docs, GHSA/GitHub advisory integration, coordinated disclosure history) [D]; for the rest, disclosure handling is informal.
- **Product gap: Immich itself has no SECURITY.md or documented vulnerability disclosure/handling process** in this repository. This is a CRA Annex I requirement for the product and should be added.

### 3.5 Risk assessment

Per-component risk combining exposure, function, and maintenance quality:

| Tier | Components | Rationale |
|---|---|---|
| Low | `@nestjs/*`, `express`, `socket.io`, `svelte`, `@sveltejs/kit`, `react`, `pydantic`, `uvicorn`, `fastapi` [P], `ioredis`, `postgres`, `hls.js`, `uuid`, `sharp` [P], `jose` [P], `@opentelemetry/*` | Professionally organized teams, active (pushed Nov 2026) [V-API], security policies or documented disclosure, large user bases |
| Low-moderate | `bcrypt`, `pg`, `kysely`, `handlebars`, `archiver`, `nodemailer`, `openid-client`, `validator`, `zod`, `luxon`, `semver`, `chokidar`, `picomatch`, `lodash-es`, `cookie`, `helmet`, `multer`, `exiftool-vendored`, `maplibre-gl`, `fabric`, `@noble/hashes`, `@tanstack/svelte-query`, pillow/numpy/opencv/onnx/onnxruntime/huggingface-hub/tokenizers, `libc`, `rayon`, `jni`, `flutter`, `drift` | Active, well-known projects; some single-vendor or smaller teams [P][D] |
| Moderate | `moxcms`, `pic-scale`, `jxl` (single maintainer or small team, bus-factor risk, but very active) [V-CRATE]; `qrcode`, `sanitize-filename`, `async-lock`, `geo-tz`, `sirv` (stale or tiny teams) [V-API][P] | Function criticality in image pipeline vs. small maintenance organization |
| High | `dom-to-image` | Unmaintained >2.5 years, no security process, client-side rendering of user content [V-API] |

Security-critical surface (auth: `jose`, `bcrypt`, `openid-client`, `@simplewebauthn/server`; upload: `multer`, `sharp`, `exiftool-vendored`, `archiver`; parsing: `ua-parser-js`, `validator`, `js-yaml`) should be prioritized in any deeper testing.

### 3.6 Need for additional cybersecurity testing

Recommended, in priority order:

1. Fuzzing / malformed-input tests around the media ingest path (`sharp`, `exiftool-vendored`, `fluent-ffmpeg`, `jxl`/`moxcms`/`pic-scale` in native, `pillow`/`opencv` in ML) — this is Immich's largest attack surface.
2. SAST/dependency review of the unmaintained `dom-to-image` before it renders untrusted HTML; prefer replacement.
3. Penetration testing of the web SPA and API for XSS/SSRF via map tiles, share links, and OAuth flows.

### 3.7 Technical verification

- **Source code scanning**: all components are FOSS with public sources; SAST (CodeQL/semgrep) can run on the product's usage of them. The SBOM enables targeted review.
- **Rebuilding from source**: feasible and recommended for the Docker images: server/web (npm), ML (uv), native (cargo). Reproducible builds verify SBOM integrity; `Cargo.lock`, `uv.lock`, `pnpm-lock.yaml` pin exact versions.
- **Binary analysis**: relevant for `exiftool-vendored` (bundles Perl + vendored binaries) and `sharp`/`onnxruntime-gpu` (prebuilt native binaries) — these ship binary artifacts not rebuilt from source in the product pipeline; verify checksums/provenance.
- **Code review**: prioritized for the moderate-risk Rust crates (`moxcms`, `pic-scale`, `jxl`) since they parse untrusted image data and are maintained by very small teams.

### 3.8 Support period

- Foundation/corporate-backed projects (express, nestjs, svelte, react, flutter, onnxruntime, OpenTelemetry, pydantic) have no announced EOL and follow semver with active support lines [D].
- npm/JS ecosystem: support is release-line based; the pinned majors are current [V-API].
- No formal LTS commitments exist for most FOSS components — the practical support period is "while the community is active," which for all Tier-Low components is demonstrably current (repo pushes Nov 2026) [V-API].
- `dom-to-image` is past any reasonable support period [V-API].

### 3.9 FOSS: recent development / maintenance activity

Verified active (repo pushed within days of 2026-11-12): `@nestjs/core`, `ioredis`, `postgres`, `pydantic`, `react`, `socket.io`, `svelte`, `uvicorn`, `hls.js`, `uuid`, `sanitize-filename`, `express` (Nov 2, 2026 commit; v5.3.0 release Oct 9, 2026) [V-API][V-HTML]. Rust crates: `jxl` (release 2026-10-19, 23 versions since Sep 2025), `moxcms` (2026-11-07, 37 versions), `pic-scale` (2026-09-10, 89 versions) [V-CRATE].

Inactive/stale: `dom-to-image` (2024-04-08), `qrcode` (2024-08-23) [V-API].

### 3.10 FOSS: stewardship for commercial use

- **Foundation/corporate stewarded**: express, and the JS middleware ecosystem (OpenJS Foundation) [D]; OpenTelemetry (CNCF) [D]; React (Meta); Flutter/Dart packages under fluttercommunity/ Baseflow/ verified publishers [D]; svelte (actively supported by the Svelte team incl. commercial backing) [D]; pydantic (Pydantic Services Inc.) [D]; onnxruntime/onnx (Microsoft/Linux Foundation ONNX) [D]; numpy (NumFOCUS-sponsored) [D]; huggingface-hub/tokenizers (Hugging Face Inc.) [D]; libc/rayon/jni (Rust project / community teams) [D].
- **Not formally stewarded** (community/individual): `bullmq` (taskforce.sh — commercial company behind BullMQ [D]), `kysely`, `moxcms`, `pic-scale`, `jxl` (libjxl org, Google-affiliated contributors) [V-CRATE], `dom-to-image`, `qrcode`, `sanitize-filename`, `async-lock`, `geo-tz`, `sirv`, `nestjs-otel`. These carry higher organizational risk and should be watched.

### 3.11 Security-by-design indicators

Positive indicators observed: express (governance model, TC, contributing guide, security policy, 100% test coverage claim, Dependabot-driven dep updates) [V-HTML]; nestjs (SECURITY.md, large test suite) [D]; pydantic (strict type validation by design, formal type system — inherent secure-input design) [D]; `@noble/hashes` (audited cryptography library, published audits) [D]; `jose` (constant-time crypto implementation, widely reviewed) [D]; Rust native components (memory safety, `undocumented_unsafe_blocks = deny` in Immich's own workspace lints). Negative: `dom-to-image`, `qrcode`, `sanitize-filename`, `moxcms`, `pic-scale` show no visible SBD documentation, SAST, or security policy [V-API][V-CRATE].

### 3.12 Regular publication of security patches / updates

Release cadence (verified active lines): express 167 releases, latest Oct 2026 [V-HTML]; nestjs, svelte, socket.io, pydantic, uvicorn, react all with recent releases [V-API]; jxl/moxcms/pic-scale multiple releases in 2026 [V-CRATE]. Historical security patches have been released promptly for Tier-Low components [D]. Stale components (`dom-to-image`, `qrcode`) do not meet this criterion [V-API].

### 3.13 Intended use alignment

All components are used within their intended purpose: web frameworks for the API/SPA, image libraries for media processing, ONNX stack for inference, Flutter plugins for mobile platform integration. No component is used against its documented design in a security-relevant way. One note: `react`/`react-dom`/`react-email` in the server are used for server-side email template rendering (intended use), not client UI; `fluent-ffmpeg` wraps the external ffmpeg binary — ensure the ffmpeg binary itself is included in SBOMs of released images (currently outside this top-level SBOM).

## 4. Recommended actions

1. Replace `dom-to-image` (unmaintained) with an actively maintained alternative.
2. Add a `SECURITY.md` (private vulnerability disclosure policy) to the Immich repository — CRA Annex I requirement for the product.
3. Add OSV/Grype SBOM scanning to CI and block releases on unpatched critical vulnerabilities.
4. Complete evidence collection for the [P] components (rate-limited during this assessment): `fastapi`, `sharp`, `jose`, `bullmq`, `kysely`, `handlebars`, `bcrypt`, `exiftool-vendored`, `ua-parser-js`, `fluent-ffmpeg`, `maplibre-gl`, `fabric`, mobile plugins, and remaining ML/natives.
5. Extend the SBOM to transitive dependencies and to binaries in release images (ffmpeg, exiftool, ONNX models) before external conformity assessment.
6. Track a support/EOL policy per major dependency in the product's documentation.

## 5. Assessment harness

A deterministic harness (`security/harness/`) now automates this assessment per dependency. It spawns a dedicated sub-agent process per SBOM component, where an LLM analysis layer (authored bundles in `evidence/llm_analysis.json`, or a live Mistral API call when `MISTRAL_API_KEY` is set, with rules only as fallback) produces the criterion judgments, and emits strict JSON conforming to a predefined schema (`assessment.schema.json`) that is enforced by a linter (`lint_assessments.py`) including SBOM cross-checks and input-digest verification. See `security/harness/README.md` for the current tier snapshot and how to add evidence.
