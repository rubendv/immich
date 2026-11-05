"""Build the ASVS 5.0.0 L1 assessment file for Immich from the source document."""

import json

SOURCE = "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
TARGET = "ASVS-5.0.0-L1-assessment-immich.json"

# Shortcode -> (Applicability, Implemented, Tested, Evidence)
ASSESSMENTS = {
    "V1.2.1": (
        "yes", "yes", "partial",
        "Web UI is Svelte, which context-escapes all interpolated output by default; API responses are serialized JSON (server/src/controllers, web/src). No manual HTML string building found.",
    ),
    "V1.2.2": (
        "yes", "partial", "no",
        "Web builds URLs from route params and API responses; no explicit URL-encoding validation or javascript:/data: protocol allowlist was found in dynamic URL construction.",
    ),
    "V1.2.3": (
        "yes", "yes", "partial",
        "All API responses are JSON serialized by NestJS; the web app consumes JSON via typed fetch wrappers and renders through Svelte's escaping. No dynamic JS/JSON string building found.",
    ),
    "V1.2.4": (
        "yes", "yes", "partial",
        "Server uses Kysely query builder with bound parameters (server/src/repositories); the few sql.raw/sql`...` fragments interpolate only internal constants (e.g. interval strings, array casts), not user input.",
    ),
    "V1.2.5": (
        "yes", "yes", "partial",
        "External tools (ffmpeg, exiftool) are invoked via child_process spawn with argument arrays and no shell interpolation (server/src/repositories/process.repository.ts); user data never reaches a shell command line.",
    ),
    "V1.3.1": (
        "no", "n/a", "n/a",
        "Immich accepts no HTML input: there is no WYSIWYG editor; all user text (descriptions, names, comments) is stored and rendered as escaped text by Svelte.",
    ),
    "V1.3.2": (
        "yes", "yes", "partial",
        "No eval()/new Function() in server or web source. External plugins execute in a separate sandboxed process and are admin-installed packages, not user input.",
    ),
    "V1.5.1": (
        "yes", "yes", "no",
        "XMP sidecar uploads are parsed with exiftool as an external tool (server/src/services/metadata.service.ts); no in-process XML parser with external-entity resolution is used in server or ML code.",
    ),
    "V2.1.1": (
        "yes", "partial", "no",
        "DTO schemas are defined with zod and annotated with descriptions/examples, exposed via generated OpenAPI spec (server/src/dtos, open-api). This documents expected structures, but there is no dedicated input-validation documentation.",
    ),
    "V2.2.1": (
        "yes", "yes", "partial",
        "Every endpoint DTO is validated by zod schemas (server/src/dtos, validation.ts) with typed constraints (lengths, enums, UUIDs, regex); server/test/validation.spec.ts covers parts of the schema surface.",
    ),
    "V2.2.2": (
        "yes", "yes", "partial",
        "Validation runs in the NestJS server via zod DTOs; web/mobile validation is UX-only. The security-relevant decisions (auth, permissions, quotas) are all validated server-side.",
    ),
    "V2.3.1": (
        "yes", "partial", "partial",
        "Critical flows are sequence-guarded: admin onboarding is only available before an admin exists (auth.guard.ts setup routes) and setup is disabled afterwards; most other flows are single-step and need no ordering.",
    ),
    "V3.2.1": (
        "yes", "partial", "no",
        "User-uploaded files are never served from a public folder; they are streamed through authenticated API routes with explicit Content-Type (server/src/controllers/assets). No CSP sandbox or Content-Disposition: attachment hardening for inline rendering contexts.",
    ),
    "V3.2.2": (
        "yes", "yes", "partial",
        "The web app renders untrusted content (file names, comments, metadata) exclusively through Svelte text interpolation, which escapes by default; no innerHTML/dangerouslySetInnerHTML usage found.",
    ),
    "V3.3.1": (
        "yes", "partial", "yes",
        "Auth cookies are HttpOnly, SameSite=Lax and Secure when the connection is secure (server/src/utils/response.ts), but names (immich_access etc.) lack the __Host-/__Secure- prefix and the Secure flag depends on request protocol. Cookie attributes asserted in server/src/controllers/auth.controller.spec.ts.",
    ),
    "V3.4.1": (
        "yes", "partial", "no",
        "Helmet middleware is enabled in production (server/src/app.common.ts), which sends HSTS by default, but with helmet's default max-age of 180 days (< 1 year) and without includeSubDomains; no explicit HSTS configuration.",
    ),
    "V3.4.2": (
        "yes", "yes", "no",
        "CORS is only enabled in development (app.enableCors() guarded by isDev()); production responses send no Access-Control-Allow-Origin at all, so cross-origin browser access is blocked rather than reflected.",
    ),
    "V3.5.1": (
        "yes", "partial", "partial",
        "No anti-forgery tokens. CSRF defense relies on SameSite=Lax cookies plus the absence of CORS headers in production; cookie attributes and auth flow are covered by auth.controller.spec.ts and e2e/src/specs/web/auth.e2e-spec.ts.",
    ),
    "V3.5.2": (
        "yes", "partial", "no",
        "The app does not rely on CORS preflight; state-changing endpoints expect JSON bodies (non-safelisted content type) and cookies are SameSite=Lax, so cross-site requests carry no credentials for POSTs. No explicit Origin/Content-Type validation tests.",
    ),
    "V3.5.3": (
        "yes", "yes", "no",
        "All state-changing API routes use POST/PUT/DELETE/PATCH via NestJS controllers; GET routes are read-only. No explicit test asserts method usage per route.",
    ),
    "V4.1.1": (
        "yes", "yes", "partial",
        "NestJS/Express sets application/json; charset=utf-8 for API responses; asset/file responses set the correct media type from the internal mime-type map. Covered indirectly by API e2e specs.",
    ),
    "V4.4.1": (
        "yes", "partial", "no",
        "WebSockets are served on the same HTTP server as the API (server/src/middleware/websocket.adapter.ts); TLS is terminated by the reverse proxy, the app itself listens on plain HTTP inside the container network.",
    ),
    "V5.2.1": (
        "yes", "no", "no",
        "Multer is configured without file size limits (server/src/middleware/file-upload.interceptor.ts) and the JSON body limit (10mb) does not apply to multipart uploads; no server-side upload size cap exists, relying on reverse proxy limits.",
    ),
    "V5.2.2": (
        "yes", "partial", "partial",
        "Upload fileFilter allowlists extensions per upload type (asset/sidecar/profile via mimeTypes.isAsset etc.); actual content is validated later by ffprobe/exiftool processing and thumbnail generation, not by magic bytes at upload time. Covered partially by e2e/src/specs/server/api/asset.e2e-spec.ts.",
    ),
    "V5.3.1": (
        "yes", "yes", "partial",
        "Uploads are stored in a storage folder outside the web root and served only through authenticated API endpoints that stream the file with a safe Content-Type; the static web root contains only built assets.",
    ),
    "V5.3.2": (
        "yes", "yes", "partial",
        "Stored filenames are generated server-side: uuid + sanitized extension (asset-media.service.ts getUploadFilename uses sanitize() and only takes the extension from user input); folders are built from internal ids/uuids, preventing traversal.",
    ),
    "V6.1.1": (
        "yes", "no", "no",
        "No documentation defines rate limiting, anti-automation or adaptive response controls for login; docs only mention reverse proxy setup in general.",
    ),
    "V6.2.1": (
        "yes", "yes", "yes",
        "ChangePasswordSchema enforces z.string().min(8) (server/src/dtos/auth.dto.ts:138); password rules covered in auth.service.spec.ts and API e2e specs.",
    ),
    "V6.2.2": (
        "yes", "yes", "yes",
        "POST /api/auth/change-password endpoint exists (auth.controller.ts) and is covered by auth.service.spec.ts and e2e specs.",
    ),
    "V6.2.3": (
        "yes", "yes", "yes",
        "ChangePasswordDto requires both current password and newPassword (server/src/dtos/auth.dto.ts:134-140); asserted in auth.service.spec.ts.",
    ),
    "V6.2.4": (
        "yes", "no", "no",
        "No check of submitted passwords against a common/top-3000 password list (no zxcvbn or blocklist dependency in server).",
    ),
    "V6.2.5": (
        "yes", "yes", "yes",
        "The only rule is minimum length; no character-class composition requirements exist in any password schema.",
    ),
    "V6.2.6": (
        "yes", "yes", "no",
        "Web login and password forms use type=password (web/src/routes/auth/login/+page.svelte, settings components); no explicit test asserts this.",
    ),
    "V6.2.7": (
        "yes", "yes", "no",
        "No paste-blocking, autocomplete=off or password-manager-hostile handlers anywhere in web/src; browsers and managers work unimpeded.",
    ),
    "V6.2.8": (
        "yes", "yes", "partial",
        "Passwords are compared exactly as received via bcrypt compare (crypto.repository.ts compareBcrypt); no truncation, trimming or case transformation in the login/change-password paths.",
    ),
    "V6.3.1": (
        "yes", "no", "no",
        "No rate limiting, account lockout or throttling in the server (no @nestjs/throttler or equivalent). Only a constant-time dummy bcrypt compare prevents timing-based user enumeration (auth.service.ts login).",
    ),
    "V6.3.2": (
        "yes", "yes", "partial",
        "No built-in default accounts: the first admin is created interactively during onboarding; setup routes are disabled once an admin exists (auth.guard.spec.ts covers this).",
    ),
    "V6.4.1": (
        "yes", "partial", "partial",
        "CLI bootstrap admin password is generated with randomBytes(24) (cli.service.ts) and meets the length policy, but there is no expiry after first use or time limit. Covered by cli.service.spec.ts.",
    ),
    "V6.4.2": (
        "yes", "yes", "no",
        "No password hints or knowledge-based secret questions exist anywhere in the schema, DTOs or UI.",
    ),
    "V7.2.1": (
        "yes", "yes", "yes",
        "Session tokens are validated server-side: AuthGuard hashes the presented token and looks up the session row in Postgres (auth.service.ts validateSession; middleware/auth.guard.ts). Covered by auth.guard.spec.ts and session e2e specs.",
    ),
    "V7.2.2": (
        "yes", "yes", "yes",
        "Each login generates a fresh random reference token stored hashed in the session table (base.service.ts createLoginResponse). Static API keys exist but are an explicit opt-in separate credential, not the session mechanism.",
    ),
    "V7.2.3": (
        "yes", "yes", "partial",
        "Session tokens are randomBytes(32) base64-encoded (>=128 bits entropy) from node crypto CSPRNG; only the SHA-256 hash is stored. Token format asserted in api-key/session specs; entropy is by construction, not measured by tests.",
    ),
    "V7.2.4": (
        "yes", "partial", "partial",
        "A new session token is created on every authentication, but previously issued sessions for the same user are not terminated on re-login; password change offers invalidateSessions as an opt-in.",
    ),
    "V7.4.1": (
        "yes", "yes", "yes",
        "Logout deletes the session row server-side (auth.service.ts logout -> sessionRepository.delete); the token is unusable afterwards. Covered by auth.service.spec.ts and e2e session specs.",
    ),
    "V7.4.2": (
        "yes", "partial", "partial",
        "Sessions are FK-cascade deleted with the user (session.table.ts onDelete: CASCADE), so account deletion removes sessions; password change can invalidate all sessions (invalidateSessions flag). Merely disabling a user does not proactively kill existing sessions.",
    ),
    "V8.1.1": (
        "yes", "no", "no",
        "There is no authorization documentation in docs/ defining function-level and data-level rules; the model exists only in code (Permission enum, access repository).",
    ),
    "V8.2.1": (
        "yes", "yes", "yes",
        "Routes are guarded by @Authenticated({ admin, permission }) with a central Permission enum checked in AuthGuard (middleware/auth.guard.ts); covered by auth.guard.spec.ts and controller specs.",
    ),
    "V8.2.2": (
        "yes", "yes", "yes",
        "Data-level access is enforced via the access repository (owner/partner/album/shared-link checks) for assets, albums and people; extensively covered by service specs and e2e specs (asset, album, shared-link).",
    ),
    "V8.3.1": (
        "yes", "yes", "yes",
        "All authorization decisions run in the NestJS server (guard + services + access repository); the web client only hides UI elements and never grants access.",
    ),
    "V9.1.1": (
        "yes", "yes", "partial",
        "Self-contained JWTs (workflow execution tokens) are verified with HS256 signature before use (crypto.repository.ts verifyJwt, workflow-execution.service.ts).",
    ),
    "V9.1.2": (
        "yes", "yes", "partial",
        "jwt.verify is called with an explicit algorithm allowlist algorithms: ['HS256'] and signing is pinned to HS256; 'none' cannot be accepted.",
    ),
    "V9.1.3": (
        "yes", "yes", "no",
        "The JWT secret comes from the server's environment config only; no jku/x5u/jwk header handling exists, so untrusted key sources cannot be injected.",
    ),
    "V9.2.1": (
        "yes", "partial", "no",
        "Reference session tokens are validated against the DB with no client-side expiry. The self-contained workflow JWTs are signed without exp/nbf claims, so no validity timespan is enforced for them.",
    ),
    "V10.4.1": (
        "no", "n/a", "n/a",
        "Immich is an OAuth client, not an authorization server; it consumes external OIDC providers via openid-client and never issues authorization codes.",
    ),
    "V10.4.2": (
        "no", "n/a", "n/a",
        "Not an authorization server; no authorization codes are issued by Immich.",
    ),
    "V10.4.3": (
        "no", "n/a", "n/a",
        "Not an authorization server; no authorization codes are issued by Immich.",
    ),
    "V10.4.4": (
        "no", "n/a", "n/a",
        "Not an authorization server; Immich only performs the authorization-code + PKCE flow as a client.",
    ),
    "V10.4.5": (
        "no", "n/a", "n/a",
        "Not an authorization server; refresh tokens of the upstream provider are stored server-side per session, never exposed to browser clients.",
    ),
    "V11.3.1": (
        "yes", "yes", "no",
        "No direct block-cipher usage in server code; only bcrypt (passwords) and SHA-256 (token hashing) are used, so no ECB mode or PKCS#1 v1.5 padding appears.",
    ),
    "V11.3.2": (
        "yes", "yes", "no",
        "No bulk encryption is implemented in application code; at-rest encryption is delegated to the database/storage layer, and the only crypto primitives used are bcrypt and SHA-256.",
    ),
    "V11.4.1": (
        "yes", "yes", "no",
        "SHA-256 (token/session hashing) and bcrypt are the only security hashes; SHA-1 is used solely for asset dedup checksums, a non-security purpose.",
    ),
    "V12.1.1": (
        "yes", "partial", "no",
        "The application itself listens on plain HTTP; TLS protocol versions and preference are determined by the reverse proxy / deployment environment, which the docs require but the app neither enforces nor tests.",
    ),
    "V12.2.1": (
        "yes", "partial", "no",
        "No TLS code or HTTP->HTTPS fallback exists in the app; secure transport is a deployment responsibility (reverse proxy per docs/docs/install). Cookies are marked Secure only when the incoming connection is trusted as secure.",
    ),
    "V12.2.2": (
        "partial", "partial", "no",
        "Certificate issuance/trust is entirely outside the codebase (self-hosted deployments choose their own reverse proxy certificates); not verifiable from the project.",
    ),
    "V13.4.1": (
        "yes", "yes", "no",
        "The production Docker image COPYs only source directories and build outputs (server/Dockerfile); .git/.svn metadata is never copied into the image.",
    ),
    "V14.2.1": (
        "yes", "partial", "no",
        "Session tokens travel in HttpOnly cookies or the Authorization header, API keys in x-api-key; however shared-link keys are secrets embedded in URLs by design (web/src/routes/(user)/share/[key]).",
    ),
    "V14.3.1": (
        "yes", "partial", "partial",
        "Logout clears auth cookies and deletes the server session; the web app clears its local state on logout. No Clear-Site-Data header is sent and offline cleanup is not guaranteed.",
    ),
    "V15.1.1": (
        "yes", "no", "no",
        "No documentation defines risk-based remediation time frames for vulnerable dependencies; renovate.json automates update PRs but has no security-timeframe policy.",
    ),
    "V15.2.1": (
        "yes", "partial", "no",
        "Renovate continuously updates dependencies, but there is no policy or verification that components stay within defined remediation time frames.",
    ),
    "V15.3.1": (
        "yes", "yes", "yes",
        "API responses are produced by explicit DTO mappers that whitelist fields (mapUser/mapUserAdmin never include password hashes); response shapes asserted in service and controller specs.",
    ),
}


def main():
    with open(SOURCE) as f:
        doc = json.load(f)

    counts = {"yes": 0, "partial": 0, "no": 0}

    def walk(items):
        for item in items:
            if "Items" in item:
                walk(item["Items"])
            elif item.get("L") == "1":
                shortcode = item["Shortcode"]
                if shortcode not in ASSESSMENTS:
                    raise SystemExit(f"missing assessment for {shortcode}")
                applicability, implemented, tested, evidence = ASSESSMENTS[shortcode]
                item["Applicability"] = applicability
                item["Implemented"] = implemented
                item["Tested"] = tested
                item["Evidence"] = evidence
                counts[applicability] += 1

    walk(doc["Requirements"])

    doc = {
        "Name": doc["Name"],
        "ShortName": doc["ShortName"],
        "Version": doc["Version"],
        "Description": doc["Description"],
        "Assessment": {
            "Project": "Immich",
            "Repository": "https://github.com/rubendv/immich",
            "Level": "L1",
            "Scope": "All ASVS 5.0.0 Level 1 requirements. Level 2/3 requirements are included unchanged from the source document without assessment fields.",
            "Legend": {
                "Applicability": "yes = requirement applies to this project; no = out of scope (e.g. Immich is not an authorization server); partial = applies only in part or depends on deployment.",
                "Implemented": "yes = implemented; partial = partially implemented or delegated to deployment/reverse proxy; no = not implemented; n/a = not applicable.",
                "Tested": "yes = sufficient automated test coverage found; partial = some related tests exist but do not fully verify the requirement; no = no coverage found; n/a = not applicable.",
            },
        },
        "Requirements": doc["Requirements"],
    }

    with open(TARGET, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"assessed {sum(counts.values())} L1 requirements -> {TARGET}")
    print(counts)


if __name__ == "__main__":
    main()
