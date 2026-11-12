# ASVS 5.0.0 L1 and L2 assessment — Immich

Source standard: Application Security Verification Standard Project v5.0.0. Assessed against `https://github.com/rubendv/immich`.

**Scope.** All ASVS 5.0.0 Level 1 and Level 2 requirements. Level 3 requirements are included unchanged from the source document without assessment fields.

## Summary

253 requirements assessed (L1 + L2).

| Verdict | Values |
| --- | --- |
| Applicability | no: 47, partial: 3, yes: 203 |
| Implemented | n/a: 47, no: 37, partial: 79, yes: 90 |
| Tested | n/a: 47, no: 146, partial: 43, yes: 17 |

## Legend

- **Applicability**: yes = requirement applies to this project; no = out of scope (e.g. Immich is not an authorization server, no LDAP/SAML/WebRTC); partial = applies only in part or depends on deployment.
- **Implemented**: yes = implemented; partial = partially implemented or delegated to deployment/reverse proxy; no = not implemented; n/a = not applicable.
- **Tested**: yes = sufficient automated test coverage found; partial = some related tests exist but do not fully verify the requirement; no = no coverage found; n/a = not applicable. Any verdict other than 'no' must be backed by an evidence_reference pointing to a test, e2e spec, documented practice, or enforced lint rule.
- **evidence_references**: Maps evidence codes (E1, E2, ...) cited in the Evidence text to concrete repository locations ('<file>:<line>') — implementations of security controls, security-sensitive configuration, tests, or documented/enforced practices.

## Requirements

## V1 — Encoding and Sanitization

### V1.1 Encoding and Sanitization Architecture

#### V1.1.1 (L2)

> Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Neither the server nor the web layer performs additional decoding/unescaping of input: zod validates raw strings and NestJS does not auto-decode bodies, so no double-decode or post-validation decoding occurs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137), [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L89), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L60)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137) `server/src/validation.ts:137`, [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L89) `server/src/dtos/auth.dto.ts:89`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L60) `server/src/services/auth.service.ts:60`

#### V1.1.2 (L2)

> Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Output encoding happens at the last step: Svelte escapes at render time and NestJS serializes JSON at response time; no pre-encoded fragments are stored and re-emitted. See [[E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183), [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183) `web/src/routes/auth/login/+page.svelte:183`, [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53) `server/src/dtos/user.dto.ts:53`

### V1.2 Injection Prevention

#### V1.2.1 (L1)

> Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Web UI is Svelte, which context-escapes all interpolated output by default; API responses are serialized JSON (server/src/controllers, web/src). No manual HTML string building found. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset.controller.ts#L22), [E2](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset.controller.ts#L22) `server/src/controllers/asset.controller.ts:22`, [E2](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183) `web/src/routes/auth/login/+page.svelte:183`

#### V1.2.2 (L1)

> Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:).

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Web builds URLs from route params and API responses; no explicit URL-encoding validation or javascript:/data: protocol allowlist was found in dynamic URL construction. See [[E1](https://github.com/rubendv/immich/blob/main/web/src/routes/%28user%29/share/%5Bkey%5D/%5B%5Bphotos%3Dphotos%5D%5D/%5B%5BassetId%3Did%5D%5D/%2Bpage.svelte#L1), [E2](https://github.com/rubendv/immich/blob/main/web/src/lib/utils.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/web/src/routes/%28user%29/share/%5Bkey%5D/%5B%5Bphotos%3Dphotos%5D%5D/%5B%5BassetId%3Did%5D%5D/%2Bpage.svelte#L1) `web/src/routes/(user)/share/[key]/[[photos=photos]]/[[assetId=id]]/+page.svelte:1`, [E2](https://github.com/rubendv/immich/blob/main/web/src/lib/utils.ts#L1) `web/src/lib/utils.ts:1`

#### V1.2.3 (L1)

> Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection).

**Applicability:** yes | **Implemented:** yes | **Tested:** no

All API responses are JSON serialized by NestJS; the web app consumes JSON via typed fetch wrappers and renders through Svelte's escaping. No dynamic JS/JSON string building found. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53), [E2](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53) `server/src/dtos/user.dto.ts:53`, [E2](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183) `web/src/routes/auth/login/+page.svelte:183`

#### V1.2.4 (L1)

> Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Server uses Kysely query builder with bound parameters (server/src/repositories); the few sql.raw/sql fragments interpolate only internal constants (e.g. interval strings, array casts), not user input. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/api-key.repository.ts#L1), [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/repositories/asset.repository.spec.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16) `server/src/repositories/access.repository.ts:16`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/api-key.repository.ts#L1) `server/src/repositories/api-key.repository.ts:1`, [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/repositories/asset.repository.spec.ts#L1) `server/test/medium/specs/repositories/asset.repository.spec.ts:1`

#### V1.2.5 (L1)

> Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

External tools (ffmpeg, exiftool) are invoked via child_process spawn with argument arrays and no shell interpolation (server/src/repositories/process.repository.ts); user data never reaches a shell command line. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/metadata.service.ts#L2), [E3](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.spec.ts#L42)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26) `server/src/repositories/process.repository.ts:26`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/metadata.service.ts#L2) `server/src/services/metadata.service.ts:2`, [E3](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.spec.ts#L42) `server/src/repositories/process.repository.spec.ts:42`

#### V1.2.6 (L2)

> Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

The application has no LDAP integration; the only directory-style data is its own Postgres user table. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L33)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L33) `server/src/schema/tables/user.table.ts:33`

#### V1.2.7 (L2)

> Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No XPath queries are used anywhere in server or machine-learning code. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/search.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/search.repository.ts#L1) `server/src/repositories/search.repository.ts:1`

#### V1.2.8 (L2)

> Verify that LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of commands is used to prevent LaTeX injection attacks.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No LaTeX processing exists in the project. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L1) `server/src/utils/mime-types.ts:1`

#### V1.2.9 (L2)

> Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

The one dynamic-regex site escapes special characters before building the pattern (server/src/utils/workflow.ts isAllowedHost escapes regex metacharacters around '*' wildcards); no other RegExp is built from user input. Covered by workflow utils spec. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/workflow.ts#L74), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L97), [E3](https://github.com/rubendv/immich/blob/main/server/src/utils/workflow.spec.ts#L39)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/workflow.ts#L74) `server/src/utils/workflow.ts:74`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L97) `server/src/services/workflow-execution.service.ts:97`, [E3](https://github.com/rubendv/immich/blob/main/server/src/utils/workflow.spec.ts#L39) `server/src/utils/workflow.spec.ts:39`

#### V1.2.10 (L3)

> Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\t' (tab), and '\0' (null character)) must be escaped with a single quote if they appear as the first character in a field value.

*Unassessed (Level 3).*

### V1.3 Sanitization

#### V1.3.1 (L1)

> Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich accepts no HTML input: there is no WYSIWYG editor; all user text (descriptions, names, comments) is stored and rendered as escaped text by Svelte. See [[E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183) `web/src/routes/auth/login/+page.svelte:183`

#### V1.3.2 (L1)

> Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

No eval()/new Function() in server or web source. External plugins execute in a separate sandboxed process and are admin-installed packages, not user input. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L283), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26), [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/workflow/workflow-core-plugin.spec.ts#L98)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L283) `server/src/services/workflow-execution.service.ts:283`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26) `server/src/repositories/process.repository.ts:26`, [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/workflow/workflow-core-plugin.spec.ts#L98) `server/test/medium/specs/workflow/workflow-core-plugin.spec.ts:98`

#### V1.3.3 (L2)

> Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Filenames are sanitized before storage (sanitize() in asset-media.service.ts) and zod enforces lengths/formats on most inputs, but there is no general 'safe character set' policy for all free-text fields. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L248), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.ts#L93)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L248) `server/src/validation.ts:248`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.ts#L93) `server/src/services/asset-media.service.ts:93`

#### V1.3.4 (L2)

> Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

.svg is accepted as an asset and profile image (server/src/utils/mime-types.ts) and served inline with its real content type; SVG content is never sanitized. Mitigated by the helmet CSP (script-src 'self') on API responses and by images being rendered via <img> in the UI, but direct navigation to an SVG original is not blocked. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L63), [E2](https://github.com/rubendv/immich/blob/main/server/helmet.json#L6), [E3](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L63) `server/src/utils/mime-types.ts:63`, [E2](https://github.com/rubendv/immich/blob/main/server/helmet.json#L6) `server/helmet.json:6`, [E3](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70) `server/src/utils/file.ts:70`

#### V1.3.5 (L2)

> Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Users cannot supply Markdown, CSS, XSL or BBCode that is later rendered; all user text is plain text. See [[E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183) `web/src/routes/auth/login/+page.svelte:183`

#### V1.3.6 (L2)

> Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

All outbound HTTP targets (version check, ML service, OAuth issuer/JWKS, map/reverse-geocode endpoints) are fixed constants or admin-configured settings, not end-user input; there is no URL allowlist validation of admin-entered URLs beyond new URL() parsing. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L108), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L97)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L108) `server/src/repositories/config.repository.ts:108`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L97) `server/src/services/workflow-execution.service.ts:97`

#### V1.3.7 (L2)

> Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Emails are rendered from fixed React-email templates with bound props (server/src/emails); no template strings are composed from user input. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/emails/album-invite.email.tsx#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/email.repository.ts#L134)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/emails/album-invite.email.tsx#L1) `server/src/emails/album-invite.email.tsx:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/email.repository.ts#L134) `server/src/repositories/email.repository.ts:134`

#### V1.3.8 (L2)

> Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No Java/JNDI anywhere in the stack (Node.js server, Python ML, Rust native modules). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L1) `server/src/utils/mime-types.ts:1`

#### V1.3.9 (L2)

> Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Redis is accessed exclusively through ioredis (binary-safe RESP protocol) with structured arguments; no memcached-style text commands are concatenated with user input. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/app.repository.ts#L3)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/app.repository.ts#L3) `server/src/repositories/app.repository.ts:3`

#### V1.3.10 (L2)

> Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

No printf-style format APIs are used with user input; all string formatting is JavaScript template literals, which are not format-string vulnerable. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72) `server/src/services/auth.service.ts:72`

#### V1.3.11 (L2)

> Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Email sending uses nodemailer with structured message objects; recipient addresses are validated by zod (toEmail) before use, preventing header injection. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/email.repository.ts#L134)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137) `server/src/validation.ts:137`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/email.repository.ts#L134) `server/src/repositories/email.repository.ts:134`

#### V1.3.12 (L3)

> Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks.

*Unassessed (Level 3).*

### V1.4 Memory, String, and Unmanaged Code

#### V1.4.1 (L2)

> Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

The server is TypeScript/Node (memory-safe runtime) and native components are Rust; no manual pointer arithmetic or unsafe string copies exist in JS/TS code. Rust/native code is not memory-audited here. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26) `server/src/repositories/process.repository.ts:26`

#### V1.4.2 (L2)

> Verify that sign, range, and input validation techniques are used to prevent integer overflows.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

JavaScript numbers are 64-bit and zod enforces ranges on many fields (e.g. lat/lon bounds, counts); no explicit integer-overflow checks exist for size counters used in upload accounting. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L117), [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/asset.dto.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L117) `server/src/validation.ts:117`, [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/asset.dto.ts#L1) `server/src/dtos/asset.dto.ts:1`

#### V1.4.3 (L2)

> Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Streams are piped with error handlers and cleaned up on failure (file-upload.interceptor.ts), DB connections are pooled by Kysely, and child processes are awaited/errored; no manual free() patterns exist in a GC runtime. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89) `server/src/middleware/file-upload.interceptor.ts:89`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26) `server/src/repositories/process.repository.ts:26`

### V1.5 Safe Deserialization

#### V1.5.1 (L1)

> Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

XMP sidecar uploads are parsed with exiftool as an external tool (server/src/services/metadata.service.ts); no in-process XML parser with external-entity resolution is used in server or ML code. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/metadata.service.ts#L2)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/metadata.service.ts#L2) `server/src/services/metadata.service.ts:2`

#### V1.5.2 (L2)

> Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Only JSON.parse of request bodies (via zod validation) is performed; no object-type-directed deserialization (no unserialize, no class-transformer of untrusted payloads) exists. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89), [E3](https://github.com/rubendv/immich/blob/main/server/src/validation.spec.ts#L5)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137) `server/src/validation.ts:137`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89) `server/src/middleware/file-upload.interceptor.ts:89`, [E3](https://github.com/rubendv/immich/blob/main/server/src/validation.spec.ts#L5) `server/src/validation.spec.ts:5`

#### V1.5.3 (L3)

> Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks.

*Unassessed (Level 3).*

## V2 — Validation and Business Logic

### V2.1 Validation and Business Logic Documentation

#### V2.1.1 (L1)

> Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

DTO schemas are defined with zod and annotated with descriptions/examples, exposed via generated OpenAPI spec (server/src/dtos, open-api). This documents expected structures, but there is no dedicated input-validation documentation. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138), [E2](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L117)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`, [E2](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L117) `server/src/validation.ts:117`

#### V2.1.2 (L2)

> Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No documentation defines cross-field consistency rules for combined data items. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/asset.dto.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/asset.dto.ts#L1) `server/src/dtos/asset.dto.ts:1`

#### V2.1.3 (L2)

> Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Global business limits exist in code (storage quotas per user, job concurrency), and quotas are documented in the admin UI, but there is no consolidated documentation of business-logic limits. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.ts#L93), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/user-admin.service.ts#L36)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.ts#L93) `server/src/services/asset-media.service.ts:93`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/user-admin.service.ts#L36) `server/src/services/user-admin.service.ts:36`

### V2.2 Input Validation

#### V2.2.1 (L1)

> Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Every endpoint DTO is validated by zod schemas (server/src/dtos, validation.ts) with typed constraints (lengths, enums, UUIDs, regex); server/test/validation.spec.ts covers parts of the schema surface. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L117), [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138), [E3](https://github.com/rubendv/immich/blob/main/server/src/validation.spec.ts#L5)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L117) `server/src/validation.ts:117`, [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`, [E3](https://github.com/rubendv/immich/blob/main/server/src/validation.spec.ts#L5) `server/src/validation.spec.ts:5`

#### V2.2.2 (L1)

> Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Validation runs in the NestJS server via zod DTOs; web/mobile validation is UX-only. The security-relevant decisions (auth, permissions, quotas) are all validated server-side. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L100), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/asset.e2e-spec.ts#L234)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137) `server/src/validation.ts:137`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L100) `server/src/middleware/auth.guard.ts:100`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/asset.e2e-spec.ts#L234) `e2e/src/specs/server/api/asset.e2e-spec.ts:234`

#### V2.2.3 (L2)

> Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Some combined-field rules are enforced (e.g. shared-link expiry after creation, album user permissions), but there is no systematic cross-field consistency validation across all DTOs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/shared-link.dto.ts#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L101)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/shared-link.dto.ts#L1) `server/src/dtos/shared-link.dto.ts:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L101) `server/src/services/shared-link.service.ts:101`

### V2.3 Business Logic Security

#### V2.3.1 (L1)

> Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Critical flows are sequence-guarded: admin onboarding is only available before an admin exists (auth.guard.ts setup routes) and setup is disabled afterwards; most other flows are single-step and need no ordering. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L105), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L330), [E3](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L105) `server/src/middleware/auth.guard.ts:105`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L330) `server/src/services/base.service.ts:330`, [E3](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41) `server/src/middleware/auth.guard.spec.ts:41`

#### V2.3.2 (L2)

> Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Quotas are enforced at upload time and job concurrency is bounded, but these limits are not derived from documented expectations; some flows lack explicit business limits. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.ts#L93), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/user-admin.service.ts#L1), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.spec.ts#L308)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.ts#L93) `server/src/services/asset-media.service.ts:93`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/user-admin.service.ts#L1) `server/src/services/user-admin.service.ts:1`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.spec.ts#L308) `server/src/services/asset-media.service.spec.ts:308`

#### V2.3.3 (L2)

> Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Multi-step operations run inside database transactions (Kysely transaction(), e.g. asset deletion, trash restore); covered partially by repository/service specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16), [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/trash.e2e-spec.ts#L22)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16) `server/src/repositories/access.repository.ts:16`, [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/trash.e2e-spec.ts#L22) `e2e/src/specs/server/api/trash.e2e-spec.ts:22`

#### V2.3.4 (L2)

> Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

The domain has no limited-quantity resources to double-book; DB unique constraints (e.g. asset checksum per owner, session tokens) prevent duplicate creation instead. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/asset.table.ts#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/asset.table.ts#L1) `server/src/schema/tables/asset.table.ts:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21) `server/src/schema/tables/session.table.ts:21`

#### V2.3.5 (L3)

> Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing.

*Unassessed (Level 3).*

### V2.4 Anti-automation

#### V2.4.1 (L2)

> Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No anti-automation controls exist for any endpoint (no throttling, per-user API quotas, or costly-resource limits beyond job queue concurrency). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L50)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L50) `server/src/app.common.ts:50`

#### V2.4.2 (L3)

> Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions.

*Unassessed (Level 3).*

## V3 — Web Frontend Security

### V3.1 Web Frontend Security Documentation

#### V3.1.1 (L3)

> Verify that application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access).

*Unassessed (Level 3).*

### V3.2 Unintended Content Interpretation

#### V3.2.1 (L1)

> Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

User-uploaded files are never served from a public folder; they are streamed through authenticated API routes with explicit Content-Type (server/src/controllers/assets). No CSP sandbox or Content-Disposition: attachment hardening for inline rendering contexts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset-file.controller.ts#L23), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset-file.controller.ts#L23) `server/src/controllers/asset-file.controller.ts:23`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70) `server/src/utils/file.ts:70`

#### V3.2.2 (L1)

> Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

The web app renders untrusted content (file names, comments, metadata) through Svelte text interpolation, which escapes by default. One raw-HTML site exists: the admin-configured login page message is rendered with Svelte {@html} on the login page, so an administrator can inject arbitrary HTML/JS into unauthenticated pages; regular user input never reaches an HTML sink. No test covers the escaping behavior or the {@html} site. See [[E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183) `web/src/routes/auth/login/+page.svelte:183`

#### V3.2.3 (L3)

> Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation.

*Unassessed (Level 3).*

### V3.3 Cookie Setup

#### V3.3.1 (L1)

> Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name.

**Applicability:** yes | **Implemented:** partial | **Tested:** yes

Auth cookies are HttpOnly, SameSite=Lax and Secure when the connection is secure (server/src/utils/response.ts), but names (immich_access etc.) lack the __Host-/__Secure- prefix and the Secure flag depends on request protocol. Cookie attributes asserted in server/src/controllers/auth.controller.spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L45), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L46), [E3](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L17), [E4](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.spec.ts#L164)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L45) `server/src/utils/response.ts:45`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L46) `server/src/utils/response.ts:46`, [E3](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L17) `server/src/enum.ts:17`, [E4](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.spec.ts#L164) `server/src/controllers/auth.controller.spec.ts:164`

#### V3.3.2 (L2)

> Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF).

**Applicability:** yes | **Implemented:** partial | **Tested:** no

All cookies use SameSite=Lax (server/src/utils/response.ts), which suits the session/CSRF purpose, but no cookie gets a purpose-specific decision (e.g. Strict for auth) and the non-HttpOnly isAuthenticated cookie signals auth state. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L45), [E2](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L20)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L45) `server/src/utils/response.ts:45`, [E2](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L20) `server/src/enum.ts:20`

#### V3.3.3 (L2)

> Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No cookie uses the __Host- prefix (immich_access, immich_is_authenticated, etc.); they are served on the same host across API and web paths. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L17), [E2](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L20)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L17) `server/src/enum.ts:17`, [E2](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L20) `server/src/enum.ts:20`

#### V3.3.4 (L2)

> Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field.

**Applicability:** yes | **Implemented:** partial | **Tested:** yes

The access-token cookie is HttpOnly and set via Set-Cookie, but the same session token is also returned in the login response body (mapLoginResponse) for mobile/API clients, violating the Set-Cookie-only rule. Cookie attributes asserted in auth.controller.spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L113), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L42), [E3](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.spec.ts#L164)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L113) `server/src/dtos/auth.dto.ts:113`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L42) `server/src/utils/response.ts:42`, [E3](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.spec.ts#L164) `server/src/controllers/auth.controller.spec.ts:164`

#### V3.3.5 (L3)

> Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie.

*Unassessed (Level 3).*

### V3.4 Browser Security Mechanism Headers

#### V3.4.1 (L1)

> Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Helmet middleware is enabled in production (server/src/app.common.ts), which sends HSTS by default, but with helmet's default max-age of 180 days (< 1 year) and without includeSubDomains; no explicit HSTS configuration. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L51), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L169), [E3](https://github.com/rubendv/immich/blob/main/server/helmet.json#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L51) `server/src/app.common.ts:51`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L169) `server/src/repositories/config.repository.ts:169`, [E3](https://github.com/rubendv/immich/blob/main/server/helmet.json#L1) `server/helmet.json:1`

#### V3.4.2 (L1)

> Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

CORS is only enabled in development (app.enableCors() guarded by isDev()); production responses send no Access-Control-Allow-Origin at all, so cross-origin browser access is blocked rather than reflected. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L59), [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L60)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L59) `server/src/app.common.ts:59`, [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L60) `server/src/app.common.ts:60`

#### V3.4.3 (L2)

> Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

A global CSP is configured via helmet.json with object-src 'none' and script-src 'self', but base-uri is 'self' instead of 'none' and no nonces/hashes are used for scripts (hashes are auto-applied only to style directives via applyCspHashes). See [[E1](https://github.com/rubendv/immich/blob/main/server/helmet.json#L6), [E2](https://github.com/rubendv/immich/blob/main/server/helmet.json#L19), [E3](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L157)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/helmet.json#L6) `server/helmet.json:6`, [E2](https://github.com/rubendv/immich/blob/main/server/helmet.json#L19) `server/helmet.json:19`, [E3](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L157) `server/src/repositories/config.repository.ts:157`

#### V3.4.4 (L2)

> Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Helmet defaults include X-Content-Type-Options: nosniff on all responses (helmet middleware applied in app.common.ts before routes); no test asserts the header. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L51)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L51) `server/src/app.common.ts:51`

#### V3.4.5 (L2)

> Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Helmet defaults set a Referrer-Policy header (no-referrer) on all responses; no test asserts the header. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L51)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L51) `server/src/app.common.ts:51`

#### V3.4.6 (L2)

> Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

The CSP in helmet.json has no frame-ancestors directive; only helmet's default X-Frame-Options: SAMEORIGIN (frameguard) protects against embedding, which the requirement considers obsolete. See [[E1](https://github.com/rubendv/immich/blob/main/server/helmet.json#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L203)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/helmet.json#L1) `server/helmet.json:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L203) `server/src/repositories/config.repository.ts:203`

#### V3.4.7 (L3)

> Verify that the Content-Security-Policy header field specifies a location to report violations.

*Unassessed (Level 3).*

#### V3.4.8 (L3)

> Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting.

*Unassessed (Level 3).*

### V3.5 Browser Origin Separation

#### V3.5.1 (L1)

> Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF).

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

No anti-forgery tokens. CSRF defense relies on SameSite=Lax cookies plus the absence of CORS headers in production; cookie attributes and auth flow are covered by auth.controller.spec.ts and e2e/src/specs/web/auth.e2e-spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L45), [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L59), [E3](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.spec.ts#L164)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L45) `server/src/utils/response.ts:45`, [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L59) `server/src/app.common.ts:59`, [E3](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.spec.ts#L164) `server/src/controllers/auth.controller.spec.ts:164`

#### V3.5.2 (L1)

> Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

The app does not rely on CORS preflight; state-changing endpoints expect JSON bodies (non-safelisted content type) and cookies are SameSite=Lax, so cross-site requests carry no credentials for POSTs. No explicit Origin/Content-Type validation tests. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L45), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L45) `server/src/utils/response.ts:45`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89) `server/src/middleware/file-upload.interceptor.ts:89`

#### V3.5.3 (L1)

> Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

All state-changing API routes use POST/PUT/DELETE/PATCH via NestJS controllers; GET routes are read-only. No explicit test asserts method usage per route. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset-file.controller.ts#L45), [E2](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.ts#L96)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset-file.controller.ts#L45) `server/src/controllers/asset-file.controller.ts:45`, [E2](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.ts#L96) `server/src/controllers/auth.controller.ts:96`

#### V3.5.4 (L2)

> Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich is a single application serving web and API from one origin; there are no separate applications to isolate on different hostnames. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41) `server/src/app.common.ts:41`

#### V3.5.5 (L2)

> Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

postMessage is used only for Web Workers (hash-file, file-uploader) and service-worker messaging (web/src/lib/utils/sw-messenger.ts), which are same-origin by construction; no listener accepts cross-origin messages. See [[E1](https://github.com/rubendv/immich/blob/main/web/src/lib/utils/sw-messenger.ts#L10)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/web/src/lib/utils/sw-messenger.ts#L10) `web/src/lib/utils/sw-messenger.ts:10`

#### V3.5.6 (L3)

> Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks.

*Unassessed (Level 3).*

#### V3.5.7 (L3)

> Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks.

*Unassessed (Level 3).*

#### V3.5.8 (L3)

> Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content.

*Unassessed (Level 3).*

### V3.6 External Resource Integrity

#### V3.6.1 (L3)

> Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource.

*Unassessed (Level 3).*

### V3.7 Other Browser Security Considerations

#### V3.7.1 (L2)

> Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Client-side stack is Svelte (web) and Flutter (mobile); no Flash/ActiveX/Silverlight/applet or other unsupported plugin technology is used. See [[E1](https://github.com/rubendv/immich/blob/main/web/package.json#L1), [E2](https://github.com/rubendv/immich/blob/main/mobile/pubspec.yaml#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/web/package.json#L1) `web/package.json:1`, [E2](https://github.com/rubendv/immich/blob/main/mobile/pubspec.yaml#L1) `mobile/pubspec.yaml:1`

#### V3.7.2 (L2)

> Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Redirects to other hosts occur only in the OAuth flow (to the configured IdP and back via the configured redirect URI, incl. mobile redirect handling) and to the IdP logout endpoint; these are admin-configured, effectively an allowlist. No generic redirect parameters were found. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L274), [E2](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L1), [E3](https://github.com/rubendv/immich/blob/main/server/src/controllers/oauth.controller.spec.ts#L34)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L274) `server/src/services/auth.service.ts:274`, [E2](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L1) `server/src/constants.ts:1`, [E3](https://github.com/rubendv/immich/blob/main/server/src/controllers/oauth.controller.spec.ts#L34) `server/src/controllers/oauth.controller.spec.ts:34`

#### V3.7.3 (L3)

> Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation.

*Unassessed (Level 3).*

#### V3.7.4 (L3)

> Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field.

*Unassessed (Level 3).*

#### V3.7.5 (L3)

> Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features.

*Unassessed (Level 3).*

## V4 — API and Web Service

### V4.1 Generic Web Service Security

#### V4.1.1 (L1)

> Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml".

**Applicability:** yes | **Implemented:** yes | **Tested:** no

NestJS/Express sets application/json; charset=utf-8 for API responses; asset/file responses set the correct media type from the internal mime-type map. No test asserts the response content type. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset-file.controller.ts#L23), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset-file.controller.ts#L23) `server/src/controllers/asset-file.controller.ts:23`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70) `server/src/utils/file.ts:70`

#### V4.1.2 (L2)

> Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

The app never issues HTTP->HTTPS redirects itself; this is a reverse-proxy concern. The API endpoints respond directly without redirects, satisfying the 'no transparent redirects for non-browser clients' intent at the app layer. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41) `server/src/app.common.ts:41`

#### V4.1.3 (L2)

> Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Express is configured with 'trust proxy' limited to loopback + admin-configured trustedProxies (app.common.ts), so X-Forwarded-* from untrusted hops are ignored and clientIp comes from a trusted field. Covered partially by auth.service.spec.ts IP handling. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L47), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L362), [E3](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.spec.ts#L267)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L47) `server/src/app.common.ts:47`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L362) `server/src/repositories/config.repository.ts:362`, [E3](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.spec.ts#L267) `server/src/repositories/config.repository.spec.ts:267`

#### V4.1.4 (L3)

> Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked.

*Unassessed (Level 3).*

#### V4.1.5 (L3)

> Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems.

*Unassessed (Level 3).*

### V4.2 HTTP Message Structure Validation

#### V4.2.1 (L2)

> Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

HTTP message framing is handled by Node's HTTP server and Express per RFC; no custom framing/parsing code exists. Intermediary behavior is a deployment concern. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41) `server/src/app.common.ts:41`

#### V4.2.2 (L3)

> Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks.

*Unassessed (Level 3).*

#### V4.2.3 (L3)

> Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks.

*Unassessed (Level 3).*

#### V4.2.4 (L3)

> Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\r), LF (\n), or CRLF (\r\n) sequences, to prevent header injection attacks.

*Unassessed (Level 3).*

#### V4.2.5 (L3)

> Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status.

*Unassessed (Level 3).*

### V4.3 GraphQL

#### V4.3.1 (L2)

> Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

The API is REST/JSON; no GraphQL endpoint exists. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/index.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/index.ts#L1) `server/src/controllers/index.ts:1`

#### V4.3.2 (L2)

> Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No GraphQL API exists. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/index.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/index.ts#L1) `server/src/controllers/index.ts:1`

### V4.4 WebSocket

#### V4.4.1 (L1)

> Verify that WebSocket over TLS (WSS) is used for all WebSocket connections.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

WebSockets are served on the same HTTP server as the API (server/src/middleware/websocket.adapter.ts); TLS is terminated by the reverse proxy, the app itself listens on plain HTTP inside the container network. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13) `server/src/middleware/websocket.adapter.ts:13`

#### V4.4.2 (L2)

> Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application.

**Applicability:** yes | **Implemented:** no | **Tested:** no

The socket.io server (websocket.adapter.ts) sets no Origin allowlist; connections are authenticated by session cookie but the handshake Origin is not validated. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13) `server/src/middleware/websocket.adapter.ts:13`

#### V4.4.3 (L2)

> Verify that, if the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

WebSocket channels reuse the standard session management (same cookies/session tokens as HTTP) rather than a separate weaker mechanism; the web client passes the access token during the socket handshake. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/web/websocket.e2e-spec.ts#L5)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114) `server/src/middleware/auth.guard.ts:114`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553) `server/src/services/auth.service.ts:553`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/web/websocket.e2e-spec.ts#L5) `e2e/src/specs/web/websocket.e2e-spec.ts:5`

#### V4.4.4 (L2)

> Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

The WS session is established from the already-authenticated HTTPS session (cookie/handshake token validated against the session table); no unauthenticated WS transition exists. Covered partially by e2e/src/specs/web/websocket.e2e-spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553), [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/web/websocket.e2e-spec.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553) `server/src/services/auth.service.ts:553`, [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/web/websocket.e2e-spec.ts#L1) `e2e/src/specs/web/websocket.e2e-spec.ts:1`

## V5 — File Handling

### V5.1 File Handling Documentation

#### V5.1.1 (L2)

> Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

docs describe supported media formats at a high level and the admin UI shows quota settings, but there is no documentation of per-upload maximum sizes or malicious-file handling behavior. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L54), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L167)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L54) `server/src/middleware/file-upload.interceptor.ts:54`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L167) `server/src/utils/mime-types.ts:167`

### V5.2 File Upload and Content

#### V5.2.1 (L1)

> Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack.

**Applicability:** yes | **Implemented:** no | **Tested:** no

Multer is configured without file size limits (server/src/middleware/file-upload.interceptor.ts) and the JSON body limit (10mb) does not apply to multipart uploads; no server-side upload size cap exists, relying on reverse proxy limits. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L54), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L54) `server/src/middleware/file-upload.interceptor.ts:54`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89) `server/src/middleware/file-upload.interceptor.ts:89`

#### V5.2.2 (L1)

> Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Upload fileFilter allowlists extensions per upload type (asset/sidecar/profile via mimeTypes.isAsset etc.); actual content is validated later by ffprobe/exiftool processing and thumbnail generation, not by magic bytes at upload time. Covered partially by e2e/src/specs/server/api/asset.e2e-spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L167), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/asset.e2e-spec.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89) `server/src/middleware/file-upload.interceptor.ts:89`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L167) `server/src/utils/mime-types.ts:167`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/asset.e2e-spec.ts#L1) `e2e/src/specs/server/api/asset.e2e-spec.ts:1`

#### V5.2.3 (L2)

> Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No archive formats (zip, gz, docx) are accepted as uploads; only media files, XMP sidecars and profile images pass the extension allowlist. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L141), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L102)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L141) `server/src/utils/mime-types.ts:141`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/mime-types.ts#L102) `server/src/utils/mime-types.ts:102`

#### V5.2.4 (L3)

> Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files.

*Unassessed (Level 3).*

#### V5.2.5 (L3)

> Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to).

*Unassessed (Level 3).*

#### V5.2.6 (L3)

> Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks.

*Unassessed (Level 3).*

### V5.3 File Storage

#### V5.3.1 (L1)

> Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Uploads are stored in a storage folder outside the web root and served only through authenticated API endpoints that stream the file with a safe Content-Type; the static web root contains only built assets. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset-file.controller.ts#L23), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/asset-file.controller.ts#L23) `server/src/controllers/asset-file.controller.ts:23`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70) `server/src/utils/file.ts:70`

#### V5.3.2 (L1)

> Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Stored filenames are generated server-side: uuid + sanitized extension (asset-media.service.ts getUploadFilename uses sanitize() and only takes the extension from user input); folders are built from internal ids/uuids, preventing traversal. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.ts#L93), [E2](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L248), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.spec.ts#L259)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.ts#L93) `server/src/services/asset-media.service.ts:93`, [E2](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L248) `server/src/validation.ts:248`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/asset-media.service.spec.ts#L259) `server/src/services/asset-media.service.spec.ts:259`

#### V5.3.3 (L3)

> Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip.

*Unassessed (Level 3).*

### V5.4 File Download

#### V5.4.1 (L2)

> Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Download responses set Content-Disposition with RFC 5987/6266 encoding (server/src/utils/file.ts filename*=UTF-8''..., integrity-admin.controller.ts uses attachment + encodeURIComponent); stored filenames are server-generated, user filenames are only echoed in this encoded form. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70) `server/src/utils/file.ts:70`

#### V5.4.2 (L2)

> Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Filenames in Content-Disposition are RFC 5987 encoded (filename*=UTF-8'' + encodeURIComponent), preventing header injection and preserving structure. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L70) `server/src/utils/file.ts:70`

#### V5.4.3 (L2)

> Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No antivirus scanning of uploaded files exists; content is processed by ffmpeg/exiftool/sharp but not scanned for malware. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/metadata.service.ts#L2), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/metadata.service.ts#L2) `server/src/services/metadata.service.ts:2`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/process.repository.ts#L26) `server/src/repositories/process.repository.ts:26`

## V6 — Authentication

### V6.1 Authentication Documentation

#### V6.1.1 (L1)

> Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No documentation defines rate limiting, anti-automation or adaptive response controls for login; docs only mention reverse proxy setup in general. See [[E1](https://github.com/rubendv/immich/blob/main/docs/docs/administration/reverse-proxy.md#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docs/docs/administration/reverse-proxy.md#L1) `docs/docs/administration/reverse-proxy.md:1`

#### V6.1.2 (L2)

> Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No context-specific word list (organization/product names) is documented for password screening. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`

#### V6.1.3 (L2)

> Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

docs/docs/administration documents the OAuth and password-login pathways and their enable/disable toggles, but does not document the security controls/strength that must be enforced consistently across pathways. See [[E1](https://github.com/rubendv/immich/blob/main/docs/docs/administration/oauth.md#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L62)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docs/docs/administration/oauth.md#L1) `docs/docs/administration/oauth.md:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L62) `server/src/services/auth.service.ts:62`

### V6.2 Password Security

#### V6.2.1 (L1)

> Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

ChangePasswordSchema enforces z.string().min(8) (server/src/dtos/auth.dto.ts:138); password rules covered in auth.service.spec.ts and API e2e specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93) `server/src/services/auth.service.spec.ts:93`

#### V6.2.2 (L1)

> Verify that users can change their password.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

POST /api/auth/change-password endpoint exists (auth.controller.ts) and is covered by auth.service.spec.ts and e2e specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.ts#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.ts#L1) `server/src/controllers/auth.controller.ts:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93) `server/src/services/auth.service.spec.ts:93`

#### V6.2.3 (L1)

> Verify that password change functionality requires the user's current and new password.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

ChangePasswordDto requires both current password and newPassword (server/src/dtos/auth.dto.ts:134-140); asserted in auth.service.spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L137), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L137) `server/src/dtos/auth.dto.ts:137`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93) `server/src/services/auth.service.spec.ts:93`

#### V6.2.4 (L1)

> Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No check of submitted passwords against a common/top-3000 password list (no zxcvbn or blocklist dependency in server). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`

#### V6.2.5 (L1)

> Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

The only rule is minimum length; no character-class composition requirements exist in any password schema. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`

#### V6.2.6 (L1)

> Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Web login and password forms use type=password (web/src/routes/auth/login/+page.svelte, settings components); no explicit test asserts this. See [[E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183) `web/src/routes/auth/login/+page.svelte:183`

#### V6.2.7 (L1)

> Verify that "paste" functionality, browser password helpers, and external password managers are permitted.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

No paste-blocking, autocomplete=off or password-manager-hostile handlers anywhere in web/src; browsers and managers work unimpeded. See [[E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/web/src/routes/auth/login/%2Bpage.svelte#L183) `web/src/routes/auth/login/+page.svelte:183`

#### V6.2.8 (L1)

> Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Passwords are compared exactly as received via bcrypt compare (crypto.repository.ts compareBcrypt); no truncation, trimming or case transformation in the login/change-password paths. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L21), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L69), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L105)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L21) `server/src/repositories/crypto.repository.ts:21`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L69) `server/src/services/auth.service.ts:69`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L105) `server/src/services/auth.service.spec.ts:105`

#### V6.2.9 (L2)

> Verify that passwords of at least 64 characters are permitted.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Password schemas have no maximum length (z.string().min(8)), so 64+ character passwords are accepted. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`

#### V6.2.10 (L2)

> Verify that a user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

No password expiry or rotation is enforced anywhere; passwords stay valid until changed by the user or reset by an admin. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L136)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L136) `server/src/services/auth.service.ts:136`

#### V6.2.11 (L2)

> Verify that the documented list of context specific words is used to prevent easy to guess passwords being created.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No context-specific word list is enforced at registration or password change. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`

#### V6.2.12 (L2)

> Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No breached-password check (no HIBP/k-anonymity or similar) at registration or password change. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L136)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L136) `server/src/services/auth.service.ts:136`

### V6.3 General Authentication Security

#### V6.3.1 (L1)

> Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No rate limiting, account lockout or throttling in the server (no @nestjs/throttler or equivalent). Only a constant-time dummy bcrypt compare prevents timing-based user enumeration (auth.service.ts login). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L69), [E2](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L48)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L69) `server/src/services/auth.service.ts:69`, [E2](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L48) `server/src/constants.ts:48`

#### V6.3.2 (L1)

> Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

No built-in default accounts: the first admin is created interactively during onboarding; setup routes are disabled once an admin exists (auth.guard.spec.ts covers this). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L330), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L330) `server/src/services/base.service.ts:330`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41) `server/src/middleware/auth.guard.spec.ts:41`

#### V6.3.3 (L2)

> Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Password-only single-factor login is allowed by default, so MFA is not mandatory. However, passkeys (WebAuthn/FIDO2, phishing-resistant) are supported as an additional authentication pathway, and OAuth can offload MFA to the IdP. Passkey flows are covered by passkey.controller.spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/passkey.controller.ts#L40), [E2](https://github.com/rubendv/immich/blob/main/server/src/controllers/passkey.controller.spec.ts#L44)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/passkey.controller.ts#L40) `server/src/controllers/passkey.controller.ts:40`, [E2](https://github.com/rubendv/immich/blob/main/server/src/controllers/passkey.controller.spec.ts#L44) `server/src/controllers/passkey.controller.spec.ts:44`

#### V6.3.4 (L2)

> Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Four pathways exist (password, OAuth, passkey, API key) and are documented at a high level, but strength is not enforced consistently: API keys and (depending on config) password login can bypass MFA entirely. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L62)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13) `server/src/services/api-key.service.ts:13`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L62) `server/src/services/auth.service.ts:62`

#### V6.3.5 (L3)

> Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts.

*Unassessed (Level 3).*

#### V6.3.6 (L3)

> Verify that email is not used as either a single-factor or multi-factor authentication mechanism.

*Unassessed (Level 3).*

#### V6.3.7 (L3)

> Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address.

*Unassessed (Level 3).*

#### V6.3.8 (L3)

> Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection.

*Unassessed (Level 3).*

### V6.4 Authentication Factor Lifecycle and Recovery

#### V6.4.1 (L1)

> Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

CLI bootstrap admin password is generated with randomBytes(24) (cli.service.ts) and meets the length policy, but there is no expiry after first use or time limit. Covered by cli.service.spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/cli.service.ts#L69), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/cli.service.spec.ts#L8)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/cli.service.ts#L69) `server/src/services/cli.service.ts:69`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/cli.service.spec.ts#L8) `server/src/services/cli.service.spec.ts:8`

#### V6.4.2 (L1)

> Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

No password hints or knowledge-based secret questions exist anywhere in the schema, DTOs or UI. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138), [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L138) `server/src/dtos/auth.dto.ts:138`, [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1) `server/src/schema/tables/user.table.ts:1`

#### V6.4.3 (L2)

> Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

No self-service 'forgot password' email flow exists; a forgotten password is handled by an admin resetting it (user-admin service / CLI), which cannot bypass MFA since MFA is delegated to passkeys/IdP. No automated reset token exists at all. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/user-admin.service.ts#L82), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L136), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/user-admin.e2e-spec.ts#L100)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/user-admin.service.ts#L82) `server/src/services/user-admin.service.ts:82`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L136) `server/src/services/auth.service.ts:136`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/user-admin.e2e-spec.ts#L100) `e2e/src/specs/server/api/user-admin.e2e-spec.ts:100`

#### V6.4.4 (L2)

> Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment.

**Applicability:** partial | **Implemented:** no | **Tested:** no

The only additional factor is a passkey; losing it falls back to password or OAuth login (or admin intervention) without an identity-proofing process at the enrollment level. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/passkey.controller.ts#L40), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L62)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/passkey.controller.ts#L40) `server/src/controllers/passkey.controller.ts:40`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L62) `server/src/services/auth.service.ts:62`

#### V6.4.5 (L3)

> Verify that renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary.

*Unassessed (Level 3).*

#### V6.4.6 (L3)

> Verify that administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user's password. This prevents a situation where they know the user's password.

*Unassessed (Level 3).*

### V6.5 General Multi-factor authentication requirements

#### V6.5.1 (L2)

> Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Immich's lookup secrets (shared-link keys, API keys) are long-lived by design and not single-use; no one-time lookup secrets or OTP codes exist in the application. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94) `server/src/services/shared-link.service.ts:94`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13) `server/src/services/api-key.service.ts:13`

#### V6.5.2 (L2)

> Verify that, when being stored in the application's backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Shared-link keys are generated with randomBytes(50) = 400 bits of entropy (shared-link.service.ts), well above the 112-bit threshold, but they are stored raw (unhashed) in the database instead of hashed. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94) `server/src/services/shared-link.service.ts:94`

#### V6.5.3 (L2)

> Verify that lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

All lookup secrets (shared-link keys randomBytes(50), API keys randomBytes(32), session tokens randomBytes(32)) are generated with node crypto CSPRNG. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/session.service.ts#L35)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94) `server/src/services/shared-link.service.ts:94`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13) `server/src/services/api-key.service.ts:13`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/session.service.ts#L35) `server/src/services/session.service.ts:35`

#### V6.5.4 (L2)

> Verify that lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient).

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Shared-link keys carry 400 bits of entropy and API keys 256 bits, far above the 20-bit minimum. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94) `server/src/services/shared-link.service.ts:94`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13) `server/src/services/api-key.service.ts:13`

#### V6.5.5 (L2)

> Verify that out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Shared links support an optional expiry timestamp (and admins can enforce a maximum lifetime), but expiry is optional and defaults to none; there are no OTP/TOTP lifetimes since no OTP mechanism exists. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L101)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L101) `server/src/services/shared-link.service.ts:101`

#### V6.5.6 (L3)

> Verify that any authentication factor (including physical devices) can be revoked in case of theft or other loss.

*Unassessed (Level 3).*

#### V6.5.7 (L3)

> Verify that biometric authentication mechanisms are only used as secondary factors together with either something you have or something you know.

*Unassessed (Level 3).*

#### V6.5.8 (L3)

> Verify that time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not from an untrusted or client provided time.

*Unassessed (Level 3).*

### V6.6 Out-of-Band authentication mechanisms

#### V6.6.1 (L2)

> Verify that authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No PSTN/SMS/phone-based authentication exists. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L1) `server/src/dtos/auth.dto.ts:1`

#### V6.6.2 (L2)

> Verify that out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No out-of-band authentication mechanisms exist. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L1) `server/src/dtos/auth.dto.ts:1`

#### V6.6.3 (L2)

> Verify that a code based out-of-band authentication mechanism is protected against brute force attacks by using rate limiting. Consider also using a code with at least 64 bits of entropy.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No out-of-band authentication codes exist. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/auth.dto.ts#L1) `server/src/dtos/auth.dto.ts:1`

#### V6.6.4 (L3)

> Verify that, where push notifications are used for multi-factor authentication, rate limiting is used to prevent push bombing attacks. Number matching may also mitigate this risk.

*Unassessed (Level 3).*

### V6.7 Cryptographic authentication mechanism

#### V6.7.1 (L3)

> Verify that the certificates used to verify cryptographic authentication assertions are stored in a way protects them from modification.

*Unassessed (Level 3).*

#### V6.7.2 (L3)

> Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device.

*Unassessed (Level 3).*

### V6.8 Authentication with an Identity Provider

#### V6.8.1 (L2)

> Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Only a single external IdP can be configured; OAuth identities are bound per user via a unique oauthId, so cross-IdP identity spoofing is not possible in this configuration. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L61)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L61) `server/src/schema/tables/user.table.ts:61`

#### V6.8.2 (L2)

> Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

OIDC ID tokens are validated by openid-client / jose: signature via the IdP's JWKS or client secret, issuer and audience are checked (oauth.repository.ts; validateLogoutToken validates signature, iss, aud explicitly for logout tokens). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L148), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L102), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L148)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L148) `server/src/repositories/oauth.repository.ts:148`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L102) `server/src/services/auth.service.ts:102`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L148) `e2e/src/specs/server/api/oauth.e2e-spec.ts:148`

#### V6.8.3 (L2)

> Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No SAML support; only OIDC via openid-client. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V6.8.4 (L2)

> Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth_time' (if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password).

**Applicability:** yes | **Implemented:** no | **Tested:** no

No acr/amr/auth_time claim validation is performed when accepting OIDC logins; the app assumes the IdP-enforced strength (no documented fallback either). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L301)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L301) `server/src/services/auth.service.ts:301`

## V7 — Session Management

### V7.1 Session Management Documentation

#### V7.1.1 (L2)

> Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements.

**Applicability:** yes | **Implemented:** no | **Tested:** no

Session lifetimes are not documented: sessions have no inactivity timeout and no absolute maximum lifetime (cookie maxAge 400 days, session rows persist until logout). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L48), [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L48) `server/src/utils/response.ts:48`, [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21) `server/src/schema/tables/session.table.ts:21`

#### V7.1.2 (L2)

> Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached.

**Applicability:** yes | **Implemented:** no | **Tested:** no

Concurrent sessions are unbounded and the policy/behavior on reaching a maximum is not documented (there is no maximum). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/session.service.ts#L35)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/session.service.ts#L35) `server/src/services/session.service.ts:35`

#### V7.1.3 (L2)

> Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication.

**Applicability:** yes | **Implemented:** no | **Tested:** no

SSO session coordination is not documented: OAuth logout/backchannel logout are implemented, but lifetime coordination and re-authentication conditions are not documented. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L102), [E2](https://github.com/rubendv/immich/blob/main/docs/docs/administration/oauth.md#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L102) `server/src/services/auth.service.ts:102`, [E2](https://github.com/rubendv/immich/blob/main/docs/docs/administration/oauth.md#L1) `docs/docs/administration/oauth.md:1`

### V7.2 Fundamental Session Management Security

#### V7.2.1 (L1)

> Verify that the application performs all session token verification using a trusted, backend service.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

Session tokens are validated server-side: AuthGuard hashes the presented token and looks up the session row in Postgres (auth.service.ts validateSession; middleware/auth.guard.ts). Covered by auth.guard.spec.ts and session e2e specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114), [E3](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553) `server/src/services/auth.service.ts:553`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114) `server/src/middleware/auth.guard.ts:114`, [E3](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41) `server/src/middleware/auth.guard.spec.ts:41`

#### V7.2.2 (L1)

> Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

Each login generates a fresh random reference token stored hashed in the session table (base.service.ts createLoginResponse). Static API keys exist but are an explicit opt-in separate credential, not the session mechanism. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L366), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L372), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13), [E4](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/session.e2e-spec.ts#L17)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L366) `server/src/services/base.service.ts:366`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L372) `server/src/services/base.service.ts:372`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13) `server/src/services/api-key.service.ts:13`, [E4](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/session.e2e-spec.ts#L17) `e2e/src/specs/server/api/session.e2e-spec.ts:17`

#### V7.2.3 (L1)

> Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Session tokens are randomBytes(32) base64-encoded (>=128 bits entropy) from node crypto CSPRNG; only the SHA-256 hash is stored. Token generation and hashing asserted in api-key specs; entropy is by construction, not measured by tests. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L372), [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.spec.ts#L24)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L372) `server/src/services/base.service.ts:372`, [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21) `server/src/schema/tables/session.table.ts:21`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.spec.ts#L24) `server/src/services/api-key.service.spec.ts:24`

#### V7.2.4 (L1)

> Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

A new session token is created on every authentication, but previously issued sessions for the same user are not terminated on re-login; password change offers invalidateSessions as an opt-in. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L366), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L146), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L49)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L366) `server/src/services/base.service.ts:366`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L146) `server/src/services/auth.service.ts:146`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L49) `server/src/services/auth.service.spec.ts:49`

### V7.3 Session Timeout

#### V7.3.1 (L2)

> Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No inactivity timeout exists; sessions remain valid indefinitely regardless of last use (only cookie maxAge applies client-side). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L48)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553) `server/src/services/auth.service.ts:553`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L48) `server/src/utils/response.ts:48`

#### V7.3.2 (L2)

> Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No absolute maximum session lifetime is enforced; session rows have no expiry timestamp. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21) `server/src/schema/tables/session.table.ts:21`

### V7.4 Session Termination

#### V7.4.1 (L1)

> Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

Logout deletes the session row server-side (auth.service.ts logout -> sessionRepository.delete); the token is unusable afterwards. Covered by auth.service.spec.ts and e2e session specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L79), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L1), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/session.e2e-spec.ts#L36)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L79) `server/src/services/auth.service.ts:79`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L1) `server/src/services/auth.service.spec.ts:1`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/session.e2e-spec.ts#L36) `e2e/src/specs/server/api/session.e2e-spec.ts:36`

#### V7.4.2 (L1)

> Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company).

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Sessions are FK-cascade deleted with the user (session.table.ts onDelete: CASCADE), so account deletion removes sessions; password change can invalidate all sessions (invalidateSessions flag). Merely disabling a user does not proactively kill existing sessions. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L32), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L146), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L32) `server/src/schema/tables/session.table.ts:32`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L146) `server/src/services/auth.service.ts:146`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93) `server/src/services/auth.service.spec.ts:93`

#### V7.4.3 (L2)

> Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update).

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Password change exposes an opt-in invalidateSessions flag (default false) that revokes all other sessions; passkey setup/reset does not terminate other sessions. Covered by auth.service.spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L146), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L146) `server/src/services/auth.service.ts:146`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93) `server/src/services/auth.service.spec.ts:93`

#### V7.4.4 (L2)

> Verify that all pages that require authentication have easy and visible access to logout functionality.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Every authenticated web page has the account menu with logout, and a dedicated sessions page lists and terminates individual sessions; mobile apps expose logout. Covered by web auth e2e. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.ts#L96), [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/web/auth.e2e-spec.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/controllers/auth.controller.ts#L96) `server/src/controllers/auth.controller.ts:96`, [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/web/auth.e2e-spec.ts#L1) `e2e/src/specs/web/auth.e2e-spec.ts:1`

#### V7.4.5 (L2)

> Verify that application administrators are able to terminate active sessions for an individual user or for all users.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Admins can list a user's sessions (user-admin.service.ts) and deleting the user cascades sessions, but there is no admin endpoint to revoke an individual user's sessions without deleting the account. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/user-admin.service.ts#L82), [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L32)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/user-admin.service.ts#L82) `server/src/services/user-admin.service.ts:82`, [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L32) `server/src/schema/tables/session.table.ts:32`

### V7.5 Defenses Against Session Abuse

#### V7.5.1 (L2)

> Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery.

**Applicability:** yes | **Implemented:** no | **Tested:** no

Sensitive account changes such as email update (UserUpdateMeDto) do not require re-authentication or the current password; only the password change itself does. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L93)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L93) `server/src/dtos/user.dto.ts:93`

#### V7.5.2 (L2)

> Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

The sessions UI lists all active devices/sessions for the logged-in user and allows terminating any or all of them; covered by session e2e specs and session.service specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/session.service.ts#L44), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/session.service.spec.ts#L44), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/session.e2e-spec.ts#L17)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/session.service.ts#L44) `server/src/services/session.service.ts:44`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/session.service.spec.ts#L44) `server/src/services/session.service.spec.ts:44`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/session.e2e-spec.ts#L17) `e2e/src/specs/server/api/session.e2e-spec.ts:17`

#### V7.5.3 (L3)

> Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations.

*Unassessed (Level 3).*

### V7.6 Federated Re-authentication

#### V7.6.1 (L2)

> Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

RP/IdP session behavior is implemented (logout with id_token_hint, OAuth backchannel logout invalidating sessions by sid/sub) but the lifetime coordination policy is not documented and no re-authentication window is enforced. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L102), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L265)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L102) `server/src/services/auth.service.ts:102`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L265) `server/src/services/auth.service.spec.ts:265`

#### V7.6.2 (L2)

> Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Sessions are only created on explicit login actions (credential login, OAuth callback, passkey ceremony); no mechanism creates sessions without user interaction. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L366), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L60)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L366) `server/src/services/base.service.ts:366`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L60) `server/src/services/auth.service.ts:60`

## V8 — Authorization

### V8.1 Authorization Documentation

#### V8.1.1 (L1)

> Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes.

**Applicability:** yes | **Implemented:** no | **Tested:** no

There is no authorization documentation in docs/ defining function-level and data-level rules; the model exists only in code (Permission enum, access repository). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L1) `server/src/enum.ts:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16) `server/src/repositories/access.repository.ts:16`

#### V8.1.2 (L2)

> Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No documentation defines field-level read/write rules; field-level differences exist only implicitly in DTO mappers (mapUser vs mapUserAdmin). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53), [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L134)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53) `server/src/dtos/user.dto.ts:53`, [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L134) `server/src/dtos/user.dto.ts:134`

#### V8.1.3 (L3)

> Verify that the application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization.

*Unassessed (Level 3).*

#### V8.1.4 (L3)

> Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication).

*Unassessed (Level 3).*

### V8.2 General Authorization Design

#### V8.2.1 (L1)

> Verify that the application ensures that function-level access is restricted to consumers with explicit permissions.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

Routes are guarded by @Authenticated({ admin, permission }) with a central Permission enum checked in AuthGuard (middleware/auth.guard.ts); covered by auth.guard.spec.ts and controller specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L100), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114), [E3](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L100) `server/src/middleware/auth.guard.ts:100`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114) `server/src/middleware/auth.guard.ts:114`, [E3](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41) `server/src/middleware/auth.guard.spec.ts:41`

#### V8.2.2 (L1)

> Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA).

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

Data-level access is enforced via the access repository (owner/partner/album/shared-link checks) for assets, albums and people; extensively covered by service specs and e2e specs (asset, album, shared-link). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L148), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/asset.e2e-spec.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16) `server/src/repositories/access.repository.ts:16`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L148) `server/src/repositories/access.repository.ts:148`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/asset.e2e-spec.ts#L1) `e2e/src/specs/server/api/asset.e2e-spec.ts:1`

#### V8.2.3 (L2)

> Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA).

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Response DTOs whitelist fields per role (admin mappers expose more than user mappers; password hashes are never mapped), but there is no fine-grained per-field permission model beyond the admin/user split. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53), [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L134), [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/services/user.service.spec.ts#L63)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53) `server/src/dtos/user.dto.ts:53`, [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L134) `server/src/dtos/user.dto.ts:134`, [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/services/user.service.spec.ts#L63) `server/test/medium/specs/services/user.service.spec.ts:63`

#### V8.2.4 (L3)

> Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session.

*Unassessed (Level 3).*

### V8.3 Operation Level Authorization

#### V8.3.1 (L1)

> Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

All authorization decisions run in the NestJS server (guard + services + access repository); the web client only hides UI elements and never grants access. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16), [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/services/api-key.service.spec.ts#L35)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114) `server/src/middleware/auth.guard.ts:114`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16) `server/src/repositories/access.repository.ts:16`, [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/services/api-key.service.spec.ts#L35) `server/test/medium/specs/services/api-key.service.spec.ts:35`

#### V8.3.2 (L3)

> Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage.

*Unassessed (Level 3).*

#### V8.3.3 (L3)

> Verify that access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions.

*Unassessed (Level 3).*

### V8.4 Other Authorization Considerations

#### V8.4.1 (L2)

> Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich is a single-tenant self-hosted application (one instance, one photo library with per-user sharing); there is no multi-tenant surface to isolate. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1) `server/src/schema/tables/user.table.ts:1`

#### V8.4.2 (L3)

> Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access.

*Unassessed (Level 3).*

## V9 — Self-contained Tokens

### V9.1 Token source and integrity

#### V9.1.1 (L1)

> Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Self-contained JWTs (workflow execution tokens) are verified with HS256 signature before use (crypto.repository.ts verifyJwt, workflow-execution.service.ts). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L67), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L283)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L67) `server/src/repositories/crypto.repository.ts:67`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L283) `server/src/services/workflow-execution.service.ts:283`

#### V9.1.2 (L1)

> Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

jwt.verify is called with an explicit algorithm allowlist algorithms: ['HS256'] and signing is pinned to HS256; 'none' cannot be accepted. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L67)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64) `server/src/repositories/crypto.repository.ts:64`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L67) `server/src/repositories/crypto.repository.ts:67`

#### V9.1.3 (L1)

> Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

The JWT secret comes from the server's environment config only; no jku/x5u/jwk header handling exists, so untrusted key sources cannot be injected. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1) `server/src/repositories/config.repository.ts:1`

### V9.2 Token content

#### V9.2.1 (L1)

> Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Reference session tokens are validated against the DB with no client-side expiry. The self-contained workflow JWTs are signed without exp/nbf claims, so no validity timespan is enforced for them. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L283), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L283) `server/src/services/workflow-execution.service.ts:283`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64) `server/src/repositories/crypto.repository.ts:64`

#### V9.2.2 (L2)

> Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Session/API-key tokens are opaque reference tokens validated against their DB rows (correct purpose by construction). The self-contained workflow JWTs carry no typ claim and are not type-checked beyond algorithm and signature. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64) `server/src/repositories/crypto.repository.ts:64`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553) `server/src/services/auth.service.ts:553`

#### V9.2.3 (L2)

> Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Reference tokens are inherently single-audience; however the workflow JWTs are signed without an aud claim, so an audience check is not possible for them. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64) `server/src/repositories/crypto.repository.ts:64`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553) `server/src/services/auth.service.ts:553`

#### V9.2.4 (L2)

> Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich does not issue tokens to multiple audiences; its JWTs are self-consumed only (and session tokens are opaque). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L283)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L283) `server/src/services/workflow-execution.service.ts:283`

## V10 — OAuth and OIDC

### V10.1 Generic OAuth and OIDC Security

#### V10.1.1 (L2)

> Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Backend-for-frontend pattern: the OAuth access/refresh tokens are stored server-side on the session row (oauthBearerToken); the browser only receives the HttpOnly session cookie, never upstream tokens. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L382), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L148)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L1) `server/src/schema/tables/session.table.ts:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L382) `server/src/services/auth.service.ts:382`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L148) `e2e/src/specs/server/api/oauth.e2e-spec.ts:148`

#### V10.1.2 (L2)

> Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

PKCE code_verifier and state are generated server-side with randomBytes, bound to the user agent via HttpOnly cookies (oauth.controller.ts), and verified on callback; asserted in oauth.controller.spec.ts. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L59), [E2](https://github.com/rubendv/immich/blob/main/server/src/controllers/oauth.controller.ts#L52), [E3](https://github.com/rubendv/immich/blob/main/server/src/controllers/oauth.controller.spec.ts#L34)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L59) `server/src/repositories/oauth.repository.ts:59`, [E2](https://github.com/rubendv/immich/blob/main/server/src/controllers/oauth.controller.ts#L52) `server/src/controllers/oauth.controller.ts:52`, [E3](https://github.com/rubendv/immich/blob/main/server/src/controllers/oauth.controller.spec.ts#L34) `server/src/controllers/oauth.controller.spec.ts:34`

### V10.2 OAuth Client

#### V10.2.1 (L2)

> Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

The OAuth client uses PKCE plus a state parameter bound to the handshake via cookies, preventing CSRF on the code flow; covered by oauth.controller.spec.ts and oauth e2e specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L73), [E2](https://github.com/rubendv/immich/blob/main/server/src/controllers/oauth.controller.ts#L59), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L95)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L73) `server/src/repositories/oauth.repository.ts:73`, [E2](https://github.com/rubendv/immich/blob/main/server/src/controllers/oauth.controller.ts#L59) `server/src/controllers/oauth.controller.ts:59`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L95) `e2e/src/specs/server/api/oauth.e2e-spec.ts:95`

#### V10.2.2 (L2)

> Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Only one authorization server can be configured; mix-up attacks require multiple AS configurations. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1) `server/src/repositories/config.repository.ts:1`

#### V10.2.3 (L3)

> Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server.

*Unassessed (Level 3).*

### V10.3 OAuth Resource Server

#### V10.3.1 (L2)

> Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich does not accept structured access tokens from an authorization server; its API credentials are opaque session tokens and API keys validated against the database, so the audience concept does not apply. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L553) `server/src/services/auth.service.ts:553`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13) `server/src/services/api-key.service.ts:13`

#### V10.3.2 (L2)

> Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Authorization decisions are based on the DB user/permissions behind opaque tokens, not on claims from third-party access tokens. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114) `server/src/middleware/auth.guard.ts:114`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/access.repository.ts#L16) `server/src/repositories/access.repository.ts:16`

#### V10.3.3 (L2)

> Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

User identity comes from the session/API-key row (immutable UUID), not from claims in access tokens that could be reassigned. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21) `server/src/schema/tables/session.table.ts:21`

#### V10.3.4 (L2)

> Verify that, if the resource server requires specific authentication strength, methods, or recentness, it verifies that the presented access token satisfies these constraints. For example, if present, using the OIDC 'acr', 'amr' and 'auth_time' claims respectively.

**Applicability:** partial | **Implemented:** no | **Tested:** no

No acr/amr/auth_time constraints are verified for any presented credential; if MFA strength matters, it must be enforced at the (single) IdP. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L301)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L301) `server/src/services/auth.service.ts:301`

#### V10.3.5 (L3)

> Verify that the resource server prevents the use of stolen access tokens or replay of access tokens (from unauthorized parties) by requiring sender-constrained access tokens, either Mutual TLS for OAuth 2 or OAuth 2 Demonstration of Proof of Possession (DPoP).

*Unassessed (Level 3).*

### V10.4 OAuth Authorization Server

#### V10.4.1 (L1)

> Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich is an OAuth client, not an authorization server; it consumes external OIDC providers via openid-client and never issues authorization codes. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.4.2 (L1)

> Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; no authorization codes are issued by Immich. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.4.3 (L1)

> Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; no authorization codes are issued by Immich. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.4.4 (L1)

> Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; Immich only performs the authorization-code + PKCE flow as a client. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L59), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L73)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L59) `server/src/repositories/oauth.repository.ts:59`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L73) `server/src/repositories/oauth.repository.ts:73`

#### V10.4.5 (L1)

> Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; refresh tokens of the upstream provider are stored server-side per session, never exposed to browser clients. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L382), [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L382) `server/src/services/auth.service.ts:382`, [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L1) `server/src/schema/tables/session.table.ts:1`

#### V10.4.6 (L2)

> Verify that, if the code grant is used, the authorization server mitigates authorization code interception attacks by requiring proof key for code exchange (PKCE). For authorization requests, the authorization server must require a valid 'code_challenge' value and must not accept a 'code_challenge_method' value of 'plain'. For a token request, it must require validation of the 'code_verifier' parameter.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; PKCE is used on the client side only. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L59)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L59) `server/src/repositories/oauth.repository.ts:59`

#### V10.4.7 (L2)

> Verify that if the authorization server supports unauthenticated dynamic client registration, it mitigates the risk of malicious client applications. It must validate client metadata such as any registered URIs, ensure the user's consent, and warn the user before processing an authorization request with an untrusted client application.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; no dynamic client registration is performed or offered. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1) `server/src/repositories/config.repository.ts:1`

#### V10.4.8 (L2)

> Verify that refresh tokens have an absolute expiration, including if sliding refresh token expiration is applied.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; refresh tokens belong to the upstream IdP and are only stored/revoked by Immich. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L382)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L382) `server/src/services/auth.service.ts:382`

#### V10.4.9 (L2)

> Verify that refresh tokens and reference access tokens can be revoked by an authorized user using the authorization server user interface, to mitigate the risk of malicious clients or stolen tokens.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; Immich has no token revocation UI for upstream tokens (session deletion drops the stored bearer token). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L79)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L79) `server/src/services/auth.service.ts:79`

#### V10.4.10 (L2)

> Verify that confidential client is authenticated for client-to-authorized server backchannel requests such as token requests, pushed authorization requests (PAR), and token revocation requests.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; backchannel requests to the IdP authenticate with the configured client credentials. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.4.11 (L2)

> Verify that the authorization server configuration only assigns the required scopes to the OAuth client.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Not an authorization server; scope assignment is an IdP-side concern. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.4.12 (L3)

> Verify that for a given client, the authorization server only allows the 'response_mode' value that this client needs to use. For example, by having the authorization server validate this value against the expected values or by using pushed authorization request (PAR) or JWT-secured Authorization Request (JAR).

*Unassessed (Level 3).*

#### V10.4.13 (L3)

> Verify that grant type 'code' is always used together with pushed authorization requests (PAR).

*Unassessed (Level 3).*

#### V10.4.14 (L3)

> Verify that the authorization server issues only sender-constrained (Proof-of-Possession) access tokens, either with certificate-bound access tokens using mutual TLS (mTLS) or DPoP-bound access tokens (Demonstration of Proof of Possession).

*Unassessed (Level 3).*

#### V10.4.15 (L3)

> Verify that, for a server-side client (which is not executed on the end-user device), the authorization server ensures that the 'authorization_details' parameter value is from the client backend and that the user has not tampered with it. For example, by requiring the usage of pushed authorization request (PAR) or JWT-secured Authorization Request (JAR).

*Unassessed (Level 3).*

#### V10.4.16 (L3)

> Verify that the client is confidential and the authorization server requires the use of strong client authentication methods (based on public-key cryptography and resistant to replay attacks), such as mutual TLS ('tls_client_auth', 'self_signed_tls_client_auth') or private key JWT ('private_key_jwt').

*Unassessed (Level 3).*

### V10.5 OIDC Client

#### V10.5.1 (L2)

> Verify that the client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the 'nonce' claim in the ID Token matches the 'nonce' value sent in the authentication request to the OpenID Provider (in OAuth2 refereed to as the authorization request sent to the authorization server).

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

The OIDC client (openid-client) generates and validates a nonce per authentication request, binding the ID token to the original request. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L59), [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L148)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L59) `server/src/repositories/oauth.repository.ts:59`, [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L148) `e2e/src/specs/server/api/oauth.e2e-spec.ts:148`

#### V10.5.2 (L2)

> Verify that the client uniquely identifies the user from ID Token claims, usually the 'sub' claim, which cannot be reassigned to other users (for the scope of an identity provider).

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Users are identified by the IdP's sub claim stored as a unique oauthId per user; emails may link accounts but the sub-based binding is not reassignable within the IdP. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L61), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L301), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L37)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L61) `server/src/schema/tables/user.table.ts:61`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L301) `server/src/services/auth.service.ts:301`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L37) `e2e/src/specs/server/api/oauth.e2e-spec.ts:37`

#### V10.5.3 (L2)

> Verify that the client rejects attempts by a malicious authorization server to impersonate another authorization server through authorization server metadata. The client must reject authorization server metadata if the issuer URL in the authorization server metadata does not exactly match the pre-configured issuer URL expected by the client.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

openid-client validates the issuer in the server metadata against the pre-configured issuerUrl (new URL(issuerUrl) in oauth.repository.ts); metadata from a different issuer is rejected. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.5.4 (L2)

> Verify that the client validates that the ID Token is intended to be used for that client (audience) by checking that the 'aud' claim from the token is equal to the 'client_id' value for the client.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

openid-client validates the ID token aud claim against the configured clientId before accepting the login. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.5.5 (L2)

> Verify that, when using OIDC back-channel logout, the relying party mitigates denial of service through forced logout and cross-JWT confusion in the logout flow. The client must verify that the logout token is correctly typed with a value of 'logout+jwt', contains the 'event' claim with the correct member name, and does not contain a 'nonce' claim. Note that it is also recommended to have a short expiration (e.g., 2 minutes).

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Backchannel logout tokens are validated for signature, issuer, audience, maxTokenAge 2m, presence of the backchannel-logout event claim and absence of nonce (oauth.repository.ts validateLogoutToken); the typ='logout+jwt' claim is not checked. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L148), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L265)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L148) `server/src/repositories/oauth.repository.ts:148`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L265) `server/src/services/auth.service.spec.ts:265`

### V10.6 OpenID Provider

#### V10.6.1 (L2)

> Verify that the OpenID Provider only allows values 'code', 'ciba', 'id_token', or 'id_token code' for response mode. Note that 'code' is preferred over 'id_token code' (the OIDC Hybrid flow), and 'token' (any Implicit flow) must not be used.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich is not an OpenID Provider; response modes are a property of the upstream IdP. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.6.2 (L2)

> Verify that the OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation from the end-user or, if present, validating parameters in the logout request (initiated by the relying party), such as the 'id_token_hint'.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich is not an OpenID Provider and does not host user sessions for relying parties. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

### V10.7 Consent Management

#### V10.7.1 (L2)

> Verify that the authorization server ensures that the user consents to each authorization request. If the identity of the client cannot be assured, the authorization server must always explicitly prompt the user for consent.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich is not an authorization server; consent screens are the IdP's responsibility. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.7.2 (L2)

> Verify that when the authorization server prompts for user consent, it presents sufficient and clear information about what is being consented to. When applicable, this should include the nature of the requested authorizations (typically based on scope, resource server, Rich Authorization Requests (RAR) authorization details), the identity of the authorized application, and the lifetime of these authorizations.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich is not an authorization server; no consent prompts are rendered. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

#### V10.7.3 (L2)

> Verify that the user can review, modify, and revoke consents which the user has granted through the authorization server.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

Immich is not an authorization server; there are no user-consented grants to review. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/oauth.repository.ts#L1) `server/src/repositories/oauth.repository.ts:1`

## V11 — Cryptography

### V11.1 Cryptographic Inventory and Documentation

#### V11.1.1 (L2)

> Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys).

**Applicability:** yes | **Implemented:** no | **Tested:** no

No key-management policy exists; the JWT secret and OAuth client secret are single shared secrets provided via environment variables without documented lifecycle, rotation or sharing limits. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1), [E2](https://github.com/rubendv/immich/blob/main/docker/example.env#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1) `server/src/repositories/config.repository.ts:1`, [E2](https://github.com/rubendv/immich/blob/main/docker/example.env#L1) `docker/example.env:1`

#### V11.1.2 (L2)

> Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No cryptographic inventory exists; the keys in use (JWT secret, OAuth client secret, license public keys) and algorithms (bcrypt, SHA-256, HS256) are only discoverable from code. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L46), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L46) `server/src/constants.ts:46`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17) `server/src/repositories/crypto.repository.ts:17`

#### V11.1.3 (L3)

> Verify that cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system, including encryption, hashing, and signing operations.

*Unassessed (Level 3).*

#### V11.1.4 (L3)

> Verify that a cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats.

*Unassessed (Level 3).*

### V11.2 Secure Cryptography Implementation

#### V11.2.1 (L2)

> Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

All crypto uses industry-validated implementations: node crypto (OpenSSL), bcrypt, jose/openid-client for JWT/OIDC; no hand-rolled cryptography. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17) `server/src/repositories/crypto.repository.ts:17`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64) `server/src/repositories/crypto.repository.ts:64`

#### V11.2.2 (L2)

> Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available.

**Applicability:** yes | **Implemented:** no | **Tested:** no

Algorithms and key lengths are fixed in code (bcrypt cost 10, HS256, SHA-256) with no reconfiguration or swap mechanism; keys can be rotated via env but no crypto-agility design exists. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L46), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L46) `server/src/constants.ts:46`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64) `server/src/repositories/crypto.repository.ts:64`

#### V11.2.3 (L2)

> Verify that all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides roughly 128 bits of security where RSA requires a 3072-bit key to achieve 128 bits of security.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

All primitives meet the 128-bit bar: SHA-256 and HS256 (256-bit), bcrypt (adaptive, up to 72-byte passwords), CSPRNG tokens of 256-400 bits. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L372)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17) `server/src/repositories/crypto.repository.ts:17`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L372) `server/src/services/base.service.ts:372`

#### V11.2.4 (L3)

> Verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations, or returns, to avoid leaking information.

*Unassessed (Level 3).*

#### V11.2.5 (L3)

> Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable vulnerabilities, such as Padding Oracle attacks.

*Unassessed (Level 3).*

### V11.3 Encryption Algorithms

#### V11.3.1 (L1)

> Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

No direct block-cipher usage in server code; only bcrypt (passwords) and SHA-256 (token hashing) are used, so no ECB mode or PKCS#1 v1.5 padding appears. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17) `server/src/repositories/crypto.repository.ts:17`

#### V11.3.2 (L1)

> Verify that only approved ciphers and modes such as AES with GCM are used.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

No bulk encryption is implemented in application code; at-rest encryption is delegated to the database/storage layer, and the only crypto primitives used are bcrypt and SHA-256. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17) `server/src/repositories/crypto.repository.ts:17`

#### V11.3.3 (L2)

> Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method or by combining an approved encryption method with an approved MAC algorithm.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

The application does not encrypt data at the application layer; at-rest encryption is delegated to the database/storage layer, so there is no app-level ciphertext to integrity-protect. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21) `server/src/schema/tables/session.table.ts:21`

#### V11.3.4 (L3)

> Verify that nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair. The method of generation must be appropriate for the algorithm being used.

*Unassessed (Level 3).*

#### V11.3.5 (L3)

> Verify that any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode.

*Unassessed (Level 3).*

### V11.4 Hashing and Hash-based Functions

#### V11.4.1 (L1)

> Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

SHA-256 (token/session hashing) and bcrypt are the only security hashes; SHA-1 is used solely for asset dedup checksums, a non-security purpose. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L554)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17) `server/src/repositories/crypto.repository.ts:17`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L554) `server/src/services/auth.service.ts:554`

#### V11.4.2 (L2)

> Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a "password hashing function"), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

Passwords and PIN codes are hashed with bcrypt at cost 10 (SALT_ROUNDS in constants.ts, hashBcrypt in crypto.repository.ts); an approved password-hashing function, though 10 is the lower bound of current guidance. Asserted in auth/user service specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L46), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/constants.ts#L46) `server/src/constants.ts:46`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17) `server/src/repositories/crypto.repository.ts:17`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.spec.ts#L93) `server/src/services/auth.service.spec.ts:93`

#### V11.4.3 (L2)

> Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

SHA-256 (256-bit) is used for token hashing and integrity; bcrypt (with salt) for passwords. SHA-1 appears only for non-security asset checksums. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L554), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.spec.ts#L24)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17) `server/src/repositories/crypto.repository.ts:17`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L554) `server/src/services/auth.service.ts:554`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.spec.ts#L24) `server/src/services/api-key.service.spec.ts:24`

#### V11.4.4 (L2)

> Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

No secret keys are derived from passwords; the only password-based derivations are bcrypt hashes for storage (PIN codes likewise), which is the approved use. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L17) `server/src/repositories/crypto.repository.ts:17`

### V11.5 Random Values

#### V11.5.1 (L2)

> Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

All security-relevant random values use node crypto CSPRNG with at least 128 bits (session/API keys 32 bytes, shared-link keys 50 bytes, OAuth state/verifier); UUIDs are used only for entity identifiers, not as secrets. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L372), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94), [E3](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13), [E4](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.spec.ts#L35)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/base.service.ts#L372) `server/src/services/base.service.ts:372`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/shared-link.service.ts#L94) `server/src/services/shared-link.service.ts:94`, [E3](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13) `server/src/services/api-key.service.ts:13`, [E4](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.spec.ts#L35) `server/src/services/api-key.service.spec.ts:35`

#### V11.5.2 (L3)

> Verify that the random number generation mechanism in use is designed to work securely, even under heavy demand.

*Unassessed (Level 3).*

### V11.6 Public Key Cryptography

#### V11.6.1 (L2)

> Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Only HS256 JWTs with env-provided secrets and pinned RSA public keys for license verification are used; no key generation is performed in application code. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/crypto.repository.ts#L64) `server/src/repositories/crypto.repository.ts:64`

#### V11.6.2 (L3)

> Verify that approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks.

*Unassessed (Level 3).*

### V11.7 In-Use Data Cryptography

#### V11.7.1 (L3)

> Verify that full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes.

*Unassessed (Level 3).*

#### V11.7.2 (L3)

> Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible.

*Unassessed (Level 3).*

## V12 — Secure Communication

### V12.1 General TLS Security Guidance

#### V12.1.1 (L1)

> Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

The application itself listens on plain HTTP; TLS protocol versions and preference are determined by the reverse proxy / deployment environment, which the docs require but the app neither enforces nor tests. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41), [E2](https://github.com/rubendv/immich/blob/main/docs/docs/administration/reverse-proxy.md#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41) `server/src/app.common.ts:41`, [E2](https://github.com/rubendv/immich/blob/main/docs/docs/administration/reverse-proxy.md#L1) `docs/docs/administration/reverse-proxy.md:1`

#### V12.1.2 (L2)

> Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Cipher suite selection is a reverse-proxy/deployment concern; the app does not terminate TLS and pins no cipher suites. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41) `server/src/app.common.ts:41`

#### V12.1.3 (L2)

> Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

mTLS client-certificate authentication is not used anywhere in the application or its documented deployments. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1) `server/src/repositories/config.repository.ts:1`

#### V12.1.4 (L3)

> Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured.

*Unassessed (Level 3).*

#### V12.1.5 (L3)

> Verify that Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes.

*Unassessed (Level 3).*

### V12.2 HTTPS Communication with External Facing Services

#### V12.2.1 (L1)

> Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

No TLS code or HTTP->HTTPS fallback exists in the app; secure transport is a deployment responsibility (reverse proxy per docs/docs/install). Cookies are marked Secure only when the incoming connection is trusted as secure. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L47), [E2](https://github.com/rubendv/immich/blob/main/docs/docs/administration/reverse-proxy.md#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L47) `server/src/utils/response.ts:47`, [E2](https://github.com/rubendv/immich/blob/main/docs/docs/administration/reverse-proxy.md#L1) `docs/docs/administration/reverse-proxy.md:1`

#### V12.2.2 (L1)

> Verify that external facing services use publicly trusted TLS certificates.

**Applicability:** partial | **Implemented:** partial | **Tested:** no

Certificate issuance/trust is entirely outside the codebase (self-hosted deployments choose their own reverse proxy certificates); not verifiable from the project. See [[E1](https://github.com/rubendv/immich/blob/main/docs/docs/administration/reverse-proxy.md#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docs/docs/administration/reverse-proxy.md#L1) `docs/docs/administration/reverse-proxy.md:1`

### V12.3 General Service to Service Communication Security

#### V12.3.1 (L2)

> Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Postgres supports configurable sslmode (DB_SSL_MODE), but Redis and the ML service are reached over plain HTTP/TCP on the internal Docker network by default; no end-to-end encryption policy exists. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L277), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/app.repository.ts#L3)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L277) `server/src/repositories/config.repository.ts:277`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/app.repository.ts#L3) `server/src/repositories/app.repository.ts:3`

#### V12.3.2 (L2)

> Verify that TLS clients validate certificates received before communicating with a TLS server.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Outbound TLS validation is delegated: node fetch validates certificates for https endpoints (version check, IdP metadata); the DB sslmode default does not enforce certificate validation. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L277)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L277) `server/src/repositories/config.repository.ts:277`

#### V12.3.3 (L2)

> Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications.

**Applicability:** yes | **Implemented:** no | **Tested:** no

Internal HTTP-based services (ML server, Redis, Postgres) communicate unencrypted on the container network by default; TLS is not configured between them. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/app.repository.ts#L3)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/app.repository.ts#L3) `server/src/repositories/app.repository.ts:3`

#### V12.3.4 (L2)

> Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No internal TLS trust configuration exists (no internal CA or pinned self-signed certificates); internal traffic is plaintext by default. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/app.repository.ts#L3)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/app.repository.ts#L3) `server/src/repositories/app.repository.ts:3`

#### V12.3.5 (L3)

> Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security.

*Unassessed (Level 3).*

## V13 — Configuration

### V13.1 Configuration Documentation

#### V13.1.1 (L2)

> Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

docs describe the deployment architecture (Postgres, Redis, ML server, reverse proxy, map tiles/version-check endpoints), but there is no complete, consolidated communication inventory. See [[E1](https://github.com/rubendv/immich/blob/main/docs/docs/install/docker-compose.mdx#L1), [E2](https://github.com/rubendv/immich/blob/main/docs/docs/developer/architecture.mdx#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docs/docs/install/docker-compose.mdx#L1) `docs/docs/install/docker-compose.mdx:1`, [E2](https://github.com/rubendv/immich/blob/main/docs/docs/developer/architecture.mdx#L1) `docs/docs/developer/architecture.mdx:1`

#### V13.1.2 (L3)

> Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions.

*Unassessed (Level 3).*

#### V13.1.3 (L3)

> Verify that the application documentation defines resource‑management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource‑release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back‑off algorithms. For synchronous HTTP request–response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion.

*Unassessed (Level 3).*

#### V13.1.4 (L3)

> Verify that the application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements.

*Unassessed (Level 3).*

### V13.2 Backend Communication Configuration

#### V13.2.1 (L2)

> Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Backend services authenticate with individual credentials: Postgres/Redis use credentials from environment variables per deployment; however these are static shared passwords rather than short-term tokens or certificates. See [[E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L17), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L17) `docker/example.env:17`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1) `server/src/repositories/config.repository.ts:1`

#### V13.2.2 (L2)

> Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

The application uses a single DB owner account (needed for migrations) rather than least-privilege per-service accounts; Redis access is unprivileged. See [[E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L17)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L17) `docker/example.env:17`

#### V13.2.3 (L2)

> Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin).

**Applicability:** yes | **Implemented:** yes | **Tested:** no

No default credentials are compiled in or shipped: docker-compose requires DB/Redis passwords via environment variables; example env files contain placeholders, not working credentials. See [[E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L17)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L17) `docker/example.env:17`

#### V13.2.4 (L2)

> Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No outbound allowlist exists; the server fetches admin-configured URLs (ML endpoint, map/reverse-geocode URLs, OAuth issuer) without allowlist validation. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L97), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L108)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L97) `server/src/services/workflow-execution.service.ts:97`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L108) `server/src/repositories/config.repository.ts:108`

#### V13.2.5 (L2)

> Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No allowlist restricts outbound destinations at the application layer; only fixed constants (version check) and admin-configured URLs are fetched. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L108)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L108) `server/src/repositories/config.repository.ts:108`

#### V13.2.6 (L3)

> Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies.

*Unassessed (Level 3).*

### V13.3 Secret Management

#### V13.3.1 (L2)

> Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Secrets are supplied via environment variables (no secrets in source code or build artifacts); there is no vault/KMS integration, and JWT/OAuth secrets are long-lived shared secrets. See [[E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L1) `docker/example.env:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L1) `server/src/repositories/config.repository.ts:1`

#### V13.3.2 (L2)

> Verify that access to secret assets adheres to the principle of least privilege.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Access to secrets is limited to the server process/container (env vars, docker secrets pattern), but no formal least-privilege access model for secret assets is documented or enforced. See [[E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docker/example.env#L1) `docker/example.env:1`

#### V13.3.3 (L3)

> Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module.

*Unassessed (Level 3).*

#### V13.3.4 (L3)

> Verify that secrets are configured to expire and be rotated based on the application's documentation.

*Unassessed (Level 3).*

### V13.4 Unintended Information Leakage

#### V13.4.1 (L1)

> Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

The production Docker image COPYs only source directories and build outputs (server/Dockerfile); .git/.svn metadata is never copied into the image. See [[E1](https://github.com/rubendv/immich/blob/main/server/Dockerfile#L14)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/Dockerfile#L14) `server/Dockerfile:14`

#### V13.4.2 (L2)

> Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Production mode disables dev CORS and Swagger spec writing, and log levels are configurable; however the Swagger UI remains mounted in production unless disabled, and debug logging can be enabled via env. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L59), [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L66)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L59) `server/src/app.common.ts:59`, [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L66) `server/src/app.common.ts:66`

#### V13.4.3 (L2)

> Verify that web servers do not expose directory listings to clients unless explicitly intended.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Static file serving uses sirv without directory listings (app.common.ts); only built assets and API routes are reachable. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L7)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L7) `server/src/app.common.ts:7`

#### V13.4.4 (L2)

> Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Node's HTTP server does not implement the TRACE method; such requests are rejected (404) by Express in all environments. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L41) `server/src/app.common.ts:41`

#### V13.4.5 (L2)

> Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Monitoring endpoints are opt-in: the /api/metrics endpoint requires telemetry to be enabled via env; however Swagger/OpenAPI documentation endpoints are exposed on the public API in production. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/telemetry.repository.ts#L3), [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L66)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/telemetry.repository.ts#L3) `server/src/repositories/telemetry.repository.ts:3`, [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L66) `server/src/app.common.ts:66`

#### V13.4.6 (L3)

> Verify that the application does not expose detailed version information of backend components.

*Unassessed (Level 3).*

#### V13.4.7 (L3)

> Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage.

*Unassessed (Level 3).*

## V14 — Data Protection

### V14.1 Data Protection Documentation

#### V14.1.1 (L2)

> Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No data classification or protection-level inventory exists for sensitive data (photos, tokens, user PII). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1) `server/src/schema/tables/user.table.ts:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/session.table.ts#L21) `server/src/schema/tables/session.table.ts:21`

#### V14.1.2 (L2)

> Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No documented protection requirements per data class (encryption, retention, logging rules) exist. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1) `server/src/schema/tables/user.table.ts:1`

### V14.2 General Data Protection

#### V14.2.1 (L1)

> Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Session tokens travel in HttpOnly cookies or the Authorization header, API keys in x-api-key; however shared-link keys are secrets embedded in URLs by design (web/src/routes/(user)/share/[key]). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L42), [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13), [E3](https://github.com/rubendv/immich/blob/main/web/src/routes/%28user%29/share/%5Bkey%5D/%5B%5Bphotos%3Dphotos%5D%5D/%5B%5BassetId%3Did%5D%5D/%2Bpage.svelte#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L42) `server/src/utils/response.ts:42`, [E2](https://github.com/rubendv/immich/blob/main/server/src/services/api-key.service.ts#L13) `server/src/services/api-key.service.ts:13`, [E3](https://github.com/rubendv/immich/blob/main/web/src/routes/%28user%29/share/%5Bkey%5D/%5B%5Bphotos%3Dphotos%5D%5D/%5B%5BassetId%3Did%5D%5D/%2Bpage.svelte#L1) `web/src/routes/(user)/share/[key]/[[photos=photos]]/[[assetId=id]]/+page.svelte:1`

#### V14.2.2 (L2)

> Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

API responses use private/no-cache Cache-Control for originals and thumbnails (server/src/utils/file.ts), limiting intermediary caching; the compression middleware still processes all responses and shared CDNs are a deployment concern. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L40)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L40) `server/src/utils/file.ts:40`

#### V14.2.3 (L2)

> Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

No third-party trackers or analytics are embedded; the optional telemetry feature (version check, anonymous metrics) is opt-in and documented. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/telemetry.repository.ts#L3)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/telemetry.repository.ts#L3) `server/src/repositories/telemetry.repository.ts:3`

#### V14.2.4 (L2)

> Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No per-protection-level control implementation exists because no protection levels are defined. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/schema/tables/user.table.ts#L1) `server/src/schema/tables/user.table.ts:1`

#### V14.2.5 (L3)

> Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks.

*Unassessed (Level 3).*

#### V14.2.6 (L3)

> Verify that the application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it.

*Unassessed (Level 3).*

#### V14.2.7 (L3)

> Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires.

*Unassessed (Level 3).*

#### V14.2.8 (L3)

> Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user.

*Unassessed (Level 3).*

### V14.3 Client-side Data Protection

#### V14.3.1 (L1)

> Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Logout clears auth cookies and deletes the server session; the web app clears its local state on logout. No Clear-Site-Data header is sent and offline cleanup is not guaranteed. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L79), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L42), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/session.e2e-spec.ts#L36)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L79) `server/src/services/auth.service.ts:79`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L42) `server/src/utils/response.ts:42`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/session.e2e-spec.ts#L36) `e2e/src/specs/server/api/session.e2e-spec.ts:36`

#### V14.3.2 (L2)

> Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Originals are served with 'private, no-cache, no-transform' and thumbnails with 'private, max-age...' (cacheControlHeaders in server/src/utils/file.ts); responses are not marked no-store across the API. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L43), [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L42)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L43) `server/src/utils/file.ts:43`, [E2](https://github.com/rubendv/immich/blob/main/server/src/utils/file.ts#L42) `server/src/utils/file.ts:42`

#### V14.3.3 (L2)

> Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Browser storage contains only UI preferences (search query type, scroll position); session tokens live in HttpOnly cookies, and the non-HttpOnly isAuthenticated cookie only signals auth state. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L42), [E2](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L20)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/response.ts#L42) `server/src/utils/response.ts:42`, [E2](https://github.com/rubendv/immich/blob/main/server/src/enum.ts#L20) `server/src/enum.ts:20`

## V15 — Secure Coding and Architecture

### V15.1 Secure Coding and Architecture Documentation

#### V15.1.1 (L1)

> Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No documentation defines risk-based remediation time frames for vulnerable dependencies; renovate.json automates update PRs but has no security-timeframe policy. See [[E1](https://github.com/rubendv/immich/blob/main/renovate.json#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/renovate.json#L1) `renovate.json:1`

#### V15.1.2 (L2)

> Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No SBOM is maintained in the repository; dependency tracking relies on lockfiles and GitHub's dependency graph. See [[E1](https://github.com/rubendv/immich/blob/main/server/package.json#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/package.json#L1) `server/package.json:1`

#### V15.1.3 (L2)

> Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

docs describe hardware transcoding and job queues at a high level, but there is no documentation identifying resource-demanding functionality and defenses against availability loss. See [[E1](https://github.com/rubendv/immich/blob/main/docs/docs/administration/jobs-workers.md#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/docs/docs/administration/jobs-workers.md#L1) `docs/docs/administration/jobs-workers.md:1`

#### V15.1.4 (L3)

> Verify that application documentation highlights third-party libraries which are considered to be "risky components".

*Unassessed (Level 3).*

#### V15.1.5 (L3)

> Verify that application documentation highlights parts of the application where "dangerous functionality" is being used.

*Unassessed (Level 3).*

### V15.2 Security Architecture and Dependencies

#### V15.2.1 (L1)

> Verify that the application only contains components which have not breached the documented update and remediation time frames.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Renovate continuously updates dependencies, but there is no policy or verification that components stay within defined remediation time frames. See [[E1](https://github.com/rubendv/immich/blob/main/renovate.json#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/renovate.json#L1) `renovate.json:1`

#### V15.2.2 (L2)

> Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Heavy work (thumbnailing, transcoding, ML) runs asynchronously through BullMQ job queues with per-queue concurrency limits and job deduplication; upload/download streams are throttled by backpressure. Covered partially by job service specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/job.repository.ts#L147), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/job.repository.ts#L97), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/jobs.e2e-spec.ts#L16)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/job.repository.ts#L147) `server/src/repositories/job.repository.ts:147`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/job.repository.ts#L97) `server/src/repositories/job.repository.ts:97`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/jobs.e2e-spec.ts#L16) `e2e/src/specs/server/api/jobs.e2e-spec.ts:16`

#### V15.2.3 (L2)

> Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Dev-only behavior is gated behind isDev() (CORS, swagger writing); the production image contains only built server/web artifacts, but the Swagger UI remains exposed in production. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L59), [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L66)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L59) `server/src/app.common.ts:59`, [E2](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L66) `server/src/app.common.ts:66`

#### V15.2.4 (L3)

> Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack.

*Unassessed (Level 3).*

#### V15.2.5 (L3)

> Verify that the application implements additional protections around parts of the application which are documented as containing "dangerous functionality" or using third-party libraries considered to be "risky components". This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application.

*Unassessed (Level 3).*

### V15.3 Defensive Coding

#### V15.3.1 (L1)

> Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

API responses are produced by explicit DTO mappers that whitelist fields (mapUser/mapUserAdmin never include password hashes); response shapes asserted in service and controller specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53), [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L134), [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/services/user.service.spec.ts#L63)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53) `server/src/dtos/user.dto.ts:53`, [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L134) `server/src/dtos/user.dto.ts:134`, [E3](https://github.com/rubendv/immich/blob/main/server/test/medium/specs/services/user.service.spec.ts#L63) `server/test/medium/specs/services/user.service.spec.ts:63`

#### V15.3.2 (L2)

> Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Outbound fetches (version check, ML ping, OAuth metadata/JWKS) use default redirect-following; the URLs are fixed constants or admin-configured, which limits but does not eliminate redirect-based SSRF. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L97)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/workflow-execution.service.ts#L97) `server/src/services/workflow-execution.service.ts:97`

#### V15.3.3 (L2)

> Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action.

**Applicability:** yes | **Implemented:** yes | **Tested:** yes

All write endpoints accept zod DTOs that strip unknown keys; entity updates map only whitelisted fields, so mass assignment of unintended fields is not possible. Covered by validation and service specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137), [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53), [E3](https://github.com/rubendv/immich/blob/main/server/src/validation.spec.ts#L5)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137) `server/src/validation.ts:137`, [E2](https://github.com/rubendv/immich/blob/main/server/src/dtos/user.dto.ts#L53) `server/src/dtos/user.dto.ts:53`, [E3](https://github.com/rubendv/immich/blob/main/server/src/validation.spec.ts#L5) `server/src/validation.spec.ts:5`

#### V15.3.4 (L2)

> Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

Express trust proxy is restricted to loopback + configured trustedProxies, so clientIp used for logging/security decisions comes only from trusted hops; covered by config repository specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L47), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L362), [E3](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.spec.ts#L267)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/app.common.ts#L47) `server/src/app.common.ts:47`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.ts#L362) `server/src/repositories/config.repository.ts:362`, [E3](https://github.com/rubendv/immich/blob/main/server/src/repositories/config.repository.spec.ts#L267) `server/src/repositories/config.repository.spec.ts:267`

#### V15.3.5 (L2)

> Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

TypeScript with strict type checking and zod runtime validation enforces correct types; comparisons use strict equality consistently (lint-enforced) preventing type juggling. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L117), [E2](https://github.com/rubendv/immich/blob/main/server/eslint.config.mjs#L81)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L117) `server/src/validation.ts:117`, [E2](https://github.com/rubendv/immich/blob/main/server/eslint.config.mjs#L81) `server/eslint.config.mjs:81`

#### V15.3.6 (L2)

> Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

User input is parsed into fresh objects by zod (no recursive merge of user-controlled keys into prototypes); no prototype-pollution-prone deep-merge utilities were found, though there is no explicit hardening test. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137) `server/src/validation.ts:137`

#### V15.3.7 (L2)

> Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields).

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Header extraction takes the first value deliberately (fromMaybeArray in utils/request.ts) and zod rejects unexpected duplicates for most inputs, but there is no systematic HTTP parameter pollution defense. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/utils/request.ts#L8)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/utils/request.ts#L8) `server/src/utils/request.ts:8`

### V15.4 Safe Concurrency

#### V15.4.1 (L3)

> Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption.

*Unassessed (Level 3).*

#### V15.4.2 (L3)

> Verify that checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user’s access before granting it.

*Unassessed (Level 3).*

#### V15.4.3 (L3)

> Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code.

*Unassessed (Level 3).*

#### V15.4.4 (L3)

> Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe.

*Unassessed (Level 3).*

## V16 — Security Logging and Error Handling

### V16.1 Security Logging Documentation

#### V16.1.1 (L2)

> Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept.

**Applicability:** yes | **Implemented:** no | **Tested:** no

No logging inventory exists; logging behavior (stdout/JSON, levels, telemetry) is only implicitly defined by the code and env variables. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L1) `server/src/repositories/logging.repository.ts:1`

### V16.2 General Logging

#### V16.2.1 (L2)

> Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Log entries include timestamp, severity, app context and a per-request correlation id via AsyncLocalStorage (logging.repository.ts, logging.interceptor.ts), but not the acting user or target resource in every entry. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L48), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/logging.interceptor.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L48) `server/src/repositories/logging.repository.ts:48`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/logging.interceptor.ts#L1) `server/src/middleware/logging.interceptor.ts:1`

#### V16.2.2 (L2)

> Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Timestamps come from the host clock in ISO format; UTC usage is not enforced and time synchronization is a deployment concern. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L48)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L48) `server/src/repositories/logging.repository.ts:48`

#### V16.2.3 (L2)

> Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Logs go to stdout (optionally JSON) and optionally to OTLP telemetry endpoints; destinations are bounded by env config but not by a documented inventory. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L1), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/telemetry.repository.ts#L3)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L1) `server/src/repositories/logging.repository.ts:1`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/telemetry.repository.ts#L3) `server/src/repositories/telemetry.repository.ts:3`

#### V16.2.4 (L2)

> Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

A JSON log format is available (LogFormat json via env) and the console format is consistent, allowing correlation by log processors. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L1) `server/src/repositories/logging.repository.ts:1`

#### V16.2.5 (L2)

> Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Passwords/tokens are not logged by the logger, but user emails are logged on failed login (auth.service.ts warn) and no formal protection-level-based logging rules or redaction pipeline exist. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L48)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72) `server/src/services/auth.service.ts:72`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L48) `server/src/repositories/logging.repository.ts:48`

### V16.3 Security Events

#### V16.3.1 (L2)

> Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Failed logins are logged with IP and email (auth.service.ts); successful logins create session rows (device/OS/IP recorded) rather than log lines; no factor metadata is logged. No test asserts the content of security log entries. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72) `server/src/services/auth.service.ts:72`

#### V16.3.2 (L2)

> Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself).

**Applicability:** yes | **Implemented:** no | **Tested:** no

Failed authorization attempts (403 from AuthGuard/access checks) are not systematically logged. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L114) `server/src/middleware/auth.guard.ts:114`

#### V16.3.3 (L2)

> Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Some security events are logged (failed logins, upload validation failures) but there is no defined security event list and bypass attempts (validation, anti-automation) are not logged. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72) `server/src/services/auth.service.ts:72`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/file-upload.interceptor.ts#L89) `server/src/middleware/file-upload.interceptor.ts:89`

#### V16.3.4 (L2)

> Verify that the application logs unexpected errors and security control failures such as backend TLS failures.

**Applicability:** yes | **Implemented:** yes | **Tested:** no

Unexpected errors are caught by the global exception filter and logged with stack traces (middleware/global-exception.filter.ts); job failures are logged via the job repository. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/global-exception.filter.ts#L19)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/global-exception.filter.ts#L19) `server/src/middleware/global-exception.filter.ts:19`

### V16.4 Log Protection

#### V16.4.1 (L2)

> Verify that all logging components appropriately encode data to prevent log injection.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Log messages are built via template literals into structured entries; user-controlled values (e.g. email in login warnings) are included without encoding, so log injection via newlines is not fully prevented. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72), [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L48)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/services/auth.service.ts#L72) `server/src/services/auth.service.ts:72`, [E2](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L48) `server/src/repositories/logging.repository.ts:48`

#### V16.4.2 (L2)

> Verify that logs are protected from unauthorized access and cannot be modified.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Logs are written to container stdout with normal file permissions; protection against unauthorized access/modification is a deployment (Docker/host) concern, not enforced by the app. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L1)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/logging.repository.ts#L1) `server/src/repositories/logging.repository.ts:1`

#### V16.4.3 (L2)

> Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised.

**Applicability:** yes | **Implemented:** partial | **Tested:** no

Optional OTLP telemetry can ship signals to a separate collector (telemetry.repository.ts), but logs themselves are not transmitted to a separate system by default. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/telemetry.repository.ts#L3)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/telemetry.repository.ts#L3) `server/src/repositories/telemetry.repository.ts:3`

### V16.5 Error Handling

#### V16.5.1 (L2)

> Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

The global exception filter maps errors to generic HTTP exceptions without stack traces or SQL; unhandled errors return a generic 500 message. Covered by error interceptor/filter specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/global-exception.filter.ts#L19), [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/error.interceptor.ts#L34), [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L331)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/global-exception.filter.ts#L19) `server/src/middleware/global-exception.filter.ts:19`, [E2](https://github.com/rubendv/immich/blob/main/server/src/middleware/error.interceptor.ts#L34) `server/src/middleware/error.interceptor.ts:34`, [E3](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/oauth.e2e-spec.ts#L331) `e2e/src/specs/server/api/oauth.e2e-spec.ts:331`

#### V16.5.2 (L2)

> Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation.

**Applicability:** yes | **Implemented:** partial | **Tested:** partial

Failures of external resources (ML service, Redis, DB) are handled with retries/queue re-runs and logged errors rather than crashing, but there is no circuit-breaker pattern. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/job.repository.ts#L147), [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/jobs.e2e-spec.ts#L16)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/repositories/job.repository.ts#L147) `server/src/repositories/job.repository.ts:147`, [E2](https://github.com/rubendv/immich/blob/main/e2e/src/specs/server/api/jobs.e2e-spec.ts#L16) `e2e/src/specs/server/api/jobs.e2e-spec.ts:16`

#### V16.5.3 (L2)

> Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic.

**Applicability:** yes | **Implemented:** yes | **Tested:** partial

The app fails closed: AuthGuard throws on any validation error (no fail-open), zod validation rejects malformed input, and upload errors abort the pipeline; covered by guard and validation specs. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L102), [E2](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137), [E3](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.ts#L102) `server/src/middleware/auth.guard.ts:102`, [E2](https://github.com/rubendv/immich/blob/main/server/src/validation.ts#L137) `server/src/validation.ts:137`, [E3](https://github.com/rubendv/immich/blob/main/server/src/middleware/auth.guard.spec.ts#L41) `server/src/middleware/auth.guard.spec.ts:41`

#### V16.5.4 (L3)

> Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability.

*Unassessed (Level 3).*

## V17 — WebRTC

### V17.1 TURN Server

#### V17.1.1 (L2)

> Verify that the Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not reserved for special purposes (e.g., internal networks, broadcast, loopback). Note that this applies to both IPv4 and IPv6 addresses.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No TURN service or NAT traversal exists; Immich does not use WebRTC. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13) `server/src/middleware/websocket.adapter.ts:13`

#### V17.1.2 (L3)

> Verify that the Traversal Using Relays around NAT (TURN) service is not susceptible to resource exhaustion when legitimate users attempt to open a large number of ports on the TURN server.

*Unassessed (Level 3).*

### V17.2 Media

#### V17.2.1 (L2)

> Verify that the key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the documented policy for management of cryptographic keys.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No DTLS/SRTP media server exists; streaming is done via HTTP(S) progressive download and HLS/DASH from the app server. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13) `server/src/middleware/websocket.adapter.ts:13`

#### V17.2.2 (L2)

> Verify that the media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher suites and a secure protection profile for the DTLS Extension for establishing keys for the Secure Real-time Transport Protocol (DTLS-SRTP).

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No DTLS-SRTP media server exists in the stack. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13) `server/src/middleware/websocket.adapter.ts:13`

#### V17.2.3 (L2)

> Verify that Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent Real-time Transport Protocol (RTP) injection attacks from leading to either a Denial of Service condition or audio or video media insertion into media streams.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No SRTP streams are processed by the application. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13) `server/src/middleware/websocket.adapter.ts:13`

#### V17.2.4 (L2)

> Verify that the media server is able to continue processing incoming media traffic when encountering malformed Secure Real-time Transport Protocol (SRTP) packets.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No SRTP packets are handled by the application. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13) `server/src/middleware/websocket.adapter.ts:13`

#### V17.2.5 (L3)

> Verify that the media server is able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users.

*Unassessed (Level 3).*

#### V17.2.6 (L3)

> Verify that the media server is not susceptible to the "ClientHello" Race Condition vulnerability in Datagram Transport Layer Security (DTLS) by checking if the media server is publicly known to be vulnerable or by performing the race condition test.

*Unassessed (Level 3).*

#### V17.2.7 (L3)

> Verify that any audio or video recording mechanisms associated with the media server are able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users.

*Unassessed (Level 3).*

#### V17.2.8 (L3)

> Verify that the Datagram Transport Layer Security (DTLS) certificate is checked against the Session Description Protocol (SDP) fingerprint attribute, terminating the media stream if the check fails, to ensure the authenticity of the media stream.

*Unassessed (Level 3).*

### V17.3 Signaling

#### V17.3.1 (L2)

> Verify that the signaling server is able to continue processing legitimate incoming signaling messages during a flood attack. This should be achieved by implementing rate limiting at the signaling level.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No WebRTC signaling server exists (socket.io is used for app notifications, not media signaling). See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13) `server/src/middleware/websocket.adapter.ts:13`

#### V17.3.2 (L2)

> Verify that the signaling server is able to continue processing legitimate signaling messages when encountering malformed signaling message that could cause a denial of service condition. This could include implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques.

**Applicability:** no | **Implemented:** n/a | **Tested:** n/a

No WebRTC signaling messages are processed by the application. See [[E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13)].

*References:* [E1](https://github.com/rubendv/immich/blob/main/server/src/middleware/websocket.adapter.ts#L13) `server/src/middleware/websocket.adapter.ts:13`
