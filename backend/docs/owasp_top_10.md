# OWASP Top 10 Security & Compliance Standard

## A01:2021 — Broken Access Control
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.
- Compliance Rule: Enforce least privilege, disable directory listing, reject user-controlled object IDs without server-side validation.

## A02:2021 — Cryptographic Failures
Failures related to cryptography often lead to sensitive data exposure or system compromise.
- Compliance Rule: Deprecate MD5 and SHA-1. Mandate SHA-256/SHA-512 for integrity hashes, and Argon2id/bcrypt for password hashing. Never transmit credentials in clear text.

## A03:2021 — Injection Flaws
A web application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized by the application before being parsed as code or queries.
- SQL Injection: Dynamic SQL concatenation using string formatting or raw concatenation must be replaced with Parameterized Queries or Prepared Statements (e.g. `cursor.execute("SELECT ... WHERE id = %s", (user_id,))`).
- Command Injection: Avoid passing user strings to system shells (`os.system`, `subprocess` with `shell=True`). Use structured array arguments with `shell=False`.
- Code Injection: Prohibit dynamic evaluation (`eval()`, `exec()`). Use strict literal parsers (`ast.literal_eval`) or standard JSON deserializers.

## A04:2021 — Insecure Design
Insecure design represents weaknesses related to missing security controls, threat modeling, and defensive architecture patterns.
- Compliance Rule: Establish defensive guardrails, rate limiting, and strict input boundary constraints before calling processing layers.

## A05:2021 — Security Misconfiguration
Applications are vulnerable when insecure default configurations are enabled, error messages leak sensitive stack traces, or unnecessary features are enabled.
- Compliance Rule: Suppress detailed runtime exception tracebacks from end-user HTTP responses. Route diagnostic exceptions to secure centralized logs.

## A07:2021 — Identification and Authentication Failures
Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.
- Compliance Rule: Prohibit hardcoded passwords, access tokens, API keys, or private certificates in source control. Enforce environment variable isolation.

## A08:2021 — Software and Data Integrity Failures
Code and infrastructure that do not protect against integrity violations. An example is software that relies on untrusted plugins, libraries, or unverified deserialization.
- Compliance Rule: Prohibit untrusted `pickle` deserialization. Utilize safe structured serialization schemas (JSON, Protocol Buffers).
