# NIST SP 800-218 Secure Software Development Framework (SSDF)

## PW.1: Design Software to Meet Security Requirements and Mitigate Security Risks
- Requirement: Identify and evaluate security risks for the software architecture and integrate mitigations into software design.
- SSDF Practice: Validate data inputs against strict type and length schemas at component boundaries.

## PW.4: Follow Secure Coding Practices
- Requirement: Adhere to established language-specific secure coding standards to avoid introducing vulnerabilities.
- SSDF Practice: Prohibit unverified memory access, unsafe string concatenation into interpreters, and unmanaged subprocess spawning.

## PW.8: Configure the Software to be Secure by Default
- Requirement: Structure default configurations with zero trust assumptions.
- SSDF Practice: Disable debug logging in production environments, suppress stack traces from client responses (CWE-209), and enforce HTTPS/TLS 1.3 by default.
