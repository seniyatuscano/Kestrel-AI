# Common Weakness Enumeration (CWE) Standards & Defensive Matrix

## CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- Definition: The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a database server.
- Defensive Remediation:
  1. Use parameterized queries (prepared statements) for all database operations.
  2. Employ Object Relational Mapping (ORM) frameworks with bound parameters.
  3. Validate input types against strict schemas (e.g. integer casting for IDs).

## CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- Definition: The software constructs an OS command using externally-influenced input, but it does not neutralize special elements that could modify the command when it is executed.
- Defensive Remediation:
  1. Use standard library language APIs instead of invoking shell commands (e.g., `os.mkdir`, `shutil.copy`).
  2. If process execution is mandatory, pass arguments as a structured list and explicitly set `shell=False`.
  3. Apply `shlex.quote()` and strict character allowlists to all command arguments.

## CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
- Definition: The software receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before interpreting or evaluating it.
- Defensive Remediation:
  1. Eliminate all invocations of `eval()`, `exec()`, and `compile()`.
  2. For mathematical calculations or expression parsing, use domain-specific parsers or `ast.literal_eval()`.
  3. Decode structured data payloads via `json.loads()`.

## CWE-798: Use of Hard-coded Credentials
- Definition: The software contains hardcoded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external systems, or encryption of internal data.
- Defensive Remediation:
  1. Migrate all sensitive secrets to environment variables (`os.getenv`) or vault managers (AWS Secrets Manager, HashiCorp Vault).
  2. Implement secret scanning in CI/CD pipeline and add `.env` to `.gitignore`.

## CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- Definition: The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements like `..` sequences.
- Defensive Remediation:
  1. Sanitize file names using `os.path.basename()`.
  2. Resolve canonical absolute paths with `pathlib.Path.resolve()` and enforce `target.is_relative_to(base_dir)`.

## CWE-502: Deserialization of Untrusted Data
- Definition: The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.
- Defensive Remediation:
  1. Replace `pickle`, `marshal`, or `yaml.load()` with `json` or `yaml.safe_load()`.
  2. If object serialization is required, verify HMAC cryptographic signatures before unpacking.
