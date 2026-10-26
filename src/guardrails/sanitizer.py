"""Input guardrails: prompt injection detection and PII redaction (D15).

Treats uploaded files as untrusted:
- Detects prompt injection in comments (e.g. `# ignore previous instructions`)
- Uses Presidio to redact secrets and PII from files and logs
- Validates outputs for safety
"""

from __future__ import annotations

import re
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ─── Prompt Injection Detection ──────────────────────────────────────────────

# Patterns that suggest prompt injection in code comments
INJECTION_PATTERNS = [
    # Direct instruction overrides
    r"(?i)ignore\s+(?:all\s+)?previous\s+instructions",
    r"(?i)forget\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?instructions",
    r"(?i)disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules|guidelines)",
    r"(?i)you\s+are\s+now\b",
    r"(?i)act\s+as\s+(?:if\s+)?(?:you\s+are|a)",
    r"(?i)pretend\s+(?:you\s+are|to\s+be)",
    r"(?i)your\s+new\s+(?:role|instructions|task)\s+(?:is|are)",
    r"(?i)system\s*:\s*you\s+are",

    # Data exfiltration attempts
    r"(?i)(?:print|output|display|show|reveal)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)",
    r"(?i)what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions)",

    # Role breaking
    r"(?i)(?:do\s+not|don't)\s+(?:follow|obey)\s+(?:your\s+)?(?:rules|instructions)",
    r"(?i)(?:override|bypass|skip)\s+(?:all\s+)?(?:safety|security|guard)",
]

COMPILED_PATTERNS = [re.compile(p) for p in INJECTION_PATTERNS]


def detect_prompt_injection(content: str) -> list[dict[str, Any]]:
    """Scan file content for prompt injection attempts in comments.

    Checks Python/TOML comments (lines starting with #) and inline
    comments for injection patterns.

    Args:
        content: Raw file content to scan.

    Returns:
        List of detected injection attempts with line number and matched text.
    """
    detections: list[dict[str, Any]] = []

    for line_num, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()

        # Check comment lines
        comment_text = ""
        if stripped.startswith("#"):
            comment_text = stripped[1:].strip()
        elif "#" in stripped:
            # Inline comment
            comment_text = stripped.split("#", 1)[1].strip()

        if not comment_text:
            continue

        for pattern in COMPILED_PATTERNS:
            match = pattern.search(comment_text)
            if match:
                detection = {
                    "line_number": line_num,
                    "line_content": line.rstrip(),
                    "matched_pattern": match.group(0),
                    "severity": "high",
                }
                detections.append(detection)
                logger.warning(
                    "prompt_injection_detected",
                    line=line_num,
                    pattern=match.group(0),
                )
                break  # One detection per line is enough

    return detections


# ─── PII / Secret Redaction ──────────────────────────────────────────────────

# Common secret patterns to redact
SECRET_PATTERNS = [
    # API keys and tokens
    (r"(?i)(?:api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-./+=]{16,})['\"]?", "API_KEY"),
    # AWS keys
    (r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}", "AWS_KEY"),
    # Private keys
    (r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", "PRIVATE_KEY"),
    # Passwords in config
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?", "PASSWORD"),
    # Database URLs with credentials
    (r"(?i)(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@", "DB_URL"),
    # Generic secrets
    (r"(?i)(?:secret|token|credential)\s*[=:]\s*['\"]?([A-Za-z0-9_\-./+=]{16,})['\"]?", "SECRET"),
]

COMPILED_SECRET_PATTERNS = [(re.compile(p), label) for p, label in SECRET_PATTERNS]


def redact_secrets(content: str) -> tuple[str, list[dict[str, Any]]]:
    """Redact secrets and sensitive data from content.

    Args:
        content: Content to scan and redact.

    Returns:
        Tuple of (redacted_content, list of redaction records).
    """
    redacted = content
    redactions: list[dict[str, Any]] = []

    for pattern, label in COMPILED_SECRET_PATTERNS:
        matches = list(pattern.finditer(redacted))
        for match in reversed(matches):  # Reverse to preserve positions
            original = match.group(0)
            replacement = f"[REDACTED_{label}]"
            redacted = redacted[:match.start()] + replacement + redacted[match.end():]
            redactions.append({
                "type": label,
                "original_length": len(original),
                "position": match.start(),
            })
            logger.info("secret_redacted", type=label, position=match.start())

    return redacted, redactions


def redact_pii_presidio(content: str) -> tuple[str, list[dict[str, Any]]]:
    """Use Presidio to redact PII from content.

    Falls back to regex-based redaction if Presidio or spacy models are unavailable.
    """
    try:
        import spacy
        # Only use Presidio if a local spacy model is already installed to avoid network download
        has_spacy_model = any(
            spacy.util.is_package(m)
            for m in ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"]
        )
        if not has_spacy_model:
            return _redact_pii_regex(content)

        from presidio_analyzer import AnalyzerEngine
        from presidio_anonymizer import AnonymizerEngine

        analyzer = AnalyzerEngine()
        anonymizer = AnonymizerEngine()

        # Analyze
        results = analyzer.analyze(
            text=content,
            entities=[
                "EMAIL_ADDRESS",
                "PHONE_NUMBER",
                "PERSON",
                "IP_ADDRESS",
                "CREDIT_CARD",
            ],
            language="en",
        )

        if not results:
            return content, []

        # Anonymize
        anonymized = anonymizer.anonymize(text=content, analyzer_results=results)

        redactions = [
            {
                "type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": r.score,
            }
            for r in results
        ]

        return anonymized.text, redactions

    except Exception:
        return _redact_pii_regex(content)


def _redact_pii_regex(content: str) -> tuple[str, list[dict[str, Any]]]:
    """Fallback regex-based PII redaction."""
    redactions: list[dict[str, Any]] = []
    redacted = content

    # Email addresses
    email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    for match in email_pattern.finditer(content):
        redacted = redacted.replace(match.group(0), "[REDACTED_EMAIL]")
        redactions.append({"type": "EMAIL", "position": match.start()})

    # IP addresses
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for match in ip_pattern.finditer(content):
        redacted = redacted.replace(match.group(0), "[REDACTED_IP]")
        redactions.append({"type": "IP_ADDRESS", "position": match.start()})

    return redacted, redactions


# ─── Output Validation ───────────────────────────────────────────────────────


def validate_output(output: str) -> tuple[bool, list[str]]:
    """Validate agent output for safety issues.

    Checks:
    - No leaked system prompts
    - No raw secrets in output
    - No harmful content patterns
    """
    issues: list[str] = []

    # Check for leaked system prompts
    if "you are the chainguard" in output.lower():
        issues.append("Potential system prompt leak detected")

    # Check for raw secrets
    for pattern, label in COMPILED_SECRET_PATTERNS:
        if pattern.search(output):
            issues.append(f"Raw {label} detected in output")

    return len(issues) == 0, issues


# ─── Combined Sanitization Pipeline ──────────────────────────────────────────


def sanitize_input(
    content: str,
    enable_injection_check: bool = True,
    enable_secret_redaction: bool = True,
    enable_pii_redaction: bool = True,
) -> tuple[str, dict[str, Any]]:
    """Run the complete input sanitization pipeline.

    Args:
        content: Raw file content.
        enable_injection_check: Check for prompt injection.
        enable_secret_redaction: Redact secrets.
        enable_pii_redaction: Redact PII.

    Returns:
        Tuple of (sanitized_content, report_dict).
    """
    report: dict[str, Any] = {
        "injections": [],
        "secrets_redacted": [],
        "pii_redacted": [],
        "is_safe": True,
    }

    sanitized = content

    # 1. Check for prompt injection
    if enable_injection_check:
        injections = detect_prompt_injection(content)
        report["injections"] = injections
        if injections:
            report["is_safe"] = False
            logger.warning(
                "injection_detected",
                count=len(injections),
            )

    # 2. Redact secrets
    if enable_secret_redaction:
        sanitized, secret_redactions = redact_secrets(sanitized)
        report["secrets_redacted"] = secret_redactions

    # 3. Redact PII
    if enable_pii_redaction:
        sanitized, pii_redactions = redact_pii_presidio(sanitized)
        report["pii_redacted"] = pii_redactions

    return sanitized, report
