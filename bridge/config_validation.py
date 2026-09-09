"""Reject recognizable web documents before configuration auditing."""
import re

HTML_PATTERN = re.compile(r"^\s*\ufeff?\s*(?:<\?xml[^>]*>\s*)?(?:<!--.*?-->\s*)*(?:<!doctype\s+html\b|<html\b|<head\b|<body\b)", re.I | re.S)
# Broader HTML/JS markers anywhere in content (defense in depth — catches error pages not at start)
HTML_ANYWHERE = re.compile(r"<\s*(?:html|head|body|script|!doctype)", re.I)
JS_ERROR_MARKERS = re.compile(r"window\.ytcfg|EMERGENCY_BASE_URL|window\.onerror|ytInitialData", re.I)
HTML_ERROR = "This is a webpage, not a device configuration. Use Website analysis for public URLs, or provide a real device configuration export."
CONFIG_SANITY_ERROR = "Fetched content does not appear to be a device configuration — check the target and try again."
# Heuristic: require at least 30% of non-empty lines to look like CLI config
CONFIG_LINE_RE = re.compile(r"^\s*(?:[!#].*|[A-Za-z0-9][\w\-\./:]*(\s+[\w\-\./:,\[\]{};='\"\(\)]+)*)\s*$")
MIN_CONFIG_RATIO = 0.30
MIN_LINES_FOR_RATIO_CHECK = 5


def is_web_document(content):
    return bool(HTML_PATTERN.search(content[:65536]))


def looks_like_html(content: str) -> bool:
    """Return True if content contains HTML/JS markers anywhere (not just prefix)."""
    if not isinstance(content, str) or not content.strip():
        return False
    head = content[:65536]
    if is_web_document(head):
        return True
    if HTML_ANYWHERE.search(head):
        return True
    if JS_ERROR_MARKERS.search(head):
        return True
    # JSON API error responses often look like {"error": ...}
    stripped = head.lstrip()
    if stripped.startswith("{") and '"error"' in stripped[:2048].lower():
        # Check if it's predominantly JSON, not config
        if stripped.count("{") >= 1 and stripped.count("}") >= 1 and len(stripped) < 5000:
            return True
    return False


def config_likeness_ratio(content: str) -> float:
    """Compute proportion of non-empty lines that match CLI config shape."""
    if not isinstance(content, str):
        return 0.0
    lines = [l for l in content.splitlines() if l.strip()]
    if not lines:
        return 0.0
    # Binary / null-byte check
    if "\x00" in content:
        return 0.0
    config_like = 0
    for line in lines:
        stripped = line.strip()
        # Lines containing HTML tags are never config-like
        if "<" in stripped and ">" in stripped:
            continue
        if len(stripped) > 500:
            continue
        if CONFIG_LINE_RE.match(line):
            # Additional filter: reject lines that are clearly prose/markup with many spaces and no CLI tokens
            # Config lines typically have limited tokens and often contain known keywords or CLI punctuation
            config_like += 1
    return config_like / len(lines) if lines else 0.0


def is_plausible_config(content: str) -> tuple[bool, str]:
    """Check whether fetched content plausibly resembles device config.

    Returns (True, "") if plausible, (False, reason) otherwise.
    Heuristic is intentionally permissive for unusual vendor syntax but catches
    obviously-wrong content (webpages, error pages, binary).
    """
    if not isinstance(content, str) or not content.strip():
        return False, "empty content"
    if len(content.encode("utf-8")) > 1024 * 1024:
        return False, "content too large"
    if "\x00" in content:
        return False, "binary content"
    # Allow JSON for cloud/SONiC: AWS SG/NACL, SONiC config_db.json
    stripped = content.strip()
    if stripped.startswith("{") and any(k in stripped[:4096] for k in ('"SecurityGroups"', '"DEVICE_METADATA"', '"ACL_TABLE"', '"NetworkAcls"', '"GroupId"')):
        return True, ""
    if looks_like_html(content):
        return False, "HTML/JavaScript detected"
    # Check for obvious error pages
    lower = content[:4096].lower()
    if "404 not found" in lower or "500 internal server error" in lower or "error_204" in lower:
        if config_likeness_ratio(content) < MIN_CONFIG_RATIO:
            return False, "error page detected"
    lines = [l for l in content.splitlines() if l.strip()]
    if len(lines) >= MIN_LINES_FOR_RATIO_CHECK:
        ratio = config_likeness_ratio(content)
        if ratio < MIN_CONFIG_RATIO:
            return False, f"low config likeness ({ratio:.0%} < {MIN_CONFIG_RATIO:.0%})"
    return True, ""
