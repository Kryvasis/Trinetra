"""Reject recognizable web documents before configuration auditing."""
import re

HTML_PATTERN = re.compile(r"^\s*\ufeff?\s*(?:<\?xml[^>]*>\s*)?(?:<!--.*?-->\s*)*(?:<!doctype\s+html\b|<html\b|<head\b|<body\b)", re.I | re.S)
HTML_ERROR = "This is a webpage, not a device configuration. Use Website analysis for public URLs, or provide a real device configuration export."


def is_web_document(content):
    return bool(HTML_PATTERN.search(content[:65536]))
