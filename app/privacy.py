"""Redact URL query strings in persistent diagnostics, including free-form errors."""
import logging
import re

# Relative redirect targets and nested query strings can contain credentials too.
_QUERY = re.compile(r"\?[^\s\"'<>#]+")
_SECRET = re.compile(r"(?i)\b(token|access_token|refresh_token|api[_-]?key|password|secret|authorization|signature)=([^\s&#]+)")


def redact(value):
    if isinstance(value, str):
        return _SECRET.sub(r"\1=…", _QUERY.sub("?…", value))
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    return value


class PrivateFormatter(logging.Formatter):
    def format(self, record):
        return redact(super().format(record))
