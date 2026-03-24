"""ANSI color helpers for terminal output."""

from __future__ import annotations

import os
import sys


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOR = _supports_color()

# ANSI escape codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN = "\033[36m"
_WHITE = "\033[37m"

_BG_RED = "\033[41m"
_BG_GREEN = "\033[42m"
_BG_YELLOW = "\033[43m"
_BG_BLUE = "\033[44m"
_BG_MAGENTA = "\033[45m"
_BG_CYAN = "\033[46m"

_BRIGHT_RED = "\033[91m"
_BRIGHT_GREEN = "\033[92m"
_BRIGHT_YELLOW = "\033[93m"
_BRIGHT_CYAN = "\033[96m"
_BRIGHT_WHITE = "\033[97m"


def _wrap(code: str, text: str) -> str:
    if not _COLOR:
        return text
    return f"{code}{text}{_RESET}"


# --- Public API ---

def bold(text: str) -> str:
    return _wrap(_BOLD, text)


def dim(text: str) -> str:
    return _wrap(_DIM, text)


def red(text: str) -> str:
    return _wrap(_RED, text)


def green(text: str) -> str:
    return _wrap(_GREEN, text)


def yellow(text: str) -> str:
    return _wrap(_YELLOW, text)


def blue(text: str) -> str:
    return _wrap(_BLUE, text)


def magenta(text: str) -> str:
    return _wrap(_MAGENTA, text)


def cyan(text: str) -> str:
    return _wrap(_CYAN, text)


def bright_red(text: str) -> str:
    return _wrap(_BRIGHT_RED, text)


def bright_green(text: str) -> str:
    return _wrap(_BRIGHT_GREEN, text)


def bright_yellow(text: str) -> str:
    return _wrap(_BRIGHT_YELLOW, text)


def bright_cyan(text: str) -> str:
    return _wrap(_BRIGHT_CYAN, text)


def bright_white(text: str) -> str:
    return _wrap(_BRIGHT_WHITE, text)


def badge(text: str, bg_code: str, fg_code: str = _BRIGHT_WHITE) -> str:
    if not _COLOR:
        return f"[{text}]"
    return f"{bg_code}{fg_code}{_BOLD} {text} {_RESET}"


# --- Status & Severity coloring ---

_STATUS_COLORS = {
    "validated": (_BG_RED, _BRIGHT_WHITE),
    "not_validated": (_BG_GREEN, _BRIGHT_WHITE),
    "inconclusive": (_BG_YELLOW, "\033[30m"),
    "host_down": (_BG_BLUE, _BRIGHT_WHITE),
    "port_closed": (_BG_BLUE, _BRIGHT_WHITE),
    "port_filtered": (_BG_BLUE, _BRIGHT_WHITE),
    "host_unreachable": (_BG_BLUE, _BRIGHT_WHITE),
    "dns_failure": (_BG_BLUE, _BRIGHT_WHITE),
    "auth_required": (_BG_MAGENTA, _BRIGHT_WHITE),
    "skipped": (_BG_CYAN, "\033[30m"),
    "error": (_BG_RED, _BRIGHT_WHITE),
}

_SEVERITY_COLORS = {
    "4": (_BG_RED, _BRIGHT_WHITE, "CRITICAL"),
    "3": ("\033[48;5;208m", _BRIGHT_WHITE, "HIGH"),
    "2": (_BG_YELLOW, "\033[30m", "MEDIUM"),
    "1": (_BG_CYAN, "\033[30m", "LOW"),
    "0": (_BG_BLUE, _BRIGHT_WHITE, "INFO"),
}


def status_badge(status: str) -> str:
    bg, fg = _STATUS_COLORS.get(status, (_BG_BLUE, _BRIGHT_WHITE))
    return badge(status.upper(), bg, fg)


def severity_badge(severity: str | None) -> str:
    sev = str(severity) if severity is not None else "-"
    bg, fg, label = _SEVERITY_COLORS.get(sev, (_BG_BLUE, _BRIGHT_WHITE, f"SEV-{sev}"))
    return badge(label, bg, fg)


def status_text(status: str) -> str:
    color_map = {
        "validated": _BRIGHT_RED,
        "not_validated": _BRIGHT_GREEN,
        "inconclusive": _BRIGHT_YELLOW,
        "host_down": _BLUE,
        "port_closed": _BLUE,
        "port_filtered": _BLUE,
        "skipped": _CYAN,
        "error": _RED,
    }
    code = color_map.get(status, _WHITE)
    return _wrap(code, status)


def separator(width: int = 72) -> str:
    line = "\u2500" * width
    return _wrap(_DIM, line)


def heavy_separator(width: int = 72) -> str:
    line = "\u2550" * width
    return _wrap(f"{_BOLD}{_CYAN}", line)
