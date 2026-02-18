#!/usr/bin/env python3
"""
Centralized configuration for the OSINT toolkit.

API keys are read from environment variables first; the placeholder strings
are used only when no environment variable is set (you must replace them or
set the env vars before the relevant lookup functions will work).

Set env vars example:
  export SHODAN_API_KEY="abc123..."
  export HIBP_API_KEY="abc123..."
"""

import os
import random

# ---------------------------------------------------------------------------
# Proxy pool — supports HTTP, HTTP with auth, and SOCKS5
# ---------------------------------------------------------------------------
PROXIES = [
    "http://user:pass@proxy1.example.com:8080",
    "http://proxy2.example.com:8080",
    "socks5://proxy3.example.com:1080",
]

# ---------------------------------------------------------------------------
# API keys — override any of these via environment variables
# ---------------------------------------------------------------------------
SHODAN_API_KEY    = os.environ.get("SHODAN_API_KEY",    "YOUR_SHODAN_KEY")
CENSYS_API_ID     = os.environ.get("CENSYS_API_ID",     "YOUR_CENSYS_ID")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "YOUR_CENSYS_SECRET")
WIGLE_API_KEY     = os.environ.get("WIGLE_API_KEY",     "YOUR_WIGLE_KEY")     # wigle.net
HIBP_API_KEY      = os.environ.get("HIBP_API_KEY",      "YOUR_HIBP_KEY")      # haveibeenpwned.com
EMAILREP_API_KEY  = os.environ.get("EMAILREP_API_KEY",  "YOUR_EMAILREP_KEY")  # emailrep.io
HUNTER_API_KEY    = os.environ.get("HUNTER_API_KEY",    "YOUR_HUNTER_KEY")    # hunter.io
GITHUB_TOKEN      = os.environ.get("GITHUB_TOKEN",      "")                   # optional — raises rate limit

# ---------------------------------------------------------------------------
# User-agent pool — rotated per request to avoid rate-limiting
# ---------------------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_random_proxy() -> str | None:
    """Return a random proxy from the pool, or None if pool is empty."""
    return random.choice(PROXIES) if PROXIES else None


def get_random_ua() -> str:
    """Return a random user-agent string from the pool."""
    return random.choice(USER_AGENTS)


def is_placeholder(key: str) -> bool:
    """Return True if an API key is still set to its placeholder value."""
    return not key or key.startswith("YOUR_")
