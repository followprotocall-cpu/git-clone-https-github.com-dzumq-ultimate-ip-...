#!/usr/bin/env python3
"""
API lookup functions for the OSINT toolkit.

Each function calls a real public API and returns a dict of results.
All API keys and proxies come from config.py (or environment variables).

Supported services:
  - Have I Been Pwned (HIBP)   — breach/paste lookup by email
  - WiGLE                      — WiFi/MAC geolocation lookup
  - EmailRep                   — email reputation scoring
  - Hunter.io                  — email address discovery by name+domain
  - Shodan                     — internet device search
  - Censys                     — certificate/IP search
  - GitHub                     — public profile/repo search by name
"""

import json

try:
    import requests
except ImportError:
    raise ImportError(
        "The 'requests' library is required.\n"
        "Install it with:  pip install requests[socks]"
    )

from config import (
    SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET,
    WIGLE_API_KEY, HIBP_API_KEY, EMAILREP_API_KEY,
    HUNTER_API_KEY, GITHUB_TOKEN,
    PROXIES, get_random_proxy, get_random_ua, is_placeholder,
)


# ---------------------------------------------------------------------------
# Shared HTTP helper — rotating proxy + user-agent
# ---------------------------------------------------------------------------
def _get(url: str, headers: dict = None, auth=None,
         proxy: str = "auto", timeout: int = 12) -> requests.Response:
    """
    Make a GET request with a rotated user-agent.
    proxy="auto"  → pick a random proxy from the pool
    proxy=""      → no proxy
    proxy="<url>" → use that specific proxy
    """
    hdrs = {"User-Agent": get_random_ua()}
    if headers:
        hdrs.update(headers)

    if proxy == "auto":
        chosen = get_random_proxy()
    elif proxy:
        chosen = proxy
    else:
        chosen = None

    proxies_dict = {"http": chosen, "https": chosen} if chosen else None
    return requests.get(url, headers=hdrs, auth=auth,
                        proxies=proxies_dict, timeout=timeout)


# ---------------------------------------------------------------------------
# Have I Been Pwned — breach lookup by email
# https://haveibeenpwned.com/API/v3
# ---------------------------------------------------------------------------
def lookup_hibp(email: str, proxy: str = "auto") -> dict:
    """Check whether an email address appears in known data breaches."""
    if is_placeholder(HIBP_API_KEY):
        return {"hibp_error": "HIBP API key not configured (set HIBP_API_KEY env var)"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        resp = _get(url, headers={"hibp-api-key": HIBP_API_KEY}, proxy=proxy)
        if resp.status_code == 404:
            return {"hibp_breaches": [], "hibp_breach_count": 0}
        if resp.status_code == 401:
            return {"hibp_error": "Invalid HIBP API key"}
        resp.raise_for_status()
        breaches = resp.json()
        return {
            "hibp_breach_count": len(breaches),
            "hibp_breaches": [
                {
                    "name": b.get("Name"),
                    "domain": b.get("Domain"),
                    "date": b.get("BreachDate"),
                    "data_classes": b.get("DataClasses", []),
                }
                for b in breaches
            ],
        }
    except requests.RequestException as exc:
        return {"hibp_error": str(exc)}


# ---------------------------------------------------------------------------
# WiGLE — WiFi network / MAC address geolocation
# https://api.wigle.net/swagger
# ---------------------------------------------------------------------------
def lookup_wigle_mac(mac: str, proxy: str = "auto") -> dict:
    """Look up a WiFi access point by its MAC address (BSSID)."""
    if is_placeholder(WIGLE_API_KEY):
        return {"wigle_error": "WiGLE API key not configured (set WIGLE_API_KEY env var)"}
    url = "https://api.wigle.net/api/v2/network/search"
    params = {"netid": mac, "resultsPerPage": 5}
    try:
        resp = _get(url + "?" + "&".join(f"{k}={v}" for k, v in params.items()),
                    headers={"Authorization": f"Basic {WIGLE_API_KEY}"}, proxy=proxy)
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", [])
        return {
            "wigle_total_found": data.get("totalResults", 0),
            "wigle_networks": [
                {
                    "ssid": r.get("ssid"),
                    "mac": r.get("netid"),
                    "lat": r.get("trilat"),
                    "lon": r.get("trilong"),
                    "city": r.get("city"),
                    "region": r.get("region"),
                    "country": r.get("country"),
                    "last_seen": r.get("lasttime"),
                }
                for r in results
            ],
        }
    except requests.RequestException as exc:
        return {"wigle_error": str(exc)}


# ---------------------------------------------------------------------------
# EmailRep — email address reputation
# https://emailrep.io
# ---------------------------------------------------------------------------
def lookup_emailrep(email: str, proxy: str = "auto") -> dict:
    """Get reputation and risk scoring for an email address."""
    if is_placeholder(EMAILREP_API_KEY):
        return {"emailrep_error": "EmailRep API key not configured (set EMAILREP_API_KEY env var)"}
    url = f"https://emailrep.io/{email}"
    try:
        resp = _get(url, headers={"Key": EMAILREP_API_KEY, "Accept": "application/json"},
                    proxy=proxy)
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("details", {})
        return {
            "emailrep_email": data.get("email"),
            "emailrep_reputation": data.get("reputation"),
            "emailrep_suspicious": data.get("suspicious"),
            "emailrep_references": data.get("references"),
            "emailrep_blacklisted": attrs.get("blacklisted"),
            "emailrep_malicious_activity": attrs.get("malicious_activity"),
            "emailrep_credentials_leaked": attrs.get("credentials_leaked"),
            "emailrep_data_breach": attrs.get("data_breach"),
            "emailrep_profiles": attrs.get("profiles", []),
        }
    except requests.RequestException as exc:
        return {"emailrep_error": str(exc)}


# ---------------------------------------------------------------------------
# Hunter.io — email discovery by name + domain
# https://hunter.io/api-documentation/v2
# ---------------------------------------------------------------------------
def lookup_hunter(first_name: str, last_name: str, domain: str,
                  proxy: str = "auto") -> dict:
    """Find a person's professional email address via Hunter.io."""
    if is_placeholder(HUNTER_API_KEY):
        return {"hunter_error": "Hunter API key not configured (set HUNTER_API_KEY env var)"}
    url = (
        f"https://api.hunter.io/v2/email-finder"
        f"?first_name={first_name}&last_name={last_name}"
        f"&domain={domain}&api_key={HUNTER_API_KEY}"
    )
    try:
        resp = _get(url, proxy=proxy)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "hunter_email": data.get("email"),
            "hunter_score": data.get("score"),
            "hunter_domain": data.get("domain"),
            "hunter_position": data.get("position"),
            "hunter_sources": [s.get("uri") for s in data.get("sources", [])],
        }
    except requests.RequestException as exc:
        return {"hunter_error": str(exc)}


# ---------------------------------------------------------------------------
# Shodan — internet-connected device search
# https://developer.shodan.io/api
# ---------------------------------------------------------------------------
def lookup_shodan(query: str, proxy: str = "auto") -> dict:
    """Search Shodan for hosts/devices matching a query string."""
    if is_placeholder(SHODAN_API_KEY):
        return {"shodan_error": "Shodan API key not configured (set SHODAN_API_KEY env var)"}
    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={query}&minify=true"
    try:
        resp = _get(url, proxy=proxy)
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        return {
            "shodan_total": data.get("total", 0),
            "shodan_results": [
                {
                    "ip": m.get("ip_str"),
                    "port": m.get("port"),
                    "org": m.get("org"),
                    "os": m.get("os"),
                    "country": m.get("location", {}).get("country_name"),
                    "city": m.get("location", {}).get("city"),
                    "product": m.get("product"),
                    "hostnames": m.get("hostnames", []),
                }
                for m in matches[:10]
            ],
        }
    except requests.RequestException as exc:
        return {"shodan_error": str(exc)}


# ---------------------------------------------------------------------------
# Censys — certificate and IP search
# https://search.censys.io/api
# ---------------------------------------------------------------------------
def lookup_censys(query: str, proxy: str = "auto") -> dict:
    """Search Censys for hosts matching a query (IP, domain, org name, etc.)."""
    if is_placeholder(CENSYS_API_ID) or is_placeholder(CENSYS_API_SECRET):
        return {"censys_error": "Censys credentials not configured (set CENSYS_API_ID / CENSYS_API_SECRET env vars)"}
    url = "https://search.censys.io/api/v2/hosts/search"
    try:
        resp = _get(url + f"?q={query}&per_page=5",
                    auth=(CENSYS_API_ID, CENSYS_API_SECRET), proxy=proxy)
        resp.raise_for_status()
        data = resp.json()
        hits = data.get("result", {}).get("hits", [])
        return {
            "censys_total": data.get("result", {}).get("total", 0),
            "censys_results": [
                {
                    "ip": h.get("ip"),
                    "services": [s.get("port") for s in h.get("services", [])],
                    "country": h.get("location", {}).get("country"),
                    "labels": h.get("labels", []),
                }
                for h in hits
            ],
        }
    except requests.RequestException as exc:
        return {"censys_error": str(exc)}


# ---------------------------------------------------------------------------
# GitHub — public profile and repository search
# https://docs.github.com/en/rest/search
# ---------------------------------------------------------------------------
def lookup_github(name: str, proxy: str = "auto") -> dict:
    """Search GitHub for users matching a name."""
    url = f"https://api.github.com/search/users?q={requests.utils.quote(name)}&per_page=5"
    hdrs = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        hdrs["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    try:
        resp = _get(url, headers=hdrs, proxy=proxy)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("items", [])
        return {
            "github_total": data.get("total_count", 0),
            "github_users": [
                {
                    "login": u.get("login"),
                    "profile_url": u.get("html_url"),
                    "type": u.get("type"),
                }
                for u in items
            ],
        }
    except requests.RequestException as exc:
        return {"github_error": str(exc)}
