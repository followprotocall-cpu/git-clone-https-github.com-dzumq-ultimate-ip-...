# OSINT Public Information Lookup Toolkit

A collection of Python CLI tools that retrieve **publicly available** information tied to phone numbers and IP addresses. No illegal data access — only open-source libraries, free public APIs, and public search engine queries.

## What It Finds

| Category | Details |
|---|---|
| **Number Validation** | Whether the number is valid/possible, E.164/international/national formats |
| **Carrier** | Network operator name (e.g. Verizon, Vodafone, T-Mobile) |
| **Line Type** | Mobile, Landline, VoIP, Toll-Free, Premium Rate, Pager, etc. |
| **Geographic Location** | Country, region, city-level location associated with the number |
| **Timezone(s)** | Timezone(s) the number's region falls under |
| **Country Info** | Country name, country calling code, region code |
| **Web Search Queries** | Auto-generated OSINT search queries across social media, directories, public records, classifieds, and more |

### Optional API Enrichment

For richer data, you can plug in free API keys:

- **[NumVerify](https://numverify.com)** — 250 free lookups/month. Enhanced carrier and location data.
- **[Abstract API](https://www.abstractapi.com/api/phone-validation-api)** — Free tier. Additional phone metadata.

## Installation

```bash
pip install -r requirements.txt
```

The only required dependency is `phonenumbers` (Google's libphonenumber for Python). No API keys needed for the base functionality.

## Usage

### Single lookup

```bash
python phone_lookup.py +14155552671
```

### JSON output

```bash
python phone_lookup.py +14155552671 -o json
```

### Interactive mode (look up multiple numbers)

```bash
python phone_lookup.py -i
```

### With optional API keys for richer data

```bash
python phone_lookup.py +14155552671 --numverify-key YOUR_KEY
python phone_lookup.py +14155552671 --abstract-key YOUR_KEY
python phone_lookup.py +14155552671 --numverify-key KEY1 --abstract-key KEY2
```

### Web search for public footprint

```bash
# Add web search queries to any lookup
python phone_lookup.py +14155552671 --web-search

# Open top results in your browser automatically
python phone_lookup.py +14155552671 --web-search --open-browser

# Or use the standalone web search tool
python phone_web_search.py 415-555-2671
python phone_web_search.py +14155552671 -o json
```

The web search generates Google-dork queries across these categories:
- **Social Media** — Facebook, Twitter/X, LinkedIn, Instagram, Reddit, TikTok, Pinterest, Nextdoor
- **Business Directories** — Yelp, BBB, Yellow Pages, Manta
- **People / Public Records** — WhitePages, TruePeopleSearch, Spokeo, 411
- **Paste Sites** — Pastebin, JustPaste.it (for data leak detection)
- **Classifieds** — Craigslist, OfferUp, Facebook Marketplace
- **Court / Government** — Public court records, government databases

## Example Output

```
============================================================
  PHONE NUMBER — PUBLIC INFORMATION LOOKUP
============================================================

--- Number Details -----------------------------------------
  Input:                     +14155552671
  E.164 Format:              +14155552671
  International:             +1 415-555-2671
  National:                  (415) 555-2671
  Valid:                     Yes
  Possible:                  Yes

--- Carrier / Line Type ------------------------------------
  Carrier:                   Unknown / Unlisted
  Line Type:                 Fixed Line or Mobile

--- Geographic Info ----------------------------------------
  Country:                   United States
  Country Code:              +1
  Region Code:               US
  Location:                  San Francisco, CA
  Timezone(s):               America/Los_Angeles

--- Disclaimer ---------------------------------------------
  All information shown is from PUBLIC sources only.
  No private or protected data was accessed.
  Lookup performed at: 2026-02-11T01:30:00Z

============================================================
```

## IP Address Web Search

Generate OSINT search queries to find an IP address across threat intelligence platforms, abuse databases, WHOIS registries, and more.

### Usage

```bash
# Basic search
python ip_web_search.py 8.8.8.8

# JSON output
python ip_web_search.py 24.189.157.220 -o json

# Open top results in your browser
python ip_web_search.py 192.168.1.1 --open-browser
```

The IP search generates Google-dork queries across these categories:
- **Threat Intelligence** — AbuseIPDB, VirusTotal, Shodan, GreyNoise, Talos, Censys, AlienVault OTX
- **WHOIS / Registry** — ARIN, RIPE, APNIC, LACNIC, AFRINIC, Whois.com
- **Blacklists / Reputation** — MXToolbox, Spamhaus, Barracuda, Project Honeypot
- **Paste / Data Leak Sites** — Pastebin, Pastie, JustPaste.it
- **Forums / Abuse Reports** — Reddit, StackOverflow, ServerFault, general abuse/spam reports

### Example Output

```
======================================================================
  IP ADDRESS — WEB SEARCH QUERY GENERATOR
======================================================================

  Target IP:  8.8.8.8
  Total queries generated: 25

--- General (4 queries) ------------------------------------------------
    1. "8.8.8.8"
       https://www.google.com/search?q=%228.8.8.8%22
    2. "8.8.8.8" intitle:"forum" OR intitle:"abuse" OR intitle:"blacklist"
       ...

--- Threat Intelligence (8 queries) ------------------------------------
    1. "8.8.8.8" site:abuseipdb.com
       ...

======================================================================
  All queries target PUBLIC search engine results only.
  No private databases or restricted sources are accessed.
======================================================================
```

## Legal Disclaimer

These tools access **only publicly available information**. They use:

1. **Google's libphonenumber** — an open-source phone number parsing library
2. **Free public APIs** (optional) — that provide carrier/location metadata available to anyone
3. **Public search engine queries** — Google dork queries targeting publicly indexed pages

No private databases, protected records, or restricted data sources are queried. These tools are intended for legitimate purposes such as verifying your own numbers/IPs, fraud prevention, or general OSINT research.
