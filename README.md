# Phone Number Public Information Lookup

A Python CLI tool that retrieves **publicly available** information tied to any phone number. No illegal data access — only open-source libraries and free public APIs.

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

## TikTok Log Analyzer

A companion script for analyzing TikTok app telemetry logs in the format publicly
disclosed by security researcher [fs0c131y](https://gist.github.com/fs0c131y/b4ef278e8863c636964793e1b27f889d).
Useful for understanding what data the TikTok app collects during a session.

### What It Extracts

| Category | Details |
|---|---|
| **Device Info** | Model, brand, OS version, CPU ABI, screen resolution, language, region |
| **App Info** | App version, package name, channel (e.g. googleplay), build info |
| **Unique Identifiers** | `openudid`, `clientudid`, `google_aid` (advertising ID), `device_id`, `install_id`, `sig_hash` |
| **Network Hosts** | All hostnames/IPs the app contacts or probes during the session |
| **Active Network Probes** | External hosts pinged via `network_observe_report` (including Facebook, Google, etc.) |
| **Event Telemetry** | All events logged: `feed_request`, `launch_log`, `stay_time`, `splash_ad`, and more |

### Usage

```bash
# Analyze a local log file
python tiktok_log_analyzer.py logs.txt

# Fetch and analyze the original public gist directly
python tiktok_log_analyzer.py --gist

# JSON output for programmatic use
python tiktok_log_analyzer.py --gist -o json

# Show every individual event in chronological order
python tiktok_log_analyzer.py logs.txt --show-events
python tiktok_log_analyzer.py --gist --show-events
```

### Example Output (text mode)

```
======================================================================
  TIKTOK LOG ANALYZER — Security Research Tool
  Based on public disclosure by fs0c131y
======================================================================

--- Device & App Info -------------------------------------------------
  device_model:                  Nexus 6P
  os:                            Android
  os_version:                    8.1.0
  app_version:                   17.2.4
  package:                       com.zhiliaoapp.musically
  region:                        US

--- Unique Identifiers Collected --------------------------------------
  openudid:                      e4340d3235274e4b
  google_aid:                    315f154c-a3a0-48de-b932-319e0595114b
  device_id:                     6727990782160700929

--- Network Hosts Observed (N) ----------------------------------------
  api19-core-c-useast1a.tiktokv.com
  tp-pay-mva.byteoversea.com
  ...

--- Active Network Probes (network_observe_report) --------------------
  graph.facebook.com:443  -> 179.60.192.3
  8.8.8.8:443             -> 8.8.8.8
  ...

--- Top Event Tags ----------------------------------------------------
      4  feed_request
      3  network_observe_report
      2  splash_ad
  ...
```

No additional dependencies required beyond the standard library.

---

## Legal Disclaimer

This tool accesses **only publicly available information**. It uses:

1. **Google's libphonenumber** — an open-source phone number parsing library
2. **Free public APIs** (optional) — that provide carrier/location metadata available to anyone

No private databases, protected records, or restricted data sources are queried. This tool is intended for legitimate purposes such as verifying your own numbers, fraud prevention, or general OSINT research.
