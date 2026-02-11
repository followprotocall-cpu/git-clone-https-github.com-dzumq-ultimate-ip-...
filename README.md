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

## Legal Disclaimer

This tool accesses **only publicly available information**. It uses:

1. **Google's libphonenumber** — an open-source phone number parsing library
2. **Free public APIs** (optional) — that provide carrier/location metadata available to anyone

No private databases, protected records, or restricted data sources are queried. This tool is intended for legitimate purposes such as verifying your own numbers, fraud prevention, or general OSINT research.
