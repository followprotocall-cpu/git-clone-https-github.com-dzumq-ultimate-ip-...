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

## Legal Disclaimer

This tool accesses **only publicly available information**. It uses:

1. **Google's libphonenumber** — an open-source phone number parsing library
2. **Free public APIs** (optional) — that provide carrier/location metadata available to anyone

No private databases, protected records, or restricted data sources are queried. This tool is intended for legitimate purposes such as verifying your own numbers, fraud prevention, or general OSINT research.

---

# File Metadata Extraction

A companion tool that analyzes **uploaded or downloaded files** to reveal hidden metadata — who created a file, where a photo was taken, what software was used, and more.

## What It Reveals

| Category | Details |
|---|---|
| **File Identity** | True file type from content (not just extension), extension mismatch detection |
| **File System Info** | Size, permissions, created/modified/accessed timestamps |
| **Cryptographic Hashes** | MD5, SHA-1, SHA-256 — identify tampered or duplicate files |
| **GPS Location** | Latitude, longitude, altitude embedded in photos — links to Google Maps |
| **Camera / Device** | Camera make, model, lens, serial number embedded in EXIF |
| **Image Details** | Date/time photo was taken, software used to edit, artist name, copyright |
| **PDF Metadata** | Author, creator application, creation/modification dates, keywords |
| **Word Metadata** | Author, last editor, company, revision number, creation date |
| **Excel Metadata** | Creator, last editor, company, sheet names |

### Critical Finding Flags

The tool automatically highlights:
- `GPS_LOCATION_EMBEDDED` — the photo contains physical coordinates of where it was taken
- `AUTHOR_IDENTIFIED` — a person's name is embedded in the document
- `COMPANY_IDENTIFIED` — an organization name is embedded in the document
- `MODIFIED_BY_DIFFERENT_USER` — the last editor is different from the original author
- `EXTENSION_MISMATCH` — the file is disguised as a different type

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Analyze a local file
```bash
python file_metadata.py photo.jpg
python file_metadata.py document.pdf
python file_metadata.py report.docx spreadsheet.xlsx
```

### Analyze all files in a folder
```bash
python file_metadata.py /path/to/folder/
python file_metadata.py /path/to/folder/ --recursive
```

### Download and analyze from a URL
```bash
python file_metadata.py --url "https://example.com/photo.jpg"
```

### Download and analyze from Google Drive (public files)
```bash
python file_metadata.py --url "https://drive.google.com/file/d/FILE_ID/view?usp=sharing"
```
> The file must be shared publicly ("Anyone with the link can view").

### JSON output (for scripting or saving results)
```bash
python file_metadata.py photo.jpg -o json
python file_metadata.py photo.jpg -o json > results.json
```

## Example Output

```
======================================================================
  FILE: suspicious_photo.jpg
======================================================================

--- File Identity -------------------------------------------------------
  Filename:                      suspicious_photo.jpg
  Extension:                     .jpg
  Detected Type:                 JPEG Image
  MIME Type:                     image/jpeg

--- File System Info ----------------------------------------------------
  Size:                          3.2 MB
  Last Modified:                 2026-01-15 09:23:11 UTC

--- Cryptographic Hashes (for verification) -----------------------------
  MD5:                           a3f1...
  SHA-256:                       9c2b...

--- Image Info ----------------------------------------------------------
  Format:                        JPEG
  Dimensions:                    4032 x 3024 px

  [GPS LOCATION FOUND]
  Latitude:                      37.774929
  Longitude:                     -122.419416
  Google Maps:                   https://maps.google.com/?q=37.774929,-122.419416

  [EXIF Data]
  Date Taken:                    2026-01-15 09:23:11
  Camera Make:                   Apple
  Camera Model:                  iPhone 15 Pro
  Software:                      17.2.1

  *** FINDINGS ***
  [!] CRITICAL: This file contains GPS coordinates — physical location where it was created.
  [!] IMPORTANT: The software used to create this file is recorded in the metadata.
```
