#!/usr/bin/env python3
"""
File Metadata Extraction Tool

Analyzes files and extracts ALL available metadata:
  - File system info: size, timestamps (created/modified/accessed), permissions
  - File type detected from CONTENT (magic bytes), not just the extension
  - Cryptographic hashes: MD5, SHA-1, SHA-256 (for identifying duplicate/tampered files)
  - Image EXIF data: GPS coordinates, camera model, lens, software, original date
  - Document metadata: author, creator tool, company, revision dates (PDF, Word, etc.)
  - Critical/suspicious finding flags — GPS embeds, author mismatches, hidden data

Supported inputs:
  - Local file paths (single file, multiple files, or a directory)
  - URLs (direct download links)
  - Google Drive share links  (public files only)

Usage:
  python file_metadata.py photo.jpg
  python file_metadata.py document.pdf report.docx
  python file_metadata.py /folder/of/files/ --recursive
  python file_metadata.py photo.jpg -o json
  python file_metadata.py --url "https://drive.google.com/file/d/FILE_ID/view"
  python file_metadata.py --url "https://example.com/file.pdf"
"""

import argparse
import hashlib
import json
import os
import stat
import sys
import struct
import tempfile
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional library imports (graceful degradation if not installed)
# ---------------------------------------------------------------------------
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

PYPDF_AVAILABLE = None  # lazy-checked on first use

try:
    import docx
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

try:
    import filetype as filetype_lib
    FILETYPE_AVAILABLE = True
except ImportError:
    FILETYPE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Magic byte signatures for file type detection (fallback if filetype not installed)
# ---------------------------------------------------------------------------
MAGIC_SIGNATURES = [
    (b'\xff\xd8\xff', 'image/jpeg', 'JPEG Image'),
    (b'\x89PNG\r\n\x1a\n', 'image/png', 'PNG Image'),
    (b'GIF87a', 'image/gif', 'GIF Image'),
    (b'GIF89a', 'image/gif', 'GIF Image'),
    (b'BM', 'image/bmp', 'BMP Image'),
    (b'II*\x00', 'image/tiff', 'TIFF Image (little-endian)'),
    (b'MM\x00*', 'image/tiff', 'TIFF Image (big-endian)'),
    (b'RIFF', 'image/webp', 'WebP Image'),  # combined with WEBP check below
    (b'%PDF', 'application/pdf', 'PDF Document'),
    (b'PK\x03\x04', 'application/zip', 'ZIP / Office Open XML (docx/xlsx/pptx)'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'application/msoffice', 'MS Office (doc/xls/ppt)'),
    (b'{\rtf', 'application/rtf', 'RTF Document'),
    (b'<?xml', 'text/xml', 'XML Document'),
    (b'\x1f\x8b', 'application/gzip', 'GZIP Archive'),
    (b'7z\xbc\xaf\x27\x1c', 'application/7z', '7-Zip Archive'),
    (b'Rar!\x1a\x07', 'application/rar', 'RAR Archive'),
    (b'\x00\x00\x00\x0cftyp', 'video/mp4', 'MP4 Video'),
    (b'\x1aE\xdf\xa3', 'video/webm', 'WebM Video'),
    (b'fLaC', 'audio/flac', 'FLAC Audio'),
    (b'ID3', 'audio/mpeg', 'MP3 Audio'),
    (b'OggS', 'audio/ogg', 'OGG Audio'),
]

SECTION_WIDTH = 70


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def detect_file_type(data: bytes, filename: str = '') -> tuple[str, str]:
    """Return (mime_type, description) detected from file content."""
    if FILETYPE_AVAILABLE:
        kind = filetype_lib.guess(data)
        if kind:
            return kind.mime, kind.extension.upper() + ' file'

    # Manual magic byte check
    for magic, mime, desc in MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            # Special case: ZIP could be docx/xlsx/pptx
            if mime == 'application/zip':
                ext = Path(filename).suffix.lower()
                if ext == '.docx':
                    return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'Word Document (DOCX)'
                if ext == '.xlsx':
                    return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Excel Spreadsheet (XLSX)'
                if ext == '.pptx':
                    return 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'PowerPoint Presentation (PPTX)'
            return mime, desc

    # Check for plain text
    try:
        data[:512].decode('utf-8')
        return 'text/plain', 'Plain Text'
    except (UnicodeDecodeError, ValueError):
        pass

    return 'application/octet-stream', 'Unknown Binary'


def compute_hashes(filepath: str) -> dict:
    """Compute MD5, SHA-1, and SHA-256 hashes for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
        }
    except OSError as e:
        return {'error': str(e)}


def format_size(size_bytes: int) -> str:
    """Human-readable file size."""
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if size_bytes < 1024 or unit == 'TB':
            return f'{size_bytes:.1f} {unit}' if unit != 'B' else f'{size_bytes} B'
        size_bytes /= 1024


def ts_to_str(ts: float) -> str:
    """Convert Unix timestamp to readable UTC string."""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OSError, OverflowError, ValueError):
        return 'Unknown'


def gps_ref_sign(ref: str) -> int:
    """Return -1 for S or W, else 1."""
    return -1 if ref.upper() in ('S', 'W') else 1


def convert_gps_to_decimal(values, ref: str) -> float | None:
    """Convert EXIF GPS rational values to decimal degrees."""
    try:
        # values can be a tuple of IFDRational or floats
        def to_float(v):
            if hasattr(v, 'numerator'):
                return v.numerator / v.denominator if v.denominator else 0.0
            if hasattr(v, 'real'):
                return float(v)
            return float(v)

        deg = to_float(values[0])
        min_ = to_float(values[1])
        sec = to_float(values[2])
        decimal = deg + min_ / 60.0 + sec / 3600.0
        return decimal * gps_ref_sign(ref)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# File system metadata
# ---------------------------------------------------------------------------

def get_filesystem_metadata(filepath: str) -> dict:
    """Extract file system level metadata."""
    try:
        s = os.stat(filepath)
        mode = s.st_mode
        perms = stat.filemode(mode)
        result = {
            'file_size_bytes': s.st_size,
            'file_size_human': format_size(s.st_size),
            'permissions': perms,
            'modified_time': ts_to_str(s.st_mtime),
            'accessed_time': ts_to_str(s.st_atime),
            'inode': s.st_ino,
        }
        # ctime is "creation time" on Windows, "metadata change time" on Unix
        if s.st_ctime:
            result['ctime'] = ts_to_str(s.st_ctime)
        # Python 3.12+ may have st_birthtime on macOS/Windows
        if hasattr(s, 'st_birthtime') and s.st_birthtime:
            result['created_time'] = ts_to_str(s.st_birthtime)
        return result
    except OSError as e:
        return {'error': str(e)}


# ---------------------------------------------------------------------------
# Image / EXIF metadata
# ---------------------------------------------------------------------------

def get_image_metadata(filepath: str) -> dict:
    """Extract EXIF and image metadata using Pillow."""
    if not PIL_AVAILABLE:
        return {'_note': 'Install Pillow for image metadata: pip install Pillow'}

    result = {}
    flags = []

    try:
        with Image.open(filepath) as img:
            result['image_format'] = img.format or 'Unknown'
            result['image_mode'] = img.mode
            result['image_width'] = img.width
            result['image_height'] = img.height

            # Get raw EXIF data
            exif_data = img._getexif() if hasattr(img, '_getexif') else None
            if not exif_data:
                # Try alternate method for PNG, TIFF, etc.
                try:
                    exif_data = {
                        TAGS.get(k, k): v
                        for k, v in img.getexif().items()
                    } if hasattr(img, 'getexif') else None
                    if exif_data:
                        result['exif'] = exif_data
                        return result
                except Exception:
                    pass
                result['exif'] = {}
                return result

            exif = {}
            gps_info = {}

            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, str(tag_id))

                if tag == 'GPSInfo':
                    for gps_tag_id, gps_value in value.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                        gps_info[gps_tag] = gps_value
                    continue

                # Skip large binary blobs (thumbnails, etc.)
                if isinstance(value, bytes) and len(value) > 200:
                    exif[tag] = f'<binary data, {len(value)} bytes>'
                    continue

                try:
                    exif[tag] = str(value) if not isinstance(value, (str, int, float)) else value
                except Exception:
                    exif[tag] = '<unreadable>'

            result['exif'] = exif

            # Parse GPS
            if gps_info:
                lat = convert_gps_to_decimal(
                    gps_info.get('GPSLatitude', []),
                    gps_info.get('GPSLatitudeRef', 'N')
                )
                lon = convert_gps_to_decimal(
                    gps_info.get('GPSLongitude', []),
                    gps_info.get('GPSLongitudeRef', 'E')
                )
                if lat is not None and lon is not None:
                    result['gps_latitude'] = round(lat, 6)
                    result['gps_longitude'] = round(lon, 6)
                    result['gps_maps_url'] = f'https://maps.google.com/?q={lat},{lon}'
                    flags.append('GPS_LOCATION_EMBEDDED')

                alt_raw = gps_info.get('GPSAltitude')
                if alt_raw is not None:
                    try:
                        alt = float(alt_raw.numerator) / float(alt_raw.denominator)
                        result['gps_altitude_m'] = round(alt, 1)
                    except Exception:
                        pass

                result['gps_raw'] = {k: str(v) for k, v in gps_info.items()}

    except Exception as e:
        result['error'] = str(e)

    if flags:
        result['_flags'] = flags

    return result


# ---------------------------------------------------------------------------
# PDF metadata
# ---------------------------------------------------------------------------

def _try_import_pypdf():
    """Attempt to import pypdf; returns the module or None on any failure."""
    global PYPDF_AVAILABLE
    if PYPDF_AVAILABLE is True:
        import pypdf as _pypdf
        return _pypdf
    if PYPDF_AVAILABLE is False:
        return None
    # First call — probe with subprocess so a C-level panic doesn't kill us
    import subprocess
    probe = subprocess.run(
        [sys.executable, '-c', 'import pypdf; print("ok")'],
        capture_output=True, text=True, timeout=10
    )
    if probe.returncode == 0 and 'ok' in probe.stdout:
        PYPDF_AVAILABLE = True
        import pypdf as _pypdf
        return _pypdf
    PYPDF_AVAILABLE = False
    return None


def get_pdf_metadata(filepath: str) -> dict:
    """Extract metadata from PDF files."""
    _pypdf = _try_import_pypdf()
    if _pypdf is None:
        return {'_note': 'Install pypdf for PDF metadata: pip install pypdf'}

    result = {}
    flags = []

    try:
        with open(filepath, 'rb') as f:
            reader = _pypdf.PdfReader(f)

        meta = reader.metadata
        if meta:
            fields = {
                '/Title': 'title',
                '/Author': 'author',
                '/Subject': 'subject',
                '/Creator': 'creator_application',
                '/Producer': 'pdf_producer',
                '/Keywords': 'keywords',
                '/CreationDate': 'creation_date',
                '/ModDate': 'modification_date',
            }
            for pdf_key, friendly_key in fields.items():
                val = meta.get(pdf_key)
                if val:
                    result[friendly_key] = str(val)

        result['page_count'] = len(reader.pages)
        result['is_encrypted'] = reader.is_encrypted

        if result.get('author'):
            flags.append('AUTHOR_IDENTIFIED')
        if result.get('creator_application'):
            flags.append('CREATOR_SOFTWARE_IDENTIFIED')

    except Exception as e:
        result['error'] = str(e)

    if flags:
        result['_flags'] = flags

    return result


# ---------------------------------------------------------------------------
# Word document (DOCX) metadata
# ---------------------------------------------------------------------------

def get_docx_metadata(filepath: str) -> dict:
    """Extract metadata from Word .docx files."""
    if not DOCX_AVAILABLE:
        return {'_note': 'Install python-docx for Word metadata: pip install python-docx'}

    result = {}
    flags = []

    try:
        doc = docx.Document(filepath)
        props = doc.core_properties

        fields = {
            'author': props.author,
            'last_modified_by': props.last_modified_by,
            'created': str(props.created) if props.created else None,
            'modified': str(props.modified) if props.modified else None,
            'title': props.title,
            'subject': props.subject,
            'description': props.description,
            'keywords': props.keywords,
            'category': props.category,
            'company': getattr(props, 'company', None),
            'revision': props.revision,
            'content_status': props.content_status,
            'identifier': props.identifier,
            'language': props.language,
            'version': props.version,
        }

        for key, val in fields.items():
            if val:
                result[key] = val

        if result.get('author'):
            flags.append('AUTHOR_IDENTIFIED')
        if result.get('last_modified_by') and result.get('last_modified_by') != result.get('author'):
            flags.append('MODIFIED_BY_DIFFERENT_USER')
        if result.get('company'):
            flags.append('COMPANY_IDENTIFIED')

    except Exception as e:
        result['error'] = str(e)

    if flags:
        result['_flags'] = flags

    return result


# ---------------------------------------------------------------------------
# Excel (XLSX) metadata
# ---------------------------------------------------------------------------

def get_xlsx_metadata(filepath: str) -> dict:
    """Extract metadata from Excel .xlsx files."""
    if not OPENPYXL_AVAILABLE:
        return {'_note': 'Install openpyxl for Excel metadata: pip install openpyxl'}

    result = {}
    flags = []

    try:
        wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
        props = wb.properties

        fields = {
            'creator': props.creator,
            'last_modified_by': props.lastModifiedBy,
            'created': str(props.created) if props.created else None,
            'modified': str(props.modified) if props.modified else None,
            'title': props.title,
            'subject': props.subject,
            'description': props.description,
            'keywords': props.keywords,
            'category': props.category,
            'company': getattr(props, 'company', None),
            'version': props.version,
        }

        for key, val in fields.items():
            if val:
                result[key] = val

        result['sheet_names'] = wb.sheetnames

        if result.get('creator'):
            flags.append('AUTHOR_IDENTIFIED')
        if result.get('company'):
            flags.append('COMPANY_IDENTIFIED')

        wb.close()
    except Exception as e:
        result['error'] = str(e)

    if flags:
        result['_flags'] = flags

    return result


# ---------------------------------------------------------------------------
# Google Drive URL conversion
# ---------------------------------------------------------------------------

def resolve_google_drive_url(url: str) -> str:
    """Convert a Google Drive share link to a direct download URL."""
    # Format: https://drive.google.com/file/d/FILE_ID/view?...
    if 'drive.google.com/file/d/' in url:
        parts = url.split('/file/d/')
        if len(parts) >= 2:
            file_id = parts[1].split('/')[0].split('?')[0]
            return f'https://drive.google.com/uc?export=download&id={file_id}'

    # Format: https://drive.google.com/open?id=FILE_ID
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if 'id' in params:
        file_id = params['id'][0]
        return f'https://drive.google.com/uc?export=download&id={file_id}'

    return url  # Return as-is if we can't parse it


def download_file(url: str) -> tuple[str, str]:
    """
    Download a file from a URL to a temp file.
    Returns (temp_filepath, original_filename).
    Supports Google Drive share links.
    """
    original_url = url

    # Handle Google Drive
    if 'drive.google.com' in url:
        url = resolve_google_drive_url(url)
        print(f"  [Google Drive] Resolved to: {url}")

    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (compatible; FileMetadataTool/1.0)',
    })

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Try to get filename from Content-Disposition header
            filename = ''
            cd = resp.headers.get('Content-Disposition', '')
            if 'filename=' in cd:
                filename = cd.split('filename=')[-1].strip().strip('"\'')

            if not filename:
                # Fall back to URL path
                path = urllib.parse.urlparse(original_url).path
                filename = Path(path).name or 'downloaded_file'

            # Write to temp file with correct extension
            suffix = Path(filename).suffix or ''
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(resp.read())
                return tmp.name, filename

    except urllib.error.HTTPError as e:
        if e.code == 403 and 'drive.google.com' in original_url:
            raise RuntimeError(
                f"Google Drive returned 403 Forbidden.\n"
                f"  Make sure the file is shared publicly (Anyone with the link can view).\n"
                f"  URL tried: {url}"
            )
        raise RuntimeError(f"HTTP {e.code}: {e.reason} — {url}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error: {e.reason}")


# ---------------------------------------------------------------------------
# Critical flags aggregator
# ---------------------------------------------------------------------------

CRITICAL_FLAG_DESCRIPTIONS = {
    'GPS_LOCATION_EMBEDDED': (
        'CRITICAL: This file contains GPS coordinates — physical location where it was created.'
    ),
    'AUTHOR_IDENTIFIED': (
        'IMPORTANT: The file has an embedded author/creator name — may identify who made it.'
    ),
    'MODIFIED_BY_DIFFERENT_USER': (
        'IMPORTANT: The file was last edited by a different user than the original author.'
    ),
    'COMPANY_IDENTIFIED': (
        'IMPORTANT: A company or organization name is embedded in the file.'
    ),
    'CREATOR_SOFTWARE_IDENTIFIED': (
        'NOTABLE: The software used to create this file is recorded in the metadata.'
    ),
    'EXTENSION_MISMATCH': (
        'WARNING: The file extension does not match the actual file content type.'
    ),
}


def collect_all_flags(result: dict) -> list[str]:
    """Collect all flags from nested result dict."""
    flags = []
    for section_data in result.values():
        if isinstance(section_data, dict):
            flags.extend(section_data.get('_flags', []))
    return flags


# ---------------------------------------------------------------------------
# Master analyzer
# ---------------------------------------------------------------------------

def analyze_file(filepath: str, original_name: str = '') -> dict:
    """Run all metadata extractors on a single file and return combined results."""
    name = original_name or os.path.basename(filepath)
    extension = Path(name).suffix.lower()

    # Read first 8KB for magic byte detection
    try:
        with open(filepath, 'rb') as f:
            header = f.read(8192)
    except OSError as e:
        return {'error': f'Cannot read file: {e}'}

    mime_type, type_desc = detect_file_type(header, name)

    # Check for extension mismatch
    ext_mime_map = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png', '.gif': 'image/gif',
        '.bmp': 'image/bmp', '.tif': 'image/tiff', '.tiff': 'image/tiff',
        '.pdf': 'application/pdf',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    }
    ext_mismatch = (
        extension in ext_mime_map and
        not mime_type.startswith(ext_mime_map.get(extension, '').split('/')[0])
    )

    result = {
        'filename': name,
        'extension': extension,
        'detected_type': type_desc,
        'detected_mime': mime_type,
        'extension_mismatch': ext_mismatch,
        'filesystem': get_filesystem_metadata(filepath),
        'hashes': compute_hashes(filepath),
    }

    if ext_mismatch:
        result['_flags'] = ['EXTENSION_MISMATCH']

    # Route to type-specific extractors
    if mime_type.startswith('image/'):
        result['image'] = get_image_metadata(filepath)

    elif mime_type == 'application/pdf':
        result['pdf'] = get_pdf_metadata(filepath)

    elif mime_type in (
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/zip',
    ) and extension == '.docx':
        result['word_document'] = get_docx_metadata(filepath)

    elif extension == '.xlsx' or mime_type == (
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ):
        result['excel'] = get_xlsx_metadata(filepath)

    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_banner(title: str = 'FILE METADATA ANALYSIS'):
    print()
    print('=' * SECTION_WIDTH)
    print(f'  {title}')
    print('=' * SECTION_WIDTH)


def print_section(title: str):
    print()
    pad = SECTION_WIDTH - len(title) - 5
    print(f'--- {title} {"-" * max(pad, 2)}')


def print_field(label: str, value, indent: int = 2):
    prefix = ' ' * indent
    if isinstance(value, (list, tuple)):
        value = ', '.join(str(v) for v in value)
    print(f'{prefix}{label:<30} {value}')


def print_flags(flags: list[str]):
    if not flags:
        return
    print()
    print('  *** FINDINGS ***')
    for flag in flags:
        desc = CRITICAL_FLAG_DESCRIPTIONS.get(flag, flag)
        print(f'  [!] {desc}')


def display_result_text(result: dict):
    """Print a full analysis result in human-readable format."""
    print_banner(f"FILE: {result.get('filename', 'Unknown')}")

    if 'error' in result:
        print(f'\n  ERROR: {result["error"]}\n')
        return

    # --- File Identity ---
    print_section('File Identity')
    print_field('Filename:', result.get('filename', ''))
    print_field('Extension:', result.get('extension', '(none)'))
    print_field('Detected Type:', result.get('detected_type', ''))
    print_field('MIME Type:', result.get('detected_mime', ''))
    if result.get('extension_mismatch'):
        print(f'  *** WARNING: Extension does not match actual file content! ***')

    # --- File System ---
    fs = result.get('filesystem', {})
    if fs and 'error' not in fs:
        print_section('File System Info')
        print_field('Size:', fs.get('file_size_human', ''))
        print_field('Permissions:', fs.get('permissions', ''))
        if fs.get('created_time'):
            print_field('Created:', fs['created_time'])
        if fs.get('ctime'):
            print_field('Metadata Changed:', fs['ctime'])
        print_field('Last Modified:', fs.get('modified_time', ''))
        print_field('Last Accessed:', fs.get('accessed_time', ''))

    # --- Hashes ---
    hashes = result.get('hashes', {})
    if hashes and 'error' not in hashes:
        print_section('Cryptographic Hashes (for verification)')
        print_field('MD5:', hashes.get('md5', ''))
        print_field('SHA-1:', hashes.get('sha1', ''))
        print_field('SHA-256:', hashes.get('sha256', ''))

    # --- Image / EXIF ---
    img = result.get('image', {})
    if img:
        print_section('Image Info')
        if '_note' in img:
            print(f'  {img["_note"]}')
        else:
            print_field('Format:', img.get('image_format', ''))
            print_field('Dimensions:', f"{img.get('image_width', '?')} x {img.get('image_height', '?')} px")
            print_field('Color Mode:', img.get('image_mode', ''))

            if img.get('gps_latitude') is not None:
                print()
                print('  [GPS LOCATION FOUND]')
                print_field('  Latitude:', img['gps_latitude'])
                print_field('  Longitude:', img['gps_longitude'])
                print_field('  Google Maps:', img.get('gps_maps_url', ''))
                if img.get('gps_altitude_m') is not None:
                    print_field('  Altitude (m):', img['gps_altitude_m'])

            exif = img.get('exif', {})
            important_exif = [
                ('DateTime', 'Date/Time (original)'),
                ('DateTimeOriginal', 'Date Taken'),
                ('DateTimeDigitized', 'Date Digitized'),
                ('Make', 'Camera Make'),
                ('Model', 'Camera Model'),
                ('LensModel', 'Lens Model'),
                ('Software', 'Software'),
                ('Artist', 'Artist / Creator'),
                ('Copyright', 'Copyright'),
                ('ImageDescription', 'Image Description'),
                ('UserComment', 'User Comment'),
                ('XPComment', 'Comment'),
                ('XPAuthor', 'Author'),
                ('XPTitle', 'Title'),
                ('XPKeywords', 'Keywords'),
                ('HostComputer', 'Host Computer'),
                ('CameraOwnerName', 'Camera Owner'),
                ('BodySerialNumber', 'Camera Serial No.'),
            ]
            shown = False
            for exif_key, label in important_exif:
                val = exif.get(exif_key)
                if val:
                    if not shown:
                        print()
                        print('  [EXIF Data]')
                        shown = True
                    print_field(f'  {label}:', val)

    # --- PDF ---
    pdf = result.get('pdf', {})
    if pdf:
        print_section('PDF Document Metadata')
        if '_note' in pdf:
            print(f'  {pdf["_note"]}')
        else:
            for key in ['title', 'author', 'subject', 'keywords', 'creator_application',
                        'pdf_producer', 'creation_date', 'modification_date']:
                val = pdf.get(key)
                if val:
                    print_field(key.replace('_', ' ').title() + ':', val)
            print_field('Pages:', pdf.get('page_count', ''))
            print_field('Encrypted:', 'Yes' if pdf.get('is_encrypted') else 'No')

    # --- Word ---
    doc = result.get('word_document', {})
    if doc:
        print_section('Word Document Metadata')
        if '_note' in doc:
            print(f'  {doc["_note"]}')
        else:
            for key in ['title', 'author', 'last_modified_by', 'created', 'modified',
                        'subject', 'description', 'keywords', 'category',
                        'company', 'revision', 'language']:
                val = doc.get(key)
                if val:
                    print_field(key.replace('_', ' ').title() + ':', val)

    # --- Excel ---
    xl = result.get('excel', {})
    if xl:
        print_section('Excel Spreadsheet Metadata')
        if '_note' in xl:
            print(f'  {xl["_note"]}')
        else:
            for key in ['title', 'creator', 'last_modified_by', 'created', 'modified',
                        'subject', 'description', 'keywords', 'category', 'company']:
                val = xl.get(key)
                if val:
                    print_field(key.replace('_', ' ').title() + ':', val)
            if xl.get('sheet_names'):
                print_field('Sheets:', ', '.join(xl['sheet_names']))

    # --- Flags / Critical Findings ---
    all_flags = collect_all_flags(result)
    if result.get('_flags'):
        all_flags = result['_flags'] + all_flags
    print_flags(all_flags)

    print()
    print('=' * SECTION_WIDTH)
    print()


# ---------------------------------------------------------------------------
# Batch output helpers
# ---------------------------------------------------------------------------

def strip_private_keys(d: dict) -> dict:
    """Remove keys starting with _ for JSON output (internal flags are included differently)."""
    result = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = strip_private_keys(v)
        elif k != '_note':
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Extract metadata from files: EXIF, GPS, author, hashes, and more.',
        epilog=(
            'Examples:\n'
            '  python file_metadata.py photo.jpg\n'
            '  python file_metadata.py document.pdf report.docx -o json\n'
            '  python file_metadata.py /folder/ --recursive\n'
            '  python file_metadata.py --url "https://drive.google.com/file/d/FILE_ID/view"\n'
            '  python file_metadata.py --url "https://example.com/photo.jpg"\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'files',
        nargs='*',
        help='File path(s) or directory to analyze',
    )
    parser.add_argument(
        '--url',
        help='Download and analyze a file from a URL or Google Drive share link',
    )
    parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        help='Recursively scan directories',
    )
    parser.add_argument(
        '-o', '--output',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )
    return parser


def collect_files(paths: list[str], recursive: bool = False) -> list[str]:
    """Expand paths (files + directories) into a list of file paths."""
    result = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            result.append(str(path))
        elif path.is_dir():
            pattern = '**/*' if recursive else '*'
            for fp in sorted(path.glob(pattern)):
                if fp.is_file() and not fp.name.startswith('.'):
                    result.append(str(fp))
        else:
            print(f'  [!] Path not found: {p}', file=sys.stderr)
    return result


def main():
    parser = build_parser()
    args = parser.parse_args()

    temp_files_to_clean = []
    all_results = []

    # Check library availability
    if args.output == 'text':
        missing = []
        if not PIL_AVAILABLE:
            missing.append('Pillow (images)')
        if not PYPDF_AVAILABLE:
            missing.append('pypdf (PDFs)')
        if not DOCX_AVAILABLE:
            missing.append('python-docx (Word)')
        if not OPENPYXL_AVAILABLE:
            missing.append('openpyxl (Excel)')
        if missing:
            print(f'\n  [Note] Optional libraries not installed: {", ".join(missing)}')
            print(f'  Run: pip install -r requirements.txt  for full metadata support.\n')

    try:
        # --- URL download ---
        if args.url:
            print(f'\n  Downloading: {args.url}')
            try:
                tmp_path, original_name = download_file(args.url)
                temp_files_to_clean.append(tmp_path)
                print(f'  Saved as: {original_name}  ({format_size(os.path.getsize(tmp_path))})')
                result = analyze_file(tmp_path, original_name)
                all_results.append(result)
            except RuntimeError as e:
                print(f'\n  ERROR: {e}\n', file=sys.stderr)
                sys.exit(1)

        # --- Local files ---
        if args.files:
            filepaths = collect_files(args.files, recursive=args.recursive)
            if not filepaths:
                print('  No files found.', file=sys.stderr)
                sys.exit(1)
            for fp in filepaths:
                result = analyze_file(fp)
                all_results.append(result)

        if not all_results:
            parser.print_help()
            sys.exit(1)

        # --- Output ---
        if args.output == 'json':
            output = all_results if len(all_results) > 1 else all_results[0]
            print(json.dumps(output, indent=2, default=str))
        else:
            for result in all_results:
                display_result_text(result)

    finally:
        for tmp in temp_files_to_clean:
            try:
                os.unlink(tmp)
            except OSError:
                pass


if __name__ == '__main__':
    main()
