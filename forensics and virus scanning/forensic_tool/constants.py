from typing import Dict

# Known magic signatures and their human friendly names
MAGIC_SIGNATURES: Dict[bytes, str] = {
    b"\xFF\xD8\xFF": "JPEG Image",
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"GIF87a": "GIF Image",
    b"GIF89a": "GIF Image",
    b"%PDF-": "PDF Document",
    b"PK\x03\x04": "ZIP Archive",
    b"MZ": "Windows PE Executable",
    b"\x7fELF": "Linux ELF Executable",
}

FILE_CATEGORIES: Dict[str, str] = {
    "JPEG Image": "Image",
    "PNG Image": "Image",
    "GIF Image": "Image",
    "PDF Document": "Document",
    "ZIP Archive": "Archive",
    "Windows PE Executable": "Executable",
    "Linux ELF Executable": "Executable",
}

# Entropy threshold for likely encrypted/compressed content
HIGH_ENTROPY_THRESHOLD = 7.5

DEFAULT_DB_NAME = "forensics.db"
LOG_DIR = "logs"
LOG_FILE = "forensic_tool.log"

# Optional local AV integration
# ClamAV settings (cross-platform)
CLAMSCAN_ENV_VAR = "CLAMSCAN_PATH"
CLAMSCAN_TIMEOUT = 120  # seconds per file

# Microsoft Defender settings (Windows only)
DEFENDER_ENV_VAR = "DEFENDER_MPCMDRUN_PATH"
DEFENDER_TIMEOUT = 180  # seconds per file

APP_NAME = "Automated File Forensics & Virus Scanner"
