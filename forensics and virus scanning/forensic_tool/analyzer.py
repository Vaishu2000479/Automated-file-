from __future__ import annotations
import math
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional

from PIL import Image
from PIL.ExifTags import TAGS
import PyPDF2

try:
    import pefile  # type: ignore
except Exception:
    pefile = None

try:
    import lief  # type: ignore
except Exception:
    lief = None

from .constants import MAGIC_SIGNATURES, FILE_CATEGORIES, HIGH_ENTROPY_THRESHOLD
from .logger import get_logger

logger = get_logger()


def calculate_entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    # Probabilities over 0..255
    counts = [0] * 256
    for b in sample:
        counts[b] += 1
    entropy = 0.0
    length = len(sample)
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def detect_file_type(path: Path, num_bytes: int = 8) -> str:
    try:
        with path.open('rb') as f:
            magic = f.read(num_bytes)
        for sig, name in MAGIC_SIGNATURES.items():
            if magic.startswith(sig):
                return name
        return 'Unknown'
    except Exception as e:
        logger.warning(f"Type detect failed for {path}: {e}")
        return 'Error'


def get_signature_hex(path: Path, num_bytes: int = 8) -> str:
    try:
        with path.open('rb') as f:
            return f.read(num_bytes).hex().upper()
    except Exception as e:
        logger.debug(f"Signature read failed for {path}: {e}")
        return ""


def hash_file(path: Path, algo: str) -> str:
    try:
        h = hashlib.new(algo)
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.warning(f"Hash {algo} failed for {path}: {e}")
        return ""


def extract_exif(path: Path) -> Dict[str, Any]:
    try:
        img = Image.open(path)
        exif = img._getexif() or {}
        return {TAGS.get(k, k): v for k, v in exif.items()}
    except Exception:
        return {}


def extract_pdf_metadata(path: Path) -> Dict[str, Any]:
    try:
        with path.open('rb') as f:
            reader = PyPDF2.PdfReader(f)
            data = reader.metadata or {}
            # Convert to plain dict
            return {k: str(v) for k, v in data.items()}
    except Exception:
        return {}


def analyze_pe(path: Path) -> Dict[str, Any]:
    if not pefile:
        return {"available": False}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
        suspicious_sections = [
            s.Name.decode(errors='ignore').strip('\x00')
            for s in pe.sections if s.get_entropy() and s.get_entropy() > 7.2
        ]
        imports = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore')
                imports[dll] = [imp.name.decode(errors='ignore') if imp.name else None for imp in entry.imports]
        return {
            "available": True,
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase) if hasattr(pe, 'OPTIONAL_HEADER') else None,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe, 'OPTIONAL_HEADER') else None,
            "sections": [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections],
            "suspicious_sections": suspicious_sections,
            "imports": imports,
        }
    except Exception as e:
        logger.debug(f"PE analysis failed for {path}: {e}")
        return {"available": False}


def analyze_elf(path: Path) -> Dict[str, Any]:
    if not lief:
        return {"available": False}
    try:
        binary = lief.parse(str(path))
        sections = [s.name for s in binary.sections]
        return {
            "available": True,
            "type": str(binary.header.file_type) if binary and binary.header else None,
            "entry_point": hex(binary.entrypoint) if binary else None,
            "sections": sections,
        }
    except Exception as e:
        logger.debug(f"ELF analysis failed for {path}: {e}")
        return {"available": False}


def analyze_file(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    info["signature_hex"] = get_signature_hex(path)
    info["type"] = detect_file_type(path)

    # Sample first 4096 bytes for entropy
    sample = b""
    try:
        with path.open('rb') as f:
            sample = f.read(4096)
    except Exception:
        pass
    info["entropy"] = round(calculate_entropy(sample), 4)
    info["high_entropy"] = info["entropy"] > HIGH_ENTROPY_THRESHOLD

    # Hashes
    info["md5"] = hash_file(path, 'md5')
    info["sha256"] = hash_file(path, 'sha256')

    # Category
    info["category"] = FILE_CATEGORIES.get(info["type"], "Other")

    # EXIF / PDF
    if info["type"] in ("JPEG Image", "PNG Image", "GIF Image"):
        info["exif"] = extract_exif(path)
    if info["type"] == "PDF Document":
        info["pdf_metadata"] = extract_pdf_metadata(path)

    # Executables
    if info["type"] == "Windows PE Executable":
        info["pe"] = analyze_pe(path)
    if info["type"] == "Linux ELF Executable":
        info["elf"] = analyze_elf(path)

    # Extension mismatch heuristic
    ext = path.suffix.lower().lstrip('.')
    expected = None
    mapping = {
        "jpeg": "jpeg",
        "jpg": "jpeg",
        "png": "png",
        "gif": "gif",
        "pdf": "pdf",
        "zip": "zip",
        "exe": "windows",
        "dll": "windows",
        "elf": "elf",
    }
    if info["type"] != "Unknown" and info["type"] != "Error":
        expected = info["type"].split()[0].lower()
    mismatch = False
    if expected and ext and expected not in mapping.get(ext, ext):
        mismatch = True
    info["extension_mismatch"] = mismatch

    return info
