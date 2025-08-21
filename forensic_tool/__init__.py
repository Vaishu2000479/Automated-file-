"""
Automated File Forensics and Virus Scanning Tool

This package provides:
- FileAnalyzer: file scanning, hashing, entropy, signature detection, PE/ELF analysis
- MetadataExtractor: cross-platform metadata extraction (timestamps, owner, permissions)
- LocalScanner: Windows Defender and ClamAV wrapper
- ReportGenerator: CSV/JSON/PDF reporting
- ForensicDB: SQLite-backed integrity tracking (hash history) and VT cache
- get_logger: rotating file logger configured to logs/forensic_tool.log

All components are designed to be cross-platform (Windows, Linux) with graceful fallbacks.
"""

__all__ = [
    "constants",
    "logger",
    "db",
    "metadata",
    "analyzer",
    # "virus_scanner",  # removed: VirusTotal integration deprecated
    "report",
]
