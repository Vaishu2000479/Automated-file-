from __future__ import annotations
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

from .constants import (
    CLAMSCAN_ENV_VAR, CLAMSCAN_TIMEOUT,
    DEFENDER_ENV_VAR, DEFENDER_TIMEOUT,
)
from .logger import get_logger

logger = get_logger()


class LocalScanner:
    """Local AV wrappers: tries Microsoft Defender on Windows, falls back to ClamAV.

    Returns friendly strings:
    - 'Clean'
    - 'Infected: <signature>'
    - 'Not Available' (when no local AV found)
    - 'AV Disabled' (when manually disabled)
    - 'Error: <msg>'
    """

    def __init__(self, clamscan_path: Optional[str] = None, defender_path: Optional[str] = None, enabled: bool = True):
        self.enabled = enabled
        self._clam_path_cfg = clamscan_path or os.environ.get(CLAMSCAN_ENV_VAR)
        self._def_path_cfg = defender_path or os.environ.get(DEFENDER_ENV_VAR)

    # Defender
    def _resolve_defender(self) -> Optional[str]:
        if platform.system() != 'Windows':
            return None
        if self._def_path_cfg and Path(self._def_path_cfg).exists():
            return self._def_path_cfg
        default = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
        if Path(default).exists():
            return default
        alt = r"C:\Program Files\Microsoft Defender\MpCmdRun.exe"
        if Path(alt).exists():
            return alt
        return shutil.which("MpCmdRun.exe")

    def _scan_with_defender(self, file_path: Path) -> Optional[str]:
        bin_path = self._resolve_defender()
        if not bin_path:
            return None
        try:
            # MpCmdRun exit codes vary; we'll parse stdout for detection
            # Quick scan on a specific file (ScanType 3):
            proc = subprocess.run(
                [bin_path, "-Scan", "-ScanType", "3", "-File", str(file_path)],
                capture_output=True, text=True, timeout=DEFENDER_TIMEOUT,
            )
            out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            lower = out.lower()
            # Heuristic parsing
            if "no threats" in lower or "found 0" in lower:
                return "Clean"
            if "threat" in lower or "found" in lower:
                # Try find a signature name
                sig = None
                for line in out.splitlines():
                    if "threat" in line.lower() and ":" in line:
                        # Example: "Threat  : Trojan:Script/Wacatac.B!ml"
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            sig = parts[1].strip()
                            break
                if not sig:
                    sig = "Detected"
                return f"Infected: {sig}"
            if proc.returncode == 0:
                return "Clean"
            logger.debug(f"Defender scan non-clean output: rc={proc.returncode} out={out}")
            return "Error: Scanner failed"
        except subprocess.TimeoutExpired:
            return "Error: Timeout"
        except Exception as e:
            logger.debug(f"Defender invocation failed: {e}")
            return "Error: Exception"

    # ClamAV
    def _resolve_clam(self) -> Optional[str]:
        if self._clam_path_cfg and Path(self._clam_path_cfg).exists():
            return self._clam_path_cfg
        return shutil.which("clamscan")

    def _scan_with_clam(self, file_path: Path) -> Optional[str]:
        bin_path = self._resolve_clam()
        if not bin_path:
            return None
        try:
            proc = subprocess.run(
                [bin_path, "--no-summary", str(file_path)],
                capture_output=True, text=True, timeout=CLAMSCAN_TIMEOUT,
            )
            out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            if proc.returncode == 0:
                return "Clean"
            elif proc.returncode == 1:
                sig = "Malware"
                for line in out.splitlines():
                    if line.strip().endswith("FOUND") and ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            sig_field = parts[1].strip()
                            if sig_field.endswith("FOUND"):
                                sig = sig_field[:-5].strip()
                                break
                return f"Infected: {sig}"
            else:
                logger.debug(f"clamscan error ({proc.returncode}): {out}")
                return "Error: Scanner failed"
        except subprocess.TimeoutExpired:
            return "Error: Timeout"
        except Exception as e:
            logger.debug(f"clamscan invocation failed: {e}")
            return "Error: Exception"

    # Public
    def availability(self) -> Tuple[bool, Optional[str]]:
        if not self.enabled:
            return False, "Disabled"
        if self._resolve_defender():
            return True, "Windows Defender"
        if self._resolve_clam():
            return True, "ClamAV"
        return False, "No local AV found"

    def scan_file(self, file_path: Path) -> str:
        if not self.enabled:
            return "AV Disabled"
        # Prefer Defender on Windows, else ClamAV
        res = self._scan_with_defender(file_path)
        if res is not None:
            return res
        res = self._scan_with_clam(file_path)
        if res is not None:
            return res
        return "Not Available"
