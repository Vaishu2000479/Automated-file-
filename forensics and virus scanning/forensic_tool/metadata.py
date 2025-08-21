from __future__ import annotations
import os
import platform
import stat
# POSIX-only modules; may not exist on Windows
try:
    import pwd  # type: ignore
    import grp  # type: ignore
    HAS_POSIX = True
except Exception:
    pwd = None  # type: ignore
    grp = None  # type: ignore
    HAS_POSIX = False
import datetime
from pathlib import Path
from typing import Dict, Any

try:
    import win32security  # type: ignore
    import win32api  # type: ignore
    import win32con  # type: ignore
    HAS_WIN = True
except Exception:
    HAS_WIN = False

from .logger import get_logger

logger = get_logger()


def _format_ts(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def get_metadata(path: Path) -> Dict[str, Any]:
    """Cross-platform file metadata: size, times, owner, permissions/ACL summary."""
    try:
        st = path.stat()
        meta: Dict[str, Any] = {
            "size": st.st_size,
            "created": _format_ts(getattr(st, 'st_ctime', st.st_mtime)),
            "modified": _format_ts(st.st_mtime),
            "accessed": _format_ts(st.st_atime),
            "permissions": stat.filemode(st.st_mode),
        }

        if platform.system() == 'Windows':
            meta["owner"] = _get_windows_owner(path)
            # Simplified ACL summary
            meta["acl"] = "Windows ACL present" if HAS_WIN else "N/A"
        else:
            meta["owner_uid"] = getattr(st, 'st_uid', None)
            meta["owner_gid"] = getattr(st, 'st_gid', None)
            if HAS_POSIX and meta["owner_uid"] is not None and meta["owner_gid"] is not None:
                try:
                    meta["owner"] = f"{pwd.getpwuid(st.st_uid).pw_name}:{grp.getgrgid(st.st_gid).gr_name}"
                except Exception:
                    meta["owner"] = f"{st.st_uid}:{st.st_gid}"
            else:
                meta["owner"] = "N/A"
        return meta
    except Exception as e:
        logger.warning(f"Metadata extraction failed for {path}: {e}")
        return {}


def _get_windows_owner(path: Path) -> str:
    if not HAS_WIN:
        return "N/A"
    try:
        sd = win32security.GetFileSecurity(str(path), win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
        return f"{domain}\\{name}" if domain else name
    except Exception as e:
        logger.debug(f"Windows owner lookup failed for {path}: {e}")
        return "Unknown"
