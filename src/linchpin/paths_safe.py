"""Confine client- or file-supplied relative paths to a base directory, by text first.

Used by the API (``/demo/load``) and by :func:`linchpin.scenario.load_scenario` when it runs
on behalf of a remote caller. The textual checks run *before* any filesystem call, so a
rejected path (absolute, drive-qualified, UNC, device name, ``..``) is never opened or
resolved -- resolving a UNC path on Windows would already start an SMB connection.
"""
from __future__ import annotations

import ntpath
import os
import re
from pathlib import Path

_WIN_DEVICE = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9]|conin\$|conout\$)(\..*)?$", re.IGNORECASE)


class PathNotAllowed(ValueError):
    """A path was refused because it is not a plain relative path inside the allowed base."""


def relative_parts(name: str) -> list[str]:
    r"""Validate ``name`` as a plain relative path by its text alone and return its parts.

    Raises:
        PathNotAllowed: empty, too long, NUL byte, absolute, drive-qualified, UNC/device
            (``\\server``, ``//server``), a Windows device name, or any ``..`` component.
    """
    if not name or len(name) > 1024 or "\x00" in name:
        raise PathNotAllowed("empty or malformed path")
    text = name.replace("\\", "/")
    if text.startswith("/") or ntpath.splitdrive(name)[0] or ":" in text:
        raise PathNotAllowed(f"absolute, drive-qualified or UNC paths are not accepted: {name!r}")
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if not parts:
        raise PathNotAllowed("empty path")
    for p in parts:
        if p == ".." or _WIN_DEVICE.match(p) or p.endswith((" ", ".")):
            raise PathNotAllowed(f"path component {p!r} is not accepted: {name!r}")
    return parts


def safe_join(base: str | os.PathLike[str], name: str) -> Path:
    """``base / name`` for a relative ``name`` that provably stays inside ``base``.

    The textual check (:func:`relative_parts`) and a string containment check come first;
    only then is the joined path resolved, and containment is checked again so a symlink
    inside ``base`` cannot point outside it.

    Raises:
        PathNotAllowed: the name is not a plain relative path, or it escapes ``base``.
    """
    root = os.path.abspath(os.fspath(base))
    joined = os.path.normpath(os.path.join(root, *relative_parts(name)))
    if os.path.commonpath([root, joined]) != root:
        raise PathNotAllowed(f"{name!r} escapes its base directory")
    resolved = Path(joined).resolve()
    if not resolved.is_relative_to(Path(root).resolve()):
        raise PathNotAllowed(f"{name!r} resolves outside its base directory")
    return resolved
