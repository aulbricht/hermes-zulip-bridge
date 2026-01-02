from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


def _trusted_ancestry(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parent.parts[1:]:
        current /= part
        try:
            linked = current.lstat()
        except OSError as exc:
            raise ValueError("private file ancestry is unavailable or unsafe") from exc
        if stat.S_ISLNK(linked.st_mode) and linked.st_uid == 0:
            try:
                linked = current.stat()
            except OSError as exc:
                raise ValueError("private file ancestry is unavailable or unsafe") from exc
        if (
            not stat.S_ISDIR(linked.st_mode)
            or linked.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(linked.st_mode) & 0o022
        ):
            raise ValueError("private file ancestry is unavailable or unsafe")


def secure_read_text(path: str | Path, max_bytes: int, *, label: str) -> str:
    target = Path(path).expanduser().absolute()
    _trusted_ancestry(target)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        linked = target.lstat()
        fd = os.open(target, flags)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable or unsafe") from exc
    try:
        opened = os.fstat(fd)
        identity = (opened.st_dev, opened.st_ino)
        content_identity = (opened.st_size, opened.st_mtime_ns)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or opened.st_uid not in {0, os.geteuid()}
            or linked.st_uid != opened.st_uid
            or opened.st_nlink != 1
            or linked.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) not in {0o400, 0o600}
            or stat.S_IMODE(linked.st_mode) != stat.S_IMODE(opened.st_mode)
            or identity != (linked.st_dev, linked.st_ino)
        ):
            raise ValueError(f"{label} is unavailable or unsafe")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(65536, max_bytes + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} exceeds {max_bytes} bytes")
        linked_after = target.lstat()
        opened_after = os.fstat(fd)
        if (
            not stat.S_ISREG(linked_after.st_mode)
            or linked_after.st_uid != opened.st_uid
            or linked_after.st_nlink != 1
            or stat.S_IMODE(linked_after.st_mode) != stat.S_IMODE(opened.st_mode)
            or identity != (linked_after.st_dev, linked_after.st_ino)
            or identity != (opened_after.st_dev, opened_after.st_ino)
            or (opened_after.st_size, opened_after.st_mtime_ns) != content_identity
            or opened_after.st_size != total
        ):
            raise ValueError(f"{label} changed during read")
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{label} is not valid UTF-8") from exc
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"{label} is unavailable or unsafe") from exc
    finally:
        os.close(fd)


def opaque_log_value(value: object) -> str:
    return "ref:" + hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:16]
