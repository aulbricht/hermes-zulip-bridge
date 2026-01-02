from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


PROCESS_LOCK_UNAVAILABLE = "Another Hermes Zulip bridge or standalone smoke test is already running"
PROCESS_LOCK_FAILED = "Unable to secure the Hermes Zulip process lock"
_LOCK_DIRECTORY = ".hermes-zulip-locks"


class ProcessLockError(RuntimeError):
    def __init__(self, message: str = PROCESS_LOCK_UNAVAILABLE) -> None:
        super().__init__(message)


def _normalized_state_path(state_path: Path) -> Path:
    lexical = Path(os.path.abspath(os.path.expanduser(os.fspath(state_path))))
    return Path(os.path.realpath(lexical.parent)) / lexical.name


def canonical_state_path(state_path: Path) -> Path:
    return _normalized_state_path(state_path)


def _secure_state_file(state_path: Path) -> None:
    try:
        linked = state_path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(linked.st_mode)
        or linked.st_nlink != 1
        or linked.st_uid != os.geteuid()
        or stat.S_IMODE(linked.st_mode) & 0o022
    ):
        raise ProcessLockError(PROCESS_LOCK_FAILED)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(state_path, flags)
    except PermissionError:
        try:
            os.chmod(state_path, 0o600, follow_symlinks=False)
            fd = os.open(state_path, flags)
        except (OSError, NotImplementedError):
            raise ProcessLockError(PROCESS_LOCK_FAILED) from None
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise ProcessLockError(PROCESS_LOCK_FAILED)
        os.fchmod(fd, 0o600)
        opened = os.fstat(fd)
        linked = state_path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not stat.S_ISREG(linked.st_mode)
            or linked.st_nlink != 1
            or linked.st_uid != os.geteuid()
            or stat.S_IMODE(linked.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise ProcessLockError(PROCESS_LOCK_FAILED)
    except ProcessLockError:
        raise
    except OSError:
        raise ProcessLockError(PROCESS_LOCK_FAILED) from None
    finally:
        os.close(fd)


@dataclass(frozen=True)
class HeldProcessLock:
    path: Path
    guard_path: Path
    fd: int
    state_path: Path
    dev: int
    ino: int
    position: int

    def validate(self, expected_state_path: Path) -> None:
        try:
            if self.state_path != _normalized_state_path(expected_state_path):
                raise ProcessLockError(PROCESS_LOCK_FAILED)
            _secure_state_file(self.state_path)
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise ProcessLockError(PROCESS_LOCK_FAILED) from None
                raise
            opened = os.fstat(self.fd)
            linked = self.path.lstat()
            guarded = self.guard_path.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (opened.st_dev, opened.st_ino) != (self.dev, self.ino)
                or (linked.st_dev, linked.st_ino) != (self.dev, self.ino)
                or (guarded.st_dev, guarded.st_ino) != (self.dev, self.ino)
                or linked.st_uid != os.geteuid()
                or guarded.st_uid != os.geteuid()
                or not stat.S_ISREG(linked.st_mode)
                or not stat.S_ISREG(guarded.st_mode)
                or stat.S_IMODE(linked.st_mode) != 0o600
                or stat.S_IMODE(guarded.st_mode) != 0o600
                or os.lseek(self.fd, 0, os.SEEK_CUR) != self.position
            ):
                raise ProcessLockError(PROCESS_LOCK_FAILED)
        except ProcessLockError:
            raise
        except (OSError, ValueError):
            raise ProcessLockError(PROCESS_LOCK_FAILED) from None


def process_lock_path(state_path: Path) -> Path:
    return Path(str(state_path) + ".lock")


def process_lock_bundle_paths(state_path: Path) -> tuple[Path, Path, Path]:
    state_path = _normalized_state_path(state_path)
    lock_directory = state_path.parent / _LOCK_DIRECTORY
    anchor = _anchor_path(state_path, lock_directory)
    return process_lock_path(state_path), anchor, anchor.with_suffix(".guard")


def _secure_directory(path: Path) -> int:
    try:
        path.mkdir(parents=True, mode=0o700)
    except FileExistsError:
        pass
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        linked = path.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or not stat.S_ISDIR(linked.st_mode)
            or linked.st_uid != os.geteuid()
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise ProcessLockError(PROCESS_LOCK_FAILED)
        identity = (opened.st_dev, opened.st_ino)
        os.fchmod(fd, 0o700)
    except Exception:
        os.close(fd)
        raise
    os.close(fd)
    fd = os.open(path, flags)
    opened = os.fstat(fd)
    linked = path.lstat()
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or not stat.S_ISDIR(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or stat.S_IMODE(linked.st_mode) != 0o700
        or (opened.st_dev, opened.st_ino) != identity
        or (linked.st_dev, linked.st_ino) != identity
    ):
        os.close(fd)
        raise ProcessLockError(PROCESS_LOCK_FAILED)
    return fd


def _anchor_path(state_path: Path, lock_directory: Path) -> Path:
    digest = hashlib.sha256(os.fsencode(state_path)).hexdigest()
    return lock_directory / f"{digest}.lock"


def _validate_open_anchor(fd: int, path: Path) -> os.stat_result:
    opened = os.fstat(fd)
    linked = path.lstat()
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o600
        or not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or stat.S_IMODE(linked.st_mode) != 0o600
        or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
    ):
        raise ProcessLockError(PROCESS_LOCK_FAILED)
    return opened


def _lock_visible_anchor(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = _validate_open_anchor(fd, path)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise ProcessLockError(PROCESS_LOCK_UNAVAILABLE) from None
            raise ProcessLockError(PROCESS_LOCK_FAILED) from None
        return fd, opened
    except Exception:
        os.close(fd)
        raise


def _acquire_anchor(path: Path, guard_path: Path, directory_fd: int) -> tuple[int, os.stat_result]:
    try:
        fd, opened = _lock_visible_anchor(path)
    except FileNotFoundError:
        try:
            guard_path.lstat()
        except FileNotFoundError:
            pass
        else:
            try:
                path.lstat()
            except FileNotFoundError:
                raise ProcessLockError(PROCESS_LOCK_FAILED) from None
            return _acquire_anchor(path, guard_path, directory_fd)
    else:
        try:
            try:
                guard = guard_path.lstat()
            except FileNotFoundError:
                os.link(path, guard_path, follow_symlinks=False)
                os.fsync(directory_fd)
                opened = _validate_open_anchor(fd, path)
                guard = guard_path.lstat()
            if (guard.st_dev, guard.st_ino) != (opened.st_dev, opened.st_ino):
                raise ProcessLockError(PROCESS_LOCK_FAILED)
            return fd, opened
        except Exception:
            os.close(fd)
            raise

    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd: int | None = None
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temporary, flags, 0o600)
        os.fchmod(fd, 0o600)
        created = os.fstat(fd)
        if not stat.S_ISREG(created.st_mode) or created.st_uid != os.geteuid() or stat.S_IMODE(created.st_mode) != 0o600:
            raise ProcessLockError(PROCESS_LOCK_FAILED)
        os.fsync(fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            os.close(fd)
            fd = None
            return _acquire_anchor(path, guard_path, directory_fd)
        os.link(temporary, guard_path, follow_symlinks=False)
        os.fsync(directory_fd)
        return fd, created
    except Exception:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _repair_public_path(anchor: Path, public_path: Path) -> None:
    temporary = public_path.with_name(f".{public_path.name}.{secrets.token_hex(8)}.tmp")
    try:
        os.link(anchor, temporary, follow_symlinks=False)
        os.replace(temporary, public_path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def process_lock(state_path: Path) -> Iterator[HeldProcessLock]:
    state_path = _normalized_state_path(state_path)
    state_directory_fd: int | None = None
    lock_directory_fd: int | None = None
    fd: int | None = None
    try:
        try:
            state_directory_fd = _secure_directory(state_path.parent)
            lock_directory = state_path.parent / _LOCK_DIRECTORY
            lock_directory_fd = _secure_directory(lock_directory)
            _public, anchor, guard = process_lock_bundle_paths(state_path)
            fd, opened = _acquire_anchor(anchor, guard, lock_directory_fd)
            linked = anchor.lstat()
            if (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino):
                raise ProcessLockError(PROCESS_LOCK_FAILED)
            position = secrets.randbelow(2**31 - 1) + 1
            os.lseek(fd, position, os.SEEK_SET)
            held = HeldProcessLock(anchor, guard, fd, state_path, opened.st_dev, opened.st_ino, position)
            held.validate(state_path)
            _repair_public_path(anchor, process_lock_path(state_path))
            _secure_state_file(state_path)
        except ProcessLockError:
            raise
        except (OSError, ValueError):
            raise ProcessLockError(PROCESS_LOCK_FAILED) from None
        yield held
    finally:
        if fd is not None:
            os.close(fd)
        if lock_directory_fd is not None:
            os.close(lock_directory_fd)
        if state_directory_fd is not None:
            os.close(state_directory_fd)
