from __future__ import annotations

import concurrent.futures
import errno
import fcntl
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hermes_zulip_bridge import locking


class ProcessLockTests(unittest.TestCase):
    def test_state_permission_open_retry_repairs_owner_file_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state.json"
            state.write_bytes(b"{}")
            state.chmod(0o644)
            inode = state.stat().st_ino
            real_open = os.open
            calls = 0

            def deny_once(path: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise PermissionError("simulated owner-only open policy")
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(locking.os, "open", side_effect=deny_once):
                locking._secure_state_file(state)

            self.assertEqual((state.stat().st_ino, stat.S_IMODE(state.stat().st_mode)), (inode, 0o600))

    def test_restart_repairs_anchor_left_by_second_link_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            real_link = os.link
            calls = 0

            def fail_second_link(source: Path, destination: Path, **kwargs: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected guard publication failure")
                real_link(source, destination, **kwargs)

            with mock.patch.object(locking.os, "link", side_effect=fail_second_link), self.assertRaisesRegex(
                locking.ProcessLockError, locking.PROCESS_LOCK_FAILED
            ):
                with locking.process_lock(state):
                    self.fail("half-published lock was acquired")

            anchors = list((state.parent / ".hermes-zulip-locks").glob("*.lock"))
            self.assertEqual(len(anchors), 1)
            self.assertFalse(anchors[0].with_suffix(".guard").exists())
            with locking.process_lock(state) as held:
                self.assertEqual(held.guard_path.stat().st_ino, held.ino)
                self.assertEqual(held.path.stat().st_ino, held.ino)

    def test_fifty_process_cold_start_has_one_winner_and_only_unavailable_contenders(self) -> None:
        code = """
import sys
from pathlib import Path
from hermes_zulip_bridge.locking import ProcessLockError, process_lock
sys.stdin.read(1)
try:
    with process_lock(Path(sys.argv[1])):
        print("winner", flush=True)
        sys.stdin.read(1)
except ProcessLockError as exc:
    print(str(exc), flush=True)
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
            processes = [
                subprocess.Popen(
                    [sys.executable, "-c", code, str(state)],
                    env=env,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(50)
            ]
            results: list[str] = []
            records: list[tuple[int, str, str, int | None]] = []
            try:
                for process in processes:
                    process.stdin.write("x")
                    process.stdin.flush()
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(processes)) as readers:
                    futures = [readers.submit(process.stdout.readline) for process in processes]
                    results = [future.result().strip() for future in futures]
            finally:
                for process in processes:
                    try:
                        process.stdin.write("x")
                        process.stdin.flush()
                    except (BrokenPipeError, OSError):
                        pass
                for index, process in enumerate(processes):
                    try:
                        stdout, stderr = process.communicate(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate()
                    records.append((index, stdout, stderr, process.returncode))
                    process.stdin.close()
                    process.stdout.close()
                    process.stderr.close()
            details = "\n".join(
                f"child {index}: first={results[index]!r} tail={stdout!r} stderr={stderr!r} exit={returncode}"
                for index, stdout, stderr, returncode in records
            )
            self.assertEqual(results.count("winner"), 1, details)
            self.assertEqual(results.count(locking.PROCESS_LOCK_UNAVAILABLE), 49, details)
            self.assertNotIn(locking.PROCESS_LOCK_FAILED, results, details)
            self.assertTrue(all(returncode == 0 for _index, _stdout, _stderr, returncode in records), details)

    def test_repairs_public_symlink_without_touching_target_and_rejects_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target"
            target.write_text("untouched", encoding="utf-8")
            symlink_state = root / "symlink-state"
            locking.process_lock_path(symlink_state).symlink_to(target)

            with locking.process_lock(symlink_state) as held:
                self.assertEqual(locking.process_lock_path(symlink_state).stat().st_ino, held.ino)
            self.assertEqual(target.read_text(encoding="utf-8"), "untouched")

            directory_state = root / "directory-state"
            locking.process_lock_path(directory_state).mkdir()
            with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                with locking.process_lock(directory_state):
                    self.fail("directory lock target was accepted")

    @unittest.skipUnless(hasattr(os, "geteuid"), "effective ownership is POSIX-only")
    def test_rejects_state_directory_not_owned_by_effective_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state"

            with mock.patch.object(locking.os, "geteuid", return_value=os.geteuid() + 1), self.assertRaisesRegex(
                locking.ProcessLockError, locking.PROCESS_LOCK_FAILED
            ):
                with locking.process_lock(state_path):
                    self.fail("foreign-owned lock target was accepted")

    def test_upgrades_existing_owner_state_directory_mode(self) -> None:
        for initial_mode in (0o755, 0o777):
            with self.subTest(initial_mode=oct(initial_mode)), tempfile.TemporaryDirectory() as tmpdir:
                state_dir = Path(tmpdir) / "state-dir"
                old_umask = os.umask(0)
                try:
                    state_dir.mkdir(mode=initial_mode)
                finally:
                    os.umask(old_umask)
                with locking.process_lock(state_dir / "state"):
                    self.assertEqual(stat.S_IMODE(state_dir.stat().st_mode), 0o700)

    def test_repairs_mode_under_restrictive_umask_and_remains_restartable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            existing_state = root / "existing"
            existing_lock = locking.process_lock_path(existing_state)
            existing_lock.write_text("", encoding="utf-8")
            existing_lock.chmod(0o666)

            with locking.process_lock(existing_state):
                self.assertEqual(stat.S_IMODE(existing_lock.stat().st_mode), 0o600)

            restrictive_state = root / "restrictive"
            restrictive_lock = locking.process_lock_path(restrictive_state)
            old_umask = os.umask(0o777)
            try:
                with locking.process_lock(restrictive_state):
                    self.assertEqual(stat.S_IMODE(restrictive_lock.stat().st_mode), 0o600)
            finally:
                os.umask(old_umask)

            with locking.process_lock(existing_state), locking.process_lock(restrictive_state):
                self.assertEqual(stat.S_IMODE(existing_lock.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(restrictive_lock.stat().st_mode), 0o600)

    def test_public_replacement_does_not_bypass_contention_and_reacquisition_repairs_it(self) -> None:
        holder_code = """
import sys
from pathlib import Path
from hermes_zulip_bridge.locking import process_lock
with process_lock(Path(sys.argv[1])):
    print("locked", flush=True)
    sys.stdin.read(1)
"""
        contender_code = """
import sys
from pathlib import Path
from hermes_zulip_bridge.locking import ProcessLockError, process_lock
try:
    with process_lock(Path(sys.argv[1])):
        print("acquired")
except ProcessLockError as exc:
    print(str(exc))
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state"
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
            holder = subprocess.Popen(
                [sys.executable, "-c", holder_code, str(state_path)],
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(holder.stdout.readline(), "locked\n")
                public = locking.process_lock_path(state_path)
                public.unlink()
                public.write_text("replacement", encoding="utf-8")
                contender = subprocess.run(
                    [sys.executable, "-c", contender_code, str(state_path)],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(contender.returncode, 0, contender.stderr)
                self.assertEqual(contender.stdout.strip(), locking.PROCESS_LOCK_UNAVAILABLE)
            finally:
                _stdout, stderr = holder.communicate(input="\n", timeout=5)
                holder.stdin.close()
                holder.stdout.close()
                holder.stderr.close()
            self.assertEqual(holder.returncode, 0, stderr)
            with locking.process_lock(state_path) as held:
                self.assertEqual(public.stat().st_ino, held.ino)

    def test_held_lock_validation_rejects_wrong_state_anchor_tamper_and_reused_fd(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state"
            with locking.process_lock(state_path) as held:
                with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                    held.validate(Path(tmpdir) / "other")
                held.path.unlink()
                held.path.write_text("replacement", encoding="utf-8")
                with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                    held.validate(state_path)

            held.path.chmod(0o600)
            with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                with locking.process_lock(state_path):
                    self.fail("replaced authoritative anchor was accepted")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state"
            with locking.process_lock(state_path) as held:
                moved = held.path.parent.with_name("moved-lock-directory")
                held.path.parent.rename(moved)
                held.path.parent.mkdir(mode=0o700)
                with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                    held.validate(state_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state"
            with locking.process_lock(state_path) as held:
                os.close(held.fd)
                reused = os.open(held.path, os.O_RDONLY)
                self.assertEqual(reused, held.fd)
                with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                    held.validate(state_path)

    def test_umask_zero_still_creates_private_directory_and_anchor_with_owner_only_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = Path(tmpdir) / "state-dir"
            state_path = state_dir / "state"
            old_umask = os.umask(0)
            try:
                with locking.process_lock(state_path) as held:
                    self.assertEqual(stat.S_IMODE(state_dir.stat().st_mode), 0o700)
                    self.assertEqual(stat.S_IMODE(held.path.parent.stat().st_mode), 0o700)
                    self.assertEqual(stat.S_IMODE(held.path.stat().st_mode), 0o600)
            finally:
                os.umask(old_umask)

    def test_exec_closes_descriptor_and_releases_lock(self) -> None:
        second = """
import sys
from pathlib import Path
from hermes_zulip_bridge.locking import process_lock
with process_lock(Path(sys.argv[1])):
    print("reacquired")
"""
        first = f"""
import os
import sys
from pathlib import Path
from hermes_zulip_bridge.locking import process_lock
with process_lock(Path(sys.argv[1])):
    os.execv(sys.executable, [sys.executable, "-c", {second!r}, sys.argv[1]])
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state"
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
            completed = subprocess.run(
                [sys.executable, "-c", first, str(state_path)],
                env=env,
                capture_output=True,
                text=True,
                timeout=5,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "reacquired\n")

    def test_validation_fails_when_contender_acquires_after_authoritative_fd_is_unlocked(self) -> None:
        contender_code = """
import fcntl
import os
import sys
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.flock(fd, fcntl.LOCK_EX)
print("locked", flush=True)
sys.stdin.read(1)
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state"
            with locking.process_lock(state_path) as held:
                fcntl.flock(held.fd, fcntl.LOCK_UN)
                contender = subprocess.Popen(
                    [sys.executable, "-c", contender_code, str(held.path)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    self.assertEqual(contender.stdout.readline(), "locked\n")
                    with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                        held.validate(state_path)
                finally:
                    _stdout, stderr = contender.communicate(input="\n", timeout=5)
                    contender.stdin.close()
                    contender.stdout.close()
                    contender.stderr.close()
                self.assertEqual(contender.returncode, 0, stderr)

    def test_independent_state_paths_can_be_locked_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            first_state = Path(tmpdir) / "first"
            second_state = Path(tmpdir) / "second"

            with locking.process_lock(first_state) as first, locking.process_lock(second_state) as second:
                self.assertNotEqual(first.path, second.path)

    def test_state_file_symlink_and_hardlink_aliases_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state = root / "state"
            state.write_text("{}", encoding="utf-8")
            symlink = root / "state-symlink"
            symlink.symlink_to(state)

            with locking.process_lock(state):
                with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                    with locking.process_lock(symlink):
                        self.fail("state-file symlink acquired a cooperating lock")

            hardlink = root / "state-hardlink"
            os.link(state, hardlink)
            for candidate in (state, hardlink):
                with self.subTest(candidate=candidate), self.assertRaisesRegex(
                    locking.ProcessLockError, locking.PROCESS_LOCK_FAILED
                ):
                    with locking.process_lock(candidate):
                        self.fail("multiply linked state file acquired a cooperating lock")

    def test_state_file_mode_is_repaired_and_wrong_owner_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            state.write_text("{}", encoding="utf-8")
            state.chmod(0o644)
            with locking.process_lock(state):
                self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)

            with mock.patch.object(locking.os, "geteuid", return_value=os.geteuid() + 1), self.assertRaisesRegex(
                locking.ProcessLockError, locking.PROCESS_LOCK_FAILED
            ):
                locking._secure_state_file(state)

    def test_parent_path_aliases_share_one_lock_and_held_validation_rechecks_state_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            real_parent = root / "real"
            real_parent.mkdir()
            parent_alias = root / "alias"
            parent_alias.symlink_to(real_parent, target_is_directory=True)
            real_state = real_parent / "state"
            alias_state = parent_alias / "state"

            with locking.process_lock(real_state) as held:
                with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_UNAVAILABLE):
                    with locking.process_lock(alias_state):
                        self.fail("parent alias acquired an independent lock")
                real_state.write_text("{}", encoding="utf-8")
                hardlink = root / "state-hardlink"
                os.link(real_state, hardlink)
                with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                    held.validate(alias_state)

    def test_held_canonical_state_survives_parent_symlink_retarget(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            alias = root / "current"
            alias.symlink_to(first, target_is_directory=True)

            with locking.process_lock(alias / "state.json") as held:
                alias.unlink()
                alias.symlink_to(second, target_is_directory=True)
                held.validate(held.state_path)
                self.assertEqual(held.state_path, first.resolve() / "state.json")
                self.assertNotEqual(locking.canonical_state_path(alias / "state.json"), held.state_path)

    def test_body_errors_are_not_reclassified_as_lock_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, self.assertRaisesRegex(OSError, "body failed"):
            with locking.process_lock(Path(tmpdir) / "state"):
                raise OSError("body failed")

    def test_state_security_rechecks_translate_permission_identity_and_mode_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            state.write_text("{}", encoding="utf-8")
            real_open = os.open

            with mock.patch.object(locking.os, "open", side_effect=PermissionError), mock.patch.object(
                locking.os, "chmod", side_effect=OSError
            ), self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                locking._secure_state_file(state)

            fd = real_open(state, os.O_RDONLY)
            forged = mock.Mock(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=os.geteuid(), st_dev=9, st_ino=9)
            with mock.patch.object(locking.os, "open", return_value=fd), mock.patch.object(
                locking.os, "fstat", return_value=forged
            ), self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                locking._secure_state_file(state)

            with mock.patch.object(locking.os, "fchmod", side_effect=OSError), self.assertRaisesRegex(
                locking.ProcessLockError, locking.PROCESS_LOCK_FAILED
            ):
                locking._secure_state_file(state)

    def test_lock_anchor_security_failures_close_descriptors_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            anchor = root / "anchor"
            anchor.write_text("", encoding="utf-8")
            anchor.chmod(0o600)
            real_open = os.open

            fd = real_open(anchor, os.O_RDWR)
            with mock.patch.object(locking, "_validate_open_anchor", return_value=anchor.stat()), mock.patch.object(
                locking.fcntl, "flock", side_effect=OSError(errno.EIO, "simulated")
            ), mock.patch.object(locking.os, "open", return_value=fd), self.assertRaisesRegex(
                locking.ProcessLockError, locking.PROCESS_LOCK_FAILED
            ):
                locking._lock_visible_anchor(anchor)
            with self.assertRaises(OSError):
                os.fstat(fd)

            bad = mock.Mock(st_mode=stat.S_IFREG | 0o644, st_uid=os.geteuid(), st_dev=1, st_ino=1)
            fd = real_open(anchor, os.O_RDONLY)
            try:
                with mock.patch.object(locking.os, "fstat", return_value=bad), self.assertRaisesRegex(
                    locking.ProcessLockError, locking.PROCESS_LOCK_FAILED
                ):
                    locking._validate_open_anchor(fd, anchor)
            finally:
                os.close(fd)

            guard = root / "guard"
            guard.write_text("", encoding="utf-8")
            directory_fd = real_open(root, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(locking.ProcessLockError, locking.PROCESS_LOCK_FAILED):
                    locking._acquire_anchor(root / "missing", guard, directory_fd)
            finally:
                os.close(directory_fd)


if __name__ == "__main__":
    unittest.main()
