"""Exercise version editing, idempotency, and trust boundaries without network access."""
import contextlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
MANIFEST = '[package]\nname = "zdwire"\nversion = "1.2.3"\nrust-version = "1.74"\n\n[dependencies]\n'
LOCK = 'version = 3\n\n[[package]]\nname = "zdwire"\nversion = "1.2.3"\n'
EVENT = {"repository": {"default_branch": "main", "full_name": "owner/zdwire"}}


@contextlib.contextmanager
def repository():
    with tempfile.TemporaryDirectory() as temp:
        previous = Path.cwd()
        folder = Path(temp)
        remote = folder / "remote.git"
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
        work = folder / "work"
        work.mkdir()
        os.chdir(work)
        try:
            release.git("init", "-b", "main")
            release.git("config", "user.name", "release-tests")
            release.git("config", "user.email", "tests@example.invalid")
            Path("Cargo.toml").write_text(MANIFEST)
            for filename in release.LOCKS:
                path = Path(filename)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(LOCK)
            release.git("add", ".")
            release.git("commit", "-m", "initial")
            release.git("remote", "add", "origin", str(remote))
            release.git("push", "origin", "main")
            yield
        finally:
            os.chdir(previous)


class ReleaseTests(unittest.TestCase):
    def test_version_bumps(self):
        for bump, expected in (("patch", "1.2.4"), ("minor", "1.3.0"),
                               ("major", "2.0.0"), ("current", "1.2.3")):
            self.assertEqual(release.bump_version("1.2.3", bump), expected)
        for value in ("v1.2.3", "01.2.3", "1.2.3-beta", "1.2.3\n"):
            with self.assertRaises(ValueError):
                release.bump_version(value, "patch")

    def test_manifest_edit_preserves_unrelated_versions(self):
        text = MANIFEST + 'example = { version = "1.2.3" }\n'
        changed = release.replace_package_version(text, "2.0.0")
        self.assertEqual(release.package_version(changed), "2.0.0")
        self.assertIn('example = { version = "1.2.3" }', changed)
        self.assertTrue(release.replace_lock_version(LOCK, "1.2.3", "2.0.0").startswith("version = 3"))
        with self.assertRaises(ValueError):
            release.replace_lock_version(LOCK, "0.0.0", "2.0.0")

    def test_dispatch_bump_and_rerun_are_idempotent(self):
        with repository():
            first = release.prepare("workflow_dispatch", EVENT, "refs/heads/main", "minor", "123")
            self.assertEqual(first["version"], "1.3.0")
            for filename in release.LOCKS:
                self.assertIn('version = "1.3.0"', Path(filename).read_text())
            second = release.prepare("workflow_dispatch", EVENT, "refs/heads/main", "minor", "123")
            self.assertEqual(second, first)
            self.assertEqual(release.git("rev-list", "--count", "HEAD"), "2")

    def test_nondefault_dispatch_is_rejected(self):
        with repository(), self.assertRaisesRegex(ValueError, "default branch"):
            release.prepare("workflow_dispatch", EVENT, "refs/heads/feature", "patch", "123")

    def test_release_tag_must_be_on_default_history_and_match_version(self):
        with repository():
            release.git("tag", "v1.2.3")
            release.git("push", "origin", "v1.2.3")
            event = dict(EVENT, action="published", release={
                "tag_name": "v1.2.3", "draft": False, "prerelease": False})
            result = release.prepare("release", event, "refs/tags/v1.2.3", "current", "123")
            self.assertEqual(result["sha"], release.git("rev-parse", "HEAD"))
            release.git("checkout", "-b", "untrusted")
            Path("Cargo.toml").write_text(MANIFEST.replace("1.2.3", "9.0.0"))
            release.git("add", "Cargo.toml")
            release.git("commit", "-m", "off default")
            release.git("tag", "v9.0.0")
            release.git("push", "origin", "v9.0.0")
            event["release"]["tag_name"] = "v9.0.0"
            with self.assertRaisesRegex(ValueError, "outside"):
                release.prepare("release", event, "refs/tags/v9.0.0", "current", "123")

    def test_mismatched_tag_is_rejected(self):
        with repository():
            release.git("tag", "v1.2.4")
            release.git("push", "origin", "v1.2.4")
            event = dict(EVENT, action="published", release={
                "tag_name": "v1.2.4", "draft": False, "prerelease": False})
            with self.assertRaisesRegex(ValueError, "Cargo.toml"):
                release.prepare("release", event, "refs/tags/v1.2.4", "current", "123")


if __name__ == "__main__":
    unittest.main()
