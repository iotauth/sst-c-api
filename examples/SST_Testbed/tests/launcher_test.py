"""Validate launcher plans without starting clients or requesting sudo."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BUILD_DIRECTORY = Path(sys.argv[1])
LAUNCHER = Path(__file__).resolve().parents[1] / "clients_dos_attack" / "run_clients.sh"


class LauncherTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=BUILD_DIRECTORY)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.cwd = self.root / "clients_dos_attack"
        self.cwd.mkdir()
        shutil.copyfile(LAUNCHER, self.cwd / "run_clients.sh")
        (self.root / "build").mkdir()
        client = self.root / "build" / "client"
        client.write_text("#!/bin/sh\nexit 99\n")
        client.chmod(0o700)
        configs = self.root / "config_clones"
        configs.mkdir()
        for suffix in ("", "_udp"):
            (configs / f"client0{suffix}.config").touch()

    def plan(self, name, contents, *options):
        csv = self.root / name
        csv.write_text(contents)
        return subprocess.run(
            ["bash", "run_clients.sh", "1", str(csv), "--dry-run", *options],
            cwd=self.cwd, capture_output=True, text=True, timeout=5, check=False)

    def test_renamed_udp_scenario(self):
        result = self.plan("attack.csv", "0,hello,dosu,1,Server\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("client0_udp.config", result.stdout)
        self.assertIn("Validated 1 clients using UDP profile", result.stdout)

    def test_filename_does_not_choose_protocol(self):
        result = self.plan("udp.csv", "0,hello\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("client0.config", result.stdout)

    def test_explicit_udp_and_metrics(self):
        result = self.plan("basic.csv", "0,hello\n", "--protocol", "UDP", "-metrics")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("client0_udp.config", result.stdout)
        self.assertIn("'-metrics'", result.stdout)

    def test_reject_conflicting_protocols(self):
        cases = [
            ("0,hello,DOSU,1,Server\n", ["--protocol", "TCP"]),
            ("0,hello,DOSS,1,Server\n", ["--protocol", "UDP"]),
            ("0,hello,DOSU,1,Server\n0,hello,DOSS,1,Server\n", []),
        ]
        for contents, options in cases:
            with self.subTest(contents=contents, options=options):
                result = self.plan("mixed.csv", contents, *options)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Would launch", result.stdout)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
