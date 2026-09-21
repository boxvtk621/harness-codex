#!/usr/bin/env python3
"""Regression tests for source-side provenance validation."""

import csv
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("verify_provenance.py")
SPEC = importlib.util.spec_from_file_location("verify_provenance", SCRIPT)
PROVENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVENANCE)


class ProvenanceVerificationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "item.txt").write_bytes(b"destination")
        self.manifest = self.root / "source-manifest.csv"
        self.exclusions = (("excluded/path", "not part of the standalone repository"),)
        self.rows = [
            {
                "status": "adapted", "source_commit": PROVENANCE.SOURCE_COMMIT,
                "source_path": "source/item.txt", "destination_path": "item.txt",
                "source_sha256": hashlib.sha256(b"source").hexdigest(),
                "destination_sha256": hashlib.sha256(b"destination").hexdigest(),
                "rationale": "fixture",
            },
            {
                "status": "excluded", "source_commit": PROVENANCE.SOURCE_COMMIT,
                "source_path": "excluded/path", "destination_path": "",
                "source_sha256": "", "destination_sha256": "",
                "rationale": self.exclusions[0][1],
            },
        ]

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, rows):
        with self.manifest.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=PROVENANCE.FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def verify(self):
        with mock.patch.object(PROVENANCE, "ROOT", self.root), \
             mock.patch.object(PROVENANCE, "MANIFEST", self.manifest), \
             mock.patch.object(PROVENANCE, "EXCLUSIONS", self.exclusions), \
             mock.patch.object(PROVENANCE, "destination_map", return_value={"item.txt": "source/item.txt"}), \
             mock.patch.object(PROVENANCE, "git_bytes", return_value=b"source"):
            PROVENANCE.verify(Path("source"))

    def test_rejects_corrupt_source_hash(self):
        rows = [dict(row) for row in self.rows]
        rows[0]["source_sha256"] = "0" * 64
        self.write(rows)
        with self.assertRaisesRegex(SystemExit, "source digest mismatch"):
            self.verify()

    def test_rejects_missing_exclusion(self):
        self.write(self.rows[:1])
        with self.assertRaisesRegex(SystemExit, "missing exclusion"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
