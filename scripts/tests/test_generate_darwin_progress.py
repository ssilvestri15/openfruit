import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import generate_darwin_progress as driver


class DriverTests(unittest.TestCase):
    def test_seed_has_no_runtime_evidence(self):
        ledger = SCRIPTS.parent / "docs/DARWIN_CONTRACT_LEDGER.json"
        source = driver.read_json(ledger)
        seed = driver.seed_report(ledger)
        self.assertEqual(len(seed["contracts"]), len(source["contracts"]))
        self.assertEqual(seed["summary"]["verified_scopes"], 0)
        self.assertFalse(seed["summary"]["manifest_present"])
        self.assertEqual(seed["candidate_sha256"], "")
        for actual, declared in zip(seed["contracts"], source["contracts"]):
            self.assertEqual(actual["implementation"], declared["implementation"])
            self.assertFalse(actual["verified_scope"])
            self.assertEqual(actual["evidence"], [])

    def test_retained_provenance_rejects_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = "a" * 64
            paths = []
            for name, payload in (("inventory", {}), ("probe", {}),
                                  ("command", {"sha256": candidate}), ("ledger", {})):
                path = root / f"{name}.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                paths.append(path)
            artifact = root / "proof.txt"
            artifact.write_text("retained result", encoding="utf-8")
            report = {
                "candidate_sha256": candidate, "probe_sha256": driver.digest(paths[1]),
                "inputs": [{"path": str(path), "sha256": driver.digest(path)} for path in paths],
                "contracts": [{"evidence": [{"accepted": True, "artifact": "proof.txt",
                                               "sha256": driver.digest(artifact)}]}],
            }
            report_path = root / "native.json"
            driver.validate_native_inputs(report, report_path)
            artifact.write_text("replaced result", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "evidence artifact"):
                driver.validate_native_inputs(report, report_path)
            artifact.write_text("retained result", encoding="utf-8")
            paths[0].write_text('{"changed":true}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "input hash"):
                driver.validate_native_inputs(report, report_path)

    def test_candidate_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / f"{n}.json" for n in range(4)]
            for path in paths:
                path.write_text('{}', encoding="utf-8")
            report = {"inputs": [{"path": str(p), "sha256": driver.digest(p)} for p in paths],
                      "candidate_sha256": "b" * 64, "probe_sha256": driver.digest(paths[1]),
                      "contracts": []}
            with self.assertRaisesRegex(ValueError, "candidate identity"):
                driver.validate_native_inputs(report, root / "report.json")

    def test_seed_generates_complete_site_from_catalog(self):
        catalog_path = SCRIPTS.parent / "docs/DARWIN_CONTRACT_CATALOG.json"
        if not catalog_path.exists():
            self.skipTest("Catalog generation is not integrated yet")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            progress = driver.generate(catalog_path, output)
            for name in ("index.html", "progress.json", "progress.svg"):
                self.assertTrue((output / name).is_file(), name)
            published = driver.read_json(output / "progress.json")
            self.assertEqual(published, progress)
            self.assertEqual(len(published["contracts"]), len(driver.read_json(catalog_path)["contracts"]))
            self.assertTrue(all(not r["verified_scope"] for r in published["contracts"]))
            self.assertTrue(all(r["dispatch_registered"] is None for r in published["contracts"]))
            self.assertNotIn("C:/Users/", (output / "progress.json").read_text(encoding="utf-8"))

    def test_changed_source_ledger_refreshes_without_apple_changes(self):
        catalog = SCRIPTS.parent / "docs/DARWIN_CONTRACT_CATALOG.json"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = driver.read_json(SCRIPTS.parent / "docs/DARWIN_CONTRACT_LEDGER.json")
            ledger["contracts"][0]["scope"] += " changed scope"
            changed = root / "ledger.json"
            changed.write_text(json.dumps(ledger), encoding="utf-8")
            result = driver.generate(catalog, root / "site", ledger_path=changed)
            row = next(r for r in result["contracts"] if r.get("ledger_id") == ledger["contracts"][0]["id"])
            self.assertEqual(row["scope"], ledger["contracts"][0]["scope"])
            self.assertFalse(row["verified_scope"])
            original = driver.read_json(catalog)
            for item in result["catalogs"]:
                if item["id"] != "openfruit-reviewed-scopes":
                    source = next(c for c in original["catalogs"] if c["id"] == item["id"])
                    self.assertEqual(item["revision"], source["revision"])
                    self.assertEqual(item["denominator"], source["denominator"])


if __name__ == "__main__":
    unittest.main()
