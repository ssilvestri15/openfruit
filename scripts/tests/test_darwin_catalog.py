import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("darwin_catalog", ROOT / "scripts/darwin_catalog.py")
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)


class CatalogTests(unittest.TestCase):
    def test_syscall_slot_variants_and_reserved(self):
        rows, excluded = catalog.parse_syscalls("""
0 AUE_NULL ALL { int nosys(void); }
#if SOCKETS
27 AUE_NULL ALL { int recvmsg(int s); }
#else
27 AUE_NULL ALL { int nosys(void); }
#endif
28 AUE_NULL ALL { int enosys(void); }
29 AUE_NULL ALL { int foo(void); }
#ifdef OTHER
29 AUE_NULL ALL { int foo_alias(void); }
#endif
""")
        self.assertEqual(set(rows), {27, 29})
        self.assertEqual(excluded, [0, 28])
        self.assertEqual(len(rows[29]), 2)
        self.assertEqual(rows[27][0]["conditions"], ["if SOCKETS"])

    def test_mach_table_includes_table_only_and_aliases(self):
        table = """mach_trap_table[MACH_TRAP_TABLE_COUNT] = {
/* 0 */ MACH_TRAP(kern_invalid, 0, 0, NULL),
/* 58 */ MACH_TRAP(pfz_exit, 0, 0, NULL),
/* 61 */ MACH_TRAP(thread_switch, 3, 3, NULL),
};
/* 999 */ MACH_TRAP(fake, 0, 0, NULL)
"""
        rows, aliases, excluded = catalog.parse_traps(table, "kernel_trap(syscall_thread_switch,-61,3)")
        self.assertEqual(set(rows), {-58, -61})
        self.assertEqual(aliases[-61][0]["name"], "syscall_thread_switch")
        self.assertEqual(excluded, [0])
        with self.assertRaises(ValueError):
            catalog.parse_traps(table, "kernel_trap(other,-66,3)")

    def test_mig_macros_branches_and_comments(self):
        text = """subsystem
#if KERNEL_SERVER
KernelServer
#endif
thing 400;
/* routine fake(); */
routine PREFIX(KERNEL_SERVER_SUFFIX_SANDBOX(do_it)) (target: port_t);
routine
#if KERNEL_SERVER
other_from_user(
port: port_t;
#else
other(
target: port_t;
#endif
out value: int);
routine MIG_SERVER_SUFFIX(resume2)(target: port_t);
"""
        subsystem, base, rows = catalog.parse_mig(text)
        self.assertEqual((subsystem, base), ("thing", 400))
        self.assertEqual(set(rows), {"do_it", "other_from_user", "other", "resume2"})
        with self.assertRaises(ValueError):
            catalog.parse_mig("subsystem foo 1;\nroutine UNKNOWN(name)(target: port_t);")

    def test_conditions_fail_closed(self):
        with self.assertRaises(ValueError):
            list(catalog.conditioned_lines("#if X\nx"))
        with self.assertRaises(ValueError):
            list(catalog.conditioned_lines("#endif"))

    def test_committed_catalog_counts_and_ledger_exact_mapping(self):
        result = json.loads((ROOT / "docs/DARWIN_CONTRACT_CATALOG.json").read_text(encoding="utf-8"))
        catalog.validate_catalog(result)
        expected = {row["id"] for row in json.loads((ROOT / "docs/DARWIN_CONTRACT_LEDGER.json").read_text())["contracts"]}
        scoped = [row for row in result["contracts"] if row["kind"] == "scoped"]
        self.assertEqual({row["ledger_id"] for row in scoped}, expected)
        self.assertFalse(any("ledger_id" in row for row in result["contracts"] if row["kind"] != "scoped"))
        for item in result["catalogs"]:
            for source in item["sources"]:
                if "url" in source:
                    path = source["url"].split(catalog.XNU_REVISION + "/", 1)[1]
                    self.assertEqual(source["sha256"], catalog.PINNED_SHA256[path])
        mutated = copy.deepcopy(result)
        mutated["catalogs"][0]["denominator"] += 1
        with self.assertRaises(ValueError):
            catalog.validate_catalog(mutated)
        mutated = copy.deepcopy(result)
        mutated["contracts"].append(mutated["contracts"][0])
        with self.assertRaises(ValueError):
            catalog.validate_catalog(mutated)

    def test_wrong_source_hash_rejected(self):
        with self.assertRaisesRegex(ValueError, "source hash"):
            catalog.build_catalog({path: b"modified" for path in catalog.PINNED_SHA256}, {"contracts": []})

    def test_offline_ledger_refresh_preserves_apple_catalogs(self):
        original = json.loads((ROOT / "docs/DARWIN_CONTRACT_CATALOG.json").read_text(encoding="utf-8"))
        before = copy.deepcopy(original)
        ledger = {"contracts": [{"id": "new.scope", "family": "swift", "scope": "Reviewed narrow scope"}]}
        refreshed = catalog.refresh_ledger(original, ledger)
        self.assertEqual(original, before)
        self.assertEqual(refreshed["catalogs"][:-1], original["catalogs"][:-1])
        self.assertEqual([row for row in refreshed["contracts"] if row["kind"] != "scoped"],
                         [row for row in original["contracts"] if row["kind"] != "scoped"])
        self.assertEqual(refreshed["catalogs"][-1]["denominator"], 1)
        self.assertEqual(refreshed["contracts"][-1]["ledger_id"], "new.scope")
        changed = copy.deepcopy(ledger)
        changed["contracts"][0]["scope"] = "Changed reviewed scope"
        second = catalog.refresh_ledger(refreshed, changed)
        self.assertNotEqual(refreshed["catalogs"][-1]["revision"], second["catalogs"][-1]["revision"])
        self.assertEqual(second["contracts"][-1]["scope"], "Changed reviewed scope")


if __name__ == "__main__":
    unittest.main()
