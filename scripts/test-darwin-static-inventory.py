"""Decoder boundary tests and independent LLVM comparison on retained inputs."""
import importlib.util
import json
import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("inventory", pathlib.Path(__file__).with_name("darwin-static-inventory.py"))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class DecoderTests(unittest.TestCase):
    def test_register_width_and_partial_constants(self):
        self.assertEqual(inventory.selector([0x92800370, 0xd4001001], 1), 0xffffffffffffffe4)
        self.assertEqual(inventory.selector([0x12800370, 0xd4001001], 1), 0xffffffe4)
        self.assertEqual(inventory.selector([0xd2800010, 0xf2bfffd0, 0xd4001001], 2), 0xfffe0000)
        self.assertIsNone(inventory.selector([0xf2bfffd0, 0xd4001001], 1))
        self.assertIsNone(inventory.selector([0x92800370, 0xd503201f, 0xd4001001], 2))
        self.assertIsNone(inventory.selector([0x92800371, 0xd4001001], 1))
        self.assertIsNone(inventory.selector([0x12c00010, 0xd4001001], 1))

    def test_direct_cfg_keeps_indirect_and_budget_unknown(self):
        # B skips a dead SVC; BL visits callee and continuation; RET stops.
        words = [0x14000002, 0xd4001001, 0x94000003, 0xd63f0200,
                 0xd65f03c0, 0xd4001001, 0xd65f03c0]
        report = inventory.arm64_reachability([(0x1000, words)], [0x1000])
        self.assertEqual(report["svc_pcs"], [0x1014])
        self.assertEqual(report["indirect_transfer_pcs"], [0x100c])
        self.assertFalse(report["complete"])
        self.assertFalse(report["budget_exhausted"])
        limited = inventory.arm64_reachability([(0x1000, words)], [0x1000], limit=1)
        self.assertTrue(limited["budget_exhausted"])
        # TBZ has two paths; register jump and authenticated return remain opaque.
        report = inventory.arm64_reachability([(0, [0x36000040, 0xd61f0200, 0xd65f0bff])], [0])
        self.assertEqual(report["indirect_transfer_pcs"], [4, 8])
        self.assertEqual(inventory.arm64_reachability([(0, words)], [128])["outside_code_targets"], [128])
        cycle = inventory.arm64_reachability([(0, [0xd503201f, 0xd4001001, 0xb4ffffc0, 0xd65f03c0])], [0])
        self.assertEqual(cycle["svc_pcs"], [4])
        self.assertEqual(cycle["visited_instructions"], 4)
        self.assertFalse(cycle["budget_exhausted"])

    def test_malformed_trie_and_leb(self):
        self.assertRaises(ValueError, inventory.uleb, b"\x80" * 11, 0)
        self.assertRaises(ValueError, inventory.exports, b"\0\1x\0\0")
        self.assertEqual(inventory.exports(b"\0\1x\0\5\2\0\1\0"), [{"symbol": "x", "flags": 0, "value": 1}])

    def test_classic_and_lazy_bind_declarations(self):
        raw = b"\x11\x40_read\0\x90\0"
        self.assertEqual(inventory.bind_symbols(raw)[0]["symbol"], "_read")
        self.assertEqual(len(inventory.bind_symbols(raw + raw, lazy=True)), 2)
        self.assertRaises(ValueError, inventory.bind_symbols, b"\xd0")
        self.assertRaises(ValueError, inventory.bind_symbols, b"\x90")

    def test_xnu_alternatives_not_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root)
            (root / "bsd_kern_syscalls.master").write_text("#if SOCKETS\n27 AUE_NULL ALL { int recvmsg(void); }\n#else\n27 AUE_NULL ALL { int nosys(void); }\n#endif\n")
            (root / "osfmk_mach_syscall_sw.h").write_text("kernel_trap(task_self_trap,-28,0)\n")
            (root / "osfmk_mach_arm_traps.h").write_text("#define MACH_ARM_TRAP_ABSTIME -3\n")
            rows = inventory.catalog(root)["definitions"]
            self.assertEqual([r["name"] for r in rows], ["recvmsg", "nosys", "task_self_trap", "MACH_ARM_TRAP_ABSTIME"])
            self.assertNotEqual(rows[0]["conditions"], rows[1]["conditions"])
            available = inventory.catalog(root, {"selector_ids": [27, -28]})["definitions"]
            self.assertTrue(available[0]["handler_available"])
            self.assertTrue(available[2]["handler_available"])
            self.assertFalse(available[3]["handler_available"])


class ReportInputTests(unittest.TestCase):
    def write_reports(self, root, prefix="", plugin=False):
        # Owned minimal ARM64 input exercises the real scanner and full source hash.
        source = root / f"{prefix}guest"
        raw = struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0)
        source.write_bytes(raw)
        paths = {
            "closure": root / f"{prefix}xcode-original-native-startup-sections-closure.json",
            "layout": root / f"{prefix}apple-macos-systemos-installed-dyld-cache-layout.json",
            "cache_images": root / f"{prefix}apple-macos-systemos-installed-dyld-cache-images.json",
        }
        values = {
            "closure": {"images": [{"virtual_path": f"/{prefix}guest", "source_kind": "original-file",
                                    "source": str(source), "sha256": inventory.sha(raw), "slice_offset": 0,
                                    "dependencies": [], "export_trie": {"symbol_count": 0},
                                    "chained_fixups": {}, "sections": [], "file_type": 2}], "edges": []},
            "layout": {"mappings": []},
            "cache_images": {"images": [], "dyld": {}},
        }
        if plugin:
            values["closure"]["images"].append({**values["closure"]["images"][0],
                                                "virtual_path": f"/{prefix}plugin.dylib", "file_type": 6})
        for name, path in paths.items():
            path.write_text(json.dumps(values[name]) + "\n", encoding="utf-8")
        return paths

    def check_provenance(self, result, paths):
        self.assertEqual(result["input_reports"], {
            name: {"path": str(path.resolve()), "sha256": inventory.sha(path.read_bytes())}
            for name, path in paths.items()})
        self.assertEqual(result["native_closure_sha256"], result["input_reports"]["closure"]["sha256"])
        self.assertEqual(result["summary"]["sources_fully_hashed"], 1)

    def test_default_reports_remain_backwards_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            paths = self.write_reports(root)
            result = inventory.inventory(root, {"definitions": []})
            self.check_provenance(result, paths)
            self.assertEqual(result["target_roots"], ["/guest"])
            self.assertEqual(result["explicit_target_roots"], [])

    def test_cli_routes_explicit_reports_without_renaming_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            evidence = root / "old-evidence"
            evidence.mkdir()
            defaults = self.write_reports(evidence)
            selected = self.write_reports(root, "selected-", plugin=True)
            reference = root / "reference"
            reference.mkdir()
            for name in inventory.REFERENCES:
                (reference / name.replace("/", "_")).write_text("", encoding="utf-8")
            output = root / "output"
            result = subprocess.run([
                sys.executable, str(pathlib.Path(inventory.__file__).resolve()),
                "--evidence-root", str(evidence), "--reference-root", str(reference),
                "--output-root", str(output), "--closure-report", str(selected["closure"]),
                "--layout-report", str(selected["layout"]),
                "--cache-images-report", str(selected["cache_images"]),
                "--target-root", "/selected-plugin.dylib", "--target-root", "/selected-guest",
                "--target-root", "/selected-plugin.dylib",
            ], capture_output=True, text=True, check=True)
            data = json.loads((output / "darwin-static-inventory.json").read_text())
            self.check_provenance(data, selected)
            self.assertEqual(data["target_roots"], ["/selected-guest", "/selected-plugin.dylib"])
            self.assertEqual(data["explicit_target_roots"], ["/selected-plugin.dylib", "/selected-guest"])
            self.assertEqual(data["explicit_target_roots_scope"], "diagnostic-selection-not-observed-execution")
            self.assertEqual(data["dependency_edges"], [])
            self.assertEqual(json.loads(result.stdout), data["summary"])
            for path in defaults.values():
                self.assertTrue(path.is_file())
            # Explicit invalid paths must fail rather than silently select defaults.
            with self.assertRaises(FileNotFoundError):
                inventory.inventory(evidence, {"definitions": []}, closure_report=root / "missing.json")

    def test_single_override_preserves_other_default_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            defaults = self.write_reports(root)
            selected = self.write_reports(root, "new-")
            result = inventory.inventory(root, {"definitions": []}, closure_report=selected["closure"])
            self.check_provenance(result, {**defaults, "closure": selected["closure"]})
            self.assertEqual(result["target_roots"], ["/new-guest"])

    def test_unknown_explicit_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_reports(root)
            with self.assertRaisesRegex(ValueError, "Explicit target roots absent from native closure"):
                inventory.inventory(root, {"definitions": []}, target_roots=["/guest", "/not-present"])


def verify_original(root, output=None):
    output = output or root / "static-inventory"
    data = json.loads((output / "darwin-static-inventory.json").read_text())
    graph = json.loads((root / "xcode-original-native-startup-sections-closure.json").read_text())
    checked = []
    for image in graph["images"]:
        if image["source_kind"] != "original-file":
            continue
        result = subprocess.run(["llvm-objdump", "--macho", "--syms", "--bind", "--lazy-bind", image["source"]], capture_output=True, text=True, encoding="utf-8", check=True)
        expected = {m[1] for line in result.stdout.splitlines() if (m := re.search(r"\*UND\*\s+(\S+)", line))}
        actual = {i["symbol"] for i in data["imports"] if i["image"] == image["virtual_path"] and i["mechanism"] == "LC_SYMTAB_UNDEF"}
        if actual != expected:
            raise AssertionError(f"LLVM/raw undefined symbols disagree: {image['virtual_path']}")
        checked.append({"image": image["virtual_path"], "undefined_symbols": len(expected)})
    observation = json.loads((root / "xcode-original-task-self-independent-verification.json").read_text())
    calls = observation["bootstrap"]["clock_call_prefix"] + observation["bootstrap"]["mach_task"]["call_prefix"]
    calls.append({"pc": observation["bootstrap"]["last_instruction_pc"], "selector": observation["bootstrap"]["syscall_selector"]})
    for call in calls:
        site = next(s for s in data["svc_sites"] if s["pc"] == call["pc"])
        if site["selector_raw"] != call["selector"] or site["svc_immediate"] != 128:
            raise AssertionError("Static selector disagrees with original runtime trace")
    manifest = data.get("handler_manifest")
    registry_checked = False
    if manifest:
        observation_path = pathlib.Path(manifest.get("observation_path", root / "xcode-original-native-port-context-observation.json"))
        raw_observation = observation_path.read_bytes()
        if inventory.sha(raw_observation) != manifest["observation_sha256"]:
            raise AssertionError("Static availability observation hash mismatch")
        observation = json.loads(raw_observation)
        if manifest["native_cli_sha256"] != observation["native_cli_sha256"]:
            raise AssertionError("Static availability candidate hash mismatch")
        if manifest["handlers"] != observation["result"]["bootstrap"]["implemented_trap_handlers"]:
            raise AssertionError("Static/native handler registries disagree")
        for call in observation["result"]["bootstrap"]["mach_ports"]["call_prefix"]:
            site = next(s for s in data["svc_sites"] if s["pc"] == call["pc"])
            if site["selector_raw"] != call["selector"] or not site["handler_available"]:
                raise AssertionError("Observed implemented port service missing from static inventory")
        registry_checked = True
    report = {"llvm_original_images_compared": checked, "raw_native_export_counts_agree_images": len(data["images"]), "original_observed_svc_selectors_agree": len(calls), "sources_fully_rehashed": len(data["verified_sources"]), "native_registry_candidate_hash_agrees": registry_checked, "all_possible_calls_proven": False}
    (output / "independent-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-original":
        verify_original(pathlib.Path(sys.argv[2]))
    else:
        unittest.main()
