"""Read-only diagnosis of retained native Mach-O closure; never executes a guest.

Uses native-produced closure/layout metadata, verifies raw headers, and reads
original bytes. No SDK extraction, binary rewriting, runtime or fake services.
"""
import argparse
import collections
import csv
import hashlib
import json
import pathlib
import re
import struct

XNU_COMMIT = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea"
REFERENCES = ("bsd/kern/syscalls.master", "osfmk/mach/syscall_sw.h", "osfmk/mach/arm/traps.h")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def catalog(root, handler_manifest=None):
    available = set(handler_manifest["selector_ids"]) if handler_manifest else set()
    rows, provenance = [], []
    for source in REFERENCES:
        raw = (root / source.replace("/", "_")).read_bytes()
        provenance.append({"url": f"https://raw.githubusercontent.com/apple-oss-distributions/xnu/{XNU_COMMIT}/{source}", "sha256": sha(raw)})
        conditions = []
        for line_number, line in enumerate(raw.decode().splitlines(), 1):
            stripped = line.strip()
            if re.match(r"#\s*(if|ifdef|ifndef)\b", stripped):
                conditions.append(stripped)
            elif re.match(r"#\s*(else|elif)\b", stripped) and conditions:
                conditions[-1] += " -> " + stripped
            elif re.match(r"#\s*endif\b", stripped) and conditions:
                conditions.pop()
            matches = []
            if source.endswith("syscalls.master"):
                m = re.match(r"\s*(\d+)\s+\w+\s+\w+\s+\{\s*(.*?)\}", line)
                if m:
                    name = re.search(r"([A-Za-z_]\w*)\s*\(", m[2])
                    if not name:
                        raise ValueError(f"Unparsed syscall prototype {line_number}")
                    matches = [(int(m[1]), name[1], "bsd")]
            elif source.endswith("syscall_sw.h"):
                m = re.match(r"\s*kernel_trap\(\s*(\w+)\s*,\s*(-\d+)\s*,\s*(\d+)\s*\)", line)
                if m:
                    matches = [(int(m[2]), m[1], "mach")]
            else:
                m = re.match(r"#define\s+(MACH_ARM_TRAP_\w+)\s+(-\d+)", line)
                if m:
                    matches = [(int(m[2]), m[1], "arm-special")]
            for number, name, domain in matches:
                rows.append({"id": number, "name": name, "domain": domain, "source": source,
                             "line": line_number, "conditions": list(conditions),
                             "reserved": name in ("nosys", "enosys"),
                             "handler_available": number in available})
    return {"reference_commit": XNU_COMMIT, "matches_installed_kernel_version": False,
            "conditional_alternatives_preserved": True, "sources": provenance, "definitions": rows,
            "handler_manifest": handler_manifest, "availability_scope": "bounded-bootstrap-only"}


def uleb(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise ValueError("Truncated LEB128")
        b = data[pos]
        pos += 1
        value |= (b & 127) << shift
        if not b & 128:
            return value, pos
    raise ValueError("Oversized LEB128")


def cstring(data, pos):
    end = data.index(0, pos)
    return data[pos:end].decode("utf-8", "strict"), end + 1


def exports(data):
    result = []
    def visit(pos, prefix, ancestry):
        if pos in ancestry or len(ancestry) > 512 or len(result) > 1000000:
            raise ValueError("Invalid export trie graph")
        terminal_size, start = uleb(data, pos)
        end = start + terminal_size
        if end >= len(data):
            raise ValueError("Export trie bounds")
        if terminal_size:
            flags, at = uleb(data, start)
            row = {"symbol": prefix, "flags": flags}
            if flags & 8:
                row["library_ordinal"], at = uleb(data, at)
                row["imported_name"], at = cstring(data, at)
            else:
                row["value"], at = uleb(data, at)
                if flags & 16:
                    row["resolver"], at = uleb(data, at)
            if at > end:
                raise ValueError("Export terminal bounds")
            result.append(row)
        count = data[end]
        at = end + 1
        for _ in range(count):
            suffix, at = cstring(data, at)
            child, at = uleb(data, at)
            visit(child, prefix + suffix, ancestry | {pos})
    if data:
        visit(0, "", set())
    return result


def bind_symbols(data, lazy=False):
    """Collect declarations in classic bind streams; no relocation application."""
    rows, at, ordinal, symbol, flags = [], 0, 0, None, 0
    while at < len(data):
        op = data[at] & 0xf0
        imm = data[at] & 15
        at += 1
        if op == 0:
            if not lazy:
                break
            symbol = None
            ordinal = flags = 0
        elif op == 0x10:
            ordinal = imm
        elif op == 0x20:
            ordinal, at = uleb(data, at)
        elif op == 0x30:
            ordinal = imm - 16 if imm else 0
        elif op == 0x40:
            flags = imm
            symbol, at = cstring(data, at)
        elif op == 0x50:
            pass
        elif op in (0x60, 0x70, 0x80):
            _, at = uleb(data, at)
        elif op in (0x90, 0xa0, 0xb0, 0xc0):
            if symbol is None:
                raise ValueError("Bind without symbol")
            count = 1
            if op == 0xa0:
                _, at = uleb(data, at)
            elif op == 0xc0:
                count, at = uleb(data, at)
                _, at = uleb(data, at)
            rows.append({"symbol": symbol, "library_ordinal": ordinal, "weak": bool(flags & 1), "bind_sites": count})
        else:
            raise ValueError(f"Unsupported classic bind opcode 0x{op:x}")
    return rows


def selector(words, svc_index):
    # Strict contiguous MOVZ/MOVN/MOVK chain. No guessed propagation over other
    # instructions, control flow, register copies or memory loads.
    chain = []
    for i in range(svc_index - 1, max(-1, svc_index - 9), -1):
        word = words[i]
        if word & 31 != 16 or word & 0x1f800000 != 0x12800000:
            return None
        width = 64 if word >> 31 else 32
        op = (word >> 29) & 3
        shift = ((word >> 21) & 3) * 16
        if op == 1 or shift >= width:
            return None
        chain.append((op, width, shift, (word >> 5) & 65535))
        if op in (0, 2):
            value = 0
            for opcode, bits, offset, immediate in reversed(chain):
                mask = (1 << bits) - 1
                if opcode == 0:
                    value = ~(immediate << offset) & mask
                elif opcode == 2:
                    value = immediate << offset
                else:
                    value = (value & ~(65535 << offset) | immediate << offset) & mask
            return value
    return None


class Originals:
    def __init__(self, layout):
        self.mappings = layout["mappings"]
        self.files = {}
        self.source_hashes = {m["source_path"]: m["source_file_sha256"] for m in self.mappings}

    def read(self, path, offset, size):
        if size < 0 or offset < 0 or size > 256 * 1024 * 1024:
            raise ValueError("Invalid read range")
        if path not in self.files:
            self.files[path] = open(path, "rb")
        f = self.files[path]
        f.seek(offset)
        raw = f.read(size)
        if len(raw) != size:
            raise ValueError("Short original read")
        return raw

    def vm(self, address, size):
        pieces = []
        while size:
            mapping = next((m for m in self.mappings if m["address"] <= address < m["address"] + m["size"]), None)
            if mapping is None:
                raise ValueError(f"Unmapped original VM 0x{address:x}")
            take = min(size, mapping["address"] + mapping["size"] - address)
            pieces.append(self.read(mapping["source_path"], mapping["file_offset"] + address - mapping["address"], take))
            address += take
            size -= take
        return b"".join(pieces)

    def verify(self):
        result = []
        for path, f in self.files.items():
            expected = self.source_hashes[path]
            f.seek(0)
            actual = hashlib.file_digest(f, "sha256").hexdigest()
            if expected != actual:
                raise ValueError(f"Original source hash mismatch: {path}")
            result.append({"path": path, "sha256": actual})
        return result


def arm64_reachability(sections, roots, limit=200000):
    """Bounded direct-edge skeleton, never a proof of execution or dead code.

    sections contain original aligned instruction words, not reconstructed code.
    Unknown indirect/authenticated transfers terminate a path explicitly.
    """
    def word_at(pc):
        for base, words in sections:
            if pc >= base and (pc - base) % 4 == 0 and (pc - base) // 4 < len(words):
                return words[(pc - base) // 4]
        return None
    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value
    pending, visited, svc, indirect, outside = list(roots), set(), set(), set(), set()
    while pending and len(visited) < limit:
        pc = pending.pop()
        if pc in visited:
            continue
        word = word_at(pc)
        if word is None:
            outside.add(pc)
            continue
        visited.add(pc)
        if word & 0xffe0001f == 0xd4000001:
            svc.add(pc)
        if word & 0x7c000000 == 0x14000000:  # B / BL
            pending.append(pc + 4 * signed(word & 0x3ffffff, 26))
            if word & 0x80000000:
                pending.append(pc + 4)
        elif word & 0xff000000 == 0x54000000 or word & 0x7e000000 == 0x34000000:
            pending.extend((pc + 4, pc + 4 * signed((word >> 5) & 0x7ffff, 19)))
        elif word & 0x7e000000 == 0x36000000:  # TBZ / TBNZ
            pending.extend((pc + 4, pc + 4 * signed((word >> 5) & 0x3fff, 14)))
        elif word & 0xfffffc1f == 0xd65f0000:  # RET
            pass
        elif word & 0xfe000000 == 0xd6000000:  # register/PAC branch family
            indirect.add(pc)
            if word & 0xfffffc1f == 0xd63f0000:  # BLR can return
                pending.append(pc + 4)
        elif word & 0xff000000 == 0xd4000000 and word & 0xffe0001f != 0xd4000001:
            pass  # other exceptions do not imply successful continuation
        else:
            pending.append(pc + 4)
    return {"root_count": len(roots), "visited_instructions": len(visited),
            "svc_pcs": sorted(svc), "indirect_transfer_pcs": sorted(indirect),
            "outside_code_targets": sorted(outside), "budget_exhausted": bool(pending),
            "complete": False, "scope": "bounded-direct-edge-candidates"}


def inventory(root, reference, closure_report=None, layout_report=None, cache_images_report=None, target_roots=None):
    manifest = reference.get("handler_manifest")
    available = set(manifest["selector_ids"]) if manifest else set()
    report_paths = {
        "closure": pathlib.Path(closure_report) if closure_report is not None else root / "xcode-original-native-startup-sections-closure.json",
        "layout": pathlib.Path(layout_report) if layout_report is not None else root / "apple-macos-systemos-installed-dyld-cache-layout.json",
        "cache_images": pathlib.Path(cache_images_report) if cache_images_report is not None else root / "apple-macos-systemos-installed-dyld-cache-images.json",
    }
    report_bytes = {name: path.read_bytes() for name, path in report_paths.items()}
    input_reports = {name: {"path": str(path.resolve()), "sha256": sha(report_bytes[name])}
                     for name, path in report_paths.items()}
    graph = json.loads(report_bytes["closure"])
    layout = json.loads(report_bytes["layout"])
    cache = json.loads(report_bytes["cache_images"])
    explicit_target_roots = list(dict.fromkeys(target_roots or []))
    graph_paths = {image["virtual_path"] for image in graph["images"]}
    unknown_roots = [path for path in explicit_target_roots if path not in graph_paths]
    if unknown_roots:
        raise ValueError(f"Explicit target roots absent from native closure: {unknown_roots!r}")
    selected_roots = list(dict.fromkeys(
        [image["virtual_path"] for image in graph["images"] if image["file_type"] == 2]
        + explicit_target_roots))
    cache_images = {i["path"]: i for i in cache["images"]}
    cache_images["/usr/lib/dyld"] = cache["dyld"]
    originals = Originals(layout)
    definitions = collections.defaultdict(list)
    for d in reference["definitions"]:
        definitions[d["id"]].append(d)
    images, svc_sites, imports = [], [], []
    for image in graph["images"]:
        path = image["virtual_path"]
        is_cache = image["source_kind"] == "original-dyld-cache-vm"
        if is_cache:
            header_address = cache_images[path]["address"]
            raw_header = originals.vm(header_address, 32)
            read = lambda off, size: originals.vm(header_address + off, size)
        else:
            source = image["source"]
            originals.source_hashes[source] = image["sha256"]
            base = image["slice_offset"]
            read = lambda off, size: originals.read(source, base + off, size)
            raw_header = read(0, 32)
        magic, cpu, _, _, ncmds, cmdbytes, _, _ = struct.unpack("<8I", raw_header)
        if magic != 0xfeedfacf or cpu != 0x100000c:
            raise ValueError("Expected original thin ARM64 Mach-O")
        header = read(0, 32 + cmdbytes)
        if is_cache and sha(header) != image["sha256"]:
            raise ValueError("Native/raw cache header hash disagreement")
        commands, segments, at = [], [], 32
        for _ in range(ncmds):
            kind, size = struct.unpack_from("<II", header, at)
            if size < 8 or at + size > len(header):
                raise ValueError("Load command bounds")
            data = header[at:at + size]
            commands.append((kind, data))
            if kind == 25:
                name = data[8:24].split(b"\0")[0].decode()
                address, vmsize, fileoff, filesize = struct.unpack_from("<4Q", data, 24)
                segments.append((name, address, vmsize, fileoff, filesize))
            at += size
        if at != len(header):
            raise ValueError("Load command size disagreement")
        def linkedit(offset, size):
            if not is_cache:
                return read(offset, size)
            s = next((s for s in segments if s[0] == "__LINKEDIT" and s[3] <= offset and offset + size <= s[3] + s[4]), None)
            if s is None:
                raise ValueError("LINKEDIT file-to-VM translation unavailable")
            return originals.vm(s[1] + offset - s[3], size)
        row = {"image": path, "source_kind": image["source_kind"], "dependencies": image["dependencies"], "sha256": image["sha256"],
               "coverage_gaps": [], "export_count": 0, "undefined_count": 0, "svc_sites": 0}
        export_rows = []
        for kind, data in commands:
            if kind == 2:
                symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", data, 8)
                # Shared caches use a global string table, sometimes >1GiB.
                # Read only needed strings instead of allocating that table.
                strings = linkedit(stroff, strsize) if strsize <= 16 * 1024 * 1024 else None
                symbols = linkedit(symoff, nsyms * 16) if nsyms else b""
                for i in range(nsyms):
                    index, typ, sect, desc, value = struct.unpack_from("<IBBHQ", symbols, i * 16)
                    if not typ & 0xe0 and typ & 0xe == 0 and index:
                        if index >= strsize:
                            raise ValueError("Symbol string index bounds")
                        if strings is not None:
                            symbol, _ = cstring(strings, index)
                        else:
                            text = bytearray()
                            cursor = index
                            while cursor < strsize and len(text) < 65536:
                                part = linkedit(stroff + cursor, min(256, strsize - cursor))
                                text.extend(part.split(b"\0", 1)[0])
                                if 0 in part:
                                    break
                                cursor += len(part)
                            else:
                                raise ValueError("Unterminated symbol string")
                            symbol = text.decode("utf-8", "strict")
                        imports.append({"image": path, "symbol": symbol, "mechanism": "LC_SYMTAB_UNDEF", "library_ordinal_raw": desc >> 8, "weak": bool(desc & 0x40), "common": value != 0})
                        row["undefined_count"] += 1
            elif kind in (0x22, 0x80000022):
                fields = struct.unpack_from("<10I", data, 8)
                for offset_index, mechanism in ((2, "classic_bind"), (4, "weak_bind"), (6, "lazy_bind")):
                    off, size = fields[offset_index:offset_index + 2]
                    if size:
                        try:
                            for b in bind_symbols(linkedit(off, size), mechanism == "lazy_bind"):
                                imports.append({"image": path, "mechanism": mechanism, **b})
                        except ValueError as e:
                            row["coverage_gaps"].append(str(e))
                if fields[9]:
                    export_rows = exports(linkedit(fields[8], fields[9]))
            elif kind == 0x80000033:
                off, size = struct.unpack_from("<II", data, 8)
                export_rows = exports(linkedit(off, size))
        row["export_count"] = len(export_rows)
        if row["export_count"] != image["export_trie"]["symbol_count"]:
            raise ValueError("Raw/native export count disagreement")
        row["exports"] = export_rows
        for b in image["chained_fixups"].get("imports", []):
            imports.append({"image": path, "mechanism": "native_original_chained_import", **b})
        if is_cache:
            row["coverage_gaps"].append("Shared-cache optimization may erase original bind/import declarations; optimized pointer edges not inventoried by this diagnostic.")
        code_sections = []
        for section in image["sections"]:
            if not section["flags"] & 0x80000400 or section["zero_fill"]:
                continue
            raw = originals.vm(section["address"], section["size"]) if is_cache else read(section["file_offset"], section["size"])
            if section["address"] % 4:
                row["coverage_gaps"].append(f"Unaligned instruction section {section['name']} not scanned")
                continue
            if len(raw) % 4:
                row["coverage_gaps"].append(f"Trailing {len(raw) % 4} non-instruction bytes in {section['name']}")
            words = memoryview(raw)[:len(raw) // 4 * 4].cast("I")
            code_sections.append((section["address"], words))
            for i, word in enumerate(words):
                if word & 0xffe0001f != 0xd4000001:
                    continue
                value = selector(words, i)
                normalized = None
                if value is not None and value >> 32 in (0, 0xffffffff):
                    normalized = (value & 0xffffffff) - (0x100000000 if value & 0x80000000 else 0)
                defs = definitions.get(normalized, [])
                svc_sites.append({"image": path, "section": section["name"], "pc": section["address"] + i * 4,
                                  "opcode": word, "svc_immediate": (word >> 5) & 65535,
                                  "selector_raw": value, "selector_id": normalized,
                                  "reference_names": sorted({d["name"] for d in defs if not d["reserved"]}),
                                  "handler_available": normalized in available and (word >> 5) & 65535 == 128,
                                  "evidence": "local-contiguous-move-candidate" if value is not None else "selector-unresolved"})
                row["svc_sites"] += 1
        entry = image.get("entrypoint", {})
        entry_roots = [entry["address"]] if entry.get("present") else []
        # Export values are offsets from the original Mach header, including cache images.
        header_vm = header_address if is_cache else next((s[1] for s in segments if s[3] == 0 and s[4]), 0)
        export_roots = [header_vm + e["value"] for e in export_rows if "value" in e and not e.get("flags", 0) & 3
                        and any(base <= header_vm + e["value"] < base + len(words) * 4 for base, words in code_sections)]
        row["reachability"] = {"entry": arm64_reachability(code_sections, entry_roots),
                               "export_candidates": arm64_reachability(code_sections, sorted(set(export_roots)))}
        row["file_type"] = image["file_type"]
        row["entrypoint"] = entry
        row["coverage_gaps"].append("Initializer callbacks, address-taken roots, indirect/PAC targets, runtime lookup and cross-image calls are not resolved by the direct-edge skeleton.")
        images.append(row)
    sources = originals.verify()
    for f in originals.files.values():
        f.close()
    summary = {"images": len(images), "imports_records": len(imports), "unique_import_symbols": len({i["symbol"] for i in imports}),
               "exports": sum(i["export_count"] for i in images), "svc_sites": len(svc_sites),
               "resolved_local_selector_sites": sum(i["selector_id"] is not None for i in svc_sites),
               "sources_fully_hashed": len(sources)}
    backlog = collections.Counter((s["selector_id"], tuple(s["reference_names"])) for s in svc_sites if s["selector_id"] is not None and not s["handler_available"])
    return {"schema_version": 1, "scope": "static-retained-original-arm64-closure", "summary": summary,
            "native_closure_sha256": input_reports["closure"]["sha256"], "input_reports": input_reports,
            "verified_sources": sources,
            "target_roots": selected_roots, "explicit_target_roots": explicit_target_roots,
            "explicit_target_roots_scope": "diagnostic-selection-not-observed-execution",
            "dependency_edges": graph["edges"],
            "handler_manifest": manifest, "availability_scope": "bounded-bootstrap-only",
            "runtime_frequency_measured": False, "all_possible_calls_proven": False,
            "limits": ["Local constant candidates do not prove control-flow reachability.", "Indirect selectors, dynamic lookup, generated code and optimized cache binds require further analysis.", "Imports include data and runtime symbols, not only callable functions.", "Export availability is not proof that a Darwin service is implemented.", "Reference XNU version is not asserted to match the retained SystemOS."],
            "static_backlog": [{"id": k[0], "names": list(k[1]), "static_sites": n} for k, n in backlog.most_common()],
            "svc_sites": svc_sites, "imports": imports, "images": images}


def write_readable_reports(output_root, reference, result):
    with (output_root / "xnu-system-call-catalog.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "id", "name", "conditions", "source", "line", "handler_available"])
        for d in reference["definitions"]:
            writer.writerow([d["domain"], d["id"], d["name"], " | ".join(d["conditions"]), d["source"], d["line"], d["handler_available"]])
    lines = ["# Retained original Darwin static inventory", "", "Static declarations and local SVC candidates; runtime completion is not asserted.", ""]
    lines += [f"- {key}: {value}" for key, value in result["summary"].items()]
    lines += ["", f"XNU reference: `{XNU_COMMIT}`; retained kernel version match unproved.", "",
              "Full ID/name table: [CSV](xnu-system-call-catalog.csv), [JSON](xnu-system-call-catalog.json).",
              "Full image/dependency/import/export/SVC evidence: [JSON](darwin-static-inventory.json).",
              "", "## Unimplemented local SVC candidates", "",
              "Static sites are code occurrences, not execution frequency or priority.", "",
              "| ID | Reference names | Static sites |", "| --- | --- | ---: |"]
    for b in result["static_backlog"]:
        lines.append(f"| {b['id']} | {', '.join(b['names']) or 'unmapped/reserved/indirect; inspect ABI'} | {b['static_sites']} |")
    lines += ["", "## Coverage limits", ""] + [f"- {x}" for x in result["limits"]]
    (output_root / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=pathlib.Path, required=True)
    parser.add_argument("--reference-root", type=pathlib.Path, required=True)
    parser.add_argument("--output-root", type=pathlib.Path, required=True)
    parser.add_argument("--closure-report", type=pathlib.Path,
                        help="Native closure JSON (defaults to the retained startup closure under evidence-root)")
    parser.add_argument("--layout-report", type=pathlib.Path,
                        help="Native dyld cache layout JSON (defaults to the installed layout under evidence-root)")
    parser.add_argument("--cache-images-report", type=pathlib.Path,
                        help="Native dyld cache images JSON (defaults to the installed images under evidence-root)")
    parser.add_argument("--target-root", action="append", default=[],
                        help="Additional exact image virtual path to analyze as a root (repeatable; not observed execution)")
    parser.add_argument("--runtime-observation", type=pathlib.Path,
                        help="Native bootstrap observation with candidate hash and actual handler registry")
    args = parser.parse_args()
    args.output_root.mkdir(parents=True, exist_ok=True)
    manifest = None
    if args.runtime_observation:
        raw = args.runtime_observation.read_bytes()
        observation = json.loads(raw)
        native = observation["result"]
        if not native["mapped"] or not native["bootstrap"]["entered"]:
            raise ValueError("Handler manifest requires an entered native bootstrap")
        handlers = native["bootstrap"]["implemented_trap_handlers"]
        manifest = {"selector_ids": [int(h["selector_id"]) for h in handlers], "handlers": handlers,
                    "native_cli_sha256": observation["native_cli_sha256"], "observation_sha256": sha(raw),
                    "observation_path": str(args.runtime_observation.resolve())}
    reference = catalog(args.reference_root, manifest)
    result = inventory(args.evidence_root, reference, args.closure_report, args.layout_report,
                       args.cache_images_report, args.target_root)
    for name, data in (("xnu-system-call-catalog.json", reference), ("darwin-static-inventory.json", result)):
        (args.output_root / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    write_readable_reports(args.output_root, reference, result)
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()
