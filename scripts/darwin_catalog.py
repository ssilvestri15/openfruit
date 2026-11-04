"""Bounded, source-derived Darwin diagnostic catalog; never a runtime scanner."""
import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from urllib.request import urlopen

XNU_REVISION = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea"
BASE_URL = f"https://raw.githubusercontent.com/apple-oss-distributions/xnu/{XNU_REVISION}/"
SOURCES = ["bsd/kern/syscalls.master", "osfmk/kern/syscall_sw.c", "osfmk/mach/syscall_sw.h"]
MIG_SOURCES = [f"osfmk/mach/{name}.defs" for name in
               ("mach_vm", "mach_port", "task", "thread_act", "clock", "host_priv", "restartable")]
PINNED_SHA256 = {
    "bsd/kern/syscalls.master": "7e866891439ad5b3464777d2cacc3b82fc2e7f439fb5a8686c3e6f160d5aeab5",
    "osfmk/kern/syscall_sw.c": "3dd906c21aba6e2f195710b877587de739ea2836bf60e834aba8180baad15d3d",
    "osfmk/mach/syscall_sw.h": "4e10e2eb7e496982b345a7a45e9e526e0107abadcb8bf6ded32ca0ff10831e54",
    "osfmk/mach/mach_vm.defs": "14d6a56bff28f5fc046a7e2f48a7347463ed28087645279e6b8b544ce95141ad",
    "osfmk/mach/mach_port.defs": "f0a51838fbec52fe636068bf909f32edb5b5ffd3e2cc7fda2686220cd63d07f9",
    "osfmk/mach/task.defs": "f5c7269165d61c377164ee322da38a56493cdfc165bd16b1dc0706b9aff16ad7",
    "osfmk/mach/thread_act.defs": "18acc1e381743f175fc6397629e0a79ed7c091aa593ef9156c16179182c726f7",
    "osfmk/mach/clock.defs": "7c97eebd4acbf12ad982b60a0f9b383feddf917f305c765f5d609a74a0dcf22e",
    "osfmk/mach/host_priv.defs": "67714620eed7afb09a49ef1d55c4cee1b009f2243ac644e6d72c58ef4af1cab8",
    "osfmk/mach/restartable.defs": "c3930b9d12583926acd59147a601e5c15ad6bc6495a0342e460f5760756e9d91",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strip_comments(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: "\n" * m[0].count("\n"), text, flags=re.S)


def conditioned_lines(text):
    """Retain conditional branches without pretending to preprocess a kernel config."""
    stack = []
    for number, line in enumerate(text.splitlines(), 1):
        directive = re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)", line)
        if directive:
            op, expression = directive.groups()
            if op in ("if", "ifdef", "ifndef"):
                stack.append(op + " " + expression.strip())
            elif op in ("else", "elif"):
                if not stack:
                    raise ValueError("unbalanced conditional")
                stack[-1] = op + " " + expression.strip() + " [alternative branch]"
            elif op == "endif":
                if not stack:
                    raise ValueError("unbalanced conditional")
                stack.pop()
            continue
        yield number, line, list(stack)
    if stack:
        raise ValueError("unterminated conditional")


def parse_syscalls(text):
    rows, excluded = {}, set()
    for line, content, conditions in conditioned_lines(strip_comments(text)):
        match = re.match(r"\s*(\d+)\s+\S+\s+\S+\s+\{\s*[^{};]*?\b(\w+)\s*\(", content)
        if not match:
            if re.match(r"\s*\d+\s", content):
                raise ValueError(f"unparsed syscall declaration at line {line}")
            continue
        selector, name = int(match[1]), match[2]
        if name in ("nosys", "enosys", "munge_nosys"):
            excluded.add(selector)
            continue
        rows.setdefault(selector, []).append({"name": name, "line": line, "conditions": conditions})
    return rows, sorted(excluded - rows.keys())


def parse_traps(table, header):
    # Limit to the real table, not its separate name table or comments.
    table = table.split("mach_trap_table[MACH_TRAP_TABLE_COUNT] = {", 1)[1].split("};", 1)[0]
    rows, excluded = {}, set()
    for line, content, conditions in conditioned_lines(table):
        match = re.match(r"\s*/\*\s*(\d+)\s*\*/\s*MACH_TRAP\(\s*(\w+)\s*,\s*(\d+)", content)
        if not match:
            continue
        selector, name = -int(match[1]), match[2]
        if name == "kern_invalid":
            excluded.add(selector)
            continue
        rows.setdefault(selector, []).append({"name": name, "argument_count": int(match[3]),
                                              "conditions": conditions})
    aliases = {}
    for _, content, conditions in conditioned_lines(strip_comments(header)):
        match = re.match(r"\s*kernel_trap\(\s*(\w+)\s*,\s*(-\d+)\s*,\s*(\d+)\s*\)", content)
        if match:
            selector = int(match[2])
            if selector not in rows:
                raise ValueError(f"header trap {selector} absent from kernel table")
            aliases.setdefault(selector, []).append({"name": match[1], "stub_argument_words": int(match[3]),
                                                      "conditions": conditions})
    return rows, aliases, sorted(excluded - rows.keys())


def parse_mig(text):
    clean = strip_comments(text)
    declarations = re.sub(r"^\s*#[^\n]*", "", clean, flags=re.M)
    subsystem = re.search(r"\bsubsystem\s+((?:\w+\s+)+)(\d+)\s*;", declarations)
    if not subsystem:
        raise ValueError("MIG subsystem declaration missing")
    subsystem_names = [word for word in subsystem[1].split() if word not in ("KernelUser", "KernelServer")]
    routines = {}
    # Declarations may span lines; retain the condition applying at the start.
    lines = list(conditioned_lines(clean))
    pending = False
    for line, content, conditions in lines:
        declaration = re.match(r"\s*(?:simpleroutine|routine)\b(.*)", content)
        if declaration:
            pending = True
            content = declaration[1]
        if not pending:
            continue
        # Unwrap lexical PREFIX/KERNEL_SERVER_SUFFIX annotations, not arbitrary macros.
        expression = content.strip()
        while True:
            unwrapped = re.sub(r"\b(?:PREFIX|KERNEL_SERVER_SUFFIX|KERNEL_SERVER_SUFFIX_SANDBOX|MIG_SERVER_SUFFIX)\((\w+)\)", r"\1", expression)
            if expression == unwrapped:
                break
            expression = unwrapped
        match = re.match(r"(\w+)\s*\(", expression)
        if match:
            if match[1].isupper():
                raise ValueError(f"unrecognized MIG name macro at line {line}: {match[1]}")
            routines.setdefault(match[1], []).append({"line": line, "conditions": conditions})
        if ");" in content or re.match(r"\s*skip\s*;", content):
            pending = False
    return subsystem_names[0], int(subsystem[2]), routines


def build_catalog(source_bytes, ledger):
    """All denominators count emitted unique rows, not parser regex matches."""
    for path, expected in PINNED_SHA256.items():
        if digest(source_bytes[path]) != expected:
            raise ValueError(f"source hash does not match pinned XNU revision: {path}")
    catalogs, contracts = [], []
    def add_catalog(identifier, title, paths, completeness, rows, **extra):
        catalogs.append({"id": identifier, "title": title, "revision": XNU_REVISION,
                         "denominator": len(rows), "completeness": completeness,
                         "sources": [{"url": BASE_URL + path, "sha256": digest(source_bytes[path])}
                                     for path in paths], **extra})
        contracts.extend(rows)
    syscall_rows, exclusions = parse_syscalls(source_bytes[SOURCES[0]].decode())
    rows = []
    for selector, variants in sorted(syscall_rows.items()):
        rows.append({"id": f"xnu.bsd.{selector}", "catalog_id": "xnu-bsd-selectors", "name": variants[0]["name"],
                     "family": "BSD", "kind": "syscall", "selector_id": selector,
                     "source": BASE_URL + SOURCES[0], "variants": variants,
                     "scope": "Named syscall selector in conditional source union; kernel configuration not selected"})
    add_catalog("xnu-bsd-selectors", "XNU named BSD syscall slots", [SOURCES[0]],
                "bounded conditional union of syscalls.master", rows, excluded_reserved_selectors=exclusions)
    trap_rows, aliases, exclusions = parse_traps(source_bytes[SOURCES[1]].decode(), source_bytes[SOURCES[2]].decode())
    rows = []
    for selector, variants in sorted(trap_rows.items(), reverse=True):
        name = variants[0]["name"]
        family = "Mach VM" if "mach_vm" in name else "Mach IPC"
        if any(word in name for word in ("thread_switch", "swtch", "semaphore")):
            family = "Mach scheduling"
        elif any(word in name for word in ("timer", "time", "clock")):
            family = "Mach clocks"
        rows.append({"id": f"xnu.mach.{-selector}", "catalog_id": "xnu-mach-traps", "name": name,
                     "family": family, "kind": "mach-trap", "selector_id": selector,
                     "source": BASE_URL + SOURCES[1], "variants": variants, "aliases": aliases.get(selector, []),
                     "scope": "Named Mach trap table slot; header aliases are not additional contracts"})
    add_catalog("xnu-mach-traps", "XNU named Mach trap slots", SOURCES[1:],
                "bounded conditional union of mach_trap_table plus stub aliases", rows,
                excluded_reserved_selectors=exclusions)
    for path in MIG_SOURCES:
        subsystem, base, routines = parse_mig(source_bytes[path].decode())
        identifier = f"xnu-mig-{subsystem}"
        rows = [{"id": f"xnu.mig.{subsystem}.{name}", "catalog_id": identifier, "name": name,
                 "family": "Mach VM" if subsystem == "mach_vm" else "Mach IPC",
                 "kind": "mig", "source": BASE_URL + path, "variants": variants,
                 "scope": "Direct routine declaration; message numbering, imported definitions and ABI preprocessing excluded"}
                for name, variants in sorted(routines.items())]
        add_catalog(identifier, f"MIG {subsystem} direct routines", [path],
                    "bounded direct-declaration conditional union, not all MIG", rows, subsystem_base=base)
    result = {"schema_version": 1, "catalogs": catalogs, "contracts": contracts,
              "measurement_limits": ["No total Darwin denominator or overall completion percentage is known.",
                 "Conditional source union is not a selected Apple kernel ABI or proof of runtime reachability.",
                 "Only selected MIG direct declarations are enumerated; includes, message layouts and generated stubs are excluded.",
                 "Objective-C, Swift, pthread/TLS, commpage and dyld universes remain open; reviewed ledger scopes cover bounded subsets.",
                 "Selector registration is not semantic implementation; scoped ledger mappings are never inferred from names."]}
    return refresh_ledger(result, ledger)


def refresh_ledger(catalog, ledger):
    """Refresh source-defined scoped rows offline; preserve pinned Apple catalogs."""
    result = copy.deepcopy(catalog)
    identifier = "openfruit-reviewed-scopes"
    result["catalogs"] = [item for item in result["catalogs"] if item["id"] != identifier]
    result["contracts"] = [row for row in result["contracts"] if row["catalog_id"] != identifier]
    rows = [{"id": f"scope.{item['id']}", "catalog_id": identifier,
             "name": item["id"], "family": item.get("workgroup", item["family"]), "kind": "scoped",
             "ledger_id": item["id"], "scope": item["scope"], "source": "docs/DARWIN_CONTRACT_LEDGER.json"}
            for item in ledger["contracts"]]
    # Scopes are separate units; never sum them with Apple selector denominators.
    data = json.dumps(ledger, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    result["catalogs"].append({"id": identifier, "title": "Reviewed OPENFRUIT ledger scopes",
                              "revision": digest(data), "denominator": len(rows),
                              "completeness": "bounded explicit ledger scopes, not complete semantic contracts",
                              "sources": [{"path": "docs/DARWIN_CONTRACT_LEDGER.json", "sha256": digest(data),
                                           "hash_encoding": "canonical sorted compact UTF-8 JSON"}]})
    result["contracts"].extend(rows)
    validate_catalog(result)
    return result


def validate_catalog(catalog):
    identifiers = [row["id"] for row in catalog["contracts"]]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("duplicate contract IDs")
    catalogs = {item["id"]: item for item in catalog["catalogs"]}
    if len(catalogs) != len(catalog["catalogs"]):
        raise ValueError("duplicate catalog IDs")
    for row in catalog["contracts"]:
        if row["catalog_id"] not in catalogs:
            raise ValueError("unknown catalog")
    for identifier, item in catalogs.items():
        if item["denominator"] != sum(row["catalog_id"] == identifier for row in catalog["contracts"]):
            raise ValueError("catalog denominator mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True, help="Pinned XNU source/cache directory")
    parser.add_argument("--fetch", action="store_true", help="Fetch pinned immutable files and verify any cached copies")
    parser.add_argument("--ledger", type=Path, default=Path(__file__).resolve().parents[1] / "docs/DARWIN_CONTRACT_LEDGER.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = {}
    for path in SOURCES + MIG_SOURCES:
        source = args.source_dir / path
        legacy = args.source_dir / path.replace("/", "_")
        existing = source if source.exists() else legacy
        if args.fetch:
            with urlopen(BASE_URL + path, timeout=60) as response:
                downloaded = response.read()
            if existing.exists() and existing.read_bytes() != downloaded:
                raise ValueError(f"cached source does not match pinned upstream: {path}")
            if not existing.exists():
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(downloaded)
            data[path] = downloaded
        else:
            data[path] = existing.read_bytes()
    output = build_catalog(data, json.loads(args.ledger.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({item["id"]: item["denominator"] for item in output["catalogs"]}))


if __name__ == "__main__":
    main()
