"""Generate the diagnostic site from the existing native report or seed ledger.

This driver never runs Apple code, scans binaries, or decides runtime correctness.
Native evidence remains bound to its historical candidate, not today's sources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_native_inputs(report: dict, report_path: Path) -> None:
    """Check retained inputs and accepted artifacts before exporting verification.

    The native reporter establishes evidence eligibility. This check prevents
    silently exporting a stale report after its retained inputs were replaced.
    It does not upgrade an attestation to an independent semantic proof.
    """
    inputs = report.get("inputs", [])
    if len(inputs) != 4:
        raise ValueError("Native report must retain inventory/probe/command/ledger identities")
    resolved = []
    for item in inputs:
        path = Path(item["path"])
        if not path.is_absolute():
            path = report_path.parent / path
        if digest(path) != item.get("sha256"):
            raise ValueError("Retained native input hash mismatch")
        resolved.append(path)
    command = read_json(resolved[2])
    if command.get("sha256") != report.get("candidate_sha256"):
        raise ValueError("Native candidate identity differs from command input")
    if report.get("probe_sha256") != inputs[1].get("sha256"):
        raise ValueError("Native probe identity differs from retained probe")
    for row in report.get("contracts", []):
        for proof in row.get("evidence", []):
            if proof.get("accepted") is not True:
                continue
            artifact = Path(proof["artifact"])
            if not artifact.is_absolute():
                artifact = resolved[3].parent / artifact
            if digest(artifact) != proof.get("sha256"):
                raise ValueError("Accepted evidence artifact hash mismatch")


def seed_report(ledger_path: Path) -> dict:
    ledger = read_json(ledger_path)
    rows = []
    for specification in ledger["contracts"]:
        row = dict(specification)
        row.update(evidence=[], verified_scope=False)
        rows.append(row)
    counts = {state: sum(row["implementation"] == state for row in rows)
              for state in ("implemented", "partial", "missing", "unreviewed")}
    return {
        "schema_version": 1,
        "scope": ledger.get("scope", "retained-closure-and-bounded-bootstrap"),
        "candidate_sha256": "", "probe_sha256": "",
        "command_probe_hash_bound": False,
        "inputs": [{"path": str(ledger_path), "sha256": digest(ledger_path)}],
        "contracts": rows, "selector_candidates": [], "target_requirements": [],
        "summary": {
            "identified_scoped_contracts": len(rows),
            **{f"{state}_scoped_contracts": count for state, count in counts.items()},
            "verified_scopes": 0, "static_selector_candidates": 0,
            "registered_candidate_dispatches": None, "manifest_present": False,
            "unresolved_selector_sites": 0,
        },
        "current_blocker": {}, "comparison": {"available": False},
        "priorities": ledger.get("priorities", []),
        "measurement_limits": [
            "Source-ledger seed only: no native candidate, manifest, trace or verification artifacts supplied.",
            "Implementation labels are reviewed scoped declarations, not proof of full API correctness.",
            "Total Darwin requirements and original swift-plugin-server execution remain unknown.",
        ],
    }


def generate(catalog_path: Path, output: Path, report_path: Path | None = None,
             previous_path: Path | None = None, ledger_path: Path | None = None):
    from darwin_coverage import build_progress
    from darwin_progress_web import render
    catalog = read_json(catalog_path)
    report = read_json(report_path) if report_path else seed_report(
        ledger_path or ROOT / "docs/DARWIN_CONTRACT_LEDGER.json")
    if not report_path:
        from darwin_catalog import refresh_ledger
        ledger = read_json(ledger_path or ROOT / "docs/DARWIN_CONTRACT_LEDGER.json")
        catalog = refresh_ledger(catalog, ledger)
    if report_path:
        validate_native_inputs(report, report_path)
    previous = read_json(previous_path) if previous_path else None
    if previous and "selector_candidates" in previous:
        validate_native_inputs(previous, previous_path)
    progress = build_progress(catalog, report, previous)
    progress.setdefault("checkpoint", {})["input_mode"] = "native-report" if report_path else "source-ledger-seed"
    progress["checkpoint"]["catalog_sha256"] = digest(catalog_path)
    progress["checkpoint"]["effective_catalog_sha256"] = hashlib.sha256(json.dumps(
        catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    progress["checkpoint"]["native_report_sha256"] = digest(report_path) if report_path else None
    render(progress, output)
    return progress


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "docs/DARWIN_CONTRACT_CATALOG.json")
    parser.add_argument("--ledger", type=Path, default=ROOT / "docs/DARWIN_CONTRACT_LEDGER.json")
    parser.add_argument("--report", type=Path, help="Retained native report; inputs/artifacts are hash checked")
    parser.add_argument("--previous", type=Path, help="Prior native report or sanitized public progress.json")
    parser.add_argument("--output", type=Path, required=True, help="Generated site directory outside tracked source")
    args = parser.parse_args()
    try:
        progress = generate(args.catalog, args.output, args.report, args.previous, args.ledger)
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        parser.exit(1, f"Darwin progress generation failed: {error}\n")
    print(f"Generated {args.output.resolve()}: {len(progress['contracts'])} catalog rows; "
          f"mode={progress['checkpoint']['input_mode']}. No global runtime percentage.")


if __name__ == "__main__":
    main()
