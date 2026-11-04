"""Diagnostic gate for Delta 1.6's complete OpenIB/official NIB corpus.

The strict graph comparison remains authoritative for ordinary NIBs. Only
two independently examined exceptions are allowed here: a small content-size
measurement difference and a cross-file-consistent outlet proxy renaming.
This script is not a production compiler or a replacement for UIKit testing.
"""

import argparse
from pathlib import Path
import plistlib
import re
import subprocess
import sys


LICENSE_VIEW = Path("Settings.storyboardc/Vew-Fv-phU-view-OFY-Qi-vAX.nib")
TABLE_VIEW = Path("Settings.storyboardc/eHi-aO-uGS-view-hRw-wV-lch.nib")
TABLE_CONTROLLER = Path("Settings.storyboardc/UINavigationController-ssH-mM-uG6.nib")
CONTENT_SIZE = re.compile(r"^\s*UIContentSize = \(bytes\) \{([0-9.]+), ([0-9.]+)\}$", re.MULTILINE)


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8")


def official_path(app: Path, relative: Path) -> Path:
    localized = app / "Base.lproj" / relative
    return localized if localized.is_file() else app / relative


def content_size(openib: Path, nib: Path) -> tuple[float, float]:
    result = run(str(openib), "dump", str(nib))
    if result.returncode:
        raise ValueError(f"cannot dump {nib}: {result.stderr.strip()}")
    sizes = CONTENT_SIZE.findall(result.stdout)
    if len(sizes) != 1:
        raise ValueError(f"expected one UITextView content size in {nib}, found {len(sizes)}")
    return tuple(map(float, sizes[0]))


def outlet_lines(openib: Path, view: Path, controller: Path) -> list[str]:
    inspector = Path(__file__).with_name("inspect-nib-outlets.py")
    result = run(sys.executable, str(inspector), str(openib), str(view),
                 "--controller", str(controller), "--semantic")
    if result.returncode:
        raise ValueError(f"cannot inspect linked outlets: {result.stderr.strip()}")
    return result.stdout.splitlines()


def verify_exception(openib: Path, generated: Path, official: Path,
                     relative: Path, diff: str, max_delta: float) -> str | None:
    lines = diff.splitlines()
    differences = [line.strip() for line in lines if line.strip().startswith("[")]
    if relative == LICENSE_VIEW:
        if len(differences) != 2 or not all(
            line.startswith("[scalar] UIContentSize=") for line in differences
        ):
            return None
        actual = content_size(openib, generated / relative)
        expected = content_size(openib, official_path(official, relative))
        if actual[0] != expected[0] or abs(actual[1] - expected[1]) > max_delta:
            return None
        if abs(actual[1] - expected[1]) / expected[1] > 0.005:
            return None
        return f"content-size tolerance {actual[1]:g} vs {expected[1]:g}"
    if relative == TABLE_VIEW:
        if len(differences) != 1 or not differences[0].startswith(
            "[topology] round 2: UIRuntimeOutletConnection"
        ):
            return None
        left = outlet_lines(openib, generated / relative, generated / TABLE_CONTROLLER)
        right = outlet_lines(openib, official_path(official, relative),
                             official_path(official, TABLE_CONTROLLER))
        if len(left) != 22 or left != right:
            return None
        return "22 linked outlet endpoints equal after proxy renaming"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("openib", type=Path)
    parser.add_argument("generated", type=Path)
    parser.add_argument("official_app", type=Path)
    parser.add_argument("--max-content-height-delta", type=float, default=8)
    args = parser.parse_args()

    generated_nibs = sorted(p.relative_to(args.generated) for p in args.generated.rglob("*.nib"))
    if len(generated_nibs) != 67:
        print(f"FAIL: expected 67 generated NIBs, found {len(generated_nibs)}")
        return 1
    failures = []
    strict = 0
    tolerated = []
    for relative in generated_nibs:
        official = official_path(args.official_app, relative)
        if not official.is_file():
            failures.append(f"missing official NIB: {relative}")
            continue
        result = run(str(args.openib), "diff", str(args.generated / relative), str(official))
        if result.returncode == 0:
            strict += 1
            continue
        reason = verify_exception(args.openib, args.generated, args.official_app,
                                  relative, result.stdout, args.max_content_height_delta)
        if reason:
            tolerated.append(f"{relative}: {reason}")
        else:
            failures.append(f"{relative}: {result.stdout.strip() or result.stderr.strip()}")

    plists = sorted(args.generated.rglob("*.storyboardc/Info.plist"))
    if len(plists) != 6:
        failures.append(f"expected six generated storyboard Info.plists, found {len(plists)}")
    for generated_plist in plists:
        relative = generated_plist.relative_to(args.generated)
        official_plist = official_path(args.official_app, relative)
        if not official_plist.is_file():
            failures.append(f"missing official plist: {relative}")
            continue
        with generated_plist.open("rb") as left, official_plist.open("rb") as right:
            if plistlib.load(left) != plistlib.load(right):
                failures.append(f"plist differs: {relative}")
        generated_files = {p.name for p in generated_plist.parent.iterdir() if p.is_file()}
        official_files = {p.name for p in official_plist.parent.iterdir() if p.is_file()}
        if generated_files != official_files:
            failures.append(f"storyboard file set differs: {relative.parent}")

    for item in tolerated:
        print("TOLERATED", item)
    for item in failures:
        print("FAIL", item)
    print(f"STRICT={strict} TOLERATED={len(tolerated)} FAIL={len(failures)} "
          f"NIBS={len(generated_nibs)} PLISTS={len(plists)}")
    return 0 if strict == 65 and len(tolerated) == 2 and not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
