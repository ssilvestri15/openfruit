# OpenIB roadmap

## Milestone 0 — archive foundation (implemented)

- C++20 project and Windows build scripts
- dependency-free XML DOM parser
- modern UIKit NIBArchive reader
- modern UIKit NIBArchive writer
- VInt32 codec
- all known coder value types 0x00–0x0A
- class fallback decoding
- dump command
- semantic diff command
- round-trip tests

## Milestone 1 — Delta LaunchScreen (golden graph match achieved)

Target files:

```text
LaunchScreen.storyboard
 -> LaunchScreen.storyboardc/Info.plist
 -> UIViewController-dkK-ii-Bx4.nib
 -> dkK-ii-Bx4-view-8Uu-wz-ps8.nib
```

Validation sequence:

1. Compile with OpenIB. **PASS**
2. Dump both OpenIB and official Apple NIBs. **PASS**
3. Compare class, key, scalar, and reference-edge graphs. **PASS**
4. Keep extending semantic comparison toward full graph isomorphism.
5. Replace only `LaunchScreen.storyboardc` in an unsigned Delta app.
6. Re-sign and launch on iPhone.

## Milestone 2 — exact LaunchScreen semantics

The current mappings now match the official Delta artifacts at OpenIB's
class/key/scalar/reference-edge level. Remaining proof:

- full normalized graph/isomorphism comparison;
- UIKit on-device decoding after normal OPENFRUIT staging and signing;
- additional system/dynamic color variants beyond the calibrated launch file;
- compatibility corpus from multiple Xcode versions.

## Milestone 3 — Main.storyboard

Implement and validate:

- container views
- navigation-controller relationship semantics
- custom segue templates
- button-triggered segue proxies
- storyboard placeholders/references
- UIPageViewController
- custom collection layouts/cells
- all Delta custom-class connections
- container-view external-object tables and relationship-child coalescing

## Milestone 4 — PauseMenu and Settings

- static and prototype table cells
- table sections
- switches and controls
- collection prototypes
- runtime attributes
- variations and trait constraints
- modern colors and appearances
- presentation-controller metadata

## Milestone 5 — XIB parity needed by Delta

- `GameTableViewCell.xib`
- `PausePresentationControllerContentView.xib`
- footer/header XIBs
- external objects / File's Owner semantics

## Milestone 6 — generalized compiler

- compatibility profiles keyed by document capabilities rather than hard-coded Xcode versions
- binary plist writer for `.storyboardc/Info.plist`
- normalized graph diff with recursive references
- golden corpus from multiple Xcode versions
- fuzz tests for NIB reader/writer
- deterministic output mode
- C ABI for OPENFRUIT integration

## Definition of success

OpenIB is considered usable by OPENFRUIT when a source-only build of Delta can compile all Interface Builder resources on Windows, install after normal signing, and exercise the relevant UI paths without replacing generated resources with artifacts from an official IPA.
