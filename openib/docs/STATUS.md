# Validation status

Updated on 2026-09-22.

## Build

- CMake configure: PASS
- GCC 14.2 C++20 build: PASS
- CTest: PASS

## Delta source analysis

```text
GamesDatabase.storyboard
type: com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB
format: 3.0
toolsVersion: 15705
targetRuntime: iOS.CocoaTouch
scenes: 2
outlets: 2
actions: 0
segues: 2
constraints: 0
unsupported tags: 0
```

```text
LaunchScreen.storyboard
type: com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB
format: 3.0
toolsVersion: 32700.99.1234
targetRuntime: iOS.CocoaTouch
scenes: 1
outlets: 0
actions: 0
segues: 0
constraints: 7
unsupported tags: 0
```

```text
Main.storyboard
type: com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB
format: 3.0
toolsVersion: 23504
targetRuntime: iOS.CocoaTouch
scenes: 13
outlets: 18
actions: 3
segues: 15
constraints: 20
unsupported tags: 0
```

```text
PauseMenu.storyboard
type: com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB
format: 3.0
toolsVersion: 24506
targetRuntime: iOS.CocoaTouch
scenes: 6
outlets: 18
actions: 6
segues: 9
constraints: 29
unsupported tags: 0
```

```text
Settings.storyboard
type: com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB
format: 3.0
toolsVersion: 24128
targetRuntime: iOS.CocoaTouch
scenes: 21
outlets: 69
actions: 25
segues: 24
constraints: 107
unsupported tags: 0
```

```text
PausePresentationControllerContentView.xib
type: com.apple.InterfaceBuilder3.CocoaTouch.XIB
format: 3.0
toolsVersion: 13528
targetRuntime: iOS.CocoaTouch
scenes: 0
outlets: 3
actions: 0
segues: 0
constraints: 7
unsupported tags: 0
```

## Golden compatibility checks

All supplied storyboard/XIB fixtures compile in non-strict mode and every generated LaunchScreen NIB round-trips through the OpenIB decoder.

Against the unpacked official Delta 1.6 IPA:

- `LaunchScreen.storyboardc/Info.plist` matches semantically;
- controller NIB matches at class/key/scalar/reference-edge graph level
  (19 objects, 43 values);
- view NIB matches at the same level (43 objects, 229 values);
- the entry-point external-storyboard placeholder NIB matches at the same
  level;
- `Main.storyboardc/Info.plist` generated from the matching `v1.6` source has
  the same nib-name and external-storyboard-reference maps as Apple output.

This is not yet proof that all of `Main.storyboard` is UIKit-runtime
equivalent. Container views and relationship segues are the next known graph
mismatch, and an on-device test still requires native OPENFRUIT integration and
re-signing.
