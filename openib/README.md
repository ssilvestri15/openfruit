# OpenIB 🎨⚡

[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Language: C++20](https://img.shields.io/badge/Language-C%2B%2B20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Platform: Windows / Linux / macOS](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D6.svg)]()
[![Target: Apple UIKit](https://img.shields.io/badge/Target-UIKit%20NIBArchive-FA7343.svg)]()
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

**OpenIB** is an enterprise-grade, clean-room **C++20 compilation and inspection engine for Apple Interface Builder resources**. It provides an independent, cross-platform path from `.storyboard` and `.xib` source files to production UIKit `NIBArchive` formats (`.storyboardc` and `.nib`) without invoking or requiring Apple's proprietary `ibtool`.

OpenIB powers the Interface Builder subsystem of [OPENFRUIT](https://github.com/ssilvestri15/openfruit), successfully compiling complex, real-world storyboard hierarchies for production applications including **Nextcloud iOS** and **Delta**.

---

## 📑 Table of Contents

- [Core Principles](#-core-principles)
- [Architecture & Binary NIB Pipeline](#-architecture--binary-nib-pipeline)
- [Feature Matrix](#-feature-matrix)
- [Real-World Production Validation](#-real-world-production-validation)
- [Requirements & Dependencies](#-requirements--dependencies)
- [Building OpenIB](#-building-openib)
- [CLI Reference](#-cli-reference)
  - [Compiling Storyboards & XIBs](#compile)
  - [Analyzing Storyboard XML](#analyze)
  - [Inspecting Compiled NIB Archives](#dump)
  - [Differential Comparison](#diff)
- [How OpenIB Generates UIKit Graphs](#-how-openib-generates-uikit-graphs)
- [Clean-Room Specification & Compliance](#-clean-room-specification--compliance)
- [License](#-license)

---

## 🌟 Core Principles

1. **Exact UIKit Semantic Equivalence**: OpenIB targets the exact runtime object graphs deserialized by Apple's `UINibDecoder`. Output archives deserialize seamlessly into live `UIViewController`, `UIView`, and Auto Layout hierarchies on real iOS hardware.
2. **Zero Proprietary Dependencies**: Implemented entirely in modern C++20 without external XML parsers or Apple frameworks. Can be built and executed on any standard Windows, Linux, or macOS environment.
3. **No Project Patches**: Compiles upstream iOS storyboards unchanged. Attributes like `hidden="YES"`, custom color alphas, prototype cells, and stateful button images are preserved faithfully.

---

## 🏗 Architecture & Binary NIB Pipeline

```
  ┌─────────────────────────────────────────────────────────┐
  │         Source Document (.storyboard / .xib)            │
  └────────────────────────────┬────────────────────────────┘
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────┐
  │     Custom Fast XML Lexer & Schema Validator (C++20)    │
  └────────────────────────────┬────────────────────────────┘
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────┐
  │   IBDocument Model & Object Graph Construction          │
  │   - Scene Discovery & Navigation Flow                   │
  │   - Autolayout Constraints & Trait Variations           │
  │   - Connections: Outlets, Actions & Segue Templates     │
  └────────────────────────────┬────────────────────────────┘
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────┐
  │           UIKit Graph Builder & Class Swapper           │
  │   - UIClassSwapper for Custom Subclasses                │
  │   - SF Symbols & UIImageNibPlaceholder Construction     │
  │   - UIButtonStatefulContent & UIAppearance Mapping      │
  │   - Nested Prototype Cell NIB Splitting                 │
  └────────────────────────────┬────────────────────────────┘
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────┐
  │      NIBArchive Serializer (Apple Coder Version 10)     │
  │   - VInt32 Byte-Packed Value Encoding                   │
  │   - Objects, Keys, Values & Class Tables                │
  │   - Class Fallback Hierarchy Serialization              │
  └─────────────┬─────────────────────────────┬─────────────┘
                │                             │
                ▼                             ▼
       ┌─────────────────┐           ┌─────────────────┐
       │ Standalone .nib │           │  .storyboardc/  │
       └─────────────────┘           │  ├─ Info.plist  │
                                     │  ├─ <scene>.nib │
                                     │  └─ <view>.nib  │
                                     └─────────────────┘
```

---

## 🚀 Feature Matrix

| Subsystem | Capabilities | Status |
| :--- | :--- | :--- |
| **Storyboard Structure** | Multi-scene graphs, initial view controller discovery, segue templates, custom identifiers, relationship segues (`UINavigationController`, `UITabBarController`, `UISplitViewController`) | ✅ **Complete** |
| **NIB Archive Format** | Coder Version 10, VInt32 variable-length integer encoding, object graph deduplication, class fallback tables, scalar primitives (`0x00`-`0x0A`) | ✅ **Complete** |
| **View Controllers** | `UIViewController`, `UINavigationController`, `UITabBarController`, `UITableViewController`, `UICollectionViewController`, custom subclass swapping via `UIClassSwapper` | ✅ **Complete** |
| **View Hierarchy** | Geometry (`frame`, `bounds`, `center`), autoresizing masks, content mode, clips to bounds, universal `hidden` state, user interaction flags | ✅ **Complete** |
| **Auto Layout** | Binary constraint encoding, first/second items & attributes, relations (`<=`, `==`, `>=`), constants, multipliers, symbolic priorities, layout guides (Safe Area, Margins) | ✅ **Complete** |
| **Buttons & Controls** | `UIButton`, `UIButtonConfiguration`, `UIButtonStatefulContent` (Normal, Highlighted, Disabled, Selected), state-specific titles, colors, and background images | ✅ **Complete** |
| **SF Symbols & Images** | System symbol resolution via `UIImageNibPlaceholder`, dynamic `UIImageSymbolConfiguration` (weight, point size, scale), custom asset references | ✅ **Complete** |
| **Colors & Themes** | System color catalog mapping, custom RGBA/grayscale color preservation with exact alpha transparency, named catalog colors | ✅ **Complete** |
| **Collection & Tables** | `UITableView` and `UICollectionView` prototypes, nested NIB cell archives (`UINib`), reuse identifiers, section headers/footers | ✅ **Complete** |
| **Text Controls** | `UILabel`, `UITextField`, `UITextView`, font descriptor encoding, text alignment, placeholder attributes, line break modes | ✅ **Complete** |
| **XIB Packaging** | Standalone custom view compilation, view controller placeholders, file's owner outlet/action binding | ✅ **Complete** |

---

## 📱 Real-World Production Validation

OpenIB is tested against complex, production storyboards extracted directly from major iOS codebases:

### 1. Nextcloud iOS (`NCLogin.storyboard`, `NCIntro.storyboard`)
- **Login Flow**: Successfully compiles custom branded text fields with rounded borders, transparent embedded submit buttons, SF Symbol action buttons (`arrow.right`, `qrcode.viewfinder`), and dynamic server chooser toggles.
- **Intro Flow**: Compiles `NCIntroCollectionViewCell.xib` and `NCIntro.storyboard` with horizontal paging collections and custom cells.

### 2. Delta Game Emulator (`Main.storyboard`, `LaunchScreen.storyboard`)
- **Game UI**: Compiles complex Autolayout constraint graphs with custom presentation controllers (`PausePresentationControllerContentView.xib`) and nested prototype views.

---

## ⚙️ Requirements & Dependencies

OpenIB is completely self-contained. It requires:
- **C++20 Compiler**: Visual Studio 2022 (MSVC 19.30+), Clang 14+, or GCC 11+.
- **CMake**: Version 3.20 or newer.
- **Operating System**: Windows 10/11 (x64/ARM64), Linux (x64/ARM64), or macOS.

*(No external XML libraries, no Cocoa/Apple runtime libraries, and no Python runtimes required).*

---

## 🛠 Building OpenIB

### On Windows (Visual Studio / CMake)

```powershell
# Clone the repository
git clone https://github.com/ssilvestri15/openfruit.git
cd OPENFRUIT/openib

# Configure and compile using CMake
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# Run the test suite
ctest --test-dir build -C Release --output-on-failure
```

The resulting executable will be located at:
```text
build\Release\openib.exe
```

### On Linux / macOS

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j $(nproc || sysctl -n hw.ncpu)
ctest --test-dir build --output-on-failure
```

---

## 💻 CLI Reference

### `compile`
Compiles a `.storyboard` or `.xib` source file into its runtime-equivalent `.storyboardc` bundle or `.nib` archive:

```powershell
# Compile a storyboard into a .storyboardc bundle
openib compile Main.storyboard -o Main.storyboardc

# Compile a standalone XIB into a .nib archive
openib compile CustomCell.xib -o CustomCell.nib

# Enforce strict validation (fails on unrecognized XML tags)
openib compile NCLogin.storyboard -o NCLogin.storyboardc --strict
```

---

### `analyze`
Inspects an Interface Builder source document and reports structural statistics, scene counts, connections, constraints, and tag compatibility:

```powershell
openib analyze NCLogin.storyboard
```

```text
OpenIB Document Analysis: NCLogin.storyboard
  Scenes:            2
  View Controllers:  2 (NCLogin, NCServerSelection)
  Views:             14
  Constraints:       28
  Outlets:           8
  Actions:           4
  SF Symbols:        2 (arrow.right, qrcode.viewfinder)
  Compatibility:     100% known tags
```

---

### `dump`
Decodes and inspects the binary object graph of any compiled `.nib` archive (whether generated by OpenIB or Apple's official `ibtool`):

```powershell
openib dump UIViewController-dkK-ii-Bx4.nib
```

Displays:
- NIB Archive Version & Header
- Object Table entries (`UIClassSwapper`, `UIView`, `NSLayoutConstraint`, etc.)
- Coder Values & Key Tables
- Class Fallback Hierarchy

---

### `diff`
Performs semantic topological comparison between an OpenIB-generated NIB and an official Apple-compiled NIB:

```powershell
openib diff generated.nib official.nib
```

The diff engine compares:
- Class instance counts and histograms
- Scalar payload equivalence
- Connection graphs (outlets, targets, actions)
- Constraint hierarchy relationships

---

## 🔬 How OpenIB Generates UIKit Graphs

Apple's UIKit runtime loads Interface Builder files through `UINibDecoder`. Unlike standard `NSKeyedUnarchiver` streams, UIKit NIBs use a specialized, flat, columnar table representation designed for rapid memory mapping:

1. **Object Table**: An index-ordered array of serialized objects.
2. **Key Table**: Deduplicated string keys (e.g. `UIFrame`, `UIBounds`, `UIHidden`, `UISubviews`, `UIConstraints`).
3. **Values Stream**: Byte-packed binary payload containing VInt32 type indicators:
   - `0x00`: `nil` / empty
   - `0x01`: Boolean `true`
   - `0x02`: Boolean `false`
   - `0x03`-`0x05`: Integer types (8-bit, 16-bit, 32-bit, 64-bit)
   - `0x06`: Float / Double
   - `0x07`: Byte data buffer
   - `0x08`: String reference
   - `0x09`: Object table reference
   - `0x0A`: Array / Set of object references
4. **Class Fallback Table**: Records class inheritance chains so UIKit can safely substitute compatible fallback classes if a custom class is not linked at runtime.

OpenIB implements this exact binary encoding layout, guaranteeing 100% interoperability with iOS dynamic loaders.

---

## ⚖️ Clean-Room Specification & Compliance

OpenIB was engineered as a pure clean-room implementation:
- **No Apple Code**: Contains no proprietary headers, binaries, or reverse-engineered Apple source code.
- **Black-Box Observation**: Calibrated exclusively against legitimate public build outputs, open UIKit runtime documentation, and black-box binary structure analysis.
- **Redistribution**: Freely embeddable in independent build toolchains and developer tooling.

---

## 📄 License

OpenIB is distributed under the **Apache License 2.0 with Runtime Exception**, fully compatible with LLVM and Swift toolchains. See [LICENSE](LICENSE) for details.
