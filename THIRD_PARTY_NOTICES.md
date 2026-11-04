# Third-party notices

OPENFRUIT's own code is licensed under GPL-2.0-or-later (see `LICENSE`).
The components below keep their own licenses. Installed builds place each
license text under `share/licenses/openfruit`.

## Compiled into OPENFRUIT binaries

| Component | Version | License | How it is used |
| --- | --- | --- | --- |
| [Unicorn](https://github.com/unicorn-engine/unicorn) | 2.1.4 | GPL-2.0 (QEMU-derived parts LGPL-2.1) | `unicorn.dll`, ARM64 CPU emulation for the Darwin macro runtime |
| [apfs-fuse](https://github.com/sgan81/apfs-fuse) (`ApfsLib/Util.cpp`, `Unicode.cpp`, `Crc32.cpp`) | 66b86bd | GPL-2.0-or-later | statically linked, APFS metadata helpers |
| [libplist](https://github.com/libimobiledevice/libplist) | vendored in `openfruit/windows/vendor/libplist` | LGPL-2.1-or-later (bundled `jsmn` and `time64`: MIT) | statically linked, property lists |
| [zlib](https://zlib.net) | 1.3.2 | Zlib | statically linked |
| [xz / liblzma](https://github.com/tukaani-project/xz) | 5.8.4 | 0BSD | statically linked |
| [lzfse](https://github.com/lzfse/lzfse) | e634ca5 | BSD-3-Clause | statically linked |
| [bzip2](https://sourceware.org/bzip2/) | 1.0.8 | bzip2-1.0.6 (BSD-style) | statically linked |
| LLVM compiler-rt (`os_version_check.c` excerpt in `compiler_rt_support.cpp`) | — | Apache-2.0 WITH LLVM-exception | compiled into generated iOS objects |

Because Unicorn is GPL-2.0, a distributed OPENFRUIT binary as a whole is
covered by version 2 of the GNU General Public License. The corresponding
source of these components is published with each release.

## Built from source on the user's machine (not distributed)

The asset compiler (`native/asset-compiler`) is built locally with:

| Component | Version | License |
| --- | --- | --- |
| [AssetKit](https://github.com/xtool-org/AssetKit) (with `Patches/AssetKit-1.0.0-named-colors.patch`) | 1.0.0 | MIT |
| [swift-png](https://github.com/tayloraswift/swift-png) | 4.5.1 | Apache-2.0 (see its NOTICE) |
| [h](https://github.com/rarestype/h) | 1.0.1 | Apache-2.0 (see its NOTICE) |

## Downloaded from upstream and run as separate programs

OPENFRUIT does not redistribute these; they are fetched from their official
sources and keep their own licenses: Swift toolchain (Apache-2.0 with Runtime
Library Exception), LLVM (Apache-2.0 WITH LLVM-exception), Git for Windows
(GPL-2.0), RubyInstaller (Ruby/BSD-2-Clause and bundled components),
CocoaPods and its gems (mainly MIT), resvg (Apache-2.0 OR MIT), zsign (MIT),
pymobiledevice3 (GPL-3.0).

## Apple software

Xcode, the iOS SDK, macOS restore images and Apple's compiler plugins are
proprietary Apple software under Apple's license agreements. OPENFRUIT does
not redistribute them; users obtain them with their own Apple account.
Apple, iOS, macOS and Xcode are trademarks of Apple Inc. OPENFRUIT is not
affiliated with, endorsed or sponsored by Apple Inc.
