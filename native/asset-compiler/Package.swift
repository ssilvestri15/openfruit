// swift-tools-version: 6.3

import PackageDescription

let package = Package(
    name: "OPENFRUITAssetCompiler",
    products: [
        .executable(
            name: "OPENFRUIT-asset-compiler",
            targets: ["OPENFRUITAssetCompiler"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/xtool-org/AssetKit",
            exact: "1.0.0"
        ),
    ],
    targets: [
        .executableTarget(
            name: "OPENFRUITAssetCompiler",
            dependencies: ["AssetKit"],
            path: "Sources/OpenIOSAssetCompiler"
        ),
    ],
    swiftLanguageModes: [.v6]
)
