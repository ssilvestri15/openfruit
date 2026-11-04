// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "LegacyLayoutProbe",
    platforms: [.iOS(.v12)],
    products: [
        .library(
            name: "LegacyLayoutProbe",
            type: .static,
            targets: ["LegacyLayoutProbe"]
        )
    ],
    targets: [
        .target(name: "LegacyLayoutProbe")
    ]
)
