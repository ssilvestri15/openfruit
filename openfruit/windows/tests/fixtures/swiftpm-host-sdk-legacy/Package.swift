// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "OPENFRUITXcodePackages",
    products: [
        .library(
            name: "OPENFRUITXcodePackages",
            type: .static,
            targets: ["OPENFRUITXcodePackages"]
        )
    ],
    targets: [
        .target(
            name: "OPENFRUITXcodePackages",
            dependencies: [],
            path: "Sources/LegacyManifestProbe"
        )
    ]
)
