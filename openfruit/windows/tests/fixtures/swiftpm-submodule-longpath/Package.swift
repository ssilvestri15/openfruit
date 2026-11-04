// swift-tools-version:6.0

import PackageDescription

let package = Package(
    name: "OPENFRUITXcodePackages",
    platforms: [.iOS(.v18)],
    products: [
        .library(
            name: "OPENFRUITXcodePackages",
            type: .static,
            targets: ["OPENFRUITXcodePackages"]
        )
    ],
    dependencies: [
        .package(
            url: "https://github.com/LeoNatan/LNPopupController.git",
            exact: "3.0.7"
        )
    ],
    targets: [
        .target(
            name: "OPENFRUITXcodePackages",
            dependencies: [
                .product(
                    name: "LNPopupController-Static",
                    package: "LNPopupController"
                )
            ]
        )
    ]
)
