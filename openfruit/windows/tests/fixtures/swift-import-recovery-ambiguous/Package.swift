// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftImportRecoveryAmbiguous",
    products: [
        .library(
            name: "SwiftImportRecoveryAmbiguous",
            targets: ["AmbiguousConsumer"]
        ),
    ],
    targets: [
        .target(name: "FirstOwner"),
        .target(name: "SecondOwner"),
        .target(
            name: "AmbiguousConsumer",
            dependencies: ["FirstOwner", "SecondOwner"]
        ),
    ]
)
