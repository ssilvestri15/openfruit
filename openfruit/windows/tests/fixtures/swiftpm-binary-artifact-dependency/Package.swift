// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftPMBinaryArtifactDependency",
    platforms: [.iOS(.v18)],
    products: [
        .library(
            name: "SwiftPMBinaryArtifactDependency",
            targets: ["SwiftPMBinaryArtifactDependency"]
        )
    ],
    dependencies: [
        .package(
            url: "https://github.com/jellyfin/jellyfin-sdk-swift.git",
            exact: "3.1.0"
        )
    ],
    targets: [
        .target(
            name: "SwiftPMBinaryArtifactDependency",
            dependencies: [
                .product(name: "JellyfinAPI", package: "jellyfin-sdk-swift")
            ]
        )
    ]
)
