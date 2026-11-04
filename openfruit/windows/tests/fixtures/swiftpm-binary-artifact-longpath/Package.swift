// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftPMBinaryArtifactLongPath",
    platforms: [
        .iOS(.v18)
    ],
    products: [
        .library(
            name: "SwiftPMBinaryArtifactLongPath",
            targets: ["SwiftPMBinaryArtifactLongPath"]
        )
    ],
    targets: [
        .target(name: "SwiftPMBinaryArtifactLongPath"),
        .binaryTarget(
            name: "openapi-generator",
            url: "https://github.com/LePips/openapi-generator/releases/download/v0.7.1/openapi-generator.artifactbundle.zip",
            checksum: "a882367e67ddb2d23b596992dcde77d522b0c5e7301afe5c49d9c8c6523f8aca"
        )
    ]
)
