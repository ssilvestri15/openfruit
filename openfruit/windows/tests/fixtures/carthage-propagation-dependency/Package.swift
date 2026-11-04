// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "PropagationDependency",
    platforms: [.iOS(.v18)],
    products: [
        .library(
            name: "PropagationDependency",
            targets: ["PropagationDependency"]
        ),
    ],
    targets: [
        .target(name: "PropagationDependency"),
    ]
)
