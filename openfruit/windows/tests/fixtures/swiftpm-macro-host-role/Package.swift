// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "MacroHostRoleProbe",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "MacroHostRoleProbe", targets: ["MacroHostRoleProbe"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/LePips/StatefulMacro",
            exact: "0.1.7"
        ),
    ],
    targets: [
        .target(
            name: "MacroHostRoleProbe",
            dependencies: [
                .product(name: "StatefulMacros", package: "StatefulMacro"),
            ]
        ),
    ]
)
