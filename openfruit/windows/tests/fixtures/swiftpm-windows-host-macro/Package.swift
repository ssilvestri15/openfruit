// swift-tools-version: 6.0

import CompilerPluginSupport
import PackageDescription

let package = Package(
    name: "WindowsHostMacroContract",
    platforms: [.iOS(.v16)],
    products: [
        .library(
            name: "OPENFRUITXcodePackages",
            type: .static,
            targets: ["OPENFRUITXcodePackages"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/swiftlang/swift-syntax.git",
            exact: "600.0.1"
        ),
    ],
    targets: [
        .macro(
            name: "PortableBuildTool",
            dependencies: [
                .product(name: "SwiftCompilerPlugin", package: "swift-syntax"),
                .product(name: "SwiftSyntax", package: "swift-syntax"),
                .product(name: "SwiftSyntaxBuilder", package: "swift-syntax"),
                .product(name: "SwiftSyntaxMacros", package: "swift-syntax"),
            ]
        ),
        .target(
            name: "WindowsHostMacroContract",
            dependencies: ["PortableBuildTool"]
        ),
        .target(
            name: "WindowsHostMacroConsumer",
            dependencies: ["WindowsHostMacroContract"]
        ),
        .target(
            name: "OPENFRUITXcodePackages",
            dependencies: ["WindowsHostMacroConsumer"]
        ),
    ]
)
