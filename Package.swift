// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-cardano-cips",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "swift-cardano-cips",
            targets: ["swift-cardano-cips"]),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "swift-cardano-cips"),
        .testTarget(
            name: "swift-cardano-cipsTests",
            dependencies: ["swift-cardano-cips"]
        ),
    ]
)
