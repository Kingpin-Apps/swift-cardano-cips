// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftCardanoCIPs",
    platforms: [
      .iOS(.v14),
      .macOS(.v14),
      .watchOS(.v7),
      .tvOS(.v14),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftCardanoCIPs",
            targets: ["SwiftCardanoCIPs"]),
    ],
    dependencies: [
        .package(url: "https://github.com/KINGH242/PotentCodables.git", .upToNextMinor(from: "3.6.0")),
        .package(url: "https://github.com/Kingpin-Apps/swift-cose.git", .upToNextMajor(from: "0.1.14")),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-core.git", .upToNextMinor(from: "0.1.29")),
        .package(url: "https://github.com/Kingpin-Apps/swift-ncal.git", .upToNextMinor(from: "0.1.4")),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftCardanoCIPs",
            dependencies: [
                "PotentCodables",
                .product(name: "SwiftCOSE", package: "swift-cose"),
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
                .product(name: "SwiftNcal", package: "swift-ncal"),
            ]),
        .testTarget(
            name: "SwiftCardanoCIPsTests",
            dependencies: ["SwiftCardanoCIPs"],
            resources: [
               .copy("data")
           ]
        ),
    ]
)
