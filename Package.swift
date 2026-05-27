// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftCardanoCIPs",
    platforms: [
      .iOS(.v16),
      .macOS(.v14),
      .watchOS(.v9),
      .tvOS(.v16),
      .visionOS(.v1),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftCardanoCIPs",
            targets: ["SwiftCardanoCIPs"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Kingpin-Apps/swift-cbor-codable.git", from: "0.3.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cose.git", from: "0.2.1"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-core.git", from: "0.4.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-ncal.git", .upToNextMinor(from: "0.3.0")),
        // Provides CryptoKit-compatible APIs on Linux where CryptoKit itself is unavailable.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.15.1"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftCardanoCIPs",
            dependencies: [
                .product(name: "CBORCodable", package: "swift-cbor-codable"),
                .product(name: "SwiftCOSE", package: "swift-cose"),
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
                .product(name: "SwiftNcal", package: "swift-ncal"),
                .product(
                    name: "Crypto",
                    package: "swift-crypto",
                    condition: .when(platforms: [.linux])
                ),
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
