// swift-tools-version: 6.1
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
        .library(
            name: "SwiftCardanoCIPs",
            targets: ["SwiftCardanoCIPs"]),
        // CIP-21 on its own, with no dependencies, for transaction builders.
        .library(
            name: "SwiftCardanoCIP21",
            targets: ["SwiftCardanoCIP21"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", "5.7.0"..<"7.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cbor-codable.git", from: "0.3.2"),
        // 1.3.2 takes BigInt 6 as well as 5, so this package can sit beside apps on BigInt 6.
        .package(url: "https://github.com/Kingpin-Apps/swift-cose.git", from: "1.3.2"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-core.git", from: "0.4.6"),
        .package(url: "https://github.com/Kingpin-Apps/swift-nacl.git", .upToNextMinor(from: "1.0.2")),
        .package(url: "https://github.com/Kingpin-Apps/swift-jsonld.git", .upToNextMinor(from: "0.1.3")),
    ],
    targets: [
        .target(name: "SwiftCardanoCIP21"),
        .target(
            name: "SwiftCardanoCIPs",
            dependencies: [
                "SwiftCardanoCIP21",
                "BigInt",
                .product(name: "CBORCodable", package: "swift-cbor-codable"),
                .product(name: "SwiftCOSE", package: "swift-cose"),
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
                .product(name: "SwiftNaCl", package: "swift-nacl"),
                .product(name: "JSONLD", package: "swift-jsonld"),
                .product(
                    name: "Crypto",
                    package: "swift-crypto",
                    condition: .when(platforms: [.linux])
                ),
            ]),
        .testTarget(
            name: "SwiftCardanoCIP21Tests",
            dependencies: ["SwiftCardanoCIP21"]
        ),
        .testTarget(
            name: "SwiftCardanoCIPsTests",
            dependencies: ["SwiftCardanoCIPs"],
            resources: [
               .copy("data")
           ]
        ),
    ]
)
