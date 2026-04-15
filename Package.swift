// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "stallari-beacon",
    platforms: [
        .macOS(.v14),
    ],
    products: [
        .library(name: "StallariBeacon", targets: ["StallariBeacon"]),
    ],
    targets: [
        .target(
            name: "StallariBeacon",
            path: "Sources/StallariBeacon"
        ),
        .testTarget(
            name: "StallariBeaconTests",
            dependencies: ["StallariBeacon"],
            path: "Tests/StallariBeaconTests"
        ),
    ]
)
