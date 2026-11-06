// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "UniFi",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "UniFi", targets: ["UniFi"]),
        .library(name: "UniFiPlanning", targets: ["UniFiPlanning"]),
        .executable(name: "t_unifi", targets: ["UniFiTests"]),
    ],
    dependencies: [
        .package(url: "https://github.com/leviouwendijk/Primitives.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/HTTP.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Milieu.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Difference.git", branch: "master"),
    ],
    targets: [
        .target(
            name: "UniFi",
            dependencies: [
                .product(name: "Primitives", package: "Primitives"),
                .product(name: "HTTP", package: "HTTP"),
                .product(name: "Milieu", package: "Milieu"),
            ],
            path: "Sources/UniFi"
        ),
        .target(
            name: "UniFiPlanning",
            dependencies: [
                "UniFi",
                .product(name: "Primitives", package: "Primitives"),
                .product(name: "Difference", package: "Difference"),
            ],
            path: "Sources/UniFiPlanning"
        ),
        .executableTarget(
            name: "UniFiTests",
            dependencies: [
                "UniFi",
                "UniFiPlanning",
                .product(name: "Difference", package: "Difference"),
                .product(name: "Milieu", package: "Milieu"),
            ],
            path: "Testing/UniFiTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)

for target in package.targets {
    switch target.type {
    case .regular, .executable, .test, .macro:
        var settings = target.swiftSettings ?? []
        settings.append(.treatAllWarnings(as: .error))
        settings.append(.unsafeFlags(["-continue-building-after-errors"]))
        target.swiftSettings = settings
    case .plugin, .system, .binary:
        break
    @unknown default:
        break
    }
}
