// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "UniFiTests",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "t_unifi", targets: ["UniFiTests"]),
    ],
    dependencies: [
        .package(url: "https://github.com/leviouwendijk/Errors.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Milieu.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Difference.git", branch: "master"),
        .package(path: ".."),
    ],
    targets: [
        .executableTarget(
            name: "UniFiTests",
            dependencies: [
                .product(name: "UniFi", package: "UniFi"),
                .product(name: "UniFiPlanning", package: "UniFi"),
                .product(name: "Difference", package: "Difference"),
                .product(name: "Milieu", package: "Milieu"),
                .product(name: "Errors", package: "Errors"),
            ]
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
