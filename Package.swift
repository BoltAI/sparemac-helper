// swift-tools-version: 6.0
// Builds only Sparemac's privileged helper, from the same files as the app's release.
import PackageDescription

let package = Package(
    name: "SparemacHelper",
    platforms: [.macOS(.v15)],
    targets: [
        .target(name: "SparemacShared"),
        .executableTarget(name: "SparemacHelper", dependencies: ["SparemacShared"]),
    ],
    swiftLanguageModes: [.v5]
)
