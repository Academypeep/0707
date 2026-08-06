// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MythosAgentDistributedDB",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "MythosAgentDistributedDB", targets: ["MythosAgentDistributedDB"])
    ],
    dependencies: [
        .package(url: "https://github.com/anthropics/ClaudeForFoundationModels.git", from: "0.1.0")
    ],
    targets: [
        .target(
            name: "MythosAgentDistributedDB",
            dependencies: [
                .product(name: "ClaudeForFoundationModels", package: "ClaudeForFoundationModels")
            ]
        )
    ]
)
