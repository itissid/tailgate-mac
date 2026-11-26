// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TailgateMac", platforms: [.macOS(.v13)],
    products: [
        .executable(name: "TailgateReview", targets: ["TailgateReview"]),
        .executable(name: "tailgate-preview", targets: ["TailgatePreview"])
    ],
    targets: [
        .target(name: "TailgateCore"),
        .executableTarget(name: "TailgateReview", dependencies: ["TailgateCore"]),
        .executableTarget(name: "TailgatePreview", dependencies: ["TailgateCore"]),
        .testTarget(name: "TailgateCoreTests", dependencies: ["TailgateCore"])
    ]
)
