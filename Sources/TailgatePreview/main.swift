import Darwin
import Foundation
import TailgateCore

// Read-only: stdin or built-in fixture, stdout only after strict compilation.
// No submit/approve flags, no prompts, no sudo, no machine operations.
@main enum Preview {
    @MainActor static func main() {
        do {
            let proposal: Data
            switch Array(CommandLine.arguments.dropFirst()) {
            case []: proposal = Compiler.example
            case ["--stdin"]:
                var bytes = Data()
                while bytes.count <= 16_384 {
                    guard let chunk = try FileHandle.standardInput.read(upToCount: min(4096, 16_385 - bytes.count)), !chunk.isEmpty else { break }
                    bytes.append(chunk)
                }
                proposal = bytes
            default:
                FileHandle.standardError.write(Data("Usage: tailgate-preview [--stdin]\n".utf8)); exit(2)
            }
            let review = try DryRunSession().reviewPolicy(proposal: proposal)
            print(review.text); print("\nReview SHA-256: \(review.fingerprint)\nPreview only; no operations attempted.")
        } catch {
            // Never echo raw input, file paths, library errors, keys or response bodies.
            FileHandle.standardError.write(Data("Proposal rejected; no operations attempted.\n".utf8)); exit(1)
        }
    }
}
