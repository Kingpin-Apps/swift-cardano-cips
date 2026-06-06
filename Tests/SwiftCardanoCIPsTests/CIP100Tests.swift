import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoCIPs

@Suite("CIP-100 — governance metadata sign / verify")
struct CIP100Tests {

    // Reusing the same Genesis stake key fixture as CIP-8 / CIP-36 — its
    // verification key is widely cross-referenced across the suite so a
    // regression here surfaces against a known oracle.
    static let stakeSK = try! StakeSigningKey.fromTextEnvelope(
        """
        {
            "type": "StakeSigningKeyShelley_ed25519",
            "description": "Stake Signing Key",
            "cborHex": "5820ff3a330df8859e4e5f42a97fcaee73f6a00d0cf864f4bca902bd106d423f02c0"
        }
        """
    )

    static let stakeVK = try! StakeVerificationKey.fromTextEnvelope(
        """
        {
            "type": "StakeVerificationKeyShelley_ed25519",
            "description": "Stake Verification Key",
            "cborHex": "58205edaa384c658c2bd8945ae389edac0a5bd452d0cfd5d1245e3ecd540030d1e3c"
        }
        """
    )

    // A minimal CIP-100-shaped governance document with an inline
    // `@vocab` context, so the JSON-LD processor expands the body keys
    // to RDF properties instead of dropping them. Real CIP-100
    // documents reference the canonical Cardano-Foundation context
    // URLs; we use `@vocab` here purely to keep the test fixture
    // self-contained (no network reads during test runs).
    static let exampleDocument: Data = """
    {
      "@context": { "@vocab": "https://example.com/cip-100#" },
      "hashAlgorithm": "blake2b-256",
      "body": {
        "comment": "Proposal: extend the network upgrade timeline.",
        "references": []
      }
    }
    """.data(using: .utf8)!

    // MARK: - Hash determinism

    @Test("canonicalBodyHash is deterministic for the same input")
    func canonicalBodyHashIsDeterministic() async throws {
        let a = try await CIP100.canonicalBodyHash(of: Self.exampleDocument)
        let b = try await CIP100.canonicalBodyHash(of: Self.exampleDocument)
        #expect(a == b)
        #expect(a.count == 32)
    }

    @Test("canonicalBodyHash ignores authors (so adding witnesses doesn't change the hash)")
    func canonicalBodyHashIgnoresAuthors() async throws {
        let withoutAuthors = Self.exampleDocument
        let withAuthors = """
        {
          "@context": { "@vocab": "https://example.com/cip-100#" },
          "hashAlgorithm": "blake2b-256",
          "body": {
            "comment": "Proposal: extend the network upgrade timeline.",
            "references": []
          },
          "authors": [
            {
              "name": "Alice",
              "witness": {
                "witnessAlgorithm": "ed25519",
                "publicKey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "signature": "0011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344"
              }
            }
          ]
        }
        """.data(using: .utf8)!

        let hashA = try await CIP100.canonicalBodyHash(of: withoutAuthors)
        let hashB = try await CIP100.canonicalBodyHash(of: withAuthors)
        #expect(hashA == hashB)
    }

    @Test("canonicalBodyHash differs when the body changes")
    func canonicalBodyHashChangesWithBody() async throws {
        let altered = """
        {
          "@context": { "@vocab": "https://example.com/cip-100#" },
          "hashAlgorithm": "blake2b-256",
          "body": {
            "comment": "Proposal: SHRINK the network upgrade timeline.",
            "references": []
          }
        }
        """.data(using: .utf8)!

        let original = try await CIP100.canonicalBodyHash(of: Self.exampleDocument)
        let modified = try await CIP100.canonicalBodyHash(of: altered)
        #expect(original != modified)
    }

    // MARK: - Sign + verify

    @Test("signMetadata appends an author entry with a verifiable Ed25519 witness")
    func signAppendsVerifiableWitness() async throws {
        let signed = try await CIP100.signMetadata(
            document: Self.exampleDocument,
            signingKey: .signingKey(Self.stakeSK),
            authorName: "Alice"
        )

        let result = try await CIP100.verifyMetadata(signed)
        #expect(result.allValid)
        #expect(result.authorResults.count == 1)
        #expect(result.authorResults[0].name == "Alice")
        #expect(result.authorResults[0].valid)
        #expect(result.authorResults[0].publicKey == Self.stakeVK.payload)
    }

    @Test("Multiple authors verify independently")
    func multipleAuthorsRoundTrip() async throws {
        // Second key derived in-test so we have two distinct authors.
        let secondSK = try StakeSigningKey.fromTextEnvelope(
            """
            {
                "type": "StakeSigningKeyShelley_ed25519",
                "description": "Stake Signing Key",
                "cborHex": "58200000000000000000000000000000000000000000000000000000000000000001"
            }
            """
        )

        let signedOnce = try await CIP100.signMetadata(
            document: Self.exampleDocument,
            signingKey: .signingKey(Self.stakeSK),
            authorName: "Alice"
        )
        let signedTwice = try await CIP100.signMetadata(
            document: signedOnce,
            signingKey: .signingKey(secondSK),
            authorName: "Bob"
        )

        let result = try await CIP100.verifyMetadata(signedTwice)
        #expect(result.allValid)
        #expect(result.authorResults.count == 2)
        #expect(result.authorResults.map(\.name) == ["Alice", "Bob"])
        #expect(result.authorResults.allSatisfy { $0.valid })
    }

    @Test("Tampering with the body invalidates every author signature")
    func tamperedBodyFailsVerification() async throws {
        let signed = try await CIP100.signMetadata(
            document: Self.exampleDocument,
            signingKey: .signingKey(Self.stakeSK),
            authorName: "Alice"
        )

        var tamperedString = String(data: signed, encoding: .utf8)!
        tamperedString = tamperedString.replacingOccurrences(
            of: "extend the network upgrade timeline",
            with: "EXTEND THE NETWORK UPGRADE TIMELINE"
        )
        let tampered = tamperedString.data(using: .utf8)!

        let result = try await CIP100.verifyMetadata(tampered)
        #expect(!result.allValid)
        #expect(result.authorResults.count == 1)
        #expect(!result.authorResults[0].valid)
    }

    @Test("Verifying a document with no authors returns allValid: false")
    func noAuthorsMeansNotValid() async throws {
        let result = try await CIP100.verifyMetadata(Self.exampleDocument)
        #expect(!result.allValid)
        #expect(result.authorResults.isEmpty)
        #expect(result.canonicalBodyHash.count == 32)
    }

    // MARK: - Error cases

    @Test("Non-JSON input throws")
    func nonJSONThrows() async {
        await #expect(throws: CIP100Error.self) {
            _ = try await CIP100.canonicalBodyHash(
                of: Data("definitely not json {".utf8)
            )
        }
    }

    @Test("Non-object top-level JSON throws")
    func nonObjectThrows() async {
        await #expect(throws: CIP100Error.self) {
            _ = try await CIP100.canonicalBodyHash(
                of: Data("[1, 2, 3]".utf8)
            )
        }
    }
}
