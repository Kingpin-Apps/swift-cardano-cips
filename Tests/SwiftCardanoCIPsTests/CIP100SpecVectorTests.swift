import Foundation
import SwiftCardanoCore
import Testing

@testable import SwiftCardanoCIPs

/// The official CIP-100 test vector: `CIP-0100/example.json` and `test-vector.md` in
/// https://github.com/cardano-foundation/CIPs (CC-BY-4.0), copied as
/// `data/cip100-example.json`.
@Suite("CIP-100 official test vector")
struct CIP100SpecVectorTests {
    static func example() throws -> Data {
        let path = try #require(Bundle.module.path(forResource: "cip100-example", ofType: "json", inDirectory: "data"))
        return try Data(contentsOf: URL(fileURLWithPath: path))
    }

    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    /// test-vector.md: "Blake2b-256 hash digest of canonicalized body:
    /// 6d17e71c5793ed5945f58bf48e13bb1b3543187ab9c2afbd280a21afb4a90d35".
    @Test func canonicalBodyHashMatchesSpec() async throws {
        let hash = try await CIP100.canonicalBodyHash(of: Self.example())
        #expect(Self.hex(hash) == "6d17e71c5793ed5945f58bf48e13bb1b3543187ab9c2afbd280a21afb4a90d35")
    }

    /// The example's author witness (Pi Lanningham, key 7ea09a34…) must verify.
    @Test func authorWitnessVerifies() async throws {
        let result = try await CIP100.verifyMetadata(Self.example())
        #expect(result.authorResults.count == 1)
        #expect(result.authorResults.first?.name == "Pi Lanningham")
        #expect(result.authorResults.first.map { Self.hex($0.publicKey) } == "7ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a")
        #expect(result.allValid)
    }

    /// Only `@context` and `body` are hashed. The old code hashed everything but
    /// `authors`, so `hashAlgorithm` (mapped in the example's context) changed the hash.
    @Test func topLevelFieldsOutsideBodyDoNotChangeTheHash() async throws {
        var object = try #require(try JSONSerialization.jsonObject(with: Self.example()) as? [String: Any])
        object["hashAlgorithm"] = "something-else"
        object["authors"] = []
        let changed = try JSONSerialization.data(withJSONObject: object)
        let hash = try await CIP100.canonicalBodyHash(of: changed)
        #expect(Self.hex(hash) == "6d17e71c5793ed5945f58bf48e13bb1b3543187ab9c2afbd280a21afb4a90d35")
    }

    @Test func documentWithoutBodyThrows() async throws {
        let document = Data(#"{"@context": {"@vocab": "https://example.com/"}, "hashAlgorithm": "blake2b-256"}"#.utf8)
        await #expect(throws: CIP100Error.missingField("body")) {
            try await CIP100.canonicalBodyHash(of: document)
        }
    }

    /// Re-signing the example body with the test vector's author key gives the
    /// published signature (Ed25519 is deterministic). The vector gives the 64-byte
    /// extended private key and the public key; the chain code plays no part in
    /// signing, so it's zero here.
    @Test func signingWithTheVectorKeyReproducesTheSignature() async throws {
        let privateKey = Data(hex: "105d2ef2192150655a926bca9cccf5e2f6e496efa9580508192e1f4a790e6f53de06529129511d1cacb0664bcf04853fdc0055a47cc6d2c6d205127020760652")
        let publicKey = Data(hex: "7ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a")
        let key = try PaymentExtendedSigningKey(payload: privateKey + publicKey + Data(count: 32))

        var object = try #require(try JSONSerialization.jsonObject(with: Self.example()) as? [String: Any])
        object.removeValue(forKey: "authors")
        let unsigned = try JSONSerialization.data(withJSONObject: object)

        let signed = try await CIP100.signMetadata(
            document: unsigned,
            signingKey: .extendedSigningKey(key),
            authorName: "Pi Lanningham"
        )
        let signedObject = try #require(try JSONSerialization.jsonObject(with: signed) as? [String: Any])
        let authors = try #require(signedObject["authors"] as? [[String: Any]])
        let witness = try #require(authors.first?["witness"] as? [String: Any])
        #expect(witness["publicKey"] as? String == "7ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a")
        #expect(witness["signature"] as? String == "68078efeff90970d2320a2bb5021d1aea81bc4907bf33d54fd17989f020719f3f5c4da3dccf7aa61d51c1e6fececd95309c37e7eef331b199cd5f8e78992ea0d")
        #expect(try await CIP100.verifyMetadata(signed).allValid)
    }
}
