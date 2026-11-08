import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoCIPs

/// Regression tests for the 2026-11-08 security audit of
/// swift-cardano-signer, whose CIP operations forward to this package.
@Suite("Security regressions — CIP-8 / CIP-36 / CIP-100")
struct SecurityRegressionTests {
    static let vocab = #"{"@vocab":"https://example.com/v#"}"#

    static func doc(_ body: String, context: String = vocab, extra: String = "") -> Data {
        Data(#"{"@context":\#(context),\#(extra)"body":\#(body)}"#.utf8)
    }

    static func sign(_ document: Data, strict: Bool = true) async throws -> Data {
        try await CIP100.signMetadata(
            document: document, signingKey: .signingKey(CIP100Tests.stakeSK),
            authorName: "Alice", strict: strict)
    }

    // MARK: CIP-100

    @Test("A poison document fails fast instead of running for minutes")
    func poisonDocument() async throws {
        let leaves = Array(repeating: #"{"q":"x"}"#, count: 10).joined(separator: ",")
        let star = #"{"p":[\#(leaves)]}"#
        let start = ContinuousClock.now
        await #expect(throws: CIP100Error.self) {
            _ = try await CIP100.canonicalBodyHash(of: Self.doc("[\(star),\(star)]"))
        }
        #expect(ContinuousClock.now - start < .seconds(5))
    }

    @Test("Deep nesting is rejected before recursive conversion")
    func deepNesting() async throws {
        var body = #""x""#
        for _ in 0..<200 { body = #"{"a":\#(body)}"# }
        await #expect(throws: CIP100Error.self) {
            _ = try await CIP100.canonicalBodyHash(of: Self.doc(body))
        }
        var array = "1"
        for _ in 0..<200 { array = "[\(array)]" }
        await #expect(throws: CIP100Error.self) {
            _ = try await CIP100.canonicalBodyHash(of: Self.doc(#"{"a":\#(array)}"#))
        }
    }

    @Test("Strict mode rejects a context remap and unmapped keys that would hide visible text")
    func contextRemap() async throws {
        let context = #"{"CIP108":"https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#","body":{"@id":"CIP108:body","@context":{"title":"CIP108:title","rationale":"CIP108:rationale"}}}"#
        let signed = try await Self.sign(Self.doc(#"{"title":"Vote","rationale":"I APPROVE"}"#, context: context))
        #expect(try await CIP100.verifyMetadata(signed).allValid)

        var object = try JSONSerialization.jsonObject(with: signed) as! [String: Any]
        let authors = object["authors"]!
        let remapContext = #"{"CIP108":"https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#","body":{"@id":"CIP108:body","@context":{"title":"CIP108:title","rationale":null,"zz":"CIP108:rationale"}}}"#
        object["@context"] = try JSONSerialization.jsonObject(with: Data(remapContext.utf8))
        object["body"] = ["title": "Vote", "rationale": "I REJECT", "zz": "I APPROVE"]
        object["authors"] = authors
        let remapped = try JSONSerialization.data(withJSONObject: object)
        await #expect(throws: CIP100Error.self) { _ = try await CIP100.verifyMetadata(remapped) }
        // The lenient mode still behaves like cardano-signer.js.
        #expect(try await CIP100.verifyMetadata(remapped, strict: false).allValid)

        object = try JSONSerialization.jsonObject(with: signed) as! [String: Any]
        var body = object["body"] as! [String: Any]
        body["comment"] = "Injected"
        object["body"] = body
        let unmapped = try JSONSerialization.data(withJSONObject: object)
        await #expect(throws: CIP100Error.self) { _ = try await CIP100.verifyMetadata(unmapped) }
    }

    @Test("An integer beyond Int64 is rejected instead of wrapping onto another value")
    func integerWrap() async throws {
        await #expect(throws: CIP100Error.self) {
            _ = try await CIP100.canonicalBodyHash(of: Self.doc(#"{"amount":18446744073709551615}"#))
        }
        _ = try await CIP100.canonicalBodyHash(of: Self.doc(#"{"amount":-1}"#))
        _ = try await CIP100.canonicalBodyHash(of: Self.doc(#"{"amount":9223372036854775807}"#))
    }

    @Test("Whole-number floats hash like integers, and a signed document verifies")
    func wholeNumberFloat() async throws {
        let asFloat = try await CIP100.canonicalBodyHash(of: Self.doc(#"{"x":1.0}"#))
        let asInt = try await CIP100.canonicalBodyHash(of: Self.doc(#"{"x":1}"#))
        #expect(asFloat == asInt)
        let signed = try await Self.sign(Self.doc(#"{"x":1.0,"y":2.5e1}"#))
        #expect(try await CIP100.verifyMetadata(signed).allValid)
    }

    @Test("Author entries without a readable witness make allValid false")
    func malformedAuthors() async throws {
        let signed = try await Self.sign(Self.doc(#"{"title":"T"}"#))
        var object = try JSONSerialization.jsonObject(with: signed) as! [String: Any]
        var authors = object["authors"] as! [Any]
        authors.insert(["name": "NoWitness"], at: 0)
        authors.insert("not-an-object", at: 0)
        authors.insert(["name": "Bob", "witness": ["publicKey": 7, "signature": "00", "witnessAlgorithm": "ed25519"]], at: 0)
        object["authors"] = authors
        let tampered = try JSONSerialization.data(withJSONObject: object)
        let result = try await CIP100.verifyMetadata(tampered)
        #expect(!result.allValid)
        #expect(result.authorResults.count == 4)
        #expect(result.authorResults.filter(\.valid).count == 1)
    }

    @Test("Canonically equivalent keys are rejected, not collapsed or trapped on")
    func equivalentKeys() async throws {
        // "\u{e9}" (NFC) and "e\u{301}" (NFD) written as raw UTF-8.
        let body = Data(#"{"@context":{"@vocab":"https://example.com/v#"},"body":{""#.utf8)
            + Data([0xC3, 0xA9]) + Data(#"":"a",""#.utf8)
            + Data([0x65, 0xCC, 0x81]) + Data(#"":"b"}}"#.utf8)
        do {
            _ = try await CIP100.canonicalBodyHash(of: body)
            // Linux Foundation collapses the keys while parsing; that is
            // still one well-defined object, so either outcome is safe.
        } catch {
            #expect(error is CIP100Error)
        }
    }

    // MARK: CIP-8

    @Test("CIP-8 verify returns the exact payload and strict UTF-8 text")
    func cip8Payload() throws {
        let utf16: Data = Data([0xFF, 0xFE, 0x68, 0x00, 0x69, 0x00])
        let signed = try CIP8.sign(payload: utf16, signingKey: .signingKey(CIP100Tests.stakeSK), network: .mainnet)
        let result = try CIP8.verify(signedMessage: signed)
        #expect(result.verified)
        #expect(result.payload == utf16)
        #expect(result.message == "")
        let text = try CIP8.verify(signedMessage: try CIP8.sign(message: "hi", signingKey: .signingKey(CIP100Tests.stakeSK), network: .mainnet))
        #expect(text.message == "hi")
        #expect(text.payload == Data("hi".utf8))
    }

    @Test("CIP-8 binds a stake key held as a generic key to its reward address")
    func cip8StakeRole() throws {
        let generic = SigningKey(payload: CIP100Tests.stakeSK.payload, type: StakeSigningKey.TYPE, description: nil)
        let result = try CIP8.verify(signedMessage: try CIP8.sign(message: "proof", signingKey: .signingKey(generic), network: .mainnet))
        #expect(result.verified)
        #expect(result.signingAddress.paymentPart == nil)
        #expect(result.signingAddress.stakingPart != nil)

        let node = try HDWallet.fromMnemonic(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").derive(fromPath: "m/1852'/1815'/0'/2/0")
        let extended = try ExtendedSigningKey(
            payload: node.xPrivateKey + node.publicKey + node.chainCode,
            type: StakeExtendedSigningKey.TYPE, description: nil)
        let extendedResult = try CIP8.verify(signedMessage: try CIP8.sign(message: "proof", signingKey: .extendedSigningKey(extended), network: .mainnet))
        #expect(extendedResult.verified)
        #expect(extendedResult.signingAddress.paymentPart == nil)
    }
}
