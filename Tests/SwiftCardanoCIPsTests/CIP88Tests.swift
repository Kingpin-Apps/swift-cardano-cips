import Foundation
import Testing
import CBORCodable
import OrderedCollections
import SwiftCardanoCore
import SwiftNaCl
@testable import SwiftCardanoCIPs

@Suite("CIP-88 v2 / CIP-151 — Calidus pool-key registration")
struct CIP88Tests {

    // A non-extended pool cold key. CIP-151 expects a 32-byte verification
    // key, so we use the standard StakePoolSigningKey type (ed25519, not
    // ed25519_bip32). Reusing the same Genesis test seed as CIP-8 / CIP-36
    // gives us a stable, reproducible fixture across the suite.
    static let poolSK = try! StakePoolSigningKey(
        payload: Data(hex: "093be5cd3987d0c9fd8854ef908f7746b69e2d73320db6dc0f780d81585b84c2")
    )

    static let poolVK: StakePoolVerificationKey = {
        let derived: StakePoolVerificationKey = try! Self.poolSK.toVerificationKey()
        return derived
    }()

    // 32-byte test Calidus key (arbitrary fixed bytes).
    static let calidusKey = Data(repeating: 0xCA, count: 32)

    // MARK: - Envelope shape

    @Test("Registration carries the {0:2, 1:payload, 2:[witness]} envelope under label 867")
    func envelopeShape() throws {
        let aux = try CIP88.makeCalidusRegistration(
            calidusPublicKey: Self.calidusKey,
            poolSigningKey: .signingKey(Self.poolSK),
            nonce: 1
        )

        guard case let .metadata(metadata) = aux.data,
              case let .map(envelope) = metadata.data[867] else {
            Issue.record("Expected map under label 867")
            return
        }

        // Version
        guard case let .int(version) = envelope[.int(0)] else {
            Issue.record("Missing version field at envelope[0]")
            return
        }
        #expect(version == 2)

        // Payload object is a map.
        guard case .map(_) = envelope[.int(1)] else {
            Issue.record("envelope[1] is not a payload map")
            return
        }

        // Witnesses is a non-empty list of maps.
        guard case let .list(witnesses) = envelope[.int(2)],
              !witnesses.isEmpty,
              case .map(_) = witnesses[0] else {
            Issue.record("envelope[2] is not a non-empty witness array")
            return
        }
        #expect(witnesses.count == 1)
    }

    // MARK: - Payload fields

    @Test("Payload contains scope, feature set, validation method, nonce, and calidus key in the expected positions")
    func payloadFields() throws {
        let aux = try CIP88.makeCalidusRegistration(
            calidusPublicKey: Self.calidusKey,
            poolSigningKey: .signingKey(Self.poolSK),
            nonce: 9_999
        )

        guard case let .metadata(metadata) = aux.data,
              case let .map(envelope) = metadata.data[867],
              case let .map(payload) = envelope[.int(1)] else {
            Issue.record("Could not unwrap payload")
            return
        }

        // 1: scope = [1 (pool), poolID 28 bytes]
        guard case let .list(scope) = payload[.int(1)],
              scope.count == 2,
              case let .int(scopeID) = scope[0],
              case let .bytes(poolID) = scope[1] else {
            Issue.record("scope shape mismatch")
            return
        }
        #expect(scopeID == 1)
        #expect(poolID.count == 28)
        // Pool ID is blake2b-224 of the pool verification key.
        let expectedPoolID = try SwiftNaCl.Hash().blake2b(
            data: Self.poolVK.payload,
            digestSize: 28,
            encoder: RawEncoder.self
        )
        #expect(poolID == expectedPoolID)

        // 2: feature_set = []
        guard case let .list(features) = payload[.int(2)], features.isEmpty else {
            Issue.record("feature_set should be empty list")
            return
        }

        // 3: validation_method = [0]
        guard case let .list(methods) = payload[.int(3)],
              methods.count == 1,
              case let .int(method) = methods[0] else {
            Issue.record("validation_method shape mismatch")
            return
        }
        #expect(method == 0)

        // 4: nonce
        guard case let .int(nonce) = payload[.int(4)] else {
            Issue.record("nonce missing")
            return
        }
        #expect(nonce == 9_999)

        // 7: calidus key
        guard case let .bytes(calidus) = payload[.int(7)] else {
            Issue.record("calidus key missing at field 7")
            return
        }
        #expect(calidus == Self.calidusKey)
    }

    // MARK: - Witness shape & signature verification

    @Test("Witness map carries {0: type=0, 1: poolVKey 32 bytes, 2: signature 64 bytes}")
    func witnessShape() throws {
        let aux = try CIP88.makeCalidusRegistration(
            calidusPublicKey: Self.calidusKey,
            poolSigningKey: .signingKey(Self.poolSK),
            nonce: 1
        )

        guard case let .metadata(metadata) = aux.data,
              case let .map(envelope) = metadata.data[867],
              case let .list(witnesses) = envelope[.int(2)],
              case let .map(witness) = witnesses[0] else {
            Issue.record("Could not unwrap witness")
            return
        }

        guard case let .int(witnessType) = witness[.int(0)],
              case let .bytes(witnessKey) = witness[.int(1)],
              case let .bytes(signature) = witness[.int(2)] else {
            Issue.record("Witness fields missing")
            return
        }
        #expect(witnessType == 0)
        #expect(witnessKey == Self.poolVK.payload)
        #expect(witnessKey.count == 32)
        #expect(signature.count == 64)
    }

    @Test("Witness signature verifies over blake2b_256(hex(CBOR(payload)))")
    func witnessSignatureVerifies() throws {
        let aux = try CIP88.makeCalidusRegistration(
            calidusPublicKey: Self.calidusKey,
            poolSigningKey: .signingKey(Self.poolSK),
            nonce: 42
        )

        guard case let .metadata(metadata) = aux.data,
              case let .map(envelope) = metadata.data[867],
              let payload = envelope[.int(1)],
              case let .list(witnesses) = envelope[.int(2)],
              case let .map(witness) = witnesses[0],
              case let .bytes(signature) = witness[.int(2)] else {
            Issue.record("Could not extract verification inputs")
            return
        }

        // Reconstruct the signing payload exactly as CIP-151 v2 specifies:
        //   1. CBOR-encode the payload object.
        //   2. Hex-encode (lowercase ASCII, no prefix).
        //   3. Take the UTF-8 bytes of that hex string.
        //   4. Blake2b-256 of those bytes.
        let payloadCBOR = try payload.toCBORData()
        let hexString = payloadCBOR.map { String(format: "%02x", $0) }.joined()
        let signingHash = try SwiftNaCl.Hash().blake2b(
            data: Data(hexString.utf8),
            digestSize: 32,
            encoder: RawEncoder.self
        )

        let verifyKey = try VerifyKey(key: Self.poolVK.payload)
        _ = try verifyKey.verify(smessage: signingHash, signature: signature)
        // verify() throws on bad signature; reaching here = pass.
    }

    // MARK: - Validation

    @Test("Wrong-length Calidus key throws")
    func wrongLengthCalidusKey() {
        #expect(throws: CIP88Error.self) {
            _ = try CIP88.makeCalidusRegistration(
                calidusPublicKey: Data(repeating: 0xCA, count: 31),
                poolSigningKey: .signingKey(Self.poolSK),
                nonce: 1
            )
        }
        #expect(throws: CIP88Error.self) {
            _ = try CIP88.makeCalidusRegistration(
                calidusPublicKey: Data(repeating: 0xCA, count: 64),
                poolSigningKey: .signingKey(Self.poolSK),
                nonce: 1
            )
        }
    }
}

// MARK: - Hex helper

private extension Data {
    init(hex: String) {
        let clean = hex.unicodeScalars.filter { !$0.properties.isWhitespace }
        precondition(clean.count.isMultiple(of: 2))
        var bytes = [UInt8]()
        bytes.reserveCapacity(clean.count / 2)
        var iter = clean.makeIterator()
        while let hi = iter.next(), let lo = iter.next() {
            guard let h = UInt8(String(hi), radix: 16),
                  let l = UInt8(String(lo), radix: 16) else {
                preconditionFailure("invalid hex")
            }
            bytes.append(h << 4 | l)
        }
        self.init(bytes)
    }
}
