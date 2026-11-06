import Foundation
import CBORCodable
import OrderedCollections
import SwiftCardanoCore
import Testing

@testable import SwiftCardanoCIPs

/// `CIP8.verify` takes untrusted input (a wallet's or dApp's signed message), so
/// every malformed message must throw, never trap.
@Suite struct CIP8MalformedInputTests {
    let sk = try! PaymentSigningKey.fromTextEnvelope(
        """
        {
            "type": "GenesisUTxOSigningKey_ed25519",
            "description": "Genesis Initial UTxO Signing Key",
            "cborHex": "5820093be5cd3987d0c9fd8854ef908f7746b69e2d73320db6dc0f780d81585b84c2"
        }
        """
    )

    let extendedSK = try! PaymentExtendedSigningKey.fromTextEnvelope(
        """
        {
            "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32",
            "description": "Payment Signing Key",
            "cborHex": "5880e8428867ab9cc9304379a3ce0c238a592bd6d2349d2ebaf8a6ed2c6d2974a15ad59c74b6d8fa3edd032c6261a73998b7deafe983b6eeaff8b6fb3fab06bdf8019b693a62bce7a3cad1b9c02d22125767201c65db27484bb67d3cee7df7288d62c099ac0ce4a215355b149fd3114a2a7ef0438f01f8872c4487a61b469e26aae4"
        }
        """
    )

    // MARK: Helpers

    static func encode(_ item: CBOR) -> Data {
        var writer = CBORWriter()
        try! writer.encode(item)
        return writer.data
    }

    static func hex(_ item: CBOR) -> String { encode(item).toHexString() }

    var vk: Data { get throws { try (sk.toVerificationKey() as PaymentVerificationKey).payload } }

    /// The enterprise address bytes for a 32-byte key.
    static func addressBytes(for key: Data) throws -> Data {
        let vkey = try PaymentVerificationKey(payload: key)
        return try Address(
            paymentPart: .verificationKeyHash(vkey.hash()),
            stakingPart: nil,
            network: .mainnet
        ).toBytes()
    }

    /// A COSE_Sign1 hex string (untagged, as CIP-30 returns it), signed over its
    /// Sig_structure by `sign` when given.
    static func sign1(
        protected: OrderedDictionary<CBOR, CBOR>,
        unprotected: CBOR = .map([.textString("hashed"): .boolean(false)]),
        payload: CBOR = .byteString(Data("hello".utf8)),
        signature: CBOR? = nil,
        sign: ((Data) throws -> Data)? = nil
    ) throws -> String {
        let protectedBytes = encode(.map(protected))
        var sig = signature ?? .byteString(Data(repeating: 0, count: 64))
        if let sign, case .byteString(let body) = payload {
            let structure = encode(.array([
                .textString("Signature1"), .byteString(protectedBytes), .byteString(Data()), .byteString(body),
            ]))
            sig = .byteString(try sign(structure))
        }
        return hex(.array([.byteString(protectedBytes), unprotected, payload, sig]))
    }

    /// A protected header `{alg: EdDSA, kid: key, "address": address}`.
    static func header(kid: CBOR?, address: CBOR?, alg: CBOR? = .negativeInt(7)) -> OrderedDictionary<CBOR, CBOR> {
        var h: OrderedDictionary<CBOR, CBOR> = [:]
        if let alg { h[.unsignedInt(1)] = alg }
        if let kid { h[.unsignedInt(4)] = kid }
        if let address { h[.textString("address")] = address }
        return h
    }

    func validHeader() throws -> OrderedDictionary<CBOR, CBOR> {
        let key = try vk
        return Self.header(kid: .byteString(key), address: .byteString(try Self.addressBytes(for: key)))
    }

    func expectThrows(
        _ message: SignedMessage,
        _ matches: (CIP8Error) -> Bool,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            _ = try CIP8.verify(signedMessage: message)
            Issue.record("Expected verify to throw", sourceLocation: sourceLocation)
        } catch let error as CIP8Error {
            #expect(matches(error), "Unexpected CIP8Error \(error)", sourceLocation: sourceLocation)
        } catch {
            Issue.record("Expected a CIP8Error, got \(error)", sourceLocation: sourceLocation)
        }
    }

    static func isDecoding(_ e: CIP8Error) -> Bool { if case .decodingError = e { true } else { false } }
    static func isKey(_ e: CIP8Error) -> Bool { if case .invalidKey = e { true } else { false } }
    static func isAddress(_ e: CIP8Error) -> Bool { if case .invalidAddress = e { true } else { false } }
    static func isSignature(_ e: CIP8Error) -> Bool { if case .invalidSignature = e { true } else { false } }

    // MARK: Envelope

    @Test(arguments: ["", "zz", "845", "84 0", "0x84"])
    func rejectsBadHex(_ signature: String) {
        expectThrows(SignedMessage(signature: signature), Self.isDecoding)
    }

    @Test func rejectsNonArrayAndWrongArity() {
        expectThrows(SignedMessage(signature: Self.hex(.map([:]))), Self.isDecoding)
        expectThrows(SignedMessage(signature: Self.hex(.array([]))), Self.isDecoding)
        expectThrows(
            SignedMessage(signature: Self.hex(.array([.byteString(Data()), .map([:]), .byteString(Data())]))),
            Self.isDecoding
        )
    }

    @Test func rejectsTrailingBytes() throws {
        let good = try Self.sign1(protected: try validHeader(), sign: sk.sign)
        expectThrows(SignedMessage(signature: good + "00"), Self.isDecoding)
    }

    @Test func rejectsProtectedHeaderThatIsNotAMap() {
        let notMap = Self.hex(.array([
            .byteString(Self.encode(.array([]))), .map([:]), .byteString(Data()), .byteString(Data()),
        ]))
        expectThrows(SignedMessage(signature: notMap), Self.isDecoding)
        let notCBOR = Self.hex(.array([
            .byteString(Data([0xff])), .map([:]), .byteString(Data()), .byteString(Data()),
        ]))
        expectThrows(SignedMessage(signature: notCBOR), Self.isDecoding)
        let notBytes = Self.hex(.array([
            .textString("a"), .map([:]), .byteString(Data()), .byteString(Data()),
        ]))
        expectThrows(SignedMessage(signature: notBytes), Self.isDecoding)
    }

    @Test func rejectsUnprotectedHeaderThatIsNotAMap() throws {
        let message = try Self.sign1(protected: try validHeader(), unprotected: .array([]), sign: sk.sign)
        expectThrows(SignedMessage(signature: message), Self.isDecoding)
    }

    /// Used to trap inside swift-cose's decoder (`payload!`).
    @Test func rejectsDetachedPayload() throws {
        let message = try Self.sign1(protected: try validHeader(), payload: .null)
        expectThrows(SignedMessage(signature: message), Self.isDecoding)
    }

    @Test func rejectsSignatureThatIsNotBytes() throws {
        let message = try Self.sign1(protected: try validHeader(), signature: .textString("sig"))
        expectThrows(SignedMessage(signature: message), Self.isSignature)
    }

    // MARK: Headers

    /// Used to trap on `phdr[address] as! Data`.
    @Test func rejectsMissingAddress() throws {
        let message = try Self.sign1(protected: Self.header(kid: .byteString(try vk), address: nil))
        expectThrows(SignedMessage(signature: message), Self.isAddress)
    }

    /// Used to trap on `phdr[address] as! Data`.
    @Test(arguments: [CBOR.textString("addr1..."), .unsignedInt(1), .byteString(Data())])
    func rejectsAddressThatIsNotBytes(_ address: CBOR) throws {
        let message = try Self.sign1(protected: Self.header(kid: .byteString(try vk), address: address))
        expectThrows(SignedMessage(signature: message), Self.isAddress)
    }

    @Test func throwsOnUndecodableAddressBytes() throws {
        let message = try Self.sign1(
            protected: Self.header(kid: .byteString(try vk), address: .byteString(Data([0xff, 0x01])))
        )
        #expect(throws: (any Error).self) { try CIP8.verify(signedMessage: SignedMessage(signature: message)) }
    }

    /// A non-EdDSA algorithm used to trap in swift-cose (`key as! EC2Key`).
    @Test(arguments: [CBOR.negativeInt(6), .negativeInt(34), .textString("EdDSA"), nil])
    func rejectsAlgorithmOtherThanEdDSA(_ alg: CBOR?) throws {
        let key = try vk
        let message = try Self.sign1(
            protected: Self.header(kid: .byteString(key), address: .byteString(try Self.addressBytes(for: key)), alg: alg)
        )
        expectThrows(SignedMessage(signature: message), Self.isSignature)
    }

    // MARK: Keys

    @Test func rejectsMissingKey() throws {
        let message = try Self.sign1(
            protected: Self.header(kid: nil, address: .byteString(try Self.addressBytes(for: try vk)))
        )
        expectThrows(SignedMessage(signature: message), Self.isKey)
    }

    /// A kid between 33 and 63 bytes used to trap on `subdata(in: 32..<64)`.
    @Test(arguments: [0, 3, 31, 33, 40, 63, 65])
    func rejectsKidOfWrongLength(_ length: Int) throws {
        let message = try Self.sign1(
            protected: Self.header(
                kid: .byteString(Data(repeating: 1, count: length)),
                address: .byteString(try Self.addressBytes(for: try vk))
            )
        )
        expectThrows(SignedMessage(signature: message), Self.isKey)
    }

    @Test func rejectsKidThatIsNotBytes() throws {
        let message = try Self.sign1(
            protected: Self.header(kid: .textString("key"), address: .byteString(try Self.addressBytes(for: try vk)))
        )
        expectThrows(SignedMessage(signature: message), Self.isKey)
    }

    @Test func rejectsMalformedAttachedCoseKey() throws {
        let key = try vk
        let message = try Self.sign1(
            protected: Self.header(kid: nil, address: .byteString(try Self.addressBytes(for: key))),
            sign: sk.sign
        )
        let x = CBOR.byteString(key)
        let badKeys: [String] = [
            "zz",
            "a4",  // truncated CBOR
            Self.hex(.array([])),
            // No kty.
            Self.hex(.map([.negativeInt(0): .unsignedInt(6), .negativeInt(1): x])),
            // An EC2 (kty 2) P-256 key used to trap in swift-cose.
            Self.hex(.map([
                .unsignedInt(1): .unsignedInt(2), .negativeInt(0): .unsignedInt(1),
                .negativeInt(1): x, .negativeInt(2): x,
            ])),
            // Wrong curve (X25519).
            Self.hex(.map([.unsignedInt(1): .unsignedInt(1), .negativeInt(0): .unsignedInt(4), .negativeInt(1): x])),
            // Wrong algorithm.
            Self.hex(.map([.unsignedInt(1): .unsignedInt(1), .unsignedInt(3): .negativeInt(6), .negativeInt(1): x])),
            // x missing, short, or not bytes.
            Self.hex(.map([.unsignedInt(1): .unsignedInt(1), .negativeInt(0): .unsignedInt(6)])),
            Self.hex(.map([.unsignedInt(1): .unsignedInt(1), .negativeInt(1): .byteString(Data(repeating: 1, count: 5))])),
            Self.hex(.map([.unsignedInt(1): .unsignedInt(1), .negativeInt(1): .textString("x")])),
        ]
        for badKey in badKeys {
            expectThrows(SignedMessage(signature: message, key: badKey), Self.isKey)
        }

        // The same message with a well-formed attached key verifies.
        let goodKey = Self.hex(.map([
            .unsignedInt(1): .unsignedInt(1), .unsignedInt(3): .negativeInt(7),
            .negativeInt(0): .unsignedInt(6), .negativeInt(1): x,
        ]))
        #expect(try CIP8.verify(signedMessage: SignedMessage(signature: message, key: goodKey)).verified)
    }

    // MARK: Results that don't throw

    @Test func wrongSignatureIsNotVerified() throws {
        let short = try Self.sign1(protected: try validHeader(), signature: .byteString(Data([1, 2, 3])))
        #expect(try CIP8.verify(signedMessage: SignedMessage(signature: short)).verified == false)

        let zero = try Self.sign1(protected: try validHeader())
        #expect(try CIP8.verify(signedMessage: SignedMessage(signature: zero)).verified == false)
    }

    @Test func handBuiltMessageVerifies() throws {
        let message = try Self.sign1(protected: try validHeader(), sign: sk.sign)
        let result = try CIP8.verify(signedMessage: SignedMessage(signature: message))
        #expect(result.verified)
        #expect(result.message == "hello")
    }

    /// A 64-byte `kid` (public key + chain code) is verified against its first 32
    /// bytes, for the signature and for the address. Before, the address check hashed
    /// all 64 bytes, so these messages never verified, and a bad signature threw.
    @Test func extendedKidVerifies() throws {
        let extendedVK: PaymentExtendedVerificationKey = try extendedSK.toVerificationKey()
        let header = Self.header(
            kid: .byteString(extendedVK.payload),
            address: .byteString(try Self.addressBytes(for: extendedVK.payload.prefix(32)))
        )
        let signed = try Self.sign1(protected: header, sign: extendedSK.sign)
        #expect(try CIP8.verify(signedMessage: SignedMessage(signature: signed)).verified)

        let forged = try Self.sign1(protected: header)
        #expect(try CIP8.verify(signedMessage: SignedMessage(signature: forged)).verified == false)
    }

    // MARK: Unprotected header

    /// Messages already signed with a `null` unprotected header still verify.
    @Test func legacyNullUnprotectedHeaderVerifies() throws {
        let message = try Self.sign1(protected: try validHeader(), unprotected: .null, sign: sk.sign)
        #expect(try CIP8.verify(signedMessage: SignedMessage(signature: message)).verified)
    }
}
