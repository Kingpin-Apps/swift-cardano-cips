import Foundation
import CBORCodable
import SwiftCOSE
import OrderedCollections
import SwiftCardanoCore

public enum CIP8Error: Error {
    case invalidKey(String)
    case invalidSignature(String)
    case invalidAddress(String)
    case encodingError(String)
    case decodingError(String)
}

/// The signed message returned by the CIP-0008 sign function.
/// - Parameters:
///  - signature: The signature of the message
///  - key: The COSE key used to sign the message
public struct SignedMessage {
    public let signature: String
    public let key: String?
    
    /// Initialize a signed message with a signature and an optional key.
    /// - Parameters:
    ///   - signature: The signature of the message
    ///   - key: The COSE key used to sign the message
    public init(signature: String, key: String? = nil) {
        self.signature = signature
        self.key = key
    }
}

/// Verification result of a signed message.
/// - Parameters:
///  - verified: Whether the signature is verified
///  - message: The signed payload as strict UTF-8 text, or an empty
///    string when the payload is not valid UTF-8. Compare ``payload``
///    when the exact signed bytes matter.
///  - payload: The exact payload bytes the signature covers
///  - signingAddress: The address that signed the message
public struct VerificationResult {
    public let verified: Bool
    public let message: String
    public let payload: Data
    public let signingAddress: Address
}

//public final class AddressHeaderAttribute: CoseHeaderAttribute {
//    public init() {
//        super.init(customIdentifier: -1, fullname: "address")
//    }
//}
//
//public final class HashedHeaderAttribute: CoseHeaderAttribute {
//    public init() {
//        super.init(customIdentifier: -1, fullname: "hashed")
//    }
//}

public struct CIP8 {

    /// Whether a key's text-envelope type names a stake key. A stake key
    /// held as a generic key struct (for example straight from HD
    /// derivation) still carries its role here.
    static func isStakeEnvelope(_ type: String) -> Bool {
        type.hasPrefix("StakeSigningKey") || type.hasPrefix("StakeExtendedSigningKey")
    }
    
    /// Sign an arbitrary byte payload with a payment or stake key following CIP-0008.
    ///
    /// Use this overload when the payload isn't a UTF-8 string — for example CIP-30
    /// `signData` requests receive raw bytes.
    ///
    /// A stake key passed in must be a `SwiftCardanoCore.StakeSigningKey` or
    /// `SwiftCardanoCore.StakeExtendedSigningKey` to be recognized as such; otherwise it
    /// is treated as a payment key.
    /// - Parameters:
    ///   - payload: Raw bytes to sign.
    ///   - signingKey: Key to sign the payload with.
    ///   - attachCoseKey: Whether to ship the public COSE_Key alongside the signature
    ///     (CIP-30 `signData` shape). When `false`, the verification key is embedded in
    ///     the protected header as `kid`.
    ///   - network: Network to use when deriving the signing address.
    ///   - address: The address to put in the protected header, such as the address a
    ///     CIP-30 dApp asked to sign for. It must be on `network`, and its payment
    ///     credential (or, for a reward address, its staking credential) must be this
    ///     key's hash, or this throws ``CIP8Error/invalidAddress(_:)``. When `nil`, the
    ///     enterprise or reward address of the key is used.
    /// - Returns: The signed message.
    public static func sign(
        payload: Data,
        signingKey: SigningKeyType,
        attachCoseKey: Bool = false,
        network: Network = .mainnet,
        address: Address? = nil
    ) throws -> SignedMessage {
        return try _sign(
            payload: payload,
            signingKey: signingKey,
            attachCoseKey: attachCoseKey,
            network: network,
            requestedAddress: address
        )
    }

    /// Sign a UTF-8 string message with a payment or stake key following CIP-0008.
    ///
    /// A stake key passed in must be a `SwiftCardanoCore.StakeSigningKey` or
    /// `SwiftCardanoCore.StakeExtendedSigningKey` to be recognized as such; otherwise it
    /// is treated as a payment key.
    /// - Parameters:
    ///   - message: Message to sign. Encoded as UTF-8 before signing.
    ///   - signingKey: Key to sign the message with.
    ///   - attachCoseKey: Whether to ship the public COSE_Key alongside the signature.
    ///   - network: Network to use when deriving the signing address.
    /// - Returns: The signed message.
    public static func sign(
        message: String,
        signingKey: SigningKeyType,
        attachCoseKey: Bool = false,
        network: Network = .mainnet
    ) throws -> SignedMessage {
        return try _sign(
            payload: Data(message.utf8),
            signingKey: signingKey,
            attachCoseKey: attachCoseKey,
            network: network,
            requestedAddress: nil
        )
    }

    private static func _sign(
        payload: Data,
        signingKey: SigningKeyType,
        attachCoseKey: Bool,
        network: Network,
        requestedAddress: Address?
    ) throws -> SignedMessage {
        var address: Address
        let verificationKey: any VerificationKeyProtocol
        let networkId = network.networkId

        // Derive verification key and address based on key type
        switch signingKey {
            case .signingKey(let sKey):
                if sKey is StakeSigningKey || Self.isStakeEnvelope(sKey.type) {
                    let vkey: StakeVerificationKey = try sKey.toVerificationKey()
                    address = try Address(
                        paymentPart: nil,
                        stakingPart: .verificationKeyHash(vkey.hash()),
                        network: networkId
                    )
                    verificationKey = vkey
                } else {
                    let vkey: PaymentVerificationKey = try sKey.toVerificationKey()
                    address = try Address(
                        paymentPart: .verificationKeyHash(vkey.hash()),
                        stakingPart: nil,
                        network: networkId
                    )
                    verificationKey = vkey
                }
            case .extendedSigningKey(let extendedSKey):
                if extendedSKey is StakeExtendedSigningKey || Self.isStakeEnvelope(extendedSKey.type) {
                    let extendedVKey: StakeExtendedVerificationKey = try extendedSKey.toVerificationKey()
                    let vkey: StakeVerificationKey = try extendedVKey.toNonExtended()
                    address = try Address(
                        paymentPart: nil,
                        stakingPart: .verificationKeyHash(try vkey.hash()),
                        network: networkId
                    )
                    verificationKey = vkey
                } else {
                    let extendedVKey: PaymentExtendedVerificationKey = try extendedSKey.toVerificationKey()
                    let vkey: PaymentVerificationKey = try extendedVKey.toNonExtended()
                    address = try Address(
                        paymentPart: .verificationKeyHash(try vkey.hash()),
                        stakingPart: nil,
                        network: networkId
                    )
                    verificationKey = vkey
                }
        }
        
        if let requestedAddress {
            let keyHash = try verificationKey.hash()
            guard requestedAddress.network == networkId else {
                throw CIP8Error.invalidAddress("The address is not on the signing network")
            }
            let credentialMatches: Bool
            switch (requestedAddress.paymentPart, requestedAddress.stakingPart) {
            case (.verificationKeyHash(let hash)?, _):
                credentialMatches = hash == keyHash
            case (nil, .verificationKeyHash(let hash)?):
                credentialMatches = hash == keyHash
            default:
                credentialMatches = false
            }
            guard credentialMatches else {
                throw CIP8Error.invalidAddress("The address's credential is not the signing key's hash")
            }
            address = requestedAddress
        }

        let addressHeader = CoseHeaderAttribute(
            customIdentifier: nil,
            fullname: "address"
        )
        
        let hashedHeader = CoseHeaderAttribute(
            customIdentifier: nil,
            fullname: "hashed"
        )

        // Create protected header
        var protectedHeader: OrderedDictionary<CoseHeaderAttribute, Any> = [
            Algorithm(): EdDSAAlgorithm(),
            addressHeader: address.toBytes(),
        ]

        if !attachCoseKey {
            protectedHeader[KID()] = verificationKey.payload
        }

        // Create unprotected header
        let unprotectedHeader: OrderedDictionary<CoseHeaderAttribute, Any> = [
            hashedHeader: false
        ]
        
        // Build the Sign1 message. We sign the Sig_structure ourselves rather
        // than going through `Sign1Message.encode()` because that path routes
        // Ed25519 signing through CryptoKit's `Curve25519.Signing.PrivateKey
        // .signature(for:)`, which is non-deterministic on Apple platforms
        // (hedged signing). Routing through `signingKey.sign(data:)` uses the
        // libsodium-backed RFC 8032 deterministic implementation, matching
        // cardano-signer.js and the CIP-30 wallet bridge expectations.
        let sign1Message = Sign1Message(
            phdr: protectedHeader,
            uhdr: unprotectedHeader,
            payload: payload
        )

        let signed = try signingKey.sign(
            data: sign1Message.createSignatureStructure()
        )

        let _message: [CBOR] = [
            .byteString(sign1Message.phdrEncoded),
            // Written out by hand: `CBOR.fromAny` can't convert swift-cose's
            // `OrderedDictionary<CoseHeaderAttribute, Any>` and silently gives
            // `null`, which isn't a valid COSE unprotected header.
            .map([.textString("hashed"): .boolean(false)]),
            .byteString(payload),
            .byteString(signed)
        ]

        let cborTag = CBOR.tagged(
            UInt64(sign1Message.cborTag),
            .array(_message)
        )
        var writer = CBORWriter()
        try writer.encode(cborTag)
        let encoded = writer.data

        // turn the enocded message into a hex string and remove the first byte
        let signedHex = encoded.dropFirst().toHexString()  // Drop the initial 0xD2 tag

        if attachCoseKey {
            // Build the attached COSE_Key map directly in canonical CBOR order
            // (RFC 8949 §4.2.3 bytewise-lex on the encoded keys) instead of
            // round-tripping through `CoseKey.fromDictionary(...).encode()`,
            // which (a) iterates an unordered `[AnyHashable: Any]` store so
            // the on-wire key order varies per process, and (b) emits a
            // spurious empty `d` entry because `OKPKey.init` always sets
            // `self.d = d ?? Data()`. The CIP-30 attached key must only carry
            // the public material: kty(1), alg(3), crv(-1), x(-2).
            let keyMap: OrderedDictionary<CBOR, CBOR> = [
                .unsignedInt(1): .unsignedInt(1),   // kty: OKP
                .unsignedInt(3): .negativeInt(7),  // alg: EdDSA (-8 on the wire as -1-7)
                .negativeInt(0): .unsignedInt(6),  // crv (-1): Ed25519
                .negativeInt(1): .byteString(verificationKey.payload), // x (-2)
            ]
            var keyWriter = CBORWriter()
            try keyWriter.encode(.map(keyMap))

            return SignedMessage(
                signature: signedHex,
                key: keyWriter.data.toHexString()
            )
        }

        return SignedMessage(signature: signedHex)
    }
    
    /// Verify the signature of a COSESign1 message and decode its contents following CIP-0008.
    ///
    /// Supports messages signed by browser wallets (CIP-30 `signData`) or ``sign(message:signingKey:attachCoseKey:network:)``.
    ///
    /// The input is untrusted: anything that isn't a well-formed CIP-8 COSE_Sign1 throws
    /// a ``CIP8Error`` rather than trapping. That covers bad hex or CBOR, a missing or
    /// non-byte-string `address` header, an algorithm other than EdDSA, a detached
    /// (`null`) payload, and a verification key that is missing or isn't an Ed25519 key
    /// of 32 bytes (or 64 bytes with a chain code, in the `kid` header).
    ///
    /// - Parameter signedMessage: Message to be verified
    /// - Returns: The verification result. ``VerificationResult/verified`` is `false`
    ///   when the signature doesn't match the key or the address doesn't belong to it.
    /// - Throws: ``CIP8Error`` for malformed input, or an address decoding error when the
    ///   `address` header bytes aren't a valid Cardano address.
    public static func verify(
        signedMessage: SignedMessage
    ) throws -> VerificationResult {
        let sign1 = try DecodedSign1(hex: signedMessage.signature)

        // The 32-byte Ed25519 public key that signed the message.
        let verificationKey: Data
        if let keyHex = signedMessage.key {
            verificationKey = try attachedKey(hex: keyHex)
        } else {
            guard let kid = sign1.protected[.unsignedInt(4)] else {
                throw CIP8Error.invalidKey(
                    "No verification key: attach a COSE_Key or put the key in the kid header"
                )
            }
            guard case .byteString(let kidData) = kid else {
                throw CIP8Error.invalidKey("The kid header must be a byte string")
            }
            switch kidData.count {
            case 32:
                verificationKey = kidData
            case 64:
                // An extended key (public key + chain code): the chain code plays no
                // part in signing or in the key hash.
                verificationKey = kidData.prefix(32)
            default:
                throw CIP8Error.invalidKey(
                    "The kid header must be a 32-byte key or a 64-byte extended key, got \(kidData.count) bytes"
                )
            }
        }

        let paymentKey = try PaymentVerificationKey(payload: verificationKey)

        // Ed25519 over the Sig_structure (RFC 9052 §4.4), built from the protected
        // header bytes exactly as received.
        let signatureVerified = (try? paymentKey.verify(
            signature: sign1.signature,
            data: try sign1.signatureStructure()
        )) ?? false

        let signingAddress: Address = try Address(from: .bytes(sign1.address))

        // check that the address attached matches the one of the verification keys used to sign the message
        let addressesMatch: Bool
        if signingAddress.paymentPart != nil {
            switch signingAddress.paymentPart {
                case .verificationKeyHash(let hash):
                    addressesMatch = try paymentKey.hash() == hash
                default:
                    addressesMatch = false
            }
        } else {
            switch signingAddress.stakingPart {
                case .verificationKeyHash(let hash):
                    addressesMatch = try StakeVerificationKey(
                        payload: verificationKey
                    ).hash() == hash
                default:
                    addressesMatch = false
            }
        }

        return VerificationResult(
            verified: signatureVerified && addressesMatch,
            message: String(data: sign1.payload, encoding: .utf8) ?? "",
            payload: sign1.payload,
            signingAddress: signingAddress
        )
    }

    /// The public key from an attached CIP-30 COSE_Key: an OKP key (kty 1) on Ed25519
    /// (crv 6) for EdDSA (alg -8), with a 32-byte `x`.
    private static func attachedKey(hex: String) throws -> Data {
        guard let bytes = Data(strictHex: hex) else {
            throw CIP8Error.invalidKey("The COSE_Key is not valid hex")
        }
        let decoded: CBOR
        do {
            decoded = try decodeSingleCBOR(bytes)
        } catch {
            throw CIP8Error.invalidKey("The COSE_Key is not valid CBOR: \(error)")
        }
        guard case .map(let key) = decoded else {
            throw CIP8Error.invalidKey("The COSE_Key must be a CBOR map")
        }
        guard key[.unsignedInt(1)] == .unsignedInt(1) else {
            throw CIP8Error.invalidKey("The COSE_Key must be an OKP key (kty 1)")
        }
        if let alg = key[.unsignedInt(3)], alg != .negativeInt(7) {
            throw CIP8Error.invalidKey("The COSE_Key algorithm must be EdDSA (-8)")
        }
        if let crv = key[.negativeInt(0)], crv != .unsignedInt(6) {
            throw CIP8Error.invalidKey("The COSE_Key curve must be Ed25519 (6)")
        }
        guard case .byteString(let x)? = key[.negativeInt(1)], x.count == 32 else {
            throw CIP8Error.invalidKey("The COSE_Key x must be a 32-byte public key")
        }
        return x
    }
}

/// A COSE_Sign1 message (RFC 9052 §4.2) parsed strictly from untrusted hex, with the
/// CIP-8 headers this package relies on checked up front.
private struct DecodedSign1 {
    let protectedBytes: Data
    let protected: OrderedDictionary<CBOR, CBOR>
    let payload: Data
    let signature: Data
    let address: Data

    init(hex: String) throws {
        guard let bytes = Data(strictHex: hex), !bytes.isEmpty else {
            throw CIP8Error.decodingError("The signature is not valid hex")
        }
        let decoded: CBOR
        do {
            decoded = try decodeSingleCBOR(bytes)
        } catch {
            throw CIP8Error.decodingError("The signature is not valid CBOR: \(error)")
        }
        guard case .array(let items) = decoded, items.count == 4 else {
            throw CIP8Error.decodingError(
                "A COSE_Sign1 is an untagged array of [protected, unprotected, payload, signature]"
            )
        }
        guard case .byteString(let protectedBytes) = items[0] else {
            throw CIP8Error.decodingError("The protected header must be a byte string")
        }
        switch items[1] {
        case .map:
            break
        case .null:
            // Messages signed by earlier versions of this package carry `null` here.
            // The unprotected header isn't signed and verification reads nothing
            // from it, so accept them.
            break
        default:
            throw CIP8Error.decodingError("The unprotected header must be a map")
        }
        let payload: Data
        switch items[2] {
        case .byteString(let data):
            payload = data
        case .null:
            throw CIP8Error.decodingError("Detached payloads are not supported")
        default:
            throw CIP8Error.decodingError("The payload must be a byte string")
        }
        guard case .byteString(let signature) = items[3] else {
            throw CIP8Error.invalidSignature("The signature must be a byte string")
        }

        let protected: OrderedDictionary<CBOR, CBOR>
        if protectedBytes.isEmpty {
            protected = [:]
        } else {
            let header: CBOR
            do {
                header = try decodeSingleCBOR(protectedBytes)
            } catch {
                throw CIP8Error.decodingError("The protected header is not valid CBOR: \(error)")
            }
            guard case .map(let map) = header else {
                throw CIP8Error.decodingError("The protected header must be a map")
            }
            protected = map
        }

        // alg (1) must be EdDSA (-8).
        guard protected[.unsignedInt(1)] == .negativeInt(7) else {
            throw CIP8Error.invalidSignature("The protected header algorithm must be EdDSA (-8)")
        }
        guard let addressItem = protected[.textString("address")] else {
            throw CIP8Error.invalidAddress("The protected header has no address")
        }
        guard case .byteString(let address) = addressItem, !address.isEmpty else {
            throw CIP8Error.invalidAddress("The address header must be a non-empty byte string")
        }

        self.protectedBytes = protectedBytes
        self.protected = protected
        self.payload = payload
        self.signature = signature
        self.address = address
    }

    /// `Sig_structure = ["Signature1", protected, external_aad = h'', payload]`.
    func signatureStructure() throws -> Data {
        var writer = CBORWriter()
        try writer.encode(.array([
            .textString("Signature1"),
            .byteString(protectedBytes),
            .byteString(Data()),
            .byteString(payload),
        ]))
        return writer.data
    }
}

/// Decode exactly one CBOR item, rejecting trailing bytes and duplicate map keys.
private func decodeSingleCBOR(_ bytes: Data) throws -> CBOR {
    var reader = CBORReader(bytes)
    return try reader.decodeTopLevel()
}

private extension Data {
    /// Decode a hex string, upper or lower case. `nil` on odd length or any non-hex
    /// character, rather than silently decoding to empty bytes.
    init?(strictHex hex: String) {
        let scalars = Array(hex.unicodeScalars)
        guard scalars.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(scalars.count / 2)
        var index = 0
        while index < scalars.count {
            guard let hi = Self.nibble(scalars[index]),
                  let lo = Self.nibble(scalars[index + 1]) else {
                return nil
            }
            bytes.append(hi << 4 | lo)
            index += 2
        }
        self.init(bytes)
    }

    private static func nibble(_ scalar: Unicode.Scalar) -> UInt8? {
        switch scalar.value {
        case 0x30...0x39: return UInt8(scalar.value - 0x30)
        case 0x41...0x46: return UInt8(scalar.value - 0x41 + 10)
        case 0x61...0x66: return UInt8(scalar.value - 0x61 + 10)
        default: return nil
        }
    }
}
