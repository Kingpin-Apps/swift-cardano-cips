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
///  - message: The message that was signed
///  - signingAddress: The address that signed the message
public struct VerificationResult {
    public let verified: Bool
    public let message: String
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
    /// - Returns: The signed message.
    public static func sign(
        payload: Data,
        signingKey: SigningKeyType,
        attachCoseKey: Bool = false,
        network: Network = .mainnet
    ) throws -> SignedMessage {
        return try _sign(
            payload: payload,
            signingKey: signingKey,
            attachCoseKey: attachCoseKey,
            network: network
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
            payload: message.data(using: .utf8)!,
            signingKey: signingKey,
            attachCoseKey: attachCoseKey,
            network: network
        )
    }

    private static func _sign(
        payload: Data,
        signingKey: SigningKeyType,
        attachCoseKey: Bool,
        network: Network
    ) throws -> SignedMessage {
        let address: Address
        let verificationKey: any VerificationKeyProtocol
        let networkId = network.networkId

        // Derive verification key and address based on key type
        switch signingKey {
            case .signingKey(let sKey):
                if sKey is StakeSigningKey {
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
                if extendedSKey is StakeExtendedSigningKey {
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
            .fromAny(sign1Message.uhdrEncoded),
            .byteString(sign1Message.payload!),
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
    /// Supports messages signed by browser wallets or `Message.sign()`.
    ///
    /// - Parameter signedMessage: Message to be verified
    /// - Returns: The verification result
    public static func verify(
        signedMessage: SignedMessage
    ) throws -> VerificationResult {
        let hasAttachedKey = signedMessage.key != nil

        // Decode the signed message
        let messageData = Data(hex: "D2" + signedMessage.signature)
        
        let decodedMessage = try CoseMessage.decode(
            Sign1Message.self,
            from: messageData
        ) as Sign1Message

        // Get or create COSE key
        let coseKey: CoseKey
        let verificationKey: Data
        if !hasAttachedKey {
            guard let verificationKeyData = decodedMessage.phdr[KID()] as? Data else {
                throw CIP8Error.invalidKey("Key must be attached if hasAttachedKey is False")
            }

            let coseKeyDict = [
                KpKty(): KtyOKP(),
                OKPKpCurve(): Ed25519Curve(),
                KpKeyOps(): [SignOp(), VerifyOp()],
                OKPKpX(): verificationKeyData
            ] as [AnyHashable : Any]

            coseKey = try CoseKey.fromDictionary(coseKeyDict)
            verificationKey = verificationKeyData
        } else {
            guard let keyHex = signedMessage.key else {
                throw CIP8Error.invalidKey("Key must be a hex string if hasAttachedKey is True")
            }
            coseKey = try CoseKey.decode(Data(hex: keyHex))!
            verificationKey = coseKey.store[OKPKpX()] as! Data
        }
        
        // attach the key to the decoded message
        decodedMessage.key = coseKey
        
        // Verify signature
        let signatureVerified: Bool
        if verificationKey.count > 32 {
           let vk = BIP32ED25519PublicKey(
               publicKey: verificationKey.subdata(in: 0..<32),
               chainCode: verificationKey.subdata(in: 32..<64)
           )
            _ = try vk.verify(
               signature: decodedMessage.signature,
               message: decodedMessage.createSignatureStructure()
           )
            signatureVerified = true
       } else {
           signatureVerified = try decodedMessage.verifySignature()
       }
        
        let addressHeader = CoseHeaderAttribute(
            customIdentifier: nil,
            fullname: "address"
        )
        
        let message = decodedMessage.payload!.toString
        let address = decodedMessage.phdr[addressHeader] as! Data
        
        let signingAddress: Address = try Address(
            from: .bytes(address)
        )
        
        // check that the address attached matches the one of the verification keys used to sign the message
        let addressesMatch: Bool
        if signingAddress.paymentPart != nil {
            switch signingAddress.paymentPart {
                case .verificationKeyHash(let hash):
                    addressesMatch = try PaymentVerificationKey(
                        payload: verificationKey
                    ).hash() == hash
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
        
        let verified = signatureVerified && addressesMatch
        
        return VerificationResult(
            verified: verified,
            message: message,
            signingAddress: signingAddress
        )
    }
}

