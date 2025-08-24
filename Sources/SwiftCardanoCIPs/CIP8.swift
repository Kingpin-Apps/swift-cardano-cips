import Foundation
import PotentCodables
import PotentCBOR
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
    
    /// Sign an arbitrary message with a payment or stake key following CIP-0008.
    ///
    /// Note that a stake key passed in must be of type ``StakeSigningKey`` or ``StakeExtendedSigningKey`` to be detected.
    /// - Parameters:
    ///   - message: Message to sign
    ///   - signingKey: Key to sign the message with
    ///   - attachCoseKey: Whether to attach the COSE key to the signed message
    ///   - network: Network to use for the address generation
    /// - Returns: The signed message
    public static func sign(
        message: String,
        signingKey: SigningKeyType,
        attachCoseKey: Bool = false,
        network: Network = .mainnet
    ) throws -> SignedMessage {
        let address: Address
        let verificationKey: any VerificationKey
        let signingKeyPayload: Data
        
        // Derive verification key and address based on key type
        switch signingKey {
            case .signingKey(let sKey):
                signingKeyPayload = sKey.payload
                if sKey is StakeSigningKey {
                    let vkey: StakeVerificationKey = try sKey.toVerificationKey()
                    address = try Address(
                        paymentPart: nil,
                        stakingPart: .verificationKeyHash(vkey.hash()),
                        network: network
                    )
                    verificationKey = vkey
                } else {
                    let vkey: PaymentVerificationKey = try sKey.toVerificationKey()
                    address = try Address(
                        paymentPart: .verificationKeyHash(vkey.hash()),
                        stakingPart: nil,
                        network: network
                    )
                    verificationKey = vkey
                }
            case .extendedSigningKey(let extendedSKey):
                signingKeyPayload = extendedSKey.payload
                if extendedSKey is StakeExtendedSigningKey {
                    let extendedVKey: StakeExtendedVerificationKey = extendedSKey.toVerificationKey()
                    let vkey: StakeVerificationKey = extendedVKey.toNonExtended()
                    address = try Address(
                        paymentPart: nil,
                        stakingPart: .verificationKeyHash(vkey.hash()),
                        network: network
                    )
                    verificationKey = vkey
                } else {
                    let extendedVKey: PaymentExtendedVerificationKey = extendedSKey.toVerificationKey()
                    let vkey: PaymentVerificationKey = extendedVKey.toNonExtended()
                    address = try Address(
                        paymentPart: .verificationKeyHash(vkey.hash()),
                        stakingPart: nil,
                        network: network
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
        
        // Create COSE key
        let keyDict: [AnyHashable: Any] = [
            OKPKpCurve(): Ed25519Curve(),
            OKPKpX(): verificationKey.payload,
            OKPKpD(): signingKeyPayload
        ]
        
        let coseKey = try OKPKey.fromDictionary(keyDict)
        coseKey.keyOps = [SignOp(), VerifyOp()]

        // Create Sign1 message
        let sign1Message = Sign1Message(
            phdr: protectedHeader,
            uhdr: unprotectedHeader,
            payload: message.data(using: .utf8)!,
            key: coseKey
        )
        
        let encoded: Data
        switch signingKey {
            case .extendedSigningKey(let extendedSKey):
                let signed = try extendedSKey.sign(
                    data: try sign1Message.createSignatureStructure()
                )
                
                let _message = [
                    CBOR.byteString(sign1Message.phdrEncoded),
                    CBOR.fromAny(sign1Message.uhdrEncoded),
                    CBOR.byteString(sign1Message.payload!),
                    CBOR.byteString(signed)
                ] as [CBOR]
                
                let cborTag = CBOR.tagged(
                    CBOR.Tag(rawValue: UInt64(sign1Message.cborTag)),
                    .array(_message)
                )
                encoded = try CBOREncoder().encode(cborTag)
            case .signingKey(_):
                encoded = try sign1Message.encode()
        }
                
        // turn the enocded message into a hex string and remove the first byte
        let signedHex = encoded.dropFirst().toHexString()  // Drop the initial 0xD2 tag

        if attachCoseKey {
            let keyToReturn = [
                KpKty(): KtyOKP(),
                KpAlg(): EdDSAAlgorithm(),
                OKPKpCurve(): Ed25519Curve(),
                OKPKpX(): verificationKey.payload
            ] as [AnyHashable : Any]

            return SignedMessage(
                signature: signedHex,
                key: try CoseKey
                    .fromDictionary(keyToReturn)
                    .encode()!
                    .toHexString()
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

