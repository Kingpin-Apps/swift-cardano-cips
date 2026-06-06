import Foundation
import CBORCodable
import OrderedCollections
import SwiftCardanoCore
import SwiftNaCl

/// Errors thrown by ``CIP88`` registration.
public enum CIP88Error: Error, Equatable {
    /// The supplied Calidus public key was the wrong length (must be 32
    /// bytes — Ed25519 raw verification key).
    case invalidCalidusKeyLength(Int)
    /// The pool cold key produced a verification key of the wrong length
    /// (must be 32 bytes).
    case invalidPoolVerificationKey(Int)
    /// CBOR encoding failed.
    case encodingError(String)
    /// Signing failed.
    case signingError(String)
}

/// CIP-88 v2 token-registration framework + CIP-151 Calidus pool-key
/// registration builder.
///
/// Builds the `metadata label 867` payload that a stake-pool operator
/// submits as `auxiliary_data` to publish a Calidus operational
/// (delegated-signing) key, per
/// [CIP-0151](https://cips.cardano.org/cip/CIP-0151) built on the
/// [CIP-0088](https://cips.cardano.org/cip/CIP-0088) v2 framework.
///
/// The Calidus key is a short-lived delegated key that a pool operator
/// uses to sign off-chain operational messages (block-production
/// announcements, pool-related identity proofs) without exposing the
/// long-lived cold key. The cold key signs a one-time registration that
/// authorises the Calidus key; from then on the Calidus key acts on the
/// pool's behalf until rotated.
public enum CIP88 {

    /// `867` — the CIP-88 v2 / CIP-151 metadata label.
    public static let metadataLabel: UInt64 = 867

    /// `2` — the CIP-88 v2 / CIP-151 protocol version.
    public static let protocolVersion: Int = 2

    /// Scope ID `1` — stake-pool registration scope.
    public static let stakePoolScopeID: Int = 1

    /// Validation method `0` — single Ed25519 signature by the pool cold
    /// key.
    public static let ed25519ValidationMethod: Int = 0

    /// Witness type `0` — simple Ed25519 witness (pool cold key).
    public static let ed25519WitnessType: Int = 0

    // MARK: - Calidus registration

    /// Build a CIP-151 Calidus pool-key registration `AuxiliaryData`.
    ///
    /// - Parameters:
    ///   - calidusPublicKey: 32-byte Ed25519 public key to register as the
    ///     pool's Calidus operational key.
    ///   - poolSigningKey: The pool cold signing key. Must produce a
    ///     32-byte verification key — i.e. a non-extended Ed25519 key.
    ///     The pool ID embedded in the scope field is the Blake2b-224 of
    ///     this key's verification key.
    ///   - nonce: Per-pool monotonic nonce. Typically the current mainnet
    ///     slot height — see ``Signer/SlotNonce`` in the signer facade.
    /// - Returns: An ``SwiftCardanoCore/AuxiliaryData`` carrying the
    ///   `{867: {0: 2, 1: payload, 2: [witness]}}` envelope.
    /// - Throws: ``CIP88Error`` on length / encoding / signing failures.
    public static func makeCalidusRegistration(
        calidusPublicKey: Data,
        poolSigningKey: SigningKeyType,
        nonce: UInt64
    ) throws -> AuxiliaryData {
        guard calidusPublicKey.count == 32 else {
            throw CIP88Error.invalidCalidusKeyLength(calidusPublicKey.count)
        }

        // Pool ID = Blake2b-224 of the pool verification key.
        let poolVKType = try poolSigningKey.toVerificationKeyType()
        let poolVKey: Data
        switch poolVKType {
        case .verificationKey(let key):
            poolVKey = key.payload
        case .extendedVerificationKey(let key):
            // For an extended cold key the chain code is stripped; the
            // pool ID is still the hash of the 32-byte verification key.
            poolVKey = key.payload.prefix(32)
        }
        guard poolVKey.count == 32 else {
            throw CIP88Error.invalidPoolVerificationKey(poolVKey.count)
        }

        let poolID: Data
        do {
            poolID = try SwiftNaCl.Hash().blake2b(
                data: poolVKey,
                digestSize: 28,
                encoder: RawEncoder.self
            )
        } catch {
            throw CIP88Error.encodingError("blake2b-224(poolVKey) failed: \(error)")
        }

        // -------------------------------------------------------------
        // Payload object (CIP-151 §3 — Token Registration Payload).
        //
        // Keys MUST be in ascending numeric order so that downstream
        // tooling can deterministically reconstruct the same CBOR bytes
        // when re-verifying the witness.
        // -------------------------------------------------------------
        var payload = OrderedDictionary<TransactionMetadatum, TransactionMetadatum>()
        // 1: scope = [stakePoolScopeID, poolID]
        payload[.int(1)] = .list([
            .int(stakePoolScopeID),
            .bytes(poolID),
        ])
        // 2: feature_set = []  (no extra features for plain Calidus)
        payload[.int(2)] = .list([])
        // 3: validation_method = [ed25519ValidationMethod]
        payload[.int(3)] = .list([.int(ed25519ValidationMethod)])
        // 4: nonce
        payload[.int(4)] = .int(Int(nonce))
        // 7: calidus_key
        payload[.int(7)] = .bytes(calidusPublicKey)

        let payloadMetadatum: TransactionMetadatum = .map(payload)

        // -------------------------------------------------------------
        // Signing payload (CIP-151 §4).
        //
        // CIP-151 v2 signs the blake2b-256 of the **hex-encoded** CBOR
        // representation of the payload, not the raw CBOR bytes. This
        // matches cardano-signer.js's `--cip88` output. The hex encoding
        // is lowercase ASCII, no `0x` prefix.
        // -------------------------------------------------------------
        let payloadCBOR: Data
        do {
            payloadCBOR = try payloadMetadatum.toCBORData()
        } catch {
            throw CIP88Error.encodingError(String(describing: error))
        }
        let payloadHexBytes = Data(payloadCBOR.map { byte in
            // Two lowercase ASCII hex chars per byte.
            (0..<2).map { i -> UInt8 in
                let nibble = (byte >> (4 * UInt8(1 - i))) & 0x0F
                return nibble < 10 ? (0x30 + nibble) : (0x57 + nibble) // '0'..'9' / 'a'..'f'
            }
        }.flatMap { $0 })

        let signingHash: Data
        do {
            signingHash = try SwiftNaCl.Hash().blake2b(
                data: payloadHexBytes,
                digestSize: 32,
                encoder: RawEncoder.self
            )
        } catch {
            throw CIP88Error.encodingError("blake2b-256(hex(CBOR(payload))) failed: \(error)")
        }

        let signature: Data
        do {
            signature = try poolSigningKey.sign(data: signingHash)
        } catch {
            throw CIP88Error.signingError(String(describing: error))
        }

        // -------------------------------------------------------------
        // Witness map (CIP-151 §3.2 — v2 map-based witness).
        //
        //   0: witness type (0 = Ed25519)
        //   1: 32-byte verification key
        //   2: 64-byte signature
        // -------------------------------------------------------------
        var witnessMap = OrderedDictionary<TransactionMetadatum, TransactionMetadatum>()
        witnessMap[.int(0)] = .int(ed25519WitnessType)
        witnessMap[.int(1)] = .bytes(poolVKey)
        witnessMap[.int(2)] = .bytes(signature)

        // -------------------------------------------------------------
        // Top-level CIP-88 envelope (CIP-151 §3).
        //
        //   0: version (2)
        //   1: payload
        //   2: witnesses (array of witness maps)
        // -------------------------------------------------------------
        var envelope = OrderedDictionary<TransactionMetadatum, TransactionMetadatum>()
        envelope[.int(0)] = .int(protocolVersion)
        envelope[.int(1)] = payloadMetadatum
        envelope[.int(2)] = .list([.map(witnessMap)])

        let metadata = try Metadata([
            metadataLabel: .map(envelope),
        ])
        return AuxiliaryData(data: .metadata(metadata))
    }
}
