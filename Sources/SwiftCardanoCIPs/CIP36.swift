import Foundation
import CBORCodable
import OrderedCollections
import SwiftCardanoCore
import SwiftNaCl

/// Errors thrown by ``CIP36`` registration / deregistration.
public enum CIP36Error: Error, Equatable {
    /// A delegation voting public key was the wrong length (must be 32 bytes).
    case invalidVotingKeyLength(Int)
    /// The delegations array was empty (CIP-36 requires at least one).
    case noDelegations
    /// The signing key produced a stake credential of the wrong length.
    case invalidStakeCredentialLength(Int)
    /// The supplied nonce or voting purpose exceeds `Int.max` and
    /// cannot be encoded through the underlying
    /// ``SwiftCardanoCore/TransactionMetadatum`` `.int` case.
    ///
    /// Mainnet slot heights are vastly below `Int.max` (≈ 1.4×10⁸ at
    /// time of writing vs `Int.max` = 9.2×10¹⁸), so this is a
    /// theoretical guard — but the public API takes `UInt64`, and
    /// throwing a clean error here beats a runtime trap inside the
    /// metadata encoder.
    case nonceOutOfRange(UInt64)
    /// CBOR encoding failed.
    case encodingError(String)
    /// Signing failed.
    case signingError(String)
}

/// CIP-36 Catalyst voting registration metadata builder.
///
/// Builds the `61284 / 61285` (registration) or `61286 / 61287`
/// (deregistration) metadata pair that a Catalyst voter submits as the
/// `auxiliary_data` of a Cardano transaction, signed with their stake
/// signing key.
///
/// See [CIP-0036](https://cips.cardano.org/cip/CIP-0036) for the wire
/// format. This implementation mirrors cardano-signer.js's
/// `sign --cip36` behaviour — including the auto-incrementing nonce
/// requirement (each registration must use a nonce strictly greater than
/// the previous on-chain registration for the same stake credential;
/// nonces are typically the current Cardano mainnet slot height).
public enum CIP36 {

    // MARK: - Metadata labels

    /// `61284` — registration data (delegations, stake credential, rewards
    /// address, nonce, voting purpose).
    public static let registrationLabel: UInt64 = 61_284

    /// `61285` — registration witness (Ed25519 signature over the
    /// `61284` map).
    public static let witnessLabel: UInt64 = 61_285

    /// `61286` — deregistration data (stake credential, nonce, voting
    /// purpose).
    public static let deregistrationLabel: UInt64 = 61_286

    /// `61287` — deregistration witness.
    public static let deregistrationWitnessLabel: UInt64 = 61_287

    // MARK: - Inputs

    /// A single voting delegation: one voting public key + its weight
    /// share of the registrant's voting power.
    public struct Delegation: Sendable, Equatable {
        public let votingKey: Data
        public let weight: UInt32

        public init(votingKey: Data, weight: UInt32) {
            self.votingKey = votingKey
            self.weight = weight
        }
    }

    // MARK: - Registration

    /// Build a CIP-36 registration `AuxiliaryData` carrying delegations,
    /// stake credential, rewards address, nonce, voting purpose, and the
    /// Ed25519 witness signature.
    ///
    /// - Parameters:
    ///   - delegations: At least one ``Delegation``. Each `votingKey` must
    ///     be 32 bytes (CIP-36 vote key — see
    ///     `Signer.Keygen.cip36(...)` for derivation).
    ///   - stakeSigningKey: The voter's stake signing key (regular or
    ///     extended). Used to derive the stake credential (field `2`) and
    ///     to sign the hashed `61284` blob.
    ///   - rewardsAddress: Address that will receive Catalyst rewards. The
    ///     full byte representation goes into field `3`.
    ///   - nonce: Monotonically-increasing per-stake-credential nonce.
    ///     Typically the current mainnet slot height.
    ///   - votingPurpose: Voting purpose discriminator. `0` = Catalyst
    ///     (default).
    /// - Returns: `AuxiliaryData` carrying both the `61284` registration
    ///   map and the `61285` witness map.
    public static func makeRegistration(
        delegations: [Delegation],
        stakeSigningKey: SigningKeyType,
        rewardsAddress: Address,
        nonce: UInt64,
        votingPurpose: UInt64 = 0
    ) throws -> AuxiliaryData {
        guard !delegations.isEmpty else {
            throw CIP36Error.noDelegations
        }
        for d in delegations {
            guard d.votingKey.count == 32 else {
                throw CIP36Error.invalidVotingKeyLength(d.votingKey.count)
            }
        }
        // The `.int(Int)` case of `TransactionMetadatum` would trap on a
        // `UInt64` above `Int.max`. Mainnet slot heights are nowhere
        // near this bound (≈ 1.4×10⁸ << `Int.max`), but the public API
        // takes `UInt64` and a clean throw beats a runtime trap.
        guard nonce <= UInt64(Int.max) else {
            throw CIP36Error.nonceOutOfRange(nonce)
        }
        guard votingPurpose <= UInt64(Int.max) else {
            throw CIP36Error.nonceOutOfRange(votingPurpose)
        }

        let stakeCredential = try deriveStakeCredential(from: stakeSigningKey)

        // Field 1 (`delegations`): always emit the array-of-pairs form,
        // never the legacy single-pubkey form. The pairs form is forward-
        // compatible with everything that reads CIP-36 today.
        let delegationsMetadatum: TransactionMetadatum = .list(
            delegations.map { d in
                .list([
                    .bytes(d.votingKey),
                    .int(Int(d.weight)),
                ])
            }
        )

        var registrationMap = OrderedDictionary<TransactionMetadatum, TransactionMetadatum>()
        registrationMap[.int(1)] = delegationsMetadatum
        registrationMap[.int(2)] = .bytes(stakeCredential)
        registrationMap[.int(3)] = .bytes(rewardsAddress.toBytes())
        registrationMap[.int(4)] = .int(Int(nonce))
        registrationMap[.int(5)] = .int(Int(votingPurpose))

        let registration: TransactionMetadatum = .map(registrationMap)

        return try buildSignedAuxiliaryData(
            payloadLabel: registrationLabel,
            payload: registration,
            witnessLabel: witnessLabel,
            signingKey: stakeSigningKey
        )
    }

    // MARK: - Deregistration

    /// Build a CIP-36 deregistration `AuxiliaryData`.
    ///
    /// Deregistration removes the voter from Catalyst voting; subsequent
    /// snapshot epochs ignore their stake credential until they
    /// re-register.
    public static func makeDeregistration(
        stakeSigningKey: SigningKeyType,
        nonce: UInt64,
        votingPurpose: UInt64 = 0
    ) throws -> AuxiliaryData {
        guard nonce <= UInt64(Int.max) else {
            throw CIP36Error.nonceOutOfRange(nonce)
        }
        guard votingPurpose <= UInt64(Int.max) else {
            throw CIP36Error.nonceOutOfRange(votingPurpose)
        }

        let stakeCredential = try deriveStakeCredential(from: stakeSigningKey)

        var deregMap = OrderedDictionary<TransactionMetadatum, TransactionMetadatum>()
        deregMap[.int(1)] = .bytes(stakeCredential)
        deregMap[.int(2)] = .int(Int(nonce))
        deregMap[.int(3)] = .int(Int(votingPurpose))

        return try buildSignedAuxiliaryData(
            payloadLabel: deregistrationLabel,
            payload: .map(deregMap),
            witnessLabel: deregistrationWitnessLabel,
            signingKey: stakeSigningKey
        )
    }

    // MARK: - Implementation

    /// Derive the 32-byte stake credential field from a signing key.
    ///
    /// CIP-36 field `2` carries the raw verification-key bytes (not the
    /// 28-byte Blake2b-224 hash that goes into addresses). For extended
    /// keys the chain code is stripped.
    private static func deriveStakeCredential(
        from signingKey: SigningKeyType
    ) throws -> Data {
        let vkType = try signingKey.toVerificationKeyType()
        switch vkType {
        case .verificationKey(let key):
            guard key.payload.count == 32 else {
                throw CIP36Error.invalidStakeCredentialLength(key.payload.count)
            }
            return key.payload
        case .extendedVerificationKey(let key):
            return key.payload.prefix(32)
        }
    }

    /// Common path for registration / deregistration: serialize the
    /// payload, blake2b-256 it, sign with the stake key, wrap the
    /// signature as a `{1: <sig>}` witness map, and bundle both into a
    /// single `AuxiliaryData` carrying labels `payloadLabel` and
    /// `witnessLabel`.
    private static func buildSignedAuxiliaryData(
        payloadLabel: UInt64,
        payload: TransactionMetadatum,
        witnessLabel: UInt64,
        signingKey: SigningKeyType
    ) throws -> AuxiliaryData {
        // CBOR-encode the payload metadatum and Blake2b-256 hash it.
        let payloadCBOR: Data
        do {
            payloadCBOR = try payload.toCBORData()
        } catch {
            throw CIP36Error.encodingError(String(describing: error))
        }

        let payloadHash: Data
        do {
            payloadHash = try SwiftNaCl.Hash().blake2b(
                data: payloadCBOR,
                digestSize: 32,
                encoder: RawEncoder.self
            )
        } catch {
            throw CIP36Error.encodingError("blake2b-256 failed: \(error)")
        }

        // Sign the hash with the stake key. CIP-36 §7 specifies signing
        // the blake2b-256 of the CBOR-encoded payload, not the payload
        // itself.
        let signature: Data
        do {
            signature = try signingKey.sign(data: payloadHash)
        } catch {
            throw CIP36Error.signingError(String(describing: error))
        }

        var witnessMap = OrderedDictionary<TransactionMetadatum, TransactionMetadatum>()
        witnessMap[.int(1)] = .bytes(signature)

        // Bundle payload + witness into a Metadata, wrap as AuxiliaryData.
        let metadata = try Metadata([
            payloadLabel: payload,
            witnessLabel: .map(witnessMap),
        ])
        return AuxiliaryData(data: .metadata(metadata))
    }
}
