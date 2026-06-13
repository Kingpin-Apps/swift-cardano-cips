import Foundation
import SwiftCardanoCore

/// Errors thrown by ``CIP1855``.
public enum CIP1855Error: Error, Equatable {
    /// The policy index was outside the valid hardened range
    /// `0 ... 2³¹ − 1` (see ``CIP1855/maxPolicyIndex``).
    case invalidPolicyIndex(UInt32)
}

/// CIP-1855 — *Forging policy keys for HD Wallets*.
///
/// Defines the derivation path for native-script minting-policy keys and a
/// couple of conveniences for turning the derived verification key into a
/// minting-policy native script and its policy ID.
///
/// The policy key lives on its own three-level, fully-hardened branch:
///
/// ```
/// m / 1855' / 1815' / policy_ix'
/// ```
///
/// where `policy_ix` is a hardened index in `0 ... 2³¹ − 1`. Unlike the
/// CIP-1852 roles there is no account / role / address structure — each
/// policy index yields a single Ed25519 key used to sign a `sig` native
/// script (optionally time-locked with an `invalid_before` clause).
///
/// See [CIP-1855](https://cips.cardano.org/cip/CIP-1855) for the
/// specification.
///
/// This type only models the path and the script/ID derivation; the actual
/// BIP32-ED25519 key derivation from a mnemonic is performed by
/// `SwiftCardanoSigner.Signer.Keygen.policy(...)`, which consumes
/// ``policyKeyPath(policyIndex:)``.
public enum CIP1855 {

    // MARK: - Path components

    /// `1855'` — the CIP-1855 purpose index.
    public static let purpose: UInt32 = 1855

    /// `1815'` — the ADA (Cardano) coin type.
    public static let coinType: UInt32 = 1815

    /// The largest valid (hardened) policy index, `2³¹ − 1`.
    public static let maxPolicyIndex: UInt32 = 0x7FFF_FFFF

    // MARK: - Derivation path

    /// Validate that a policy index is within the hardened range.
    ///
    /// - Parameter policyIndex: The CIP-1855 `policy_ix`.
    /// - Throws: ``CIP1855Error/invalidPolicyIndex(_:)`` if the index
    ///   exceeds ``maxPolicyIndex``.
    public static func validate(policyIndex: UInt32) throws {
        guard policyIndex <= maxPolicyIndex else {
            throw CIP1855Error.invalidPolicyIndex(policyIndex)
        }
    }

    /// The CIP-1855 derivation path `m/1855'/1815'/<policyIndex>'`.
    ///
    /// All three levels are hardened.
    ///
    /// - Parameter policyIndex: The CIP-1855 `policy_ix` (`0 ... 2³¹ − 1`).
    /// - Returns: A BIP-32 path string using the apostrophe hardened
    ///   notation, suitable for `HDWallet.derive(fromPath:)`.
    /// - Throws: ``CIP1855Error/invalidPolicyIndex(_:)`` for out-of-range
    ///   indices.
    public static func policyKeyPath(policyIndex: UInt32) throws -> String {
        try validate(policyIndex: policyIndex)
        return "m/\(purpose)'/\(coinType)'/\(policyIndex)'"
    }

    // MARK: - Minting policy script / ID

    /// Build a minting-policy native script for a policy key hash.
    ///
    /// Without `invalidBefore` this is a bare `sig` script (a policy that
    /// only requires the policy key's signature). With `invalidBefore` it is
    /// wrapped in an `all [ invalid_before(slot), sig ]` script — a
    /// time-locked policy that becomes invalid at or after `slot`.
    ///
    /// - Parameters:
    ///   - keyHash: The policy key's ``SwiftCardanoCore/VerificationKeyHash``.
    ///   - invalidBefore: Optional slot at which the policy expires.
    /// - Returns: The corresponding ``SwiftCardanoCore/NativeScript``.
    public static func mintingPolicyScript(
        keyHash: VerificationKeyHash,
        invalidBefore: SlotNumber? = nil
    ) -> NativeScript {
        let sig: NativeScript = .scriptPubkey(ScriptPubkey(keyHash: keyHash))
        guard let slot = invalidBefore else { return sig }
        return .scriptAll(ScriptAll(scripts: [
            .invalidBefore(BeforeScript(slot: slot)),
            sig
        ]))
    }

    /// Compute the policy ID (script hash) for a policy key hash.
    ///
    /// - Parameters:
    ///   - keyHash: The policy key's ``SwiftCardanoCore/VerificationKeyHash``.
    ///   - invalidBefore: Optional slot at which the policy expires; must
    ///     match the value used when building the script for the IDs to
    ///     agree.
    /// - Returns: The ``SwiftCardanoCore/PolicyID`` (Blake2b-224 script hash).
    /// - Throws: Any error raised while hashing the native script.
    public static func policyID(
        keyHash: VerificationKeyHash,
        invalidBefore: SlotNumber? = nil
    ) throws -> PolicyID {
        try mintingPolicyScript(
            keyHash: keyHash,
            invalidBefore: invalidBefore
        ).scriptHash()
    }
}
