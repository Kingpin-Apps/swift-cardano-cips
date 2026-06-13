import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoCIPs

@Suite("CIP-1855 — HD minting-policy keys")
struct CIP1855Tests {

    static let keyHash = VerificationKeyHash(
        payload: Data(repeating: 0xAB, count: VERIFICATION_KEY_HASH_SIZE)
    )

    // MARK: - Derivation path

    @Test("policyKeyPath builds m/1855'/1815'/<ix>' for valid indices")
    func pathShape() throws {
        #expect(try CIP1855.policyKeyPath(policyIndex: 0) == "m/1855'/1815'/0'")
        #expect(try CIP1855.policyKeyPath(policyIndex: 5) == "m/1855'/1815'/5'")
        #expect(
            try CIP1855.policyKeyPath(policyIndex: CIP1855.maxPolicyIndex)
                == "m/1855'/1815'/2147483647'"
        )
    }

    @Test("Out-of-range policy index throws invalidPolicyIndex")
    func rejectsOutOfRange() {
        let bad = CIP1855.maxPolicyIndex + 1
        #expect(throws: CIP1855Error.invalidPolicyIndex(bad)) {
            try CIP1855.validate(policyIndex: bad)
        }
        #expect(throws: CIP1855Error.invalidPolicyIndex(bad)) {
            _ = try CIP1855.policyKeyPath(policyIndex: bad)
        }
    }

    // MARK: - Native script shape

    @Test("Sig-only script when no time-lock is given")
    func sigOnlyScript() {
        let script = CIP1855.mintingPolicyScript(keyHash: Self.keyHash)
        guard case let .scriptPubkey(pub) = script else {
            Issue.record("expected .scriptPubkey, got \(script)")
            return
        }
        #expect(pub.keyHash == Self.keyHash)
    }

    @Test("Time-locked script wraps invalid_before + sig in an all script")
    func timeLockedScript() {
        let script = CIP1855.mintingPolicyScript(keyHash: Self.keyHash, invalidBefore: 1000)
        guard case let .scriptAll(all) = script else {
            Issue.record("expected .scriptAll, got \(script)")
            return
        }
        #expect(all.scripts.count == 2)
        guard case let .invalidBefore(before) = all.scripts[0] else {
            Issue.record("expected first sub-script to be .invalidBefore")
            return
        }
        #expect(before.slot == 1000)
        guard case .scriptPubkey = all.scripts[1] else {
            Issue.record("expected second sub-script to be .scriptPubkey")
            return
        }
    }

    // MARK: - Policy ID

    @Test("policyID is deterministic and matches the script hash")
    func policyIDDeterministic() throws {
        let a = try CIP1855.policyID(keyHash: Self.keyHash)
        let b = try CIP1855.policyID(keyHash: Self.keyHash)
        #expect(a == b)

        let scriptHash = try CIP1855.mintingPolicyScript(keyHash: Self.keyHash).scriptHash()
        #expect(a == scriptHash)
    }

    @Test("Time-locked policy ID differs from the sig-only policy ID")
    func timeLockChangesPolicyID() throws {
        let sigOnly = try CIP1855.policyID(keyHash: Self.keyHash)
        let timeLocked = try CIP1855.policyID(keyHash: Self.keyHash, invalidBefore: 1000)
        #expect(sigOnly != timeLocked)
    }
}
