import Foundation
import Testing
import CBORCodable
import OrderedCollections
import SwiftCardanoCore
import SwiftNaCl
@testable import SwiftCardanoCIPs

@Suite("CIP-36 — Catalyst voting registration metadata")
struct CIP36Tests {

    // Reusing CIP-8 test fixture: known stake signing key + verification key.
    static let stakeSK = try! StakeSigningKey.fromTextEnvelope(
        """
        {
            "type": "StakeSigningKeyShelley_ed25519",
            "description": "Stake Signing Key",
            "cborHex": "5820ff3a330df8859e4e5f42a97fcaee73f6a00d0cf864f4bca902bd106d423f02c0"
        }
        """
    )

    static let stakeVK = try! StakeVerificationKey.fromTextEnvelope(
        """
        {
            "type": "StakeVerificationKeyShelley_ed25519",
            "description": "Stake Verification Key",
            "cborHex": "58205edaa384c658c2bd8945ae389edac0a5bd452d0cfd5d1245e3ecd540030d1e3c"
        }
        """
    )

    static let votingKeyA = Data(repeating: 0xAA, count: 32)
    static let votingKeyB = Data(repeating: 0xBB, count: 32)

    static func makeRewardsAddress() throws -> Address {
        try Address(
            paymentPart: nil,
            stakingPart: .verificationKeyHash(Self.stakeVK.hash()),
            network: .mainnet
        )
    }

    // MARK: - Registration

    @Test("Registration produces auxiliary data with labels 61284 + 61285")
    func registrationHasCorrectLabels() throws {
        let aux = try CIP36.makeRegistration(
            delegations: [.init(votingKey: Self.votingKeyA, weight: 1)],
            stakeSigningKey: .signingKey(Self.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 12_345
        )
        guard case let .metadata(metadata) = aux.data else {
            Issue.record("Expected MetadataType.metadata, got \(aux.data)")
            return
        }
        #expect(metadata.data[61_284] != nil)
        #expect(metadata.data[61_285] != nil)
        #expect(metadata.data.count == 2)
    }

    @Test("Registration witness signature verifies against the stake vkey")
    func registrationSignatureVerifies() throws {
        let aux = try CIP36.makeRegistration(
            delegations: [.init(votingKey: Self.votingKeyA, weight: 1)],
            stakeSigningKey: .signingKey(Self.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 12_345
        )

        guard case let .metadata(metadata) = aux.data,
              let registration = metadata.data[61_284],
              case let .map(witnessMap) = metadata.data[61_285],
              case let .bytes(signature) = witnessMap[.int(1)] else {
            Issue.record("Witness map shape did not match CIP-36")
            return
        }

        let registrationHash = try SwiftNaCl.Hash().blake2b(
            data: registration.toCBORData(),
            digestSize: 32,
            encoder: RawEncoder.self
        )

        let verifyKey = try VerifyKey(key: Self.stakeVK.payload)
        _ = try verifyKey.verify(smessage: registrationHash, signature: signature)
        // verify(...) throws on bad signature; reaching here = success.
    }

    @Test("Multi-delegation encodes as an array of [vkey, weight] pairs")
    func multiDelegation() throws {
        let aux = try CIP36.makeRegistration(
            delegations: [
                .init(votingKey: Self.votingKeyA, weight: 3),
                .init(votingKey: Self.votingKeyB, weight: 7),
            ],
            stakeSigningKey: .signingKey(Self.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 1
        )

        guard case let .metadata(metadata) = aux.data,
              case let .map(reg) = metadata.data[61_284],
              case let .list(delegations) = reg[.int(1)] else {
            Issue.record("Expected delegations list under field 1")
            return
        }
        #expect(delegations.count == 2)

        // Each item is [vkey, weight].
        guard case let .list(first) = delegations[0],
              first.count == 2,
              case let .bytes(firstKey) = first[0],
              case let .int(firstWeight) = first[1] else {
            Issue.record("First delegation pair shape mismatch")
            return
        }
        #expect(firstKey == Self.votingKeyA)
        #expect(firstWeight == 3)

        guard case let .list(second) = delegations[1],
              case let .bytes(secondKey) = second[0],
              case let .int(secondWeight) = second[1] else {
            Issue.record("Second delegation pair shape mismatch")
            return
        }
        #expect(secondKey == Self.votingKeyB)
        #expect(secondWeight == 7)
    }

    @Test("Default voting_purpose is 0 (Catalyst)")
    func defaultVotingPurpose() throws {
        let aux = try CIP36.makeRegistration(
            delegations: [.init(votingKey: Self.votingKeyA, weight: 1)],
            stakeSigningKey: .signingKey(Self.stakeSK),
            rewardsAddress: try Self.makeRewardsAddress(),
            nonce: 1
        )
        guard case let .metadata(metadata) = aux.data,
              case let .map(reg) = metadata.data[61_284],
              case let .int(purpose) = reg[.int(5)] else {
            Issue.record("Missing voting_purpose field")
            return
        }
        #expect(purpose == 0)
    }

    @Test("Empty delegations throws")
    func emptyDelegationsThrows() {
        #expect(throws: CIP36Error.self) {
            _ = try CIP36.makeRegistration(
                delegations: [],
                stakeSigningKey: .signingKey(Self.stakeSK),
                rewardsAddress: try Self.makeRewardsAddress(),
                nonce: 1
            )
        }
    }

    @Test("Wrong-length voting key throws")
    func wrongLengthVotingKey() {
        #expect(throws: CIP36Error.self) {
            _ = try CIP36.makeRegistration(
                delegations: [.init(votingKey: Data(repeating: 0xAA, count: 31), weight: 1)],
                stakeSigningKey: .signingKey(Self.stakeSK),
                rewardsAddress: try Self.makeRewardsAddress(),
                nonce: 1
            )
        }
    }

    // MARK: - Deregistration

    @Test("Deregistration produces labels 61286 + 61287 with verifiable signature")
    func deregistrationRoundTrip() throws {
        let aux = try CIP36.makeDeregistration(
            stakeSigningKey: .signingKey(Self.stakeSK),
            nonce: 99
        )

        guard case let .metadata(metadata) = aux.data else {
            Issue.record("Expected MetadataType.metadata, got \(aux.data)")
            return
        }
        #expect(metadata.data[61_286] != nil)
        #expect(metadata.data[61_287] != nil)
        #expect(metadata.data[61_284] == nil)

        guard case let .map(dereg) = metadata.data[61_286],
              case let .bytes(stakeCred) = dereg[.int(1)],
              case let .int(nonce) = dereg[.int(2)] else {
            Issue.record("Deregistration map shape mismatch")
            return
        }
        #expect(stakeCred == Self.stakeVK.payload)
        #expect(nonce == 99)

        // Witness signature must verify over the blake2b-256 of the
        // 61286 payload bytes.
        guard let dereg61286 = metadata.data[61_286],
              case let .map(witnessMap) = metadata.data[61_287],
              case let .bytes(signature) = witnessMap[.int(1)] else {
            Issue.record("Witness map shape mismatch")
            return
        }
        let derHash = try SwiftNaCl.Hash().blake2b(
            data: dereg61286.toCBORData(),
            digestSize: 32,
            encoder: RawEncoder.self
        )
        let verifyKey = try VerifyKey(key: Self.stakeVK.payload)
        _ = try verifyKey.verify(smessage: derHash, signature: signature)
    }
}
