import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoCIPs

/// Golden vectors for the signed CIP-36 and CIP-88 metadata. The payload bytes
/// were produced by this package built against SwiftCardanoCore 0.4.6, before
/// the port to 0.10. The CIP-36 witnesses were regenerated when signing moved
/// to the label-wrapped sign_data ({61284|61286: payload}) used by
/// cardano-signer and the Ledger Cardano app; CIP36Tests checks them against
/// that scope independently.
@Suite("CIP-36 / CIP-88 — golden CBOR vectors")
struct CIP36CIP88VectorTests {

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// The CBOR of one metadata label's value.
    static func labelHex(_ aux: AuxiliaryData, _ label: UInt64) throws -> String {
        guard case let .metadata(metadata) = aux.data, let value = metadata.data[label] else {
            Issue.record("No metadata under label \(label)")
            return ""
        }
        return hex(try value.toCBORData())
    }

    @Test("CIP-36 registration payload and witness match the pre-port bytes")
    func cip36Registration() throws {
        let aux = try CIP36.makeRegistration(
            delegations: [
                .init(votingKey: CIP36Tests.votingKeyA, weight: 3),
                .init(votingKey: CIP36Tests.votingKeyB, weight: 7),
            ],
            stakeSigningKey: .signingKey(CIP36Tests.stakeSK),
            rewardsAddress: try CIP36Tests.makeRewardsAddress(),
            nonce: 12_345
        )
        #expect(try Self.labelHex(aux, CIP36.registrationLabel) ==
            "a50182825820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03825820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb070258205edaa384c658c2bd8945ae389edac0a5bd452d0cfd5d1245e3ecd540030d1e3c03581de14828a2dadba97ca9fd0cdc99975899470c219bdc0d828cfa6ddf6d69041930390500")
        let witness = try Self.labelHex(aux, CIP36.witnessLabel)
        #expect(witness ==
            "a10158407759d560615836a4ef047bbb43add9e9986ae0eff7f35a8df0aa11aee4b6867d7920eca4875e4d0ec37555fdf29a23b1ef942e8134c67c73e4eb6d34ae98e802")
        // Labels are written in ascending order.
        #expect(Self.hex(try aux.toCBORData()).hasPrefix("a219ef64a5"))
    }

    @Test("CIP-36 deregistration payload and witness match the pre-port bytes")
    func cip36Deregistration() throws {
        let aux = try CIP36.makeDeregistration(
            stakeSigningKey: .signingKey(CIP36Tests.stakeSK),
            nonce: 99
        )
        #expect(try Self.labelHex(aux, CIP36.deregistrationLabel) ==
            "a30158205edaa384c658c2bd8945ae389edac0a5bd452d0cfd5d1245e3ecd540030d1e3c0218630300")
        let witness = try Self.labelHex(aux, CIP36.deregistrationWitnessLabel)
        #expect(witness ==
            "a1015840e07293282dc1bd8deecabd597acaee923269bf8aa025109ca7f5b1d8f1236d25005e9c2c0c82ab70bf4fc01103b56257e71fc1b3510e82da06b409c59fff7605")
        #expect(Self.hex(try aux.toCBORData()).hasPrefix("a219ef66a3"))
    }

    @Test("CIP-88 Calidus registration matches the pre-port bytes")
    func cip88Calidus() throws {
        let aux = try CIP88.makeCalidusRegistration(
            calidusPublicKey: CIP88Tests.calidusKey,
            poolSigningKey: .signingKey(CIP88Tests.poolSK),
            nonce: 9_999
        )
        #expect(Self.hex(try aux.toCBORData()) ==
            "a1190363a3000201a5018201581cd413c1745d306023e49589e658a7b7a4b4dda165ff5c97d8c8b979bf02800381000419270f075820cacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca0281a300000158208be8339e9f3addfa6810d59e2f072f85e64d4c024c087e0d24f8317c6544f62f0258409b61541062af5f5deff98a3914033a9e533f98b59ae83b597fbef9808de609e35472f38a375065718de8edb827004700cb53acfbd71730f3282ce94788b7650e")
    }
}
