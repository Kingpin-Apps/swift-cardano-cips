import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoCIPs

/// Golden vectors for the signed CIP-36 and CIP-88 metadata. The bytes were
/// produced by this package built against SwiftCardanoCore 0.4.6, before the
/// port to 0.10, so they pin the exact CBOR that is signed.
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
        #expect(try Self.labelHex(aux, CIP36.witnessLabel) ==
            "a101584077ffa94e367e2294ad8aaa19afa88b46866d1e8e3d59b6e22b45e386aabd931a51a3c9be1480818648c73be3317bec4bbd2bf20f22bf8a3e0dc10c4964b45602")
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
        #expect(try Self.labelHex(aux, CIP36.deregistrationWitnessLabel) ==
            "a1015840c0faa43bd20c020c944017c73e50ffa3533d01dc7ed5f5d3945e693e8dc99654fd83b993f78eef3e8a06bfb4b9712f2eeb56568559e1e28d91654438fb163a03")
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
