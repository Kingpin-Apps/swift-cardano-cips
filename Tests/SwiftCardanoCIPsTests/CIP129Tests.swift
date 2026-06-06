import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoCIPs

@Suite("CIP-129 — governance bech32 IDs")
struct CIP129Tests {

    // 28-byte test hash — arbitrary fixed bytes so round-trip tests can
    // assert reproducible bech32 strings.
    static let testKeyHash = Data((0..<28).map { UInt8($0) })

    // MARK: - Header bytes

    @Test("Header bytes match the CIP-129 specification")
    func headerBytesMatchSpec() {
        // Upper nibble = credential type, lower nibble = key (0x2) / script (0x3).
        #expect(CIP129.Prefix.ccHot.headerByte(isScript: false)   == 0x02)
        #expect(CIP129.Prefix.ccHot.headerByte(isScript: true)    == 0x03)
        #expect(CIP129.Prefix.ccCold.headerByte(isScript: false)  == 0x12)
        #expect(CIP129.Prefix.ccCold.headerByte(isScript: true)   == 0x13)
        #expect(CIP129.Prefix.drep.headerByte(isScript: false)    == 0x22)
        #expect(CIP129.Prefix.drep.headerByte(isScript: true)     == 0x23)

        // Calidus per CIP-151 — key form only.
        #expect(CIP129.Prefix.calidus.headerByte(isScript: false) == 0xa1)
        #expect(CIP129.Prefix.calidus.headerByte(isScript: true)  == nil)
    }

    @Test("HRP strings match CIP-129")
    func hrpStrings() {
        #expect(CIP129.Prefix.drep.hrp    == "drep")
        #expect(CIP129.Prefix.ccCold.hrp  == "cc_cold")
        #expect(CIP129.Prefix.ccHot.hrp   == "cc_hot")
        #expect(CIP129.Prefix.calidus.hrp == "calidus")
    }

    // MARK: - Round-trip

    @Test("encode → decode round-trips for every prefix / form", arguments: [
        (CIP129.Prefix.drep,    false),
        (.drep,    true),
        (.ccCold,  false),
        (.ccCold,  true),
        (.ccHot,   false),
        (.ccHot,   true),
        (.calidus, false),
    ])
    func encodeDecodeRoundTrip(prefix: CIP129.Prefix, isScript: Bool) throws {
        let encoded = try CIP129.encode(
            keyHash: Self.testKeyHash,
            as: prefix,
            isScript: isScript
        )
        // Result starts with the HRP + checksum separator '1'.
        #expect(encoded.hasPrefix(prefix.hrp + "1"))

        let (decodedPrefix, decodedHash, decodedIsScript) = try CIP129.decode(encoded)
        #expect(decodedPrefix    == prefix)
        #expect(decodedHash      == Self.testKeyHash)
        #expect(decodedIsScript  == isScript)
    }

    @Test("Calidus script form is rejected (no script form defined)")
    func calidusScriptRejected() {
        #expect(throws: CIP129Error.self) {
            _ = try CIP129.encode(
                keyHash: Self.testKeyHash,
                as: .calidus,
                isScript: true
            )
        }
    }

    @Test("Encoding rejects non-28-byte key hashes")
    func rejectsWrongLengthHash() {
        #expect(throws: CIP129Error.self) {
            _ = try CIP129.encode(
                keyHash: Data(repeating: 0, count: 27),
                as: .drep
            )
        }
        #expect(throws: CIP129Error.self) {
            _ = try CIP129.encode(
                keyHash: Data(repeating: 0, count: 32),
                as: .drep
            )
        }
    }

    @Test("Decode rejects an unknown HRP")
    func decodeRejectsUnknownPrefix() {
        // Build a valid bech32 string with an unrelated HRP.
        let payload = Data([0x22]) + Self.testKeyHash
        let bogus = Bech32().encode(hrp: "addr", witprog: payload)!
        #expect(throws: CIP129Error.self) {
            _ = try CIP129.decode(bogus)
        }
    }

    @Test("Decode rejects a header byte that contradicts the HRP")
    func decodeRejectsHeaderHRPMismatch() {
        // Encode with a `drep` HRP but a `cc_cold` (0x12) header byte —
        // legal bech32, illegal CIP-129.
        let payload = Data([0x12]) + Self.testKeyHash
        let mismatched = Bech32().encode(hrp: "drep", witprog: payload)!
        #expect(throws: CIP129Error.self) {
            _ = try CIP129.decode(mismatched)
        }
    }

    @Test("Decode rejects a malformed (truncated) bech32 string")
    func decodeRejectsTruncated() {
        let valid = try! CIP129.encode(keyHash: Self.testKeyHash, as: .drep)
        let truncated = String(valid.dropLast(4))
        #expect(throws: CIP129Error.self) {
            _ = try CIP129.decode(truncated)
        }
    }
}
