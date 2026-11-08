import Foundation
import Testing

@testable import SwiftCardanoCIP21

/// Regression tests for the 2026-11-08 security audit of swift-cardano-cips.
@Suite("CIP-21 security regressions")
struct CIP21AuditRegressionTests {
    static func data(_ hex: String) -> Data {
        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            data.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return data
    }

    @Test("A 64-bit string length throws instead of trapping")
    func hugeLengths() {
        #expect(throws: CIP21ReadError.self) { _ = try CIP21.compatibleBody(Self.data("5bffffffffffffffff")) }
        #expect(throws: CIP21ReadError.self) { _ = try CIP21.report(Self.data("825b7fffffffffffffffa0")) }
        #expect(throws: CIP21ReadError.self) { _ = try CIP21.compatibleBody(Self.data("a1075f5bffffffffffffffffff")) }
    }

    @Test("Invalid UTF-8 text and stray breaks are refused, not rewritten")
    func malformedItems() {
        #expect(throws: CIP21ReadError.self) { _ = try CIP21.compatibleBody(Self.data("a10762c328")) }
        #expect(throws: CIP21ReadError.self) { _ = try CIP21.report(Self.data("82a10762c328a0")) }
        #expect(throws: CIP21ReadError.self) { _ = try CIP21.compatibleBody(Self.data("a107ff")) }
        #expect(throws: CIP21ReadError.self) { _ = try CIP21.report(Self.data("82a107ffa0")) }
        #expect(throws: CIP21ReadError.self) { _ = try CIP21.compatibleBody(Self.data("a107f814")) }
    }

    @Test("Nesting beyond 64 levels throws")
    func depthCap() throws {
        let deep = Data([0xa1, 0x00] + Array(repeating: 0x81, count: 100) + [0x00])
        #expect(throws: CIP21ReadError.self) { _ = try CIP21.compatibleBody(deep) }
        let fine = Data([0xa1, 0x00] + Array(repeating: 0x81, count: 40) + [0x00])
        _ = try CIP21.compatibleBody(fine)
    }
}
