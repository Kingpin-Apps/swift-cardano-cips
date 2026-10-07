import Foundation
import Testing

@testable import SwiftCardanoCIP21

/// CIP-21: what hardware wallets ask of a transaction, and writing a body
/// the way they ask.
@Suite("CIP-21")
struct CIP21Tests {
    /// Hand-written CBOR, so each rule can be broken on purpose.
    struct Writer {
        var data = Data()
        mutating func head(_ major: UInt8, _ value: UInt64) { RawCBOR.head(major, value, into: &data) }
        mutating func raw(_ bytes: [UInt8]) { data += bytes }
        mutating func bytes(_ bytes: Data) {
            head(2, UInt64(bytes.count))
            data += bytes
        }
        mutating func bytes(_ byte: UInt8, _ count: Int) { bytes(Data(repeating: byte, count: count)) }
        /// `[0, hash]`: a key credential.
        mutating func keyCredential(_ byte: UInt8) {
            head(4, 2); head(0, 0); bytes(byte, 28)
        }
        /// `[txid, index]`.
        mutating func input(_ byte: UInt8) {
            head(4, 2); bytes(byte, 32); head(0, 0)
        }
        /// `[address, coin]`: an enterprise key address.
        mutating func output(_ coin: UInt64) {
            head(4, 2); bytes(Data([0x60]) + Data(repeating: 0x11, count: 28)); head(0, coin)
        }
    }

    /// A whole transaction around `body`, with `witnesses` written as given
    /// and no auxiliary data.
    static func transaction(body: Data, witnesses: Data = Data([0xA0])) -> Data {
        Data([0x84]) + body + witnesses + Data([0xF5, 0xF6])
    }

    /// A transaction that breaks the encoding rules: keys out of order, an
    /// indefinite input list, an overlong fee, an empty certificate list, and
    /// one signature.
    static func messy() -> Data {
        var w = Writer()
        w.head(4, 4)
        w.head(5, 4)
        // outputs first: out of canonical order.
        w.head(0, 1)
        w.head(4, 1); w.output(2_000_000)
        // inputs, indefinite.
        w.head(0, 0)
        w.raw([0x9f]); w.input(0xAB); w.raw([0xff])
        // fee, written in two bytes it does not need.
        w.head(0, 2)
        w.raw([0x19, 0x00, 0x10])
        // an empty certificate list.
        w.head(0, 4)
        w.head(4, 0)
        // witnesses: one signature.
        w.head(5, 1)
        w.head(0, 0)
        w.head(4, 1)
        w.head(4, 2); w.bytes(0x01, 32); w.bytes(0x02, 64)
        w.raw([0xf5, 0xf6])
        return w.data
    }

    /// The body of `transaction`.
    static func body(_ transaction: Data) throws -> Data {
        let parts = try #require(try RawCBOR.read(transaction).array)
        return Data(transaction[parts[0].range])
    }

    /// A body with tagged inputs, one output, a fee, and `certificates`
    /// written untagged: the mix a CIP-21 check refuses.
    static func mixed(certificates: (inout Writer) -> Void, count: UInt64) -> Data {
        var w = Writer()
        w.head(5, 4)
        w.head(0, 0); w.raw([0xd9, 0x01, 0x02]); w.head(4, 1); w.input(0x77)
        w.head(0, 1); w.head(4, 1); w.output(5_000_000)
        w.head(0, 2); w.head(0, 171_529)
        w.head(0, 4); w.head(4, count); certificates(&w)
        return w.data
    }

    /// A Conway stake registration: `[7, credential, deposit]`.
    static func registration(_ w: inout Writer) {
        w.head(4, 3); w.head(0, 7); w.keyCredential(0xC6); w.head(0, 2_000_000)
    }

    @Test("Each encoding rule a transaction breaks is named")
    func findings() throws {
        let report = try CIP21.report(Self.messy())
        let rules = Set(report.findings.map(\.rule))
        #expect(rules == ["canonical-sorting", "canonical-definite", "canonical-length", "empty-collection"])
        #expect(report.findings.allSatisfy { $0.fixable })
        #expect(report.mode == .ordinary)
        #expect(report.findings.first { $0.rule == "canonical-definite" }?.path == "inputs")
        #expect(report.findings.first { $0.rule == "canonical-length" }?.path == "fee")
    }

    @Test("A compatible body is canonical, leaves out empty collections, and means the same")
    func compatibleBody() throws {
        let messy = Self.messy()
        let body = try CIP21.compatibleBody(try Self.body(messy))
        let report = try CIP21.report(Self.transaction(body: body))
        #expect(report.isCompatible, "\(report.findings)")

        let read = try RawCBOR.read(body)
        #expect(read.entries?.map { $0.key.unsigned } == [0, 1, 2])
        #expect(read[0]?.isTaggedSet == true)
        #expect(read[2]?.unsigned == 16)
        #expect(read[4] == nil)
        // Writing it again changes nothing.
        #expect(try CIP21.compatibleBody(body) == body)
    }

    @Test("Sets tagged some ways and not others are named, and every set comes out tagged")
    func setTags() throws {
        let body = Self.mixed(certificates: Self.registration, count: 1)
        #expect(try CIP21.report(Self.transaction(body: body)).findings.map(\.rule) == ["set-tags"])

        let compatible = try CIP21.compatibleBody(body)
        #expect(try CIP21.report(Self.transaction(body: compatible)).isCompatible)
        #expect(try RawCBOR.read(compatible)[4]?.isTaggedSet == true)
        // The tag is three bytes: the fee the body was built with no longer
        // covers it, which is why a builder writes the body this way before
        // it sizes the fee.
        #expect(compatible.count == body.count + 3)
    }

    @Test("A pool registration's owners are a set too")
    func poolOwners() throws {
        func pool(_ w: inout Writer) {
            // [3, operator, vrf, pledge, cost, margin, reward account, owners, relays, metadata]
            w.head(4, 10); w.head(0, 3); w.bytes(0x01, 28); w.bytes(0x09, 32); w.head(0, 1_000_000); w.head(0, 170_000_000)
            w.raw([0xd8, 0x1e]); w.head(4, 2); w.head(0, 1); w.head(0, 20)
            w.bytes(Data([0xE0]) + Data(repeating: 0x02, count: 28))
            w.head(4, 1); w.bytes(0x02, 28)
            w.head(4, 0)
            w.raw([0xf6])
        }
        let body = Self.mixed(certificates: pool, count: 1)
        let compatible = try CIP21.compatibleBody(body)
        let report = try CIP21.report(Self.transaction(body: compatible))
        #expect(report.mode == .poolRegistration)
        #expect(report.isCompatible, "\(report.findings)")
        let certificate = try #require(try RawCBOR.read(compatible)[4]?.array?.first?.array)
        #expect(certificate[7].isTaggedSet)
        // No relays: an empty list, which is not a set to tag.
        #expect(certificate[8].isTaggedSet == false)
    }

    @Test("Certificates hardware wallets cannot sign are named, and writing the body differently does not change that")
    func prohibitedCertificates() throws {
        // [11, credential, pool, deposit]: stake registration and delegation.
        func registerAndDelegate(_ w: inout Writer) {
            w.head(4, 4); w.head(0, 11); w.keyCredential(0xC6); w.bytes(0xAB, 28); w.head(0, 2_000_000)
        }
        let body = Self.mixed(certificates: registerAndDelegate, count: 1)
        let report = try CIP21.report(Self.transaction(body: try CIP21.compatibleBody(body)))
        let finding = try #require(report.findings.first)
        #expect(finding.rule == "prohibited-certificate")
        #expect(!finding.fixable)
        #expect(finding.path == "certificates[0]")
    }

    @Test("A pool registration signs alone")
    func poolRegistrationAlone() throws {
        func both(_ w: inout Writer) {
            w.head(4, 3); w.head(0, 4); w.bytes(0x01, 28); w.head(0, 300)
            Self.registration(&w)
        }
        // A retirement is not a registration: an ordinary transaction.
        let body = Self.mixed(certificates: both, count: 2)
        #expect(try CIP21.report(Self.transaction(body: body)).mode == .ordinary)
    }

    @Test("Script data, collateral or redeemers sign in Plutus mode; native scripts as multisig")
    func modes() throws {
        var w = Writer()
        w.head(5, 4)
        w.head(0, 0); w.raw([0xd9, 0x01, 0x02]); w.head(4, 1); w.input(0x77)
        w.head(0, 1); w.head(4, 1); w.output(5_000_000)
        w.head(0, 2); w.head(0, 200_000)
        w.head(0, 11); w.bytes(0x55, 32)
        #expect(try CIP21.report(Self.transaction(body: w.data)).mode == .plutus)

        // A native script in the witness set: [0, key hash].
        var witnesses = Writer()
        witnesses.head(5, 1); witnesses.head(0, 1); witnesses.head(4, 1); witnesses.head(4, 2); witnesses.head(0, 0); witnesses.bytes(0x22, 28)
        let ordinary = Self.mixed(certificates: Self.registration, count: 1)
        #expect(try CIP21.report(Self.transaction(body: ordinary, witnesses: witnesses.data)).mode == .multisig)
    }

    @Test("What is not a transaction, or not a body, is refused")
    func refused() {
        #expect(throws: CIP21ReadError.self) { try CIP21.report(Data([0x01])) }
        #expect(throws: CIP21ReadError.self) { try CIP21.compatibleBody(Data([0x80])) }
        #expect(throws: CIP21ReadError.self) { try CIP21.compatibleBody(Data([0xA1, 0x00])) }
    }
}
