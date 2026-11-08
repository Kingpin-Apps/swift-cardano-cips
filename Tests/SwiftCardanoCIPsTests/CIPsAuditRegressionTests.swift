import Foundation
import Testing
import SwiftCardanoCore
@testable import SwiftCardanoCIPs

/// Regression tests for the 2026-11-08 security audit of swift-cardano-cips.
@Suite("Security regressions — CIP-14 / CIP-30 / CIP-100 / CIP-119")
struct CIPsAuditRegressionTests {
    static let keys = CIP30Tests()

    // MARK: CIP-100 strict mode

    static let context = #"{"CIP108":"https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#","body":{"@id":"CIP108:body","@context":{"title":"CIP108:title","rationale":"CIP108:rationale"}}}"#

    @Test("Strict verification rejects a remap to an ill-formed IRI or an invalid language tag")
    func strictModeIllFormedTerms() async throws {
        let original = Data(#"{"@context":\#(Self.context),"hashAlgorithm":"blake2b-256","body":{"title":"Vote","rationale":"I APPROVE"}}"#.utf8)
        let signed = try await CIP100.signMetadata(
            document: original, signingKey: .signingKey(CIP100Tests.stakeSK), authorName: "Alice")
        let json = try #require(try JSONSerialization.jsonObject(with: signed) as? [String: Any])
        let authors = try JSONSerialization.data(withJSONObject: json["authors"]!)
        let authorsJSON = String(decoding: authors, as: UTF8.self)
        let prefix = "https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#"
        func variant(_ inner: String, _ body: String) -> Data {
            Data(#"{"@context":{"CIP108":"\#(prefix)","body":{"@id":"CIP108:body","@context":\#(inner)}},"hashAlgorithm":"blake2b-256","body":\#(body),"authors":\#(authorsJSON)}"#.utf8)
        }
        let variants = [
            variant(#"{"title":"CIP108:title","rationale":"CIP108:x y","zz":"CIP108:rationale"}"#,
                    #"{"title":"Vote","rationale":"I REJECT","zz":"I APPROVE"}"#),
            variant(#"{"title":"CIP108:title","rationale":"_:hidden"}"#,
                    #"{"title":"Vote","rationale":"I REJECT","CIP108:rationale":"I APPROVE"}"#),
            variant(#"{"title":"CIP108:title","rationale":"CIP108:rationale"}"#,
                    #"{"title":["Vote",{"@value":"Withdrawn","@language":"x y"}],"rationale":"I APPROVE"}"#),
        ]
        #expect(try await CIP100.verifyMetadata(signed).allValid)
        for doc in variants {
            await #expect(throws: (any Error).self) { _ = try await CIP100.verifyMetadata(doc) }
        }
    }

    // MARK: CIP-100 / CIP-119 depth checks

    @Test("A UTF-16 document is refused before JSONSerialization parses it")
    func utf16Refused() async throws {
        let text = #"{"@context":{},"body":{"x":"y"}}"#
        let utf16 = try #require(text.data(using: .utf16LittleEndian))
        #expect(throws: CIP100Error.self) { try CIP100.checkRawNestingDepth(utf16) }
        #expect(throws: CIP100Error.self) { try CIP100.checkRawNestingDepth(Data("]]]{".utf8)) }
        try CIP100.checkRawNestingDepth(Data(text.utf8))
    }

    @Test("DRepMetadata.fromJSON refuses deep nesting before parsing")
    func drepDepth() throws {
        let nested = String(repeating: "[", count: 300) + "1" + String(repeating: "]", count: 300)
        let json = #"{"body":{"givenName":"x","z":\#(nested)}}"#
        #expect(throws: CIP119Error.self) { _ = try DRepMetadata.fromJSON(json) }
        let ok = try DRepMetadata.fromJSON(#"{"body":{"givenName":"Alice"}}"#)
        #expect(ok.givenName == "Alice")
    }

    // MARK: CIP-14

    @Test("CIP-14 rejects malformed hex and wrong-length inputs")
    func cip14Strict() throws {
        let policy = "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373"
        #expect(try CIP14.encodeAsset(policyId: .hexString(policy), assetName: .hexString("504154415445"))
                == "asset13n25uv0yaf5kus35fm2k86cqy60z58d9xmde92")
        #expect(throws: CIP14Error.self) {
            _ = try CIP14.encodeAsset(policyId: .hexString("zz"), assetName: .hexString(policy + "504154415445"))
        }
        #expect(throws: CIP14Error.self) {
            _ = try CIP14.encodeAsset(policyId: .hexString(String(policy.dropLast(2))), assetName: .hexString("73504154415445"))
        }
        #expect(throws: CIP14Error.self) { _ = try CIP14.encodeAsset(policyId: .hexString("abc"), assetName: .hexString("")) }
        #expect(throws: CIP14Error.self) { _ = try CIP14.encodeAsset(policyId: .data(Data()), assetName: .data(Data(count: 34))) }
        #expect(throws: CIP14Error.self) {
            _ = try CIP14.encodeAsset(policyId: .hexString(policy), assetName: .data(Data(count: 33)))
        }
    }

    // MARK: CIP-30 signData

    static func provider() throws -> KeyStoreCIP30Provider {
        try KeyStoreCIP30Provider(
            info: WalletInfo(name: "Test", icon: ""),
            paymentKey: .signingKey(keys.paymentSK),
            stakeKey: .signingKey(keys.stakeSK),
            network: .preview,
            policy: .allowAll
        )
    }

    static func walletAddresses() throws -> (base: Address, enterprise: Address, reward: Address) {
        let paymentVKey: PaymentVerificationKey = try keys.paymentSK.toVerificationKey()
        let stakeVKey: StakeVerificationKey = try keys.stakeSK.toVerificationKey()
        let payment = PaymentPart.verificationKeyHash(try paymentVKey.hash())
        let staking = StakingPart.verificationKeyHash(try stakeVKey.hash())
        return (
            try Address(paymentPart: payment, stakingPart: staking, network: .testnet),
            try Address(paymentPart: payment, stakingPart: nil, network: .testnet),
            try Address(paymentPart: nil, stakingPart: staking, network: .testnet)
        )
    }

    @Test("signData signs exactly the requested wallet address")
    func signDataBindsRequestedAddress() async throws {
        let provider = try Self.provider()
        let wallet = try Self.walletAddresses()
        for target in [wallet.base, wallet.enterprise, wallet.reward] {
            let signed = try await provider.signData(address: try target.toBech32(), payload: Data("hi".utf8))
            let result = try CIP8.verify(signedMessage: SignedMessage(signature: signed.signature, key: signed.key))
            #expect(result.verified)
            #expect(result.signingAddress.toBytes() == target.toBytes())
        }
    }

    @Test("signData refuses another network or a foreign stake credential")
    func signDataRefusesForeignAddress() async throws {
        let provider = try Self.provider()
        let wallet = try Self.walletAddresses()
        let foreignStake = try Address(
            paymentPart: wallet.base.paymentPart,
            stakingPart: .verificationKeyHash(VerificationKeyHash(payload: Data(repeating: 0xab, count: 28))),
            network: .testnet)
        let mainnet = try Address(paymentPart: wallet.base.paymentPart, stakingPart: wallet.base.stakingPart, network: .mainnet)
        let mainnetReward = try Address(paymentPart: nil, stakingPart: wallet.reward.stakingPart, network: .mainnet)
        for target in [foreignStake, mainnet, mainnetReward] {
            await #expect(throws: DataSignError.self) {
                _ = try await provider.signData(address: try target.toBech32(), payload: Data("hi".utf8))
            }
        }
    }

    // MARK: CIP-30 revocation

    actor Gate {
        private var continuation: CheckedContinuation<Bool, Never>?
        private(set) var waiting = false
        func wait() async -> Bool {
            await withCheckedContinuation { continuation = $0; waiting = true }
        }
        func open(_ value: Bool) { continuation?.resume(returning: value); continuation = nil }
    }

    @Test("A revocation while consent is pending is not undone by the consent")
    func revocationWinsOverPendingConsent() async throws {
        let gate = Gate()
        let initial = KeyStoreCIP30Initial(
            info: WalletInfo(name: "Test", icon: ""),
            consent: { _, _ in await gate.wait() },
            makeProvider: { _, _ in try Self.provider() }
        )
        let context = CIP30RequestContext(origin: "https://dapp.example", isMainFrame: true)
        let enable = Task { try await initial.enable(extensions: [], context: context) }
        while await !gate.waiting { await Task.yield() }
        await initial.invalidate(origin: context.origin)
        await gate.open(true)
        await #expect(throws: APIError.self) { _ = try await enable.value }
        #expect(await initial.isEnabled(context: context) == false)
    }

    @Test("A failed makeProvider leaves the origin disabled")
    func failedProviderLeavesOriginDisabled() async throws {
        let initial = KeyStoreCIP30Initial(
            info: WalletInfo(name: "Test", icon: ""),
            consent: { _, _ in true },
            makeProvider: { _, _ in throw APIError.internalError("no keys") }
        )
        let context = CIP30RequestContext(origin: "https://dapp.example", isMainFrame: true)
        await #expect(throws: APIError.self) { _ = try await initial.enable(extensions: [], context: context) }
        #expect(await initial.isEnabled(context: context) == false)
    }
}

#if canImport(WebKit) && (os(iOS) || os(macOS) || os(visionOS))
@Suite("Security regressions — CIP-30 bridge revocation")
struct CIP30BridgeRevocationTests {
    @MainActor
    @Test("invalidateAll during a pending enable leaves the origin without a provider")
    func invalidateAllWinsOverPendingEnable() async throws {
        let gate = CIPsAuditRegressionTests.Gate()
        let initial = KeyStoreCIP30Initial(
            info: WalletInfo(name: "Test", icon: ""),
            consent: { _, _ in await gate.wait() },
            makeProvider: { _, _ in try CIPsAuditRegressionTests.provider() }
        )
        let bridge = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet")
        let context = CIP30RequestContext(origin: "https://dapp.example", isMainFrame: true)
        let enable = Task { @MainActor () -> Bool in
            _ = try await bridge.dispatch(method: "enable", params: [:], context: context)
            return true
        }
        while await !gate.waiting { await Task.yield() }
        await bridge.invalidateAll()
        await gate.open(true)
        await #expect(throws: APIError.self) { _ = try await enable.value }
        var refused = false
        do { _ = try await bridge.dispatch(method: "getNetworkId", params: [:], context: context) } catch { refused = error is APIError }
        #expect(refused)
        #expect(await initial.isEnabled(context: context) == false)
    }
}
#endif
