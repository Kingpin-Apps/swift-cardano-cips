#if canImport(WebKit) && os(macOS)

import Foundation
import Testing
import WebKit
import SwiftCardanoCore

@testable import SwiftCardanoCIPs

/// End-to-end tests for ``CIP30WebBridge`` that exercise the live JS shim through a real
/// ``WKWebView``. These complement the unit tests in `CIP30Tests.swift`, which drive the
/// bridge with synthesized contexts and don't actually evaluate the injected JS.
///
/// Gated on macOS only — `swift test` runs there by default and `WKWebView` doesn't need
/// a host app there. iOS would require an XCTest UI test target.
@Suite(.serialized) struct CIP30BridgeIntegrationTests {

    // MARK: - enable / refuse

    @MainActor
    @Test func enableAndGetNetworkIdRoundTrip() async throws {
        let fixture = try await IntegrationFixture()
        try await fixture.loadEmptyParent()
        let id = try await fixture.eval("""
            const api = await window.cardano.swiftWallet.enable();
            return await api.getNetworkId();
        """) as? Int
        #expect(id == 0)
    }

    @MainActor
    @Test func enableRefusedReturnsRefusedEnvelope() async throws {
        let fixture = try await IntegrationFixture(consentResponse: { _ in false })
        try await fixture.loadEmptyParent()
        let result = try await fixture.eval("""
            try {
                await window.cardano.swiftWallet.enable();
                return { ok: true };
            } catch (e) {
                return { ok: false, code: e.code, info: e.info };
            }
        """) as? [String: Any]
        #expect(result?["ok"] as? Bool == false)
        #expect(result?["code"] as? Int == -3)
    }

    // MARK: - read-only round-trip

    @MainActor
    @Test func getBalanceRoundTripWithEmptyDataSource() async throws {
        let fixture = try await IntegrationFixture(
            dataSource: StubDataSource(utxoSet: [], txId: "")
        )
        try await fixture.loadEmptyParent()
        let balanceHex = try await fixture.eval("""
            const api = await window.cardano.swiftWallet.enable();
            return await api.getBalance();
        """) as? String
        let balanceCBOR = try #require(Data(hexString: balanceHex ?? ""))
        let value = try Value.fromCBOR(data: balanceCBOR)
        #expect(value.coin == 0)
    }

    // MARK: - signTx + signData + submitTx

    @MainActor
    @Test func signTxRoundTripWithAllowAllPolicy() async throws {
        let fixture = try await IntegrationFixture(approvalPolicy: .allowAll)
        try await fixture.loadEmptyParent()
        let txHex = try Self.minimalTxCBOR().toHex
        let witnessHex = try await fixture.eval("""
            const api = await window.cardano.swiftWallet.enable();
            return await api.signTx(txHex, false);
        """, arguments: ["txHex": txHex]) as? String
        let witnessCBOR = try #require(Data(hexString: witnessHex ?? ""))
        let ws = try TransactionWitnessSet.fromCBOR(data: witnessCBOR)
        let vkeys = ws.vkeyWitnesses?.asList ?? []
        // Plain transfer body: only the payment witness should be emitted (PR4).
        #expect(vkeys.count == 1)
    }

    @MainActor
    @Test func signTxUnderDenyAllSurfacesUserDeclinedEnvelope() async throws {
        let fixture = try await IntegrationFixture(approvalPolicy: .denyAll)
        try await fixture.loadEmptyParent()
        let txHex = try Self.minimalTxCBOR().toHex
        let result = try await fixture.eval("""
            const api = await window.cardano.swiftWallet.enable();
            try {
                await api.signTx(txHex, false);
                return { ok: true };
            } catch (e) {
                return { ok: false, code: e.code, info: e.info };
            }
        """, arguments: ["txHex": txHex]) as? [String: Any]
        #expect(result?["ok"] as? Bool == false)
        #expect(result?["code"] as? Int == 2) // TxSignError.userDeclined
    }

    @MainActor
    @Test func signDataRoundTripWithAllowAllPolicy() async throws {
        let fixture = try await IntegrationFixture(approvalPolicy: .allowAll)
        try await fixture.loadEmptyParent()
        let walletAddress = try await fixture.walletAddressBech32()
        let result = try await fixture.eval("""
            const api = await window.cardano.swiftWallet.enable();
            return await api.signData(addr, payloadHex);
        """, arguments: ["addr": walletAddress, "payloadHex": "0102"]) as? [String: Any]
        let signature = result?["signature"] as? String
        let key = result?["key"] as? String
        #expect(signature?.isEmpty == false)
        #expect(key?.isEmpty == false)
    }

    @MainActor
    @Test func submitTxReturnsDataSourceTxId() async throws {
        let fixture = try await IntegrationFixture(
            approvalPolicy: .allowAll,
            dataSource: StubDataSource(utxoSet: [], txId: "deadbeef")
        )
        try await fixture.loadEmptyParent()
        let id = try await fixture.eval("""
            const api = await window.cardano.swiftWallet.enable();
            return await api.submitTx('00');
        """) as? String
        #expect(id == "deadbeef")
    }

    // MARK: - origin policy enforcement

    @MainActor
    @Test func iframeIsRefusedUnderMainFrameOnlyPolicy() async throws {
        let fixture = try await IntegrationFixture(originPolicy: .mainFrameOnly)
        try await fixture.loadEmptyParent()
        // Build an iframe that tries to call `isEnabled` from inside its own frame —
        // its `frameInfo.isMainFrame` is `false`, so the bridge should refuse with -3.
        let result = try await fixture.eval(#"""
            return new Promise(resolve => {
                window.recordIframeOutcome = resolve;
                const frame = document.createElement('iframe');
                // Splitting `</script>` so the inner script tag doesn't terminate the
                // outer one when the parser scans this srcdoc string.
                const inner =
                    '<scr' + 'ipt>(async () => {' +
                    '  try {' +
                    '    await window.cardano.swiftWallet.isEnabled();' +
                    '    window.parent.recordIframeOutcome({ ok: true });' +
                    '  } catch (e) {' +
                    '    window.parent.recordIframeOutcome({ ok: false, code: e.code, info: e.info });' +
                    '  }' +
                    '})();</scr' + 'ipt>';
                frame.srcdoc = inner;
                document.body.appendChild(frame);
            });
        """#) as? [String: Any]
        #expect(result?["ok"] as? Bool == false)
        #expect(result?["code"] as? Int == -3) // APIError.refused
        #expect((result?["info"] as? String)?.contains("Origin not permitted") == true)
    }

    // MARK: - helpers

    /// Build the same minimal payment-only tx body used by the unit tests so the
    /// integration witness-count assertion can be reused.
    private static func minimalTxCBOR() throws -> Data {
        let txInput = try TransactionInput(
            from: "0000000000000000000000000000000000000000000000000000000000000000",
            index: 0
        )
        let outAddr = try Address(
            from: .string("addr_test1qrwm5wkhvvfcyh60v3h44fknydcxv5aa5s8vrtj4tq5cdfrrueshdzujm6aytddd5j4eullazlknq5djuq6spcz596dqjvm8nu")
        )
        let output = TransactionOutput(address: outAddr, amount: Value(coin: 1_000_000))
        let body = TransactionBody(
            inputs: .list([txInput]),
            outputs: [output],
            fee: 200_000
        )
        let tx = Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
        return try tx.toCBORData()
    }
}

// MARK: - Fixture

/// Hosts a `WKWebView`, a `CIP30WebBridge`, and the navigation delegate needed to
/// `await` page loads. One per test for isolation.
@MainActor
private final class IntegrationFixture {
    let webView: WKWebView
    let bridge: CIP30WebBridge
    private let navDelegate: LoadCompletionDelegate

    init(
        originPolicy: CIP30OriginPolicy = .mainFrameOnly,
        approvalPolicy: CIP30ApprovalPolicy = .allowAll,
        consentResponse: @escaping @Sendable (CIP30RequestContext) async -> Bool = { _ in true },
        dataSource: CIP30DataSource? = nil
    ) async throws {
        let info = WalletInfo(name: "SwiftWallet", icon: "data:,")
        let initial = KeyStoreCIP30Initial(
            info: info,
            consent: { _, ctx in await consentResponse(ctx) },
            makeProvider: { extensions, _ in
                try KeyStoreCIP30Provider(
                    info: info,
                    paymentKey: .signingKey(integrationFixturePaymentSK),
                    stakeKey: .signingKey(integrationFixtureStakeSK),
                    network: .preview,
                    dataSource: dataSource,
                    grantedExtensions: extensions,
                    policy: approvalPolicy
                )
            }
        )
        self.bridge = try CIP30WebBridge(
            initial: initial,
            walletKey: "swiftWallet",
            originPolicy: originPolicy
        )
        let config = WKWebViewConfiguration()
        self.webView = WKWebView(frame: .zero, configuration: config)
        self.navDelegate = LoadCompletionDelegate()
        self.webView.navigationDelegate = navDelegate
        bridge.attach(to: webView)
    }

    /// Load a tiny same-origin parent page so subsequent `eval(...)` calls run with a
    /// fixed `https://app.example.com` origin (rather than `about:blank`, which has the
    /// special "null" origin that some WebKit code treats specially).
    func loadEmptyParent() async throws {
        try await load(
            html: "<!DOCTYPE html><html><body></body></html>",
            baseURL: URL(string: "https://app.example.com")!
        )
    }

    func load(html: String, baseURL: URL) async throws {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            navDelegate.next = continuation
            webView.loadHTMLString(html, baseURL: baseURL)
        }
    }

    /// Execute `js` as the body of an async JS function in the page's content world.
    /// Promises returned by the body are awaited automatically.
    func eval(_ js: String, arguments: [String: Any] = [:]) async throws -> Any? {
        try await webView.callAsyncJavaScript(js, arguments: arguments, in: nil, contentWorld: .page)
    }

    /// Convenience: bech32 of the provider's address. We compute this from the same keys
    /// the fixture provider uses so signData tests can target it directly.
    func walletAddressBech32() async throws -> String {
        let provider = try KeyStoreCIP30Provider(
            info: WalletInfo(name: "SwiftWallet", icon: "data:,"),
            paymentKey: .signingKey(integrationFixturePaymentSK),
            stakeKey: .signingKey(integrationFixtureStakeSK),
            network: .preview
        )
        let cbors = try await provider.getUsedAddresses(paginate: nil)
        let address = try Address.fromCBOR(data: cbors[0])
        return try address.toBech32()
    }
}

// File-scope key fixtures so the @MainActor IntegrationFixture's `makeProvider` closure
// (which is `@Sendable` and runs off-actor) can read them without an actor hop.
private let integrationFixturePaymentSK: PaymentSigningKey = {
    try! PaymentSigningKey.fromTextEnvelope(
        """
        {
            "type": "GenesisUTxOSigningKey_ed25519",
            "description": "Genesis Initial UTxO Signing Key",
            "cborHex": "5820093be5cd3987d0c9fd8854ef908f7746b69e2d73320db6dc0f780d81585b84c2"
        }
        """
    )
}()
private let integrationFixtureStakeSK: StakeSigningKey = {
    try! StakeSigningKey.fromTextEnvelope(
        """
        {
            "type": "StakeSigningKeyShelley_ed25519",
            "description": "Stake Signing Key",
            "cborHex": "5820ff3a330df8859e4e5f42a97fcaee73f6a00d0cf864f4bca902bd106d423f02c0"
        }
        """
    )
}()

/// Resolves the `next` continuation when the active navigation finishes (or fails). One
/// continuation at a time.
@MainActor
private final class LoadCompletionDelegate: NSObject, WKNavigationDelegate {
    var next: CheckedContinuation<Void, Never>?

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        next?.resume()
        next = nil
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        next?.resume()
        next = nil
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        next?.resume()
        next = nil
    }
}

/// In-process data source for tests that need `getBalance` or `submitTx` to work
/// without a real chain.
private struct StubDataSource: CIP30DataSource {
    let utxoSet: [UTxO]
    let txId: String
    func utxos(for address: Address) async throws -> [UTxO] { utxoSet }
    func submit(_ tx: Data) async throws -> String { txId }
}

#endif
