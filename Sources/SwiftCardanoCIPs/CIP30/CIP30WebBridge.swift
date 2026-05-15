#if canImport(WebKit) && (os(iOS) || os(macOS) || os(visionOS))

import Foundation
import os
@preconcurrency import WebKit

/// Errors raised by ``CIP30WebBridge`` itself (configuration / setup), distinct from the
/// CIP-30 error envelope that flows over the JS bridge.
public enum CIP30WebBridgeError: Error, Equatable, Sendable {
    /// `walletKey` or `messageHandlerName` failed validation. `value` echoes the input
    /// that was rejected so the integrator can see what went wrong; it is not surfaced to
    /// JS.
    case invalidIdentifier(name: String, value: String)
}

private let bridgeLog = Logger(subsystem: "swift-cardano-cips", category: "cip30.bridge")

/// Bridges a Swift ``CIP30Initial`` / ``CIP30Provider`` to a `WKWebView` so a real web dApp
/// can call the wallet via the standard `window.cardano.{walletName}` interface.
///
/// Usage:
/// ```swift
/// let initial = KeyStoreCIP30Initial(info: info, consent: { _ in true }) { ext in
///     try KeyStoreCIP30Provider(info: info, paymentKey: payment, network: .mainnet)
/// }
/// let bridge = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet")
/// bridge.attach(to: webView)
/// // dApp JS can now call: await window.cardano.swiftWallet.enable()
/// ```
///
/// The bridge owns the JS shim that gets injected into every page (via `WKUserScript`) and
/// the `WKScriptMessageHandlerWithReply` that receives RPC requests. Bytes cross the
/// boundary as hex; CBOR-encoded values stay CBOR (still hex). Errors round-trip as a JSON
/// envelope (`{code, info}`, or `{maxSize, info}` for ``PaginateError``) carried in the
/// rejection's `Error.message`; the JS shim re-parses it so dApp `catch` handlers get the
/// structured object the spec asks for.
@MainActor
public final class CIP30WebBridge: NSObject {

    /// Name used to register the script-message handler on the web view's content controller.
    /// This is also the key the injected JS shim uses for `webkit.messageHandlers.<name>`.
    public let messageHandlerName: String

    /// The key used under `window.cardano.{walletKey}`. Conventionally lowercase, no spaces.
    public let walletKey: String

    /// Origin gate. Defaults to ``CIP30OriginPolicy/mainFrameOnly`` so iframes can't
    /// invoke wallet methods using a top-frame's consent. Override at construction time
    /// to opt specific origins in.
    public let originPolicy: CIP30OriginPolicy

    private let initialAPI: CIP30Initial

    /// Provider instances scoped by origin. A single `enable(...)` only authorizes the
    /// origin it ran for; cross-origin requests look up an empty slot and are refused.
    private var providers: [String: CIP30Provider] = [:]

    /// Identifier validation rule applied to `walletKey` and `messageHandlerName`. Both
    /// strings are interpolated verbatim into the JS shim; restricting them to a JS-safe
    /// character set closes the only injection vector in the shim.
    public static let identifierPattern = "^[A-Za-z0-9_]{1,64}$"

    public init(
        initial: CIP30Initial,
        walletKey: String,
        messageHandlerName: String = "cip30",
        originPolicy: CIP30OriginPolicy = .mainFrameOnly
    ) throws {
        try Self.validateIdentifier(walletKey, name: "walletKey")
        try Self.validateIdentifier(messageHandlerName, name: "messageHandlerName")
        self.initialAPI = initial
        self.walletKey = walletKey
        self.messageHandlerName = messageHandlerName
        self.originPolicy = originPolicy
        super.init()
    }

    private static func validateIdentifier(_ value: String, name: String) throws {
        guard
            value.count <= 64,
            !value.isEmpty,
            value.range(of: identifierPattern, options: .regularExpression) != nil
        else {
            throw CIP30WebBridgeError.invalidIdentifier(name: name, value: value)
        }
    }

    /// Attach the bridge to a web view: registers the script-message handler and injects
    /// the JS shim at document start. Safe to call once per web view.
    public func attach(to webView: WKWebView) {
        let cc = webView.configuration.userContentController
        cc.addScriptMessageHandler(
            ScriptMessageHandlerProxy(target: self),
            contentWorld: .page,
            name: messageHandlerName
        )
        cc.addUserScript(userScript())
    }

    /// The injected JS shim. Exposed in case you'd rather wire it up by hand. Inject in
    /// `WKContentWorld.page` so it shares the dApp's globals (the dApp expects to find
    /// `window.cardano.<walletKey>` on the page world).
    public func userScript() -> WKUserScript {
        let js = Self.javaScriptShim(
            walletKey: walletKey,
            handlerName: messageHandlerName,
            info: initialAPI.info
        )
        return WKUserScript(
            source: js,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false,
            in: .page
        )
    }

    // MARK: - JS shim

    /// Generate the JavaScript that defines `window.cardano.{walletKey}` and the request
    /// dispatch machinery. Public to allow consumers to inspect / customize. Pure function
    /// — safe to call off the main actor.
    ///
    /// The shim talks to Swift via `WKScriptMessageHandlerWithReply.postMessage`, which
    /// returns a Promise directly — there is no `window.__cip30_*` callback path, and the
    /// dispatch IDs that used to live in JS are gone. That removes the response-spoofing
    /// vector where any script on the page could call a global resolver with a guessable
    /// id.
    public nonisolated static func javaScriptShim(
        walletKey: String,
        handlerName: String,
        info: WalletInfo
    ) -> String {
        let infoJSON = (try? String(
            data: JSONEncoder().encode(info),
            encoding: .utf8
        )) ?? "{}"

        // walletKey and handlerName are validated against `identifierPattern` in
        // `CIP30WebBridge.init`, so the only way to reach this method with an attacker-
        // controlled identifier is to call this static directly. Callers who do that take
        // on the same validation responsibility — there is nothing else escaping into JS.
        return """
        (function() {
            if (typeof window === 'undefined') return;
            const INFO = \(infoJSON);
            const HANDLER = '\(handlerName)';
            const KEY = '\(walletKey)';
            window.cardano = window.cardano || {};

            async function rpc(method, params) {
                let raw;
                try {
                    return await window.webkit.messageHandlers[HANDLER].postMessage({ method: method, params: params || {} });
                } catch (e) {
                    raw = (e && e.message) ? e.message : String(e);
                }
                let parsed = null;
                try { parsed = JSON.parse(raw); } catch (_) {}
                if (parsed && (typeof parsed.code === 'number' || typeof parsed.maxSize === 'number')) {
                    throw parsed;
                }
                throw { code: -2, info: 'CIP-30 bridge error: ' + raw };
            }

            function fullApi() {
                return {
                    getNetworkId:       ()             => rpc('getNetworkId'),
                    getExtensions:      ()             => rpc('getExtensions'),
                    getUtxos:           (amount, p)    => rpc('getUtxos', { amount: amount, paginate: p }),
                    getCollateral:      (params)       => rpc('getCollateral', params || {}),
                    getBalance:         ()             => rpc('getBalance'),
                    getUsedAddresses:   (p)            => rpc('getUsedAddresses', { paginate: p }),
                    getUnusedAddresses: ()             => rpc('getUnusedAddresses'),
                    getChangeAddress:   ()             => rpc('getChangeAddress'),
                    getRewardAddresses: ()             => rpc('getRewardAddresses'),
                    signTx:             (tx, partial)  => rpc('signTx', { tx: tx, partialSign: !!partial }),
                    signData:           (addr, payload) => rpc('signData', { address: addr, payload: payload }),
                    submitTx:           (tx)           => rpc('submitTx', { tx: tx })
                };
            }

            window.cardano[KEY] = {
                apiVersion: INFO.apiVersion,
                name: INFO.name,
                icon: INFO.icon,
                supportedExtensions: INFO.supportedExtensions || [],
                isEnabled: () => rpc('isEnabled'),
                enable: (extensions) => rpc('enable', { extensions: extensions || [] }).then(function() { return fullApi(); })
            };
        })();
        """
    }

    // MARK: - Origin invalidation

    /// Forget the enable state and provider scoped to `origin`. Call this when the user
    /// disconnects the dApp, or when you observe a `WKWebView` navigation away from
    /// `origin` and want to require fresh consent on return.
    public func invalidate(origin: String) async {
        providers.removeValue(forKey: origin)
        await initialAPI.invalidate(origin: origin)
    }

    /// Forget the enable state for every origin. Useful on app sign-out.
    public func invalidateAll() async {
        let origins = Array(providers.keys)
        providers.removeAll()
        for origin in origins {
            await initialAPI.invalidate(origin: origin)
        }
    }

    // MARK: - Context construction

    /// Build a ``CIP30RequestContext`` from a `WKFrameInfo`. `WKFrameInfo` is
    /// main-actor-isolated, so this helper is too.
    @MainActor
    static func makeContext(from frameInfo: WKFrameInfo) -> CIP30RequestContext {
        return CIP30RequestContext(
            origin: canonicalOrigin(
                scheme: frameInfo.securityOrigin.`protocol`,
                host: frameInfo.securityOrigin.host,
                port: frameInfo.securityOrigin.port
            ),
            isMainFrame: frameInfo.isMainFrame,
            pageURL: frameInfo.request.url
        )
    }

    /// Canonical origin serialization per RFC 6454 — scheme://host[:port], default ports
    /// omitted. Opaque origins (no host) collapse to `"<scheme>://"` or `"null"`.
    nonisolated static func canonicalOrigin(scheme: String, host: String, port: Int) -> String {
        guard !host.isEmpty else {
            return scheme.isEmpty ? "null" : "\(scheme)://"
        }
        if port == 0 { return "\(scheme)://\(host)" }
        return "\(scheme)://\(host):\(port)"
    }

    // MARK: - Dispatch

    fileprivate func handle(
        body: Any,
        context: CIP30RequestContext,
        replyHandler: @escaping @MainActor @Sendable (Any?, String?) -> Void
    ) {
        guard originPolicy.allows(context) else {
            bridgeLog.notice("CIP-30 request refused by origin policy: origin=\(context.origin, privacy: .public) isMainFrame=\(context.isMainFrame, privacy: .public)")
            replyHandler(nil, Self.envelopeMessage(for: APIError.refused("Origin not permitted by wallet policy: \(context.origin)")))
            return
        }
        guard
            let dict = body as? [String: Any],
            let method = dict["method"] as? String
        else {
            replyHandler(nil, Self.envelopeMessage(for: APIError.invalidRequest("Malformed message")))
            return
        }
        let params = dict["params"] as? [String: Any] ?? [:]

        Task { @MainActor [weak self] in
            guard let self else {
                replyHandler(nil, Self.envelopeMessage(for: APIError.internalError("Bridge deallocated")))
                return
            }
            do {
                let result = try await self.dispatch(method: method, params: params, context: context)
                replyHandler(result, nil)
            } catch let err as PaginateError {
                replyHandler(nil, Self.envelopeMessage(for: err))
            } catch let err as CIP30Error {
                replyHandler(nil, Self.envelopeMessage(for: err))
            } catch {
                bridgeLog.error("CIP-30 dispatch failed for method=\(method, privacy: .public): \(String(describing: error), privacy: .public)")
                #if DEBUG
                let info = "Internal wallet error: \(error)"
                #else
                let info = "Internal wallet error"
                #endif
                replyHandler(nil, Self.envelopeMessage(for: APIError.internalError(info)))
            }
        }
    }

    /// Result of `handleForTesting(...)`: either the value the JS side would receive on
    /// promise resolution, or the error envelope JSON it would receive on rejection.
    internal struct HandleTestResult: @unchecked Sendable {
        let value: Any?
        let errorEnvelope: String?
    }

    /// Test helper that drives the full `handle(...)` path (origin-policy gate + dispatch
    /// + envelope encoding) without a `WKWebView`. Internal so tests can call it via
    /// `@testable import`.
    internal func handleForTesting(
        body: Any,
        context: CIP30RequestContext
    ) async -> HandleTestResult {
        await withCheckedContinuation { (continuation: CheckedContinuation<HandleTestResult, Never>) in
            self.handle(body: body, context: context) { result, errorMessage in
                continuation.resume(returning: HandleTestResult(value: result, errorEnvelope: errorMessage))
            }
        }
    }

    /// Internal entry point used both by `handle(...)` and by tests that need to drive
    /// the dispatcher with a synthesized context (since `WKScriptMessage` is not
    /// constructible publicly).
    internal func dispatch(method: String, params: [String: Any], context: CIP30RequestContext) async throws -> Any {
        switch method {
        case "isEnabled":
            return await initialAPI.isEnabled(context: context)
        case "enable":
            let exts = (params["extensions"] as? [[String: Any]] ?? []).compactMap {
                ($0["cip"] as? Int).map(Extension.init)
            }
            let provider = try await initialAPI.enable(extensions: exts, context: context)
            self.providers[context.origin] = provider
            return NSNull()  // dApp side wraps this in fullApi()
        default:
            return try await dispatchProvider(method: method, params: params, context: context)
        }
    }

    private func dispatchProvider(method: String, params: [String: Any], context: CIP30RequestContext) async throws -> Any {
        guard let provider = providers[context.origin] else {
            throw APIError.refused("Wallet not enabled for origin: \(context.origin)")
        }
        switch method {
        case "getNetworkId":
            return try await provider.getNetworkId()
        case "getExtensions":
            return try await provider.getExtensions().map { ["cip": $0.cip] }
        case "getUtxos":
            let amount = (params["amount"] as? String).flatMap { Data(hexString: $0) }
            let paginate = decodePaginate(params["paginate"])
            let utxos = try await provider.getUtxos(amount: amount, paginate: paginate)
            return utxos?.map { $0.toHex } as Any? ?? NSNull()
        case "getCollateral":
            guard let amountHex = params["amount"] as? String,
                  let amount = Data(hexString: amountHex)
            else { throw APIError.invalidRequest("getCollateral requires amount (hex CBOR Coin)") }
            let utxos = try await provider.getCollateral(amount: amount, context: context)
            return utxos?.map { $0.toHex } as Any? ?? NSNull()
        case "getBalance":
            return try await provider.getBalance().toHex
        case "getUsedAddresses":
            let paginate = decodePaginate(params["paginate"])
            return try await provider.getUsedAddresses(paginate: paginate).map { $0.toHex }
        case "getUnusedAddresses":
            return try await provider.getUnusedAddresses().map { $0.toHex }
        case "getChangeAddress":
            return try await provider.getChangeAddress().toHex
        case "getRewardAddresses":
            return try await provider.getRewardAddresses().map { $0.toHex }
        case "signTx":
            guard let txHex = params["tx"] as? String,
                  let tx = Data(hexString: txHex)
            else { throw TxSignError.proofGeneration("signTx requires tx (hex CBOR)") }
            let partial = params["partialSign"] as? Bool ?? false
            return try await provider.signTx(tx, partialSign: partial, context: context).toHex
        case "signData":
            guard let address = params["address"] as? String,
                  let payloadHex = params["payload"] as? String,
                  let payload = Data(hexString: payloadHex)
            else { throw DataSignError.proofGeneration("signData requires address and payload (hex)") }
            let sig = try await provider.signData(address: address, payload: payload, context: context)
            return ["signature": sig.signature, "key": sig.key]
        case "submitTx":
            guard let txHex = params["tx"] as? String,
                  let tx = Data(hexString: txHex)
            else { throw TxSendError.failure("submitTx requires tx (hex CBOR)") }
            return try await provider.submitTx(tx, context: context)
        default:
            throw APIError.invalidRequest("Unknown method: \(method)")
        }
    }

    private func decodePaginate(_ raw: Any?) -> Paginate? {
        guard let dict = raw as? [String: Any],
              let page = (dict["page"] as? Int).map(UInt32.init),
              let limit = (dict["limit"] as? Int).map(UInt32.init)
        else { return nil }
        return Paginate(page: page, limit: limit)
    }

    // MARK: - Error envelope encoding

    /// JSON-encode a CIP-30 error so the JS shim can re-parse it after `await postMessage`
    /// rejects. Exposed as `internal` for unit testing. Pure function — safe to call from
    /// any actor.
    nonisolated static func envelopeMessage(for error: CIP30Error) -> String {
        let dict: [String: Any]
        if let p = error as? PaginateError {
            dict = ["maxSize": p.maxSize, "info": p.info]
        } else {
            dict = ["code": error.code, "info": error.info]
        }
        if let data = try? JSONSerialization.data(withJSONObject: dict),
           let s = String(data: data, encoding: .utf8) {
            return s
        }
        // Should be unreachable: dict is composed of String/Int only.
        return #"{"code":-2,"info":"Unencodable error envelope"}"#
    }
}

// MARK: - WKScriptMessageHandlerWithReply proxy

/// Holds a weak reference to the bridge so we don't create a retain cycle through
/// `WKUserContentController.addScriptMessageHandler(...)` (which retains the handler
/// strongly).
private final class ScriptMessageHandlerProxy: NSObject, WKScriptMessageHandlerWithReply {
    weak var target: CIP30WebBridge?

    init(target: CIP30WebBridge) {
        self.target = target
    }

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage,
        replyHandler: @escaping @MainActor @Sendable (Any?, String?) -> Void
    ) {
        guard let target else {
            replyHandler(nil, CIP30WebBridge.envelopeMessage(for: APIError.internalError("Bridge deallocated")))
            return
        }
        let context = CIP30WebBridge.makeContext(from: message.frameInfo)
        target.handle(body: message.body, context: context, replyHandler: replyHandler)
    }
}

// MARK: - Helpers

extension Data {
    fileprivate var toHex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

#endif
