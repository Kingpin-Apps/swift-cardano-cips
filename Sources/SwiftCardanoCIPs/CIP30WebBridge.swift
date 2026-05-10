#if canImport(WebKit) && (os(iOS) || os(macOS) || os(visionOS))

import Foundation
@preconcurrency import WebKit

/// Bridges a Swift ``CIP30Initial`` / ``CIP30Provider`` to a `WKWebView` so a real web dApp
/// can call the wallet via the standard `window.cardano.{walletName}` interface.
///
/// Usage:
/// ```swift
/// let initial = KeyStoreCIP30Initial(info: info, consent: { _ in true }) { ext in
///     try KeyStoreCIP30Provider(info: info, paymentKey: payment, network: .mainnet)
/// }
/// let bridge = CIP30WebBridge(initial: initial, walletKey: "swiftWallet")
/// bridge.attach(to: webView)
/// // dApp JS can now call: await window.cardano.swiftWallet.enable()
/// ```
///
/// The bridge owns the JS shim that gets injected into every page (via `WKUserScript`) and
/// the `WKScriptMessageHandler` that receives RPC requests. Bytes cross the boundary as
/// hex; CBOR-encoded values stay CBOR (still hex). Errors round-trip as `{code, info}`
/// (or `{maxSize, info}` for ``PaginateError``).
@MainActor
public final class CIP30WebBridge: NSObject {

    /// Name used to register the script-message handler on the web view's content controller.
    /// This is also the key the injected JS shim uses for `webkit.messageHandlers.<name>`.
    public let messageHandlerName: String

    /// The key used under `window.cardano.{walletKey}`. Conventionally lowercase, no spaces.
    public let walletKey: String

    private let initialAPI: CIP30Initial
    private var provider: CIP30Provider?

    public init(initial: CIP30Initial, walletKey: String, messageHandlerName: String = "cip30") {
        self.initialAPI = initial
        self.walletKey = walletKey
        self.messageHandlerName = messageHandlerName
        super.init()
    }

    /// Attach the bridge to a web view: registers the script-message handler and injects
    /// the JS shim at document start. Safe to call once per web view.
    public func attach(to webView: WKWebView) {
        let cc = webView.configuration.userContentController
        cc.add(ScriptMessageHandlerProxy(target: self), name: messageHandlerName)
        cc.addUserScript(userScript())
    }

    /// The injected JS shim. Exposed in case you'd rather wire it up by hand.
    public func userScript() -> WKUserScript {
        let js = Self.javaScriptShim(
            walletKey: walletKey,
            handlerName: messageHandlerName,
            info: initialAPI.info
        )
        return WKUserScript(
            source: js,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false
        )
    }

    // MARK: - JS shim

    /// Generate the JavaScript that defines `window.cardano.{walletKey}` and the request
    /// dispatch machinery. Public to allow consumers to inspect / customize. Pure function
    /// — safe to call off the main actor.
    public nonisolated static func javaScriptShim(
        walletKey: String,
        handlerName: String,
        info: WalletInfo
    ) -> String {
        let infoJSON = (try? String(
            data: JSONEncoder().encode(info),
            encoding: .utf8
        )) ?? "{}"

        // Note: this string is injected verbatim into pages, so the only interpolations
        // are the safe JSON-encoded `info`, the `walletKey`, and the `handlerName`. Both
        // identifiers are wallet-controlled so injection isn't a concern, but we still
        // restrict them to a sane character set in the consuming code.
        return """
        (function() {
            if (typeof window === 'undefined') return;
            const INFO = \(infoJSON);
            const HANDLER = '\(handlerName)';
            const KEY = '\(walletKey)';
            window.cardano = window.cardano || {};
            const pending = new Map();
            let nextId = 1;

            function rpc(method, params) {
                return new Promise((resolve, reject) => {
                    const id = nextId++;
                    pending.set(id, { resolve, reject });
                    try {
                        window.webkit.messageHandlers[HANDLER].postMessage({ id, method, params: params || {} });
                    } catch (e) {
                        pending.delete(id);
                        reject({ code: -2, info: 'No CIP-30 bridge installed: ' + e });
                    }
                });
            }

            window.__cip30_resolve = function(id, result) {
                const p = pending.get(id);
                if (!p) return;
                pending.delete(id);
                p.resolve(result);
            };
            window.__cip30_reject = function(id, err) {
                const p = pending.get(id);
                if (!p) return;
                pending.delete(id);
                p.reject(err);
            };

            function fullApi() {
                return {
                    getNetworkId:       ()             => rpc('getNetworkId'),
                    getExtensions:      ()             => rpc('getExtensions'),
                    getUtxos:           (amount, p)    => rpc('getUtxos', { amount, paginate: p }),
                    getCollateral:      (params)       => rpc('getCollateral', params || {}),
                    getBalance:         ()             => rpc('getBalance'),
                    getUsedAddresses:   (p)            => rpc('getUsedAddresses', { paginate: p }),
                    getUnusedAddresses: ()             => rpc('getUnusedAddresses'),
                    getChangeAddress:   ()             => rpc('getChangeAddress'),
                    getRewardAddresses: ()             => rpc('getRewardAddresses'),
                    signTx:             (tx, partial)  => rpc('signTx', { tx, partialSign: !!partial }),
                    signData:           (addr, payload) => rpc('signData', { address: addr, payload }),
                    submitTx:           (tx)           => rpc('submitTx', { tx })
                };
            }

            window.cardano[KEY] = {
                apiVersion: INFO.apiVersion,
                name: INFO.name,
                icon: INFO.icon,
                supportedExtensions: INFO.supportedExtensions || [],
                isEnabled: () => rpc('isEnabled'),
                enable: (extensions) => rpc('enable', { extensions: extensions || [] }).then(_ => fullApi())
            };
        })();
        """
    }

    // MARK: - Dispatch

    /// Dispatch an incoming `{id, method, params}` request, then resolve or reject the JS
    /// promise on `webView` with the result.
    fileprivate func handle(message body: Any, in webView: WKWebView) {
        guard
            let dict = body as? [String: Any],
            let id = dict["id"] as? Int,
            let method = dict["method"] as? String
        else { return }

        let params = dict["params"] as? [String: Any] ?? [:]

        Task { @MainActor [weak self, weak webView] in
            guard let self, let webView else { return }
            do {
                let result = try await self.dispatch(method: method, params: params)
                self.resolve(id: id, with: result, on: webView)
            } catch let err as CIP30Error {
                self.reject(id: id, with: err, on: webView)
            } catch let err as PaginateError {
                self.reject(id: id, with: err, on: webView)
            } catch {
                self.reject(
                    id: id,
                    with: APIError.internalError("\(error)"),
                    on: webView
                )
            }
        }
    }

    private func dispatch(method: String, params: [String: Any]) async throws -> Any {
        switch method {
        case "isEnabled":
            return await initialAPI.isEnabled()
        case "enable":
            let exts = (params["extensions"] as? [[String: Any]] ?? []).compactMap {
                ($0["cip"] as? Int).map(Extension.init)
            }
            self.provider = try await initialAPI.enable(extensions: exts)
            return NSNull()  // dApp side wraps this in fullApi()
        default:
            return try await dispatchProvider(method: method, params: params)
        }
    }

    private func dispatchProvider(method: String, params: [String: Any]) async throws -> Any {
        guard let provider else {
            throw APIError.refused("Wallet not enabled")
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
            let utxos = try await provider.getCollateral(amount: amount)
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
            return try await provider.signTx(tx, partialSign: partial).toHex
        case "signData":
            guard let address = params["address"] as? String,
                  let payloadHex = params["payload"] as? String,
                  let payload = Data(hexString: payloadHex)
            else { throw DataSignError.proofGeneration("signData requires address and payload (hex)") }
            let sig = try await provider.signData(address: address, payload: payload)
            return ["signature": sig.signature, "key": sig.key]
        case "submitTx":
            guard let txHex = params["tx"] as? String,
                  let tx = Data(hexString: txHex)
            else { throw TxSendError.failure("submitTx requires tx (hex CBOR)") }
            return try await provider.submitTx(tx)
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

    // MARK: - JS callbacks

    private func resolve(id: Int, with value: Any, on webView: WKWebView) {
        let json = jsonString(from: value) ?? "null"
        webView.evaluateJavaScript("window.__cip30_resolve(\(id), \(json));", completionHandler: nil)
    }

    private func reject(id: Int, with error: CIP30Error, on webView: WKWebView) {
        let envelope: [String: Any]
        if let p = error as? PaginateError {
            envelope = ["maxSize": p.maxSize, "info": p.info]
        } else {
            envelope = ["code": error.code, "info": error.info]
        }
        let json = jsonString(from: envelope) ?? "null"
        webView.evaluateJavaScript("window.__cip30_reject(\(id), \(json));", completionHandler: nil)
    }

    private func jsonString(from value: Any) -> String? {
        if value is NSNull { return "null" }
        if JSONSerialization.isValidJSONObject(value) {
            guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed]),
                  let s = String(data: data, encoding: .utf8) else { return nil }
            return s
        }
        // Wrap scalars: JSONSerialization rejects raw strings/numbers/bools without .fragmentsAllowed
        if let data = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed]),
           let s = String(data: data, encoding: .utf8) {
            return s
        }
        // Last-resort manual encoding for primitive types
        switch value {
        case let s as String:
            let escaped = s
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\n", with: "\\n")
            return "\"\(escaped)\""
        case let b as Bool:
            return b ? "true" : "false"
        case let n as Int:
            return String(n)
        case let n as Double:
            return String(n)
        default:
            return nil
        }
    }
}

// MARK: - WKScriptMessageHandler proxy

/// Holds a weak reference to the bridge so we don't create a retain cycle through
/// `WKUserContentController.add(_:name:)` (which retains the handler strongly).
private final class ScriptMessageHandlerProxy: NSObject, WKScriptMessageHandler {
    weak var target: CIP30WebBridge?

    init(target: CIP30WebBridge) {
        self.target = target
    }

    @MainActor
    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
        guard let webView = message.webView, let target else { return }
        target.handle(message: message.body, in: webView)
    }
}

// MARK: - Helpers

extension Data {
    fileprivate var toHex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

#endif
