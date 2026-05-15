import Foundation
import SwiftCardanoCore

/// Spec types and a provider protocol for [CIP-30 — Cardano dApp-Wallet Web Bridge](https://cips.cardano.org/cip/CIP-30).
///
/// CIP-30 is fundamentally a JS-injection bridge between a web dApp and a wallet. This file
/// defines the **Swift surface** of that bridge: data structures, errors, wallet metadata,
/// and a ``CIP30Provider`` protocol that a wallet implements. The companion
/// `KeyStoreCIP30Provider` (in this package) gives a reference implementation backed by
/// `SwiftCardanoCore` keys, and `CIP30WebBridge` (gated on `WebKit`) wires a provider to
/// a `WKWebView` so real dApps can call it.
///
/// All `cbor<…>` arguments and return values from the spec are `Data` (raw CBOR bytes).
/// `address` parameters that may be either bech32 or hex are accepted as `String`.
/// `DataSignature` keeps `signature`/`key` as **hex strings**, matching the spec exactly.

// MARK: - Errors

/// Common shape of every CIP-30 error: an integer ``code`` plus a human-readable ``info``
/// string. Wire format on the JS side is `{code, info}`.
public protocol CIP30Error: Error, Sendable {
    var code: Int { get }
    var info: String { get }
}

/// Codable envelope used to ship a ``CIP30Error`` across the JS/Swift boundary.
///
/// Use ``CIP30ErrorEnvelope/init(_:)`` to wrap any concrete error, then JSON-encode it.
/// On the receiving side, decode and inspect ``code``/``info`` to recover the variant.
public struct CIP30ErrorEnvelope: Codable, Equatable, Sendable {
    public let code: Int
    public let info: String

    public init(code: Int, info: String) {
        self.code = code
        self.info = info
    }

    public init(_ error: CIP30Error) {
        self.code = error.code
        self.info = error.info
    }
}

/// CIP-30 `APIError`. Codes match the spec exactly.
public enum APIError: CIP30Error, Equatable {
    /// `code: -1` — request was malformed.
    case invalidRequest(String = "")
    /// `code: -2` — wallet hit an internal error.
    case internalError(String = "")
    /// `code: -3` — user (or wallet policy) refused the request.
    case refused(String = "")
    /// `code: -4` — the active account changed during the request.
    case accountChange(String = "")

    public var code: Int {
        switch self {
        case .invalidRequest: return -1
        case .internalError:  return -2
        case .refused:        return -3
        case .accountChange:  return -4
        }
    }

    public var info: String {
        switch self {
        case .invalidRequest(let s),
             .internalError(let s),
             .refused(let s),
             .accountChange(let s):
            return s
        }
    }
}

/// CIP-30 `TxSendError` — reported from ``CIP30Provider/submitTx(_:)``.
public enum TxSendError: CIP30Error, Equatable {
    /// `code: 1` — submission was refused (by user or wallet policy).
    case refused(String = "")
    /// `code: 2` — submission failed for technical reasons (network, node, validation).
    case failure(String = "")

    public var code: Int {
        switch self {
        case .refused: return 1
        case .failure: return 2
        }
    }

    public var info: String {
        switch self {
        case .refused(let s), .failure(let s): return s
        }
    }
}

/// CIP-30 `TxSignError` — reported from ``CIP30Provider/signTx(_:partialSign:)``.
public enum TxSignError: CIP30Error, Equatable {
    /// `code: 1` — wallet could not generate the proof (missing keys, etc.).
    case proofGeneration(String = "")
    /// `code: 2` — user declined to sign.
    case userDeclined(String = "")

    public var code: Int {
        switch self {
        case .proofGeneration: return 1
        case .userDeclined:    return 2
        }
    }

    public var info: String {
        switch self {
        case .proofGeneration(let s), .userDeclined(let s): return s
        }
    }
}

/// CIP-30 `DataSignError` — reported from ``CIP30Provider/signData(address:payload:)``.
public enum DataSignError: CIP30Error, Equatable {
    /// `code: 1` — wallet could not produce the signature.
    case proofGeneration(String = "")
    /// `code: 2` — supplied address doesn't correspond to a public-key credential.
    case addressNotPK(String = "")
    /// `code: 3` — user declined to sign.
    case userDeclined(String = "")

    public var code: Int {
        switch self {
        case .proofGeneration: return 1
        case .addressNotPK:    return 2
        case .userDeclined:    return 3
        }
    }

    public var info: String {
        switch self {
        case .proofGeneration(let s), .addressNotPK(let s), .userDeclined(let s): return s
        }
    }
}

/// CIP-30 `PaginateError`. Thrown by paginated endpoints (`getUtxos`, `getUsedAddresses`)
/// when the requested page is out of range. The ``maxSize`` field tells the dApp how many
/// pages exist so it can adjust.
public struct PaginateError: CIP30Error, Equatable {
    public let maxSize: Int
    public let info: String

    public init(maxSize: Int, info: String = "") {
        self.maxSize = maxSize
        self.info = info
    }

    /// `PaginateError` does not carry an integer code in the spec; it's distinguished by
    /// shape (`{maxSize}`). We expose `0` here for protocol uniformity but JSON encoding
    /// uses ``maxSize`` directly.
    public var code: Int { 0 }
}

extension PaginateError: Codable {
    enum CodingKeys: String, CodingKey { case maxSize, info }
}

// MARK: - Data structures

/// Pagination request for `getUtxos` and `getUsedAddresses`. Page index is zero-based;
/// `limit` is the page size hint (CIP-30 leaves the actual size up to the wallet).
public struct Paginate: Equatable, Sendable, Codable {
    public let page: UInt32
    public let limit: UInt32

    public init(page: UInt32, limit: UInt32) {
        self.page = page
        self.limit = limit
    }
}

/// CIP-30 extension marker. Wallets advertise supported extensions and dApps request them
/// via ``CIP30Initial/enable(extensions:)``.
public struct Extension: Equatable, Sendable, Codable {
    public let cip: Int

    public init(cip: Int) {
        self.cip = cip
    }
}

/// Signature returned from ``CIP30Provider/signData(address:payload:)`` —
/// COSE_Sign1 signature plus the matching COSE_Key, both CBOR-hex (per spec).
public struct DataSignature: Equatable, Sendable, Codable {
    /// Hex-encoded `COSE_Sign1` CBOR.
    public let signature: String
    /// Hex-encoded `COSE_Key` CBOR.
    public let key: String

    public init(signature: String, key: String) {
        self.signature = signature
        self.key = key
    }
}

/// Wallet metadata exposed via the unauthenticated initial API (`window.cardano.{name}`).
/// The `icon` is a data URL (typically `data:image/png;base64,…`).
public struct WalletInfo: Equatable, Sendable, Codable {
    public let name: String
    public let icon: String
    public let apiVersion: String
    public let supportedExtensions: [Extension]

    public init(
        name: String,
        icon: String,
        apiVersion: String = "0.1.0",
        supportedExtensions: [Extension] = []
    ) {
        self.name = name
        self.icon = icon
        self.apiVersion = apiVersion
        self.supportedExtensions = supportedExtensions
    }
}

// MARK: - Request context & origin policy

/// Identifies *who* is making a CIP-30 request. The bridge synthesizes this from
/// `WKScriptMessage.frameInfo` (security origin + main-frame flag); custom transports
/// should populate it however is meaningful to them.
///
/// `origin` follows the standard scheme://host[:port] form used by browsers (RFC 6454).
/// Default ports are omitted. Opaque origins (`data:`, `file:` with no host) collapse
/// to `"<scheme>://"` or the literal `"null"`.
public struct CIP30RequestContext: Sendable, Equatable, Hashable {
    /// Canonical origin string, e.g. `"https://app.example.com"`.
    public let origin: String

    /// True if the request came from the top-level frame, false for any nested frame
    /// (iframe, frame, etc.).
    public let isMainFrame: Bool

    /// Best-effort URL of the requesting frame. May be `nil` for opaque origins or when
    /// `WKFrameInfo.request.url` is unset.
    public let pageURL: URL?

    public init(origin: String, isMainFrame: Bool, pageURL: URL? = nil) {
        self.origin = origin
        self.isMainFrame = isMainFrame
        self.pageURL = pageURL
    }
}

/// Origin gate applied by ``CIP30WebBridge`` before any CIP-30 method runs. The bridge
/// rejects with ``APIError/refused(_:)`` when this returns `false`.
public enum CIP30OriginPolicy: Sendable {
    /// Default. Only the top-level frame may talk to the bridge. Any iframe (ad, embed,
    /// third-party widget) is refused.
    case mainFrameOnly

    /// Allow any frame whose origin is in the supplied set. Use this when you intentionally
    /// embed a known dApp inside another and want the inner one to act as the wallet client.
    case allowOrigins(Set<String>)

    /// Application-defined check. Receives the full request context.
    case custom(@Sendable (CIP30RequestContext) -> Bool)

    /// Decide whether `context` is allowed to invoke CIP-30 methods.
    public func allows(_ context: CIP30RequestContext) -> Bool {
        switch self {
        case .mainFrameOnly:
            return context.isMainFrame
        case .allowOrigins(let allowed):
            return allowed.contains(context.origin)
        case .custom(let fn):
            return fn(context)
        }
    }
}

// MARK: - Initial API

/// Unauthenticated initial API. In a browser this corresponds to the static
/// `window.cardano.{walletName}` object the dApp inspects before calling `enable()`.
///
/// The protocol carries both an origin-blind surface (`isEnabled()`, `enable(extensions:)`)
/// and an origin-aware one (`isEnabled(context:)`, `enable(extensions:context:)`). The
/// bridge always calls the context-aware variants. Default implementations forward to the
/// origin-blind variants, so existing implementations keep compiling — but they will
/// trample per-origin state. Real wallets should implement the context-aware methods.
public protocol CIP30Initial: Sendable {
    /// Static wallet metadata.
    var info: WalletInfo { get }

    /// Origin-blind enable check. Kept for back-compat. Bridge callers prefer
    /// ``isEnabled(context:)``.
    func isEnabled() async -> Bool

    /// Origin-blind enable. Kept for back-compat. Bridge callers prefer
    /// ``enable(extensions:context:)``.
    func enable(extensions: [Extension]) async throws -> CIP30Provider

    /// Whether this dApp `context.origin` has been previously approved.
    func isEnabled(context: CIP30RequestContext) async -> Bool

    /// Request access from a specific dApp `context`. Returns the full ``CIP30Provider``
    /// on success, or throws ``APIError/refused(_:)`` if the user/wallet declines.
    func enable(extensions: [Extension], context: CIP30RequestContext) async throws -> CIP30Provider

    /// Forget the enable state for `origin` (e.g. after the user "disconnects" the dApp,
    /// or on navigation away). Default impl is a no-op.
    func invalidate(origin: String) async
}

extension CIP30Initial {
    /// Convenience: enable with no requested extensions.
    public func enable() async throws -> CIP30Provider {
        try await enable(extensions: [])
    }

    /// Default forwards to the origin-blind variant. Wallets should override.
    public func isEnabled(context: CIP30RequestContext) async -> Bool {
        await isEnabled()
    }

    /// Default forwards to the origin-blind variant. Wallets should override.
    public func enable(extensions: [Extension], context: CIP30RequestContext) async throws -> CIP30Provider {
        try await enable(extensions: extensions)
    }

    /// Default no-op.
    public func invalidate(origin: String) async {}
}

// MARK: - Provider protocol

/// Authenticated CIP-30 wallet API as a Swift protocol. A wallet implements this once
/// `enable()` succeeds; the host app then bridges or proxies it however it likes (JS bridge,
/// IPC, in-process call, etc.).
///
/// Naming and semantics mirror [the spec](https://cips.cardano.org/cip/CIP-30) one-to-one.
/// `cbor<…>` arguments and return values are `Data`; `bech32` / `hex` strings are `String`.
public protocol CIP30Provider: Sendable {
    /// `0` for testnet networks, `1` for mainnet.
    func getNetworkId() async throws -> Int

    /// Extensions the wallet grants for this session (subset of the requested ones).
    func getExtensions() async throws -> [Extension]

    /// Wallet's UTxO set, optionally constrained by `amount` (CBOR-encoded `Value`) and
    /// pagination. Returns `nil` if no UTxOs match. Throws ``PaginateError`` if the
    /// requested page is out of range.
    func getUtxos(amount: Data?, paginate: Paginate?) async throws -> [Data]?

    /// UTxOs available as collateral for Plutus tx, totalling at least `amount` lovelace
    /// (CBOR-encoded `Coin`). Optional in CIP-30; default impl returns `nil`.
    func getCollateral(amount: Data) async throws -> [Data]?

    /// Total balance as a CBOR-encoded `Value`.
    func getBalance() async throws -> Data

    /// Addresses the wallet has used (i.e. seen on-chain), optionally paginated.
    /// Each entry is a CBOR-encoded address. Throws ``PaginateError`` if out of range.
    func getUsedAddresses(paginate: Paginate?) async throws -> [Data]

    /// Addresses the wallet considers unused (gap-limit tail).
    func getUnusedAddresses() async throws -> [Data]

    /// Wallet's preferred change address (CBOR-encoded).
    func getChangeAddress() async throws -> Data

    /// Reward (stake) addresses (CBOR-encoded).
    func getRewardAddresses() async throws -> [Data]

    /// Sign a transaction. Returns a CBOR-encoded `TransactionWitnessSet`. With
    /// `partialSign: false`, the wallet must sign all required witnesses or throw
    /// ``TxSignError/proofGeneration(_:)``.
    func signTx(_ tx: Data, partialSign: Bool) async throws -> Data

    /// Sign arbitrary `payload` bytes under `address`. Returns ``DataSignature``
    /// (COSE_Sign1 + COSE_Key, both hex).
    func signData(address: String, payload: Data) async throws -> DataSignature

    /// Submit a CBOR-encoded transaction to the chain. Returns the transaction id (hex).
    func submitTx(_ tx: Data) async throws -> String

    // MARK: Context-aware overloads

    /// Sign a transaction, with the requesting dApp's ``CIP30RequestContext`` so the wallet
    /// can show the user which site is asking. Default impl forwards to
    /// ``signTx(_:partialSign:)`` and ignores the context.
    func signTx(_ tx: Data, partialSign: Bool, context: CIP30RequestContext?) async throws -> Data

    /// Sign data, with the requesting dApp's ``CIP30RequestContext``. Default impl forwards
    /// to ``signData(address:payload:)`` and ignores the context.
    func signData(address: String, payload: Data, context: CIP30RequestContext?) async throws -> DataSignature

    /// Submit a transaction, with the requesting dApp's ``CIP30RequestContext``. Default
    /// impl forwards to ``submitTx(_:)`` and ignores the context.
    func submitTx(_ tx: Data, context: CIP30RequestContext?) async throws -> String

    /// Get collateral, with the requesting dApp's ``CIP30RequestContext``. Default impl
    /// forwards to ``getCollateral(amount:)``.
    func getCollateral(amount: Data, context: CIP30RequestContext?) async throws -> [Data]?
}

extension CIP30Provider {
    /// Default `getCollateral` returns no collateral candidates. Wallets that participate in
    /// Plutus interactions should override with their own collateral-selection policy.
    public func getCollateral(amount: Data) async throws -> [Data]? { nil }

    /// Default `getExtensions` reports no enabled extensions.
    public func getExtensions() async throws -> [Extension] { [] }

    /// Convenience: `signTx` defaulting to full (non-partial) signing per the spec.
    public func signTx(_ tx: Data) async throws -> Data {
        try await signTx(tx, partialSign: false)
    }

    // MARK: Context-aware default forwarders

    /// Defaults forward to the non-context method. ``KeyStoreCIP30Provider`` overrides each
    /// of these to thread the context through the wallet's per-operation approval policy.
    public func signTx(_ tx: Data, partialSign: Bool, context: CIP30RequestContext?) async throws -> Data {
        try await signTx(tx, partialSign: partialSign)
    }

    public func signData(address: String, payload: Data, context: CIP30RequestContext?) async throws -> DataSignature {
        try await signData(address: address, payload: payload)
    }

    public func submitTx(_ tx: Data, context: CIP30RequestContext?) async throws -> String {
        try await submitTx(tx)
    }

    public func getCollateral(amount: Data, context: CIP30RequestContext?) async throws -> [Data]? {
        try await getCollateral(amount: amount)
    }
}
