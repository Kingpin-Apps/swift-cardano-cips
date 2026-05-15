import Foundation
import SwiftCardanoCore

/// Source of on-chain data the wallet needs to answer CIP-30 queries it can't compute
/// from keys alone (UTxOs, balance, transaction submission). Provide an implementation
/// backed by your chosen indexer (Blockfrost, Koios, Ogmios, a local node, …).
///
/// If you already use `SwiftCardanoChain`, the two methods map 1:1 onto `ChainContext`,
/// so the adapter is a few lines:
///
/// ```swift
/// import SwiftCardanoChain
///
/// struct ChainContextDataSource: CIP30DataSource {
///     let context: any ChainContext
///     func utxos(for address: Address) async throws -> [UTxO] {
///         try await context.utxos(address: address)
///     }
///     func submit(_ tx: Data) async throws -> String {
///         try await context.submitTxCBOR(cbor: tx)
///     }
/// }
/// ```
public protocol CIP30DataSource: Sendable {
    /// Return all UTxOs at `address`. The provider will compose, paginate, and balance
    /// these for the dApp.
    func utxos(for address: Address) async throws -> [UTxO]

    /// Submit a CBOR-encoded transaction. Return the tx id (hex).
    func submit(_ tx: Data) async throws -> String
}

/// Per-operation user-approval policy for ``KeyStoreCIP30Provider``.
///
/// Every sensitive call (`signTx`, `signData`, `submitTx`) consults the matching closure
/// before doing any signing or network I/O. Returning `false` causes the provider to throw
/// the appropriate "user declined" error from the CIP-30 spec.
///
/// The default for ``KeyStoreCIP30Provider`` is ``denyAll`` — a single `enable()` does
/// **not** authorize unbounded signing. Wallet apps must supply their own policy that pops
/// a UI sheet, hits biometrics, etc. ``allowAll`` exists for tests and developer harnesses
/// only; the name is deliberately scary.
///
/// Closures receive an optional ``CIP30RequestContext`` so the wallet UI can show "Site X
/// is asking to sign…". The context is `nil` when the provider is called outside the
/// bridge (e.g. directly from native code without a per-frame origin).
public struct CIP30ApprovalPolicy: Sendable {
    public typealias ApproveSignTx   = @Sendable (_ tx: Transaction, _ partialSign: Bool, _ context: CIP30RequestContext?) async -> Bool
    public typealias ApproveSignData = @Sendable (_ address: Address, _ payload: Data, _ context: CIP30RequestContext?) async -> Bool
    public typealias ApproveSubmitTx = @Sendable (_ tx: Data, _ context: CIP30RequestContext?) async -> Bool

    public var approveSignTx: ApproveSignTx
    public var approveSignData: ApproveSignData
    public var approveSubmitTx: ApproveSubmitTx

    public init(
        approveSignTx: @escaping ApproveSignTx,
        approveSignData: @escaping ApproveSignData,
        approveSubmitTx: @escaping ApproveSubmitTx
    ) {
        self.approveSignTx = approveSignTx
        self.approveSignData = approveSignData
        self.approveSubmitTx = approveSubmitTx
    }

    /// Refuses every sensitive operation. The safe default. Real wallets must replace
    /// this with closures that prompt the user.
    public static let denyAll = CIP30ApprovalPolicy(
        approveSignTx: { _, _, _ in false },
        approveSignData: { _, _, _ in false },
        approveSubmitTx: { _, _ in false }
    )

    /// Approves every sensitive operation. **For tests and developer harnesses only** —
    /// using this in a shipping wallet would let any dApp drain funds.
    public static let allowAll = CIP30ApprovalPolicy(
        approveSignTx: { _, _, _ in true },
        approveSignData: { _, _, _ in true },
        approveSubmitTx: { _, _ in true }
    )
}

/// Reference ``CIP30Provider`` implementation backed by a single payment key (and an
/// optional stake key) plus a ``CIP30DataSource`` for chain access.
///
/// This is intentionally minimal — a single-address wallet — but it composes enough of
/// `SwiftCardanoCore` to be useful and to demonstrate that the protocol is actually
/// implementable end-to-end. Wallets with HD-derived address sets should subclass the
/// pattern: hold many keys, keep an internal address set, and override the address
/// accessors.
///
/// **Approvals.** `signTx`, `signData`, and `submitTx` consult ``policy`` before doing
/// any signing or network I/O. The default ``CIP30ApprovalPolicy/denyAll`` refuses
/// everything, so every host app must supply its own policy. See ``CIP30ApprovalPolicy``.
public actor KeyStoreCIP30Provider: CIP30Provider {
    public let info: WalletInfo
    public let network: Network

    private let paymentKey: SigningKeyType
    private let stakeKey: SigningKeyType?
    private let address: Address
    private let rewardAddress: Address?
    private let dataSource: CIP30DataSource?
    private let grantedExtensions: [Extension]
    private let policy: CIP30ApprovalPolicy

    /// - Parameters:
    ///   - info: Wallet metadata (name, icon, …) advertised via the initial API.
    ///   - paymentKey: The payment signing key. Used for `signTx`, `signData` (when the
    ///     supplied address is the payment-credential address), and to derive
    ///     ``getChangeAddress``.
    ///   - stakeKey: Optional stake signing key. Required for ``getRewardAddresses`` and
    ///     for `signData` over a reward address.
    ///   - network: Network the wallet operates on.
    ///   - dataSource: Source of UTxOs / submission. If `nil`, on-chain methods throw
    ///     ``APIError/internalError(_:)``.
    ///   - grantedExtensions: Extensions this provider instance has been granted (filled
    ///     in by ``KeyStoreCIP30Initial`` during `enable`).
    ///   - policy: Per-operation approval policy. Defaults to ``CIP30ApprovalPolicy/denyAll``
    ///     so a misconfigured wallet can't sign anything; supply a closure-backed policy
    ///     in production.
    public init(
        info: WalletInfo,
        paymentKey: SigningKeyType,
        stakeKey: SigningKeyType? = nil,
        network: Network = .mainnet,
        dataSource: CIP30DataSource? = nil,
        grantedExtensions: [Extension] = [],
        policy: CIP30ApprovalPolicy = .denyAll
    ) throws {
        self.info = info
        self.network = network
        self.paymentKey = paymentKey
        self.stakeKey = stakeKey
        self.dataSource = dataSource
        self.grantedExtensions = grantedExtensions
        self.policy = policy

        let paymentVKey = try paymentKey.toVerificationKey()
        let paymentHash = try paymentVKey.hash()

        let stakingPart: StakingPart?
        if let stake = stakeKey {
            let stakeVKey = try stake.toVerificationKey()
            stakingPart = .verificationKeyHash(try stakeVKey.hash())
            self.rewardAddress = try Address(
                paymentPart: nil,
                stakingPart: stakingPart,
                network: network.networkId
            )
        } else {
            stakingPart = nil
            self.rewardAddress = nil
        }

        self.address = try Address(
            paymentPart: .verificationKeyHash(paymentHash),
            stakingPart: stakingPart,
            network: network.networkId
        )
    }

    // MARK: - CIP30Provider

    public func getNetworkId() async throws -> Int {
        network.networkId.rawValue
    }

    public func getExtensions() async throws -> [Extension] {
        grantedExtensions
    }

    public func getUtxos(amount: Data?, paginate: Paginate?) async throws -> [Data]? {
        guard let dataSource else { throw APIError.internalError("No data source configured") }
        let all = try await dataSource.utxos(for: address)
        if all.isEmpty { return nil }

        let cbor = try all.map { try $0.toCBORData() }

        if let p = paginate {
            let start = Int(p.page) * Int(p.limit)
            guard start < cbor.count else {
                let pages = max(1, (cbor.count + Int(p.limit) - 1) / Int(p.limit))
                throw PaginateError(maxSize: pages, info: "Page \(p.page) out of range")
            }
            let end = min(start + Int(p.limit), cbor.count)
            return Array(cbor[start..<end])
        }
        return cbor
    }

    public func getBalance() async throws -> Data {
        guard let dataSource else { throw APIError.internalError("No data source configured") }
        let utxos = try await dataSource.utxos(for: address)
        var total = Value(coin: 0)
        for u in utxos { total += u.output.amount }
        return try total.toCBORData()
    }

    public func getUsedAddresses(paginate: Paginate?) async throws -> [Data] {
        // Single-address wallet: report our address as "used" if any UTxO has been
        // observed there. With no data source we can't tell, so we report it.
        let used: [Data]
        if let dataSource {
            let utxos = try await dataSource.utxos(for: address)
            used = utxos.isEmpty ? [] : [try address.toCBORData()]
        } else {
            used = [try address.toCBORData()]
        }

        if let p = paginate {
            let start = Int(p.page) * Int(p.limit)
            guard start < used.count else {
                let pages = max(1, (used.count + Int(p.limit) - 1) / Int(p.limit))
                throw PaginateError(maxSize: pages)
            }
            let end = min(start + Int(p.limit), used.count)
            return Array(used[start..<end])
        }
        return used
    }

    public func getUnusedAddresses() async throws -> [Data] {
        guard let dataSource else { return [try address.toCBORData()] }
        let utxos = try await dataSource.utxos(for: address)
        return utxos.isEmpty ? [try address.toCBORData()] : []
    }

    public func getChangeAddress() async throws -> Data {
        try address.toCBORData()
    }

    public func getRewardAddresses() async throws -> [Data] {
        guard let rewardAddress else { return [] }
        return [try rewardAddress.toCBORData()]
    }

    public func signTx(_ tx: Data, partialSign: Bool) async throws -> Data {
        try await signTx(tx, partialSign: partialSign, context: nil)
    }

    public func signTx(_ tx: Data, partialSign: Bool, context: CIP30RequestContext?) async throws -> Data {
        let transaction: Transaction
        do {
            transaction = try Transaction.fromCBOR(data: tx)
        } catch {
            throw TxSignError.proofGeneration("Could not decode transaction: \(error)")
        }

        guard await policy.approveSignTx(transaction, partialSign, context) else {
            throw TxSignError.userDeclined("User declined to sign transaction")
        }

        let body = transaction.transactionBody

        // Hashes the wallet can sign for.
        let paymentVKey = try paymentKey.toVerificationKey()
        let paymentHashBytes = try paymentVKey.hash().payload
        let stakeHashBytes: Data?
        if let stake = stakeKey {
            stakeHashBytes = try (try stake.toVerificationKey()).hash().payload
        } else {
            stakeHashBytes = nil
        }

        // CIP-30 partialSign=false: wallet MUST sign all required witnesses or throw
        // proofGeneration. CIP-30 doesn't pass UTxO context to signTx, so we can only
        // reason from `requiredSigners`, certificates, and withdrawals — anything that
        // requires signatures from input UTxOs we don't own is invisible here. Document
        // limitation in errors.
        let requiredHashes = Self.requiredKeyHashes(in: body)
        if !partialSign {
            let missing = requiredHashes.subtracting(
                [paymentHashBytes] + (stakeHashBytes.map { [$0] } ?? [])
            )
            if !missing.isEmpty {
                let hexes = missing.map { $0.toHex }.sorted().joined(separator: ", ")
                throw TxSignError.proofGeneration("Required signers not held by wallet: \(hexes)")
            }
        }

        // Build witness set: payment witness is always added (we can't tell from the body
        // alone which inputs are ours, so we sign defensively). Stake witness is added
        // only when the body actually needs it — appending it unconditionally bloats the
        // witness set and exposes the stake key signature for transactions that don't
        // need it.
        let bodyHash = body.hash()
        var witnesses: [VerificationKeyWitness] = []

        let paymentSig = try paymentKey.sign(data: bodyHash)
        witnesses.append(
            VerificationKeyWitness(
                vkey: .verificationKey(paymentVKey),
                signature: paymentSig
            )
        )

        if let stake = stakeKey,
           let stakeHashBytes,
           bodyRequiresStakeWitness(body, stakeHashBytes: stakeHashBytes, requiredHashes: requiredHashes) {
            let stakeVKey = try stake.toVerificationKey()
            let stakeSig = try stake.sign(data: bodyHash)
            witnesses.append(
                VerificationKeyWitness(
                    vkey: .verificationKey(stakeVKey),
                    signature: stakeSig
                )
            )
        }

        let witnessSet = TransactionWitnessSet(vkeyWitnesses: .list(witnesses))

        do {
            return try witnessSet.toCBORData()
        } catch {
            throw TxSignError.proofGeneration("Could not encode witness set: \(error)")
        }
    }

    /// Collect the verification-key-hash payloads that a transaction body explicitly
    /// requires the wallet to sign for — `requiredSigners`, plus the stake credentials of
    /// any stake-credential certificate, plus the stake credential implied by each
    /// withdrawal's reward account. We can't see input UTxO key hashes from the body
    /// alone (CIP-30 doesn't pass UTxO context), so the returned set is a *lower bound*
    /// on what the chain will demand; that's fine for `partialSign:false` checking
    /// against the wallet's own keys.
    private static func requiredKeyHashes(in body: TransactionBody) -> Set<Data> {
        var hashes: Set<Data> = []

        if let signers = body.requiredSigners {
            for h in signers.asList { hashes.insert(h.payload) }
        }

        if let certificates = body.certificates {
            for cert in certificates.asList {
                if let credential = stakeCredential(of: cert),
                   case .verificationKeyHash(let h) = credential.credential {
                    hashes.insert(h.payload)
                }
            }
        }

        if let withdrawals = body.withdrawals {
            // RewardAccount = Data containing the 29-byte reward address. The first byte
            // is a header; the remaining 28 bytes are the credential. Strip the header to
            // get the bare key hash so it lines up with `requiredSigners` payloads.
            for (account, _) in withdrawals.data where account.count == 29 {
                let header = account[account.startIndex]
                // Header low nibble: 0 = key, 1 = script. Stake credential is the high
                // nibble, but for reward addresses the low nibble of the header carries
                // the credential type (per CIP-19). We only count key-hash withdrawals.
                if header & 0x10 == 0 {
                    hashes.insert(account.dropFirst())
                }
            }
        }

        return hashes
    }

    /// Pull the stake credential out of any certificate type that carries one. Returns
    /// `nil` for cert kinds (pool reg/retire, genesis, MIR, DRep) that don't use a stake
    /// credential the wallet would witness.
    private static func stakeCredential(of cert: Certificate) -> StakeCredential? {
        switch cert {
        case .stakeRegistration(let c):         return c.stakeCredential
        case .stakeDeregistration(let c):       return c.stakeCredential
        case .stakeDelegation(let c):           return c.stakeCredential
        case .register(let c):                  return c.stakeCredential
        case .unregister(let c):                return c.stakeCredential
        case .voteDelegate(let c):              return c.stakeCredential
        case .stakeVoteDelegate(let c):         return c.stakeCredential
        case .stakeRegisterDelegate(let c):     return c.stakeCredential
        case .voteRegisterDelegate(let c):      return c.stakeCredential
        case .stakeVoteRegisterDelegate(let c): return c.stakeCredential
        case .poolRegistration, .poolRetirement, .genesisKeyDelegation,
             .moveInstantaneousRewards, .authCommitteeHot, .resignCommitteeCold,
             .registerDRep, .unRegisterDRep, .updateDRep:
            return nil
        }
    }

    /// True when the transaction body requires a witness from the wallet's stake key —
    /// either listed in `requiredSigners`, contained in a stake-credential certificate,
    /// or referenced by a withdrawal at the wallet's reward address. `requiredHashes`
    /// already aggregates all three sources, so this is a single membership check.
    private func bodyRequiresStakeWitness(
        _ body: TransactionBody,
        stakeHashBytes: Data,
        requiredHashes: Set<Data>
    ) -> Bool {
        requiredHashes.contains(stakeHashBytes)
    }

    public func signData(address addressString: String, payload: Data) async throws -> DataSignature {
        try await signData(address: addressString, payload: payload, context: nil)
    }

    public func signData(address addressString: String, payload: Data, context: CIP30RequestContext?) async throws -> DataSignature {
        let target: Address
        do {
            target = try Address(from: .string(addressString))
        } catch {
            // Try hex bytes
            guard let bytes = Data(hexString: addressString),
                  let parsed = try? Address(from: .bytes(bytes)) else {
                throw DataSignError.proofGeneration("Invalid address: \(addressString)")
            }
            target = parsed
        }

        // Pick which of our keys matches the requested address.
        let keyForSigning: SigningKeyType
        if let payment = target.paymentPart {
            switch payment {
            case .verificationKeyHash(let hash):
                let ourHash = try (try paymentKey.toVerificationKey()).hash()
                guard ourHash == hash else {
                    throw DataSignError.proofGeneration("Address payment credential does not match this wallet")
                }
                keyForSigning = paymentKey
            case .scriptHash:
                throw DataSignError.addressNotPK("Address payment credential is a script hash")
            }
        } else if let staking = target.stakingPart {
            switch staking {
            case .verificationKeyHash(let hash):
                guard let stake = stakeKey else {
                    throw DataSignError.proofGeneration("No stake key configured for reward-address signing")
                }
                let ourHash = try (try stake.toVerificationKey()).hash()
                guard ourHash == hash else {
                    throw DataSignError.proofGeneration("Address staking credential does not match this wallet")
                }
                keyForSigning = stake
            case .scriptHash:
                throw DataSignError.addressNotPK("Address staking credential is a script hash")
            case .pointerAddress:
                throw DataSignError.addressNotPK("Pointer addresses are not supported for signData")
            }
        } else {
            throw DataSignError.addressNotPK("Address has no signable credential")
        }

        // Address validity is checked above so we don't bother the user about a request
        // we can't fulfil anyway. Approval is the last gate before signing.
        guard await policy.approveSignData(target, payload, context) else {
            throw DataSignError.userDeclined("User declined to sign data")
        }

        let signed: SignedMessage
        do {
            signed = try CIP8.sign(
                payload: payload,
                signingKey: keyForSigning,
                attachCoseKey: true,
                network: network
            )
        } catch {
            throw DataSignError.proofGeneration("CIP-8 signing failed: \(error)")
        }

        guard let coseKeyHex = signed.key else {
            throw DataSignError.proofGeneration("CIP-8 returned no COSE key")
        }
        return DataSignature(signature: signed.signature, key: coseKeyHex)
    }

    public func submitTx(_ tx: Data) async throws -> String {
        try await submitTx(tx, context: nil)
    }

    public func submitTx(_ tx: Data, context: CIP30RequestContext?) async throws -> String {
        guard let dataSource else { throw TxSendError.failure("No data source configured") }
        guard await policy.approveSubmitTx(tx, context) else {
            throw TxSendError.refused("User declined to submit transaction")
        }
        do {
            return try await dataSource.submit(tx)
        } catch {
            throw TxSendError.failure("\(error)")
        }
    }
}

/// Reference ``CIP30Initial`` that hands out a ``KeyStoreCIP30Provider`` once the user
/// approves. The `consent` closure is the wallet's UI hook — return `true` to grant access.
///
/// Enable state is tracked **per origin**, so consent for `https://app-a.example` does not
/// grant access to `https://attacker.example`. Both `consent` and `makeProvider` receive
/// the full ``CIP30RequestContext`` so the wallet UI can show the user which site is
/// asking and the resulting provider can be scoped (or logged) appropriately.
public final class KeyStoreCIP30Initial: CIP30Initial {
    public typealias OriginAwareConsent = @Sendable (_ requestedExtensions: [Extension], _ context: CIP30RequestContext) async -> Bool
    public typealias OriginAwareMakeProvider = @Sendable (_ extensions: [Extension], _ context: CIP30RequestContext) async throws -> CIP30Provider

    public let info: WalletInfo

    private let makeProvider: OriginAwareMakeProvider
    private let consent: OriginAwareConsent
    private let enabledOrigins: EnabledOriginsBox

    /// Origin-aware initializer. The bridge always supplies a ``CIP30RequestContext``;
    /// non-bridge callers can synthesize one with whatever origin string is meaningful
    /// to them.
    public init(
        info: WalletInfo,
        consent: @escaping OriginAwareConsent,
        makeProvider: @escaping OriginAwareMakeProvider
    ) {
        self.info = info
        self.consent = consent
        self.makeProvider = makeProvider
        self.enabledOrigins = EnabledOriginsBox()
    }

    /// Back-compat initializer for existing call sites that don't yet thread origin
    /// context through their consent UI. Wraps the supplied closures so they ignore the
    /// context — meaning the wallet UI cannot tell the user *which* site is asking and
    /// every origin gets the same answer. Prefer the origin-aware initializer.
    @available(*, deprecated, message: "Origin-blind consent cannot show the user which site is asking; use init(info:consent:makeProvider:) with the (Extension, CIP30RequestContext) closures.")
    public convenience init(
        info: WalletInfo,
        consent: @escaping @Sendable (_ requestedExtensions: [Extension]) async -> Bool,
        makeProvider: @escaping @Sendable ([Extension]) async throws -> CIP30Provider
    ) {
        self.init(
            info: info,
            consent: { exts, _ in await consent(exts) },
            makeProvider: { exts, _ in try await makeProvider(exts) }
        )
    }

    // MARK: - Origin-blind surface (kept for back-compat; do not call directly)

    /// Without an origin, this implementation cannot answer accurately — returns `false`
    /// so callers fall through to an explicit `enable(...)` call.
    public func isEnabled() async -> Bool {
        false
    }

    /// Without an origin, this implementation cannot run a meaningful consent prompt.
    /// Throws ``APIError/refused(_:)`` so accidental origin-blind callers don't bypass
    /// the per-origin gate.
    public func enable(extensions: [Extension]) async throws -> CIP30Provider {
        throw APIError.refused("Origin context required: call enable(extensions:context:) instead")
    }

    // MARK: - Origin-aware surface

    public func isEnabled(context: CIP30RequestContext) async -> Bool {
        await enabledOrigins.contains(context.origin)
    }

    public func enable(extensions: [Extension], context: CIP30RequestContext) async throws -> CIP30Provider {
        let granted = await consent(extensions, context)
        guard granted else {
            throw APIError.refused("User declined access for origin \(context.origin)")
        }
        await enabledOrigins.insert(context.origin)
        return try await makeProvider(extensions, context)
    }

    public func invalidate(origin: String) async {
        await enabledOrigins.remove(origin)
    }
}

/// Internal actor used by ``KeyStoreCIP30Initial`` to track which origins have completed
/// `enable(...)`. Replaces the old single-bool `EnabledBox`.
private actor EnabledOriginsBox {
    private var origins: Set<String> = []
    func contains(_ origin: String) -> Bool { origins.contains(origin) }
    func insert(_ origin: String) { origins.insert(origin) }
    func remove(_ origin: String) { origins.remove(origin) }
    func clear() { origins.removeAll() }
}
