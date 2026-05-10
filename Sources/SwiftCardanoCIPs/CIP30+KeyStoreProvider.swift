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

/// Reference ``CIP30Provider`` implementation backed by a single payment key (and an
/// optional stake key) plus a ``CIP30DataSource`` for chain access.
///
/// This is intentionally minimal — a single-address wallet — but it composes enough of
/// `SwiftCardanoCore` to be useful and to demonstrate that the protocol is actually
/// implementable end-to-end. Wallets with HD-derived address sets should subclass the
/// pattern: hold many keys, keep an internal address set, and override the address
/// accessors.
public actor KeyStoreCIP30Provider: CIP30Provider {
    public let info: WalletInfo
    public let network: Network

    private let paymentKey: SigningKeyType
    private let stakeKey: SigningKeyType?
    private let address: Address
    private let rewardAddress: Address?
    private let dataSource: CIP30DataSource?
    private let grantedExtensions: [Extension]

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
    public init(
        info: WalletInfo,
        paymentKey: SigningKeyType,
        stakeKey: SigningKeyType? = nil,
        network: Network = .mainnet,
        dataSource: CIP30DataSource? = nil,
        grantedExtensions: [Extension] = []
    ) throws {
        self.info = info
        self.network = network
        self.paymentKey = paymentKey
        self.stakeKey = stakeKey
        self.dataSource = dataSource
        self.grantedExtensions = grantedExtensions

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
        let transaction: Transaction
        do {
            transaction = try Transaction.fromCBOR(data: tx)
        } catch {
            throw TxSignError.proofGeneration("Could not decode transaction: \(error)")
        }

        let bodyHash = transaction.transactionBody.hash()

        var witnesses: [VerificationKeyWitness] = []

        let paymentVKey = try paymentKey.toVerificationKey()
        let paymentSig = try paymentKey.sign(data: bodyHash)
        witnesses.append(
            VerificationKeyWitness(
                vkey: .verificationKey(paymentVKey),
                signature: paymentSig
            )
        )

        if let stake = stakeKey {
            let stakeVKey = try stake.toVerificationKey()
            let stakeSig = try stake.sign(data: bodyHash)
            witnesses.append(
                VerificationKeyWitness(
                    vkey: .verificationKey(stakeVKey),
                    signature: stakeSig
                )
            )
        }

        // partialSign=false in the spec means "must produce all required witnesses or
        // throw proofGeneration". A single-key wallet has no view of which witnesses
        // are required; we sign with what we hold and let validation reject if short.
        // Real wallets that know their full key set should override this method.
        _ = partialSign

        let witnessSet = TransactionWitnessSet(vkeyWitnesses: .list(witnesses))

        do {
            return try witnessSet.toCBORData()
        } catch {
            throw TxSignError.proofGeneration("Could not encode witness set: \(error)")
        }
    }

    public func signData(address addressString: String, payload: Data) async throws -> DataSignature {
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
        guard let dataSource else { throw TxSendError.failure("No data source configured") }
        do {
            return try await dataSource.submit(tx)
        } catch {
            throw TxSendError.failure("\(error)")
        }
    }
}

/// Reference ``CIP30Initial`` that hands out a ``KeyStoreCIP30Provider`` once the user
/// approves. The `consent` closure is the wallet's UI hook — return `true` to grant access.
public final class KeyStoreCIP30Initial: CIP30Initial {
    public let info: WalletInfo

    private let makeProvider: @Sendable ([Extension]) async throws -> CIP30Provider
    private let consent: @Sendable (_ requestedExtensions: [Extension]) async -> Bool
    private let enabledBox: EnabledBox

    public init(
        info: WalletInfo,
        consent: @escaping @Sendable (_ requestedExtensions: [Extension]) async -> Bool,
        makeProvider: @escaping @Sendable ([Extension]) async throws -> CIP30Provider
    ) {
        self.info = info
        self.consent = consent
        self.makeProvider = makeProvider
        self.enabledBox = EnabledBox()
    }

    public func isEnabled() async -> Bool {
        await enabledBox.value
    }

    public func enable(extensions: [Extension]) async throws -> CIP30Provider {
        let granted = await consent(extensions)
        guard granted else {
            throw APIError.refused("User declined access")
        }
        await enabledBox.set(true)
        return try await makeProvider(extensions)
    }
}

/// Internal actor used by ``KeyStoreCIP30Initial`` to track the enabled state across
/// concurrent calls to `isEnabled` / `enable`.
private actor EnabledBox {
    var value: Bool = false
    func set(_ v: Bool) { value = v }
}
