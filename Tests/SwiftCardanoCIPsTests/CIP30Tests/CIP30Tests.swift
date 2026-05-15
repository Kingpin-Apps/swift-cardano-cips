import Foundation
import SwiftCardanoCore
import Testing

@testable import SwiftCardanoCIPs

@Suite struct CIP30Tests {

    // Reuse the same keys as CIP8Tests for end-to-end signing.
    let paymentSK = try! PaymentSigningKey.fromTextEnvelope(
        """
        {
            "type": "GenesisUTxOSigningKey_ed25519",
            "description": "Genesis Initial UTxO Signing Key",
            "cborHex": "5820093be5cd3987d0c9fd8854ef908f7746b69e2d73320db6dc0f780d81585b84c2"
        }
        """
    )

    let stakeSK = try! StakeSigningKey.fromTextEnvelope(
        """
        {
            "type": "StakeSigningKeyShelley_ed25519",
            "description": "Stake Signing Key",
            "cborHex": "5820ff3a330df8859e4e5f42a97fcaee73f6a00d0cf864f4bca902bd106d423f02c0"
        }
        """
    )

    // MARK: - Error envelope

    @Test func apiErrorRoundTripsThroughJSON() throws {
        let envelope = CIP30ErrorEnvelope(APIError.refused("user said no"))
        let data = try JSONEncoder().encode(envelope)
        let decoded = try JSONDecoder().decode(CIP30ErrorEnvelope.self, from: data)
        #expect(decoded.code == -3)
        #expect(decoded.info == "user said no")
    }

    @Test func everyErrorTypeReportsItsCodeAndInfo() {
        #expect(APIError.invalidRequest("x").code == -1)
        #expect(APIError.internalError("x").code == -2)
        #expect(APIError.refused("x").code == -3)
        #expect(APIError.accountChange("x").code == -4)
        #expect(TxSendError.refused("x").code == 1)
        #expect(TxSendError.failure("x").code == 2)
        #expect(TxSignError.proofGeneration("x").code == 1)
        #expect(TxSignError.userDeclined("x").code == 2)
        #expect(DataSignError.proofGeneration("x").code == 1)
        #expect(DataSignError.addressNotPK("x").code == 2)
        #expect(DataSignError.userDeclined("x").code == 3)

        // info round-trips for every variant
        #expect(APIError.refused("hello").info == "hello")
        #expect(TxSendError.failure("net down").info == "net down")
        #expect(TxSignError.userDeclined("nope").info == "nope")
        #expect(DataSignError.addressNotPK("script").info == "script")
    }

    @Test func paginateErrorEncodesMaxSize() throws {
        let err = PaginateError(maxSize: 7, info: "out of range")
        let data = try JSONEncoder().encode(err)
        let decoded = try JSONDecoder().decode(PaginateError.self, from: data)
        #expect(decoded.maxSize == 7)
        #expect(decoded.info == "out of range")
    }

    // MARK: - Data structures

    @Test func paginateRoundTrips() throws {
        let p = Paginate(page: 0, limit: 25)
        let data = try JSONEncoder().encode(p)
        let decoded = try JSONDecoder().decode(Paginate.self, from: data)
        #expect(decoded == p)
    }

    @Test func extensionRoundTrips() throws {
        let ext = Extension(cip: 95)
        let data = try JSONEncoder().encode(ext)
        let decoded = try JSONDecoder().decode(Extension.self, from: data)
        #expect(decoded.cip == 95)
    }

    @Test func walletInfoRoundTrips() throws {
        let info = WalletInfo(
            name: "Swift Wallet",
            icon: "data:image/png;base64,abc",
            apiVersion: "0.1.0",
            supportedExtensions: [Extension(cip: 95)]
        )
        let data = try JSONEncoder().encode(info)
        let decoded = try JSONDecoder().decode(WalletInfo.self, from: data)
        #expect(decoded == info)
    }

    // MARK: - KeyStoreCIP30Provider

    /// Default test provider uses `.allowAll` so the happy-path signing tests stay green.
    /// Tests that exercise the deny path construct their own provider with `.denyAll`.
    func makeProvider(policy: CIP30ApprovalPolicy = .allowAll) throws -> KeyStoreCIP30Provider {
        try KeyStoreCIP30Provider(
            info: WalletInfo(name: "Test", icon: ""),
            paymentKey: .signingKey(paymentSK),
            stakeKey: .signingKey(stakeSK),
            network: .preview,
            policy: policy
        )
    }

    @Test func getNetworkIdReportsTestnetForNonMainnet() async throws {
        let provider = try makeProvider()
        let id = try await provider.getNetworkId()
        #expect(id == 0)
    }

    @Test func getChangeAddressReturnsCBOREncodedAddress() async throws {
        let provider = try makeProvider()
        let cbor = try await provider.getChangeAddress()
        // Should be decodable back into an Address with both parts
        let addr = try Address.fromCBOR(data: cbor)
        #expect(addr.paymentPart != nil)
        #expect(addr.stakingPart != nil)
        #expect(addr.network == .testnet)
    }

    @Test func getRewardAddressesReturnsStakeOnlyAddress() async throws {
        let provider = try makeProvider()
        let cbors = try await provider.getRewardAddresses()
        #expect(cbors.count == 1)
        let addr = try Address.fromCBOR(data: cbors[0])
        #expect(addr.paymentPart == nil)
        #expect(addr.stakingPart != nil)
    }

    @Test func getRewardAddressesIsEmptyWithoutStakeKey() async throws {
        let provider = try KeyStoreCIP30Provider(
            info: WalletInfo(name: "Test", icon: ""),
            paymentKey: .signingKey(paymentSK),
            stakeKey: nil,
            network: .preview
        )
        let cbors = try await provider.getRewardAddresses()
        #expect(cbors.isEmpty)
    }

    @Test func getBalanceWithoutDataSourceThrowsInternalError() async throws {
        let provider = try makeProvider()
        do {
            _ = try await provider.getBalance()
            Issue.record("Expected internalError")
        } catch let err as APIError {
            #expect(err.code == -2)
        }
    }

    // MARK: - signData round trip

    @Test func signDataProducesCIP8VerifiableSignature() async throws {
        let provider = try makeProvider()
        let cbors = try await provider.getUsedAddresses(paginate: nil)
        let address = try Address.fromCBOR(data: cbors[0])
        let bech32 = try address.toBech32()

        let payload = "hello cardano".data(using: .utf8)!
        let signature = try await provider.signData(address: bech32, payload: payload)

        #expect(!signature.signature.isEmpty)
        #expect(!signature.key.isEmpty)

        // Verify via CIP8 — should round-trip cleanly.
        let result = try CIP8.verify(
            signedMessage: SignedMessage(signature: signature.signature, key: signature.key)
        )
        #expect(result.verified)
        #expect(result.message == "hello cardano")
    }

    @Test func signDataRejectsAddressNotMatchingWallet() async throws {
        let provider = try makeProvider()
        // A well-formed but unrelated bech32 address
        let stranger = "addr_test1qrwm5wkhvvfcyh60v3h44fknydcxv5aa5s8vrtj4tq5cdfrrueshdzujm6aytddd5j4eullazlknq5djuq6spcz596dqjvm8nu"
        do {
            _ = try await provider.signData(address: stranger, payload: Data([0x01, 0x02]))
            Issue.record("Expected DataSignError")
        } catch let err as DataSignError {
            #expect(err.code == 1) // proofGeneration
        }
    }

    // MARK: - signTx round trip

    @Test func signTxProducesPaymentOnlyWitnessForPlainTransfer() async throws {
        // A plain payment-only transfer doesn't reference the stake key (no withdrawal,
        // no stake-credential cert, not in requiredSigners). The wallet should emit only
        // the payment witness — appending the stake witness here was the bloat that the
        // pre-PR4 implementation produced.
        let provider = try makeProvider()
        let txCBOR = try Self.minimalTxCBOR()

        let witnessCBOR = try await provider.signTx(txCBOR, partialSign: false)
        let witnessSet = try TransactionWitnessSet.fromCBOR(data: witnessCBOR)
        let vkeys = witnessSet.vkeyWitnesses?.asList ?? []

        #expect(vkeys.count == 1)
        #expect(vkeys.allSatisfy { $0.signature.count == 64 })
    }

    // MARK: - Approval policy

    @Test func denyAllRefusesSignTx() async throws {
        let provider = try makeProvider(policy: .denyAll)
        let txCBOR = try Self.minimalTxCBOR()
        do {
            _ = try await provider.signTx(txCBOR, partialSign: false)
            Issue.record("Expected TxSignError.userDeclined")
        } catch let err as TxSignError {
            #expect(err.code == 2) // userDeclined
        }
    }

    @Test func denyAllRefusesSignData() async throws {
        let provider = try makeProvider(policy: .denyAll)
        let cbors = try await provider.getUsedAddresses(paginate: nil)
        let address = try Address.fromCBOR(data: cbors[0])
        let bech32 = try address.toBech32()
        do {
            _ = try await provider.signData(address: bech32, payload: Data([0x01]))
            Issue.record("Expected DataSignError.userDeclined")
        } catch let err as DataSignError {
            #expect(err.code == 3) // userDeclined
        }
    }

    @Test func denyAllRefusesSubmitTx() async throws {
        let provider = try KeyStoreCIP30Provider(
            info: WalletInfo(name: "Test", icon: ""),
            paymentKey: .signingKey(paymentSK),
            stakeKey: .signingKey(stakeSK),
            network: .preview,
            dataSource: AlwaysOKDataSource(),
            policy: .denyAll
        )
        do {
            _ = try await provider.submitTx(Data([0x00]))
            Issue.record("Expected TxSendError.refused")
        } catch let err as TxSendError {
            #expect(err.code == 1) // refused
        }
    }

    @Test func defaultPolicyIsDenyAll() async throws {
        // Constructing with no explicit policy must NOT silently allow signing.
        let provider = try KeyStoreCIP30Provider(
            info: WalletInfo(name: "Test", icon: ""),
            paymentKey: .signingKey(paymentSK),
            stakeKey: .signingKey(stakeSK),
            network: .preview
        )
        let txCBOR = try Self.minimalTxCBOR()
        do {
            _ = try await provider.signTx(txCBOR, partialSign: false)
            Issue.record("Expected default policy to deny signing")
        } catch let err as TxSignError {
            #expect(err.code == 2) // userDeclined
        }
    }

    @Test func policyReceivesContext() async throws {
        let recorder = ContextRecorder()
        let policy = CIP30ApprovalPolicy(
            approveSignTx: { _, _, ctx in
                await recorder.record(ctx)
                return true
            },
            approveSignData: { _, _, ctx in
                await recorder.record(ctx)
                return true
            },
            approveSubmitTx: { _, ctx in
                await recorder.record(ctx)
                return true
            }
        )
        let provider = try makeProvider(policy: policy)
        let txCBOR = try Self.minimalTxCBOR()
        let ctx = CIP30RequestContext(origin: "https://app.example.com", isMainFrame: true)
        _ = try await provider.signTx(txCBOR, partialSign: false, context: ctx)
        let seen = await recorder.contexts
        #expect(seen.count == 1)
        #expect(seen.first??.origin == "https://app.example.com")
    }

    @Test func signDataAddressMismatchOutranksPolicy() async throws {
        // .denyAll would reject ANY signData, but address-mismatch is a wallet-level
        // pre-check that should fire first so the user isn't asked about a request the
        // wallet can't fulfil. Verify the existing behaviour is preserved.
        let provider = try makeProvider(policy: .denyAll)
        let stranger = "addr_test1qrwm5wkhvvfcyh60v3h44fknydcxv5aa5s8vrtj4tq5cdfrrueshdzujm6aytddd5j4eullazlknq5djuq6spcz596dqjvm8nu"
        do {
            _ = try await provider.signData(address: stranger, payload: Data([0x01]))
            Issue.record("Expected proofGeneration before user prompt")
        } catch let err as DataSignError {
            #expect(err.code == 1) // proofGeneration, not userDeclined (3)
        }
    }

    // MARK: - partialSign + stake-witness selection

    @Test func signTxAddsStakeWitnessWhenRequiredSignersIncludesStakeHash() async throws {
        let provider = try makeProvider()
        let stakeVKey: StakeVerificationKey = try Self.fixtures.stakeSK.toVerificationKey()
        let stakeHash = try stakeVKey.hash()
        let txCBOR = try Self.minimalTxCBOR(requiredSigners: [stakeHash])

        let witnessCBOR = try await provider.signTx(txCBOR, partialSign: false)
        let vkeys = try TransactionWitnessSet.fromCBOR(data: witnessCBOR).vkeyWitnesses?.asList ?? []
        #expect(vkeys.count == 2)
    }

    @Test func signTxOmitsStakeWitnessWhenRequiredSignersOnlyHasPaymentHash() async throws {
        let provider = try makeProvider()
        let paymentVKey: PaymentVerificationKey = try Self.fixtures.paymentSK.toVerificationKey()
        let paymentHash = try paymentVKey.hash()
        let txCBOR = try Self.minimalTxCBOR(requiredSigners: [paymentHash])

        let witnessCBOR = try await provider.signTx(txCBOR, partialSign: false)
        let vkeys = try TransactionWitnessSet.fromCBOR(data: witnessCBOR).vkeyWitnesses?.asList ?? []
        #expect(vkeys.count == 1)
    }

    @Test func signTxAddsStakeWitnessWhenWithdrawalAtOurRewardAddress() async throws {
        let provider = try makeProvider()
        let stakeVKey: StakeVerificationKey = try Self.fixtures.stakeSK.toVerificationKey()
        let stakeHash = try stakeVKey.hash()
        let rewardAddress = try Address(
            paymentPart: nil,
            stakingPart: .verificationKeyHash(stakeHash),
            network: Network.preview.networkId
        )
        let withdrawals = Withdrawals([rewardAddress.toBytes(): Coin(0)])
        let txCBOR = try Self.minimalTxCBOR(withdrawals: withdrawals)

        let witnessCBOR = try await provider.signTx(txCBOR, partialSign: false)
        let vkeys = try TransactionWitnessSet.fromCBOR(data: witnessCBOR).vkeyWitnesses?.asList ?? []
        #expect(vkeys.count == 2)
    }

    @Test func signTxAddsStakeWitnessWhenStakeRegistrationCertReferencesUs() async throws {
        let provider = try makeProvider()
        let stakeVKey: StakeVerificationKey = try Self.fixtures.stakeSK.toVerificationKey()
        let stakeHash = try stakeVKey.hash()
        let cert = Certificate.stakeRegistration(
            StakeRegistration(stakeCredential: StakeCredential(credential: .verificationKeyHash(stakeHash)))
        )
        let txCBOR = try Self.minimalTxCBOR(certificates: [cert])

        let witnessCBOR = try await provider.signTx(txCBOR, partialSign: false)
        let vkeys = try TransactionWitnessSet.fromCBOR(data: witnessCBOR).vkeyWitnesses?.asList ?? []
        #expect(vkeys.count == 2)
    }

    @Test func signTxOmitsStakeWitnessForUnrelatedStakeRegistration() async throws {
        let provider = try makeProvider()
        // A registration certificate for some *other* stake credential — wallet must NOT
        // sign with its stake key. Use partialSign:true so the partial-sign required-
        // hash check (which would otherwise correctly refuse, since the stranger's hash
        // IS required by the cert) doesn't fire — we're testing witness selection here,
        // not the partial-sign gate.
        let strangerHash = VerificationKeyHash(payload: Data(repeating: 0xAB, count: 28))
        let cert = Certificate.stakeRegistration(
            StakeRegistration(stakeCredential: StakeCredential(credential: .verificationKeyHash(strangerHash)))
        )
        let txCBOR = try Self.minimalTxCBOR(certificates: [cert])

        let witnessCBOR = try await provider.signTx(txCBOR, partialSign: true)
        let vkeys = try TransactionWitnessSet.fromCBOR(data: witnessCBOR).vkeyWitnesses?.asList ?? []
        #expect(vkeys.count == 1)
    }

    @Test func signTxRejectsRequiredSignerNotHeldWhenPartialSignFalse() async throws {
        let provider = try makeProvider()
        // requiredSigners includes a hash we don't hold — must throw proofGeneration.
        let stranger = VerificationKeyHash(payload: Data(repeating: 0xFE, count: 28))
        let txCBOR = try Self.minimalTxCBOR(requiredSigners: [stranger])

        do {
            _ = try await provider.signTx(txCBOR, partialSign: false)
            Issue.record("Expected TxSignError.proofGeneration")
        } catch let err as TxSignError {
            #expect(err.code == 1) // proofGeneration
            #expect(err.info.contains(stranger.payload.toHex))
        }
    }

    @Test func signTxAllowsRequiredSignerNotHeldWhenPartialSignTrue() async throws {
        let provider = try makeProvider()
        let stranger = VerificationKeyHash(payload: Data(repeating: 0xFE, count: 28))
        let txCBOR = try Self.minimalTxCBOR(requiredSigners: [stranger])

        // partialSign: true means "sign what you can; the dApp will assemble the rest".
        let witnessCBOR = try await provider.signTx(txCBOR, partialSign: true)
        let vkeys = try TransactionWitnessSet.fromCBOR(data: witnessCBOR).vkeyWitnesses?.asList ?? []
        // Stranger is not us, so only payment witness is emitted.
        #expect(vkeys.count == 1)
    }

    // MARK: - helpers

    /// Hold onto signing keys without rebuilding them per-test.
    private static let fixtures = SignTxFixtures()
    private struct SignTxFixtures {
        let paymentSK: PaymentSigningKey
        let stakeSK: StakeSigningKey
        init() {
            self.paymentSK = try! PaymentSigningKey.fromTextEnvelope(
                """
                {
                    "type": "GenesisUTxOSigningKey_ed25519",
                    "description": "Genesis Initial UTxO Signing Key",
                    "cborHex": "5820093be5cd3987d0c9fd8854ef908f7746b69e2d73320db6dc0f780d81585b84c2"
                }
                """
            )
            self.stakeSK = try! StakeSigningKey.fromTextEnvelope(
                """
                {
                    "type": "StakeSigningKeyShelley_ed25519",
                    "description": "Stake Signing Key",
                    "cborHex": "5820ff3a330df8859e4e5f42a97fcaee73f6a00d0cf864f4bca902bd106d423f02c0"
                }
                """
            )
        }
    }

    private static func minimalTxCBOR(
        requiredSigners: [VerificationKeyHash]? = nil,
        withdrawals: Withdrawals? = nil,
        certificates: [Certificate]? = nil
    ) throws -> Data {
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
            fee: 200_000,
            certificates: certificates.map { .list($0) },
            withdrawals: withdrawals,
            requiredSigners: requiredSigners.map { .list($0) }
        )
        let tx = Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
        return try tx.toCBORData()
    }
}

/// Records contexts handed to approval-policy closures so tests can assert what was passed.
private actor ContextRecorder {
    private(set) var contexts: [CIP30RequestContext?] = []
    func record(_ context: CIP30RequestContext?) { contexts.append(context) }
}

/// Stub data source that approves any submit and returns a fixed tx id. Used to exercise
/// `submitTx` without involving a real chain.
private struct AlwaysOKDataSource: CIP30DataSource {
    func utxos(for address: Address) async throws -> [UTxO] { [] }
    func submit(_ tx: Data) async throws -> String { "00" }
}

#if canImport(WebKit) && (os(iOS) || os(macOS) || os(visionOS))

/// Counts consent invocations during per-origin tests.
private actor ConsentCounter {
    private(set) var value: Int = 0
    func bump() { value += 1 }
}

@Suite struct CIP30WebBridgeTests {

    @Test func javaScriptShimExposesExpectedSurface() {
        let info = WalletInfo(
            name: "SwiftWallet",
            icon: "data:,",
            apiVersion: "0.1.0",
            supportedExtensions: [Extension(cip: 30)]
        )
        let js = CIP30WebBridge.javaScriptShim(
            walletKey: "swiftWallet",
            handlerName: "cip30",
            info: info
        )

        // Wallet key registers under window.cardano
        #expect(js.contains("window.cardano[KEY] ="))
        // Both initial-API and full-API methods are present
        for method in [
            "isEnabled", "enable",
            "getNetworkId", "getExtensions", "getUtxos", "getCollateral",
            "getBalance", "getUsedAddresses", "getUnusedAddresses",
            "getChangeAddress", "getRewardAddresses",
            "signTx", "signData", "submitTx"
        ] {
            #expect(js.contains(method), "JS shim missing method: \(method)")
        }
        // The reply-based transport must NOT expose globally-callable resolvers — that was
        // the response-spoofing vector the old shim had.
        #expect(!js.contains("__cip30_resolve"))
        #expect(!js.contains("__cip30_reject"))
        #expect(!js.contains("nextId"))
        // The shim awaits postMessage directly (WKScriptMessageHandlerWithReply).
        #expect(js.contains("await window.webkit.messageHandlers[HANDLER].postMessage"))
        // Handler name and wallet key wired in
        #expect(js.contains("'cip30'"))
        #expect(js.contains("'swiftWallet'"))
        // Wallet info embedded
        #expect(js.contains("\"SwiftWallet\""))
    }

    private static func makeStubInitial() -> KeyStoreCIP30Initial {
        KeyStoreCIP30Initial(
            info: WalletInfo(name: "Test", icon: ""),
            consent: { _, _ in true },
            makeProvider: { _, _ in
                throw APIError.internalError("not used")
            }
        )
    }

    @MainActor
    @Test func bridgeRejectsInvalidWalletKey() async throws {
        let initial = Self.makeStubInitial()

        // JS-injection attempt: a key that closes the string and runs arbitrary code.
        #expect(throws: CIP30WebBridgeError.self) {
            _ = try CIP30WebBridge(initial: initial, walletKey: "x'; alert(1); //")
        }
        // Empty
        #expect(throws: CIP30WebBridgeError.self) {
            _ = try CIP30WebBridge(initial: initial, walletKey: "")
        }
        // Whitespace
        #expect(throws: CIP30WebBridgeError.self) {
            _ = try CIP30WebBridge(initial: initial, walletKey: "swift wallet")
        }
        // Hyphen (not in identifier set)
        #expect(throws: CIP30WebBridgeError.self) {
            _ = try CIP30WebBridge(initial: initial, walletKey: "swift-wallet")
        }
        // Too long
        #expect(throws: CIP30WebBridgeError.self) {
            _ = try CIP30WebBridge(initial: initial, walletKey: String(repeating: "a", count: 65))
        }
    }

    @MainActor
    @Test func bridgeRejectsInvalidHandlerName() async throws {
        let initial = Self.makeStubInitial()
        #expect(throws: CIP30WebBridgeError.self) {
            _ = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet", messageHandlerName: "cip30 handler")
        }
    }

    @MainActor
    @Test func bridgeAcceptsValidIdentifiers() async throws {
        let initial = Self.makeStubInitial()

        _ = try CIP30WebBridge(initial: initial, walletKey: "swiftwallet")
        _ = try CIP30WebBridge(initial: initial, walletKey: "SwiftWallet2")
        _ = try CIP30WebBridge(initial: initial, walletKey: "swift_wallet")
        _ = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet", messageHandlerName: "myCip30")
    }

    // MARK: - Origin policy

    @Test func originPolicyMainFrameOnlyRejectsIframes() {
        let policy = CIP30OriginPolicy.mainFrameOnly
        let main = CIP30RequestContext(origin: "https://app.example.com", isMainFrame: true)
        let iframe = CIP30RequestContext(origin: "https://attacker.example", isMainFrame: false)
        #expect(policy.allows(main))
        #expect(!policy.allows(iframe))
    }

    @Test func originPolicyAllowOriginsMatchesExactly() {
        let policy = CIP30OriginPolicy.allowOrigins(["https://app.example.com", "https://other.example"])
        // Match in iframe is fine for this policy.
        #expect(policy.allows(CIP30RequestContext(origin: "https://app.example.com", isMainFrame: false)))
        #expect(policy.allows(CIP30RequestContext(origin: "https://other.example", isMainFrame: true)))
        // Origin mismatch is not allowed even if main frame.
        #expect(!policy.allows(CIP30RequestContext(origin: "https://attacker.example", isMainFrame: true)))
        // Subdomain is not the same origin.
        #expect(!policy.allows(CIP30RequestContext(origin: "https://api.app.example.com", isMainFrame: true)))
    }

    @Test func originPolicyCustomReceivesContext() {
        let policy = CIP30OriginPolicy.custom { ctx in
            ctx.origin.hasPrefix("https://") && ctx.isMainFrame
        }
        #expect(policy.allows(CIP30RequestContext(origin: "https://x", isMainFrame: true)))
        #expect(!policy.allows(CIP30RequestContext(origin: "http://x", isMainFrame: true)))
        #expect(!policy.allows(CIP30RequestContext(origin: "https://x", isMainFrame: false)))
    }

    // MARK: - Origin canonicalization

    @Test func canonicalOriginOmitsDefaultPort() {
        // WKSecurityOrigin returns 0 for default ports.
        #expect(CIP30WebBridge.canonicalOrigin(scheme: "https", host: "app.example.com", port: 0) == "https://app.example.com")
        #expect(CIP30WebBridge.canonicalOrigin(scheme: "http", host: "app.example.com", port: 0) == "http://app.example.com")
    }

    @Test func canonicalOriginIncludesNonDefaultPort() {
        #expect(CIP30WebBridge.canonicalOrigin(scheme: "https", host: "app.example.com", port: 8443) == "https://app.example.com:8443")
        #expect(CIP30WebBridge.canonicalOrigin(scheme: "http", host: "localhost", port: 3000) == "http://localhost:3000")
    }

    @Test func canonicalOriginHandlesOpaqueOrigin() {
        // file:// pages and data: URIs typically have empty host.
        #expect(CIP30WebBridge.canonicalOrigin(scheme: "file", host: "", port: 0) == "file://")
        #expect(CIP30WebBridge.canonicalOrigin(scheme: "", host: "", port: 0) == "null")
    }

    // MARK: - Per-origin dispatch gating

    @MainActor
    @Test func dispatchRefusesWhenOriginPolicyBlocks() async throws {
        let initial = Self.makeStubInitial()
        let bridge = try CIP30WebBridge(
            initial: initial,
            walletKey: "swiftWallet",
            originPolicy: .mainFrameOnly
        )
        let iframe = CIP30RequestContext(origin: "https://app.example.com", isMainFrame: false)
        // Verify the policy classifies the iframe as not-allowed, then verify the full
        // `handle(...)` path (which is what WebKit actually drives) refuses with the
        // CIP-30 `refused` envelope rather than reaching dispatch.
        #expect(!bridge.originPolicy.allows(iframe))
        let result = await bridge.handleForTesting(
            body: ["method": "isEnabled"] as [String: Any],
            context: iframe
        )
        #expect(result.value == nil)
        let envelope = try #require(result.errorEnvelope)
        #expect(envelope.contains("\"code\":-3"))
        #expect(envelope.contains("Origin not permitted"))
    }

    @MainActor
    @Test func dispatchRefusesWhenOriginNotEnabled() async throws {
        let initial = Self.makeStubInitial()
        let bridge = try CIP30WebBridge(
            initial: initial,
            walletKey: "swiftWallet"
        )
        let context = CIP30RequestContext(origin: "https://never-enabled.example", isMainFrame: true)
        // Provider methods on an origin that hasn't enabled fail with refused.
        do {
            _ = try await bridge.dispatch(method: "getNetworkId", params: [:], context: context)
            Issue.record("Expected APIError.refused")
        } catch let err as APIError {
            #expect(err.code == -3)
        }
    }

    @MainActor
    @Test func enableScopesProviderToOrigin() async throws {
        // Build an initial that returns a stub provider on enable. We use the
        // KeyStoreCIP30Provider fixture from CIP30Tests so we don't have to roll a custom
        // CIP30Provider here.
        let info = WalletInfo(name: "Test", icon: "")
        let payment = CIP30Tests().paymentSK
        let stake = CIP30Tests().stakeSK
        let consentCount = ConsentCounter()

        let initial = KeyStoreCIP30Initial(
            info: info,
            consent: { _, _ in
                await consentCount.bump()
                return true
            },
            makeProvider: { _, _ in
                try KeyStoreCIP30Provider(
                    info: info,
                    paymentKey: .signingKey(payment),
                    stakeKey: .signingKey(stake),
                    network: .preview
                )
            }
        )
        let bridge = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet")

        let originA = CIP30RequestContext(origin: "https://app-a.example", isMainFrame: true)
        let originB = CIP30RequestContext(origin: "https://app-b.example", isMainFrame: true)

        // Enable for A only.
        _ = try await bridge.dispatch(method: "enable", params: [:], context: originA)
        await #expect(consentCount.value == 1)

        // A can call provider methods.
        let netA = try await bridge.dispatch(method: "getNetworkId", params: [:], context: originA)
        #expect(netA as? Int == 0)

        // B is still refused — A's consent does not transfer.
        do {
            _ = try await bridge.dispatch(method: "getNetworkId", params: [:], context: originB)
            Issue.record("Expected APIError.refused for unrelated origin")
        } catch let err as APIError {
            #expect(err.code == -3)
        }

        // isEnabled is also per-origin.
        let isEnabledA = try await bridge.dispatch(method: "isEnabled", params: [:], context: originA)
        let isEnabledB = try await bridge.dispatch(method: "isEnabled", params: [:], context: originB)
        #expect(isEnabledA as? Bool == true)
        #expect(isEnabledB as? Bool == false)

        // Enable for B as well — consent fires again, neither origin is short-circuited.
        _ = try await bridge.dispatch(method: "enable", params: [:], context: originB)
        await #expect(consentCount.value == 2)

        // After invalidate, A is refused again until re-enable.
        await bridge.invalidate(origin: originA.origin)
        do {
            _ = try await bridge.dispatch(method: "getNetworkId", params: [:], context: originA)
            Issue.record("Expected APIError.refused after invalidate")
        } catch let err as APIError {
            #expect(err.code == -3)
        }
        // B is still enabled.
        let netB = try await bridge.dispatch(method: "getNetworkId", params: [:], context: originB)
        #expect(netB as? Int == 0)
    }

    @MainActor
    private func driveHandle(_ bridge: CIP30WebBridge, method: String, context: CIP30RequestContext) async throws -> Any {
        try await bridge.dispatch(method: method, params: [:], context: context)
    }

    @Test func envelopeMessageEncodesCIP30Errors() throws {
        // APIError.refused -> {code: -3, info: "..."}
        let refusedJSON = CIP30WebBridge.envelopeMessage(for: APIError.refused("user said no"))
        let refused = try JSONSerialization.jsonObject(with: Data(refusedJSON.utf8)) as? [String: Any]
        #expect(refused?["code"] as? Int == -3)
        #expect(refused?["info"] as? String == "user said no")

        // TxSignError.userDeclined -> {code: 2, info: "..."}
        let signJSON = CIP30WebBridge.envelopeMessage(for: TxSignError.userDeclined("nope"))
        let sign = try JSONSerialization.jsonObject(with: Data(signJSON.utf8)) as? [String: Any]
        #expect(sign?["code"] as? Int == 2)
        #expect(sign?["info"] as? String == "nope")

        // PaginateError -> {maxSize: 7, info: "..."} (no `code` key per spec)
        let pageJSON = CIP30WebBridge.envelopeMessage(for: PaginateError(maxSize: 7, info: "out of range"))
        let page = try JSONSerialization.jsonObject(with: Data(pageJSON.utf8)) as? [String: Any]
        #expect(page?["maxSize"] as? Int == 7)
        #expect(page?["info"] as? String == "out of range")
        #expect(page?["code"] == nil)
    }
}

#endif
