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

    func makeProvider() throws -> KeyStoreCIP30Provider {
        try KeyStoreCIP30Provider(
            info: WalletInfo(name: "Test", icon: ""),
            paymentKey: .signingKey(paymentSK),
            stakeKey: .signingKey(stakeSK),
            network: .preview
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

    @Test func signTxProducesADecodableWitnessSet() async throws {
        let provider = try makeProvider()

        // Build a minimal valid transaction body.
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
        let tx = Transaction(
            transactionBody: body,
            transactionWitnessSet: TransactionWitnessSet()
        )
        let txCBOR = try tx.toCBORData()

        let witnessCBOR = try await provider.signTx(txCBOR, partialSign: false)
        let witnessSet = try TransactionWitnessSet.fromCBOR(data: witnessCBOR)
        let vkeys = witnessSet.vkeyWitnesses?.asList ?? []

        // One witness for payment + one for stake = 2.
        #expect(vkeys.count == 2)
        #expect(vkeys.allSatisfy { $0.signature.count == 64 })
    }
}

#if canImport(WebKit) && (os(iOS) || os(macOS) || os(visionOS))

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
        // Native callbacks the bridge invokes
        #expect(js.contains("__cip30_resolve"))
        #expect(js.contains("__cip30_reject"))
        // Handler name and wallet key wired in
        #expect(js.contains("'cip30'"))
        #expect(js.contains("'swiftWallet'"))
        // Wallet info embedded
        #expect(js.contains("\"SwiftWallet\""))
    }
}

#endif
