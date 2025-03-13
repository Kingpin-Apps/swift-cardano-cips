import SwiftCardanoCore
import CryptoKit
import Testing

@testable import SwiftCardanoCIPs

@Suite struct CIP8Tests {
    let extendedSK = try! PaymentExtendedSigningKey.fromJSON(
            """
            {
                "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32",
                "description": "Payment Signing Key",
                "cborHex": "5880e8428867ab9cc9304379a3ce0c238a592bd6d2349d2ebaf8a6ed2c6d2974a15ad59c74b6d8fa3edd032c6261a73998b7deafe983b6eeaff8b6fb3fab06bdf8019b693a62bce7a3cad1b9c02d22125767201c65db27484bb67d3cee7df7288d62c099ac0ce4a215355b149fd3114a2a7ef0438f01f8872c4487a61b469e26aae4"
            }
            """
    )

    let extendedVK = try! PaymentExtendedVerificationKey.fromJSON(
            """
            {
                "type": "PaymentExtendedVerificationKeyShelley_ed25519_bip32",
                "description": "Payment Verification Key",
                "cborHex": "58409b693a62bce7a3cad1b9c02d22125767201c65db27484bb67d3cee7df7288d62c099ac0ce4a215355b149fd3114a2a7ef0438f01f8872c4487a61b469e26aae4"
            }
            """
    )

    let sk = try! PaymentSigningKey.fromJSON(
            """
            {
                "type": "GenesisUTxOSigningKey_ed25519",
                "description": "Genesis Initial UTxO Signing Key",
                "cborHex": "5820093be5cd3987d0c9fd8854ef908f7746b69e2d73320db6dc0f780d81585b84c2"
            }
            """
    )

    let vk = try! PaymentVerificationKey.fromJSON(
            """
            {
                "type": "GenesisUTxOVerificationKey_ed25519",
                "description": "Genesis Initial UTxO Verification Key",
                "cborHex": "58208be8339e9f3addfa6810d59e2f072f85e64d4c024c087e0d24f8317c6544f62f"
            }
            """
    )

    let stakeSK = try! StakeSigningKey.fromJSON(
            """
            {
                "type": "StakeSigningKeyShelley_ed25519",
                "description": "Stake Signing Key",
                "cborHex": "5820ff3a330df8859e4e5f42a97fcaee73f6a00d0cf864f4bca902bd106d423f02c0"
            }
            """
    )

    let stakeVK = try! StakeVerificationKey.fromJSON(
            """
            {
                "type": "StakeVerificationKeyShelley_ed25519",
                "description": "Stake Verification Key",
                "cborHex": "58205edaa384c658c2bd8945ae389edac0a5bd452d0cfd5d1245e3ecd540030d1e3c"
            }
            """
    )

    @Test func testVerifyMessage() throws {
        let signedMessage =
            "845869a3012704582060545b786d3a6f903158e35aae9b86548a99bc47d4b0a6f503ab5e78c1a9bbfc6761646472657373583900ddba3ad76313825f4f646f5aa6d323706653bda40ec1ae55582986a463e661768b92deba45b5ada4ab9e7ffd17ed3051b2e03500e0542e9aa166686173686564f452507963617264616e6f20697320636f6f6c2e58403b09cbae8d272ff94befd28cc04b152aea3c1633caffb4924a8a8c45be3ba6332a76d9f2aba833df53803286d32a5ee700990b79a0e86fab3cccdbfd37ce250f"
        let signingAddress = try Address(from: "addr_test1qrwm5wkhvvfcyh60v3h44fknydcxv5aa5s8vrtj4tq5cdfrrueshdzujm6aytddd5j4eullazlknq5djuq6spcz596dqjvm8nu"
        )
        
        let verification = try CIP8.verify(signedMessage: SignedMessage(signature: signedMessage))
        
        #expect(verification.verified == true)
        #expect(verification.message == "Pycardano is cool.")
        #expect(verification.signingAddress == signingAddress)
    }

    @Test func testVerifyMessageWithCoseKey() throws {
        let signedMessage = SignedMessage(
            signature: "845846a201276761646472657373583900ddba3ad76313825f4f646f5aa6d323706653bda40ec1ae55582986a463e661768b92deba45b5ada4ab9e7ffd17ed3051b2e03500e0542e9aa166686173686564f452507963617264616e6f20697320636f6f6c2e584040b65c973ba6e123f1e7f738205b10c709fe214a27d21b1c382e6dfa5772aaeeb6222943fd56b1dd6bfa5abfa4a4992d2abde110cbd0c8651fdfa679ba462605",
            key: "a401010327200621582060545b786d3a6f903158e35aae9b86548a99bc47d4b0a6f503ab5e78c1a9bbfc"
        )

        let signingAddress = try Address(from: "addr_test1qrwm5wkhvvfcyh60v3h44fknydcxv5aa5s8vrtj4tq5cdfrrueshdzujm6aytddd5j4eullazlknq5djuq6spcz596dqjvm8nu"
        )
        
        let verification = try CIP8.verify(signedMessage: signedMessage)
        #expect(verification.verified == true)
        #expect(verification.message == "Pycardano is cool.")
        #expect(verification.signingAddress == signingAddress)
    }

    @Test func testVerifyMessageStakeAddress() throws {
        let signedMessage = SignedMessage(
            signature: "84582aa201276761646472657373581de0219f8e3ffefc82395df0bfcfe4e576f8f824bae0c731be35321c01d7a166686173686564f452507963617264616e6f20697320636f6f6c2e58402f2b75301a20876beba03ec68b30c5fbaebc99cb1d038b679340eb2299c2b75cd9c6c884c198e89f690548ee94a87168f5db34acf024d5788e58d119bcba630d",
            key: "a40101032720062158200d8e03b5673bf8dabc567dd6150ebcd56179a91a6c0b245f477033dcab7dc780"
        )
        let signingAddress = try Address(from: "stake_test1uqselr3llm7gyw2a7zlule89wmu0sf96urrnr034xgwqr4csd30df"
        )

        let verification = try CIP8.verify(signedMessage: signedMessage)
        
        #expect(verification.verified == true)
        #expect(verification.message == "Pycardano is cool.")
        #expect(verification.signingAddress == signingAddress)
    }

    @Test func signAndVerify() throws {
        let message = "Pycardano is cool."
        
        let signedMessage = try CIP8.sign(
            message: message,
            signingKey: .signingKey(sk),
            attachCoseKey: false,
            network: .testnet
        )

        let verification = try CIP8.verify(signedMessage: signedMessage)
        #expect(verification.verified == true)
        #expect(verification.message == "Pycardano is cool.")
    }

    @Test func signAndVerifyWithStake() throws {
        let message = "Pycardano is cool."
        let signedMessage = try CIP8.sign(
            message: message,
            signingKey: .signingKey(stakeSK),
            attachCoseKey: false,
            network: .testnet
        )

        let verification = try CIP8.verify(signedMessage: signedMessage)
        #expect(verification.verified == true)
        #expect(verification.message == "Pycardano is cool.")
    }

    @Test func signMessageWithCoseKeyAttached() throws {
        let message = "Pycardano is cool."
        let signedMessage = try CIP8.sign(
            message: message,
            signingKey: .signingKey(sk),
            attachCoseKey: true,
            network: .testnet
        )

        #expect(signedMessage.signature != nil)
        #expect(signedMessage.key != nil)
    }

    @Test func extendedSignAndVerify() throws {
        let message = "Pycardano is cool."

        let signedMessage = try CIP8.sign(
            message: message,
            signingKey: .extendedSigningKey(extendedSK),
            attachCoseKey: false,
            network: .testnet
        )

        let verification = try CIP8.verify(signedMessage: signedMessage)
        #expect(verification.verified == true)
        #expect(verification.message == "Pycardano is cool.")
    }

    @Test func extendedSignAndVerifyWithCoseKey() throws {
        let message = "Pycardano is cool."

        let signedMessage = try CIP8.sign(
            message: message,
            signingKey: .extendedSigningKey(extendedSK),
            attachCoseKey: true,
            network: .testnet
        )

        let verification = try CIP8.verify(signedMessage: signedMessage)
        #expect(verification.verified == true)
        #expect(verification.message == "Pycardano is cool.")
    }
}
