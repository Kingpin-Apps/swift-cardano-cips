import Testing
import Foundation
import SwiftCardanoCore
@testable import SwiftCardanoCIPs

struct AssetTestCase {
    let policyId: String
    let assetName: String
    let assetFingerprint: String
}

let testCases: [AssetTestCase] = [
    AssetTestCase(
        policyId: "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
        assetName: "",
        assetFingerprint: "asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3"
    ),
    AssetTestCase(
        policyId: "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc37e",
        assetName: "",
        assetFingerprint: "asset1nl0puwxmhas8fawxp8nx4e2q3wekg969n2auw3"
    ),
    AssetTestCase(
        policyId: "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
        assetName: "",
        assetFingerprint: "asset1uyuxku60yqe57nusqzjx38aan3f2wq6s93f6ea"
    ),
    AssetTestCase(
        policyId: "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
        assetName: "504154415445",
        assetFingerprint: "asset13n25uv0yaf5kus35fm2k86cqy60z58d9xmde92"
    ),
    AssetTestCase(
        policyId: "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
        assetName: "504154415445",
        assetFingerprint: "asset1hv4p5tv2a837mzqrst04d0dcptdjmluqvdx9k3"
    ),
    AssetTestCase(
        policyId: "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
        assetName: "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
        assetFingerprint: "asset1aqrdypg669jgazruv5ah07nuyqe0wxjhe2el6f"
    ),
    AssetTestCase(
        policyId: "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
        assetName: "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
        assetFingerprint: "asset17jd78wukhtrnmjh3fngzasxm8rck0l2r4hhyyt"
    ),
    AssetTestCase(
        policyId: "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
        assetName: "0000000000000000000000000000000000000000000000000000000000000000",
        assetFingerprint: "asset1pkpwyknlvul7az0xx8czhl60pyel45rpje4z8w"
    ),
]

@Suite("CIP14 Tests")
struct CIP14Tests {
    // Test cases from the original Python tests

    @Test("Test encoding assets with hex strings", arguments: testCases)
    func testEncodeAssetWithHexStrings(_ testCase: AssetTestCase) async throws {
        let fingerprint = try CIP14.encodeAsset(
            policyId: .hexString(testCase.policyId),
            assetName: .hexString(testCase.assetName)
        )
        #expect(fingerprint == testCase.assetFingerprint)
    }

    @Test("Test encoding assets with Data objects", arguments: testCases)
    func testEncodeAssetWithData(_ testCase: AssetTestCase) async throws {
        let policyIdData = Data(hex: testCase.policyId)
        let assetNameData = Data(hex: testCase.assetName)

        let fingerprint = try CIP14.encodeAsset(
            policyId: .data(policyIdData),
            assetName: .data(assetNameData)
        )
        #expect(fingerprint == testCase.assetFingerprint)
    }

    @Test("Test encoding assets with PolicyID and AssetName objects", arguments: testCases)
    func testEncodeAssetWithPolicyIDAndAssetName(_ testCase: AssetTestCase) async throws {
        let policyIdData = Data(hex: testCase.policyId)
        let assetNameData = Data(hex: testCase.assetName)

        let policyId = PolicyID(payload: policyIdData)
        let assetName = try AssetName(payload: assetNameData)

        let fingerprint = try CIP14.encodeAsset(
            policyId: .policyId(policyId),
            assetName: .assetName(assetName)
        )
        #expect(fingerprint == testCase.assetFingerprint)
    }
}
