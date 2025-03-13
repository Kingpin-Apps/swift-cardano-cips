import Testing
import Foundation
import PotentCBOR
import SwiftCardanoCore
@testable import SwiftCardanoCIPs



func normalizeJSON(_ jsonString: String) -> String? {
    guard let data = jsonString.data(using: .utf8),
          let jsonObject = try? JSONSerialization.jsonObject(with: data, options: []),
          let normalizedData = try? JSONSerialization.data(withJSONObject: jsonObject, options: [.sortedKeys, .prettyPrinted]),
          let normalizedString = String(data: normalizedData, encoding: .utf8) else {
        return nil
    }
    return normalizedString
}

@Suite struct DRepMetadataTests {
    // Sample data for testing DRepMetadata
    let sampleImage = ImageObject(contentUrl: "https://avatars.githubusercontent.com/u/44342099?v=4", sha256: "2a21e4f7b20c8c72f573707b068fb8fc6d8c64d5035c4e18ecae287947fe2b2e")
    let sampleReferences = [
        Reference(type: "Other", label: "A cool island for Ryan", uri: "https://www.google.com/maps/place/World's+only+5th+order+recursive+island/@62.6511465,-97.7946829,15.75z/data=!4m14!1m7!3m6!1s0x5216a167810cee39:0x11431abdfe4c7421!2sWorld's+only+5th+order+recursive+island!8m2!3d62.651114!4d-97.7872244!16s%2Fg%2F11spwk2b6n!3m5!1s0x5216a167810cee39:0x11431abdfe4c7421!8m2!3d62.651114!4d-97.7872244!16s%2Fg%2F11spwk2b6n?authuser=0&entry=ttu"),
        Reference(type: "Link", label: "Ryan's Twitter", uri: "https://twitter.com/Ryun1_"),
    ]

    let validDRepMetadata = DRepMetadata(
        paymentAddress: "addr1q86dnpkva4mm859c8ur7tjxn57zgsu6vg8pdetkdve3fsacnq7twy06u2ev5759vutpjgzfryx0ud8hzedhzerava35qwh3x34",
        givenName: "Ryan Williams",
        image: ImageObject(contentUrl: "https://avatars.githubusercontent.com/u/44342099?v=4", sha256: "2a21e4f7b20c8c72f573707b068fb8fc6d8c64d5035c4e18ecae287947fe2b2e"),
        objectives: "Buy myself an island.",
        motivations: "I really would like to own an island.",
        qualifications: "I have my 100m swimming badge, so I would be qualified to be able to swim around island.",
        references: [
            Reference(type: "Other", label: "A cool island for Ryan", uri: "https://www.google.com/maps/place/World's+only+5th+order+recursive+island/@62.6511465,-97.7946829,15.75z/data=!4m14!1m7!3m6!1s0x5216a167810cee39:0x11431abdfe4c7421!2sWorld's+only+5th+order+recursive+island!8m2!3d62.651114!4d-97.7872244!16s%2Fg%2F11spwk2b6n!3m5!1s0x5216a167810cee39:0x11431abdfe4c7421!8m2!3d62.651114!4d-97.7872244!16s%2Fg%2F11spwk2b6n?authuser=0&entry=ttu"),
            Reference(type: "Link", label: "Ryan's Twitter", uri: "https://twitter.com/Ryun1_"),
        ]
    )
    
    @Test func testInitialization() async throws {
        let drepMetadata = validDRepMetadata
        
        #expect(drepMetadata != nil)
    }
            

    @Test("Test JSON Encoding of DRepMetadata")
    func testEncoding() async throws {
        let json = try validDRepMetadata.toJSON()!
        let drepMetadataFromJSON = try DRepMetadata.fromJSON(json)
        
        let filePath = try getFilePath(
            forResource: drepMetadataFilePath.forResource,
            ofType: drepMetadataFilePath.ofType,
            inDirectory: drepMetadataFilePath.inDirectory
        )
        
        let expectedJSON = try String(contentsOfFile: filePath!)
        let expectedDRepMetadataHash = drepMetadataHash!
        let expectedDRepMetadata = drepMetadata
        
        let hash = try drepMetadataFromJSON.hash()

        #expect(json == expectedJSON)
        #expect(validDRepMetadata == expectedDRepMetadata)
        #expect(hash == expectedDRepMetadataHash)
    }

    @Test("Test JSON Decoding of DRepMetadata")
    func testDecoding() async throws {
        let json = try validDRepMetadata.toJSON()!
        let jsonData = json.data(using: .utf8)!
        let decodedDict = try JSONSerialization.jsonObject(with: jsonData, options: []) as! [String: Any]
        let decodedDRep = try DRepMetadata.fromDict(decodedDict)

        #expect(decodedDRep.givenName == validDRepMetadata.givenName, "Decoded givenName should match the original")
        #expect(decodedDRep.paymentAddress == validDRepMetadata.paymentAddress, "Decoded paymentAddress should match the original")
        #expect(decodedDRep.image?.contentUrl == sampleImage.contentUrl, "Decoded image URL should match the original")
        #expect(decodedDRep.references?.count == validDRepMetadata.references?.count, "Decoded references should match the original")
    }

    @Test("Test DRepMetadata Hashing")
    func testHashing() async throws {
        let hash = try validDRepMetadata.hash()
        #expect(hash.count > 0, "Generated hash should not be empty")
    }
}
