import Foundation
import Testing

@testable import SwiftCardanoCIPs

/// `DRepMetadata.toJSON()` must give valid JSON for any string content, and carry
/// `doNotList`. It used to build the document by string interpolation with no escaping
/// and drop `doNotList`.
@Suite struct CIP0119JSONTests {
    static let awkward = "Quote \" backslash \\ slash / newline \n tab \t return \r bell \u{07} nul \u{00} é 中文 🏝️ \u{2028}"

    static func parse(_ json: String) throws -> [String: Any] {
        let object = try JSONSerialization.jsonObject(with: Data(json.utf8))
        return try #require(object as? [String: Any])
    }

    @Test func awkwardStringsProduceValidJSONAndRoundTrip() throws {
        let metadata = DRepMetadata(
            paymentAddress: Self.awkward,
            givenName: Self.awkward,
            image: ImageObject(contentUrl: "https://example.com/a\"b.png", sha256: Self.awkward),
            objectives: Self.awkward,
            motivations: Self.awkward,
            qualifications: Self.awkward,
            references: [Reference(type: "Link", label: Self.awkward, uri: "https://example.com/?q=\"x\"&y=\\")]
        )
        let json = try #require(try metadata.toJSON())
        let object = try Self.parse(json)
        let body = try #require(object["body"] as? [String: Any])
        #expect(body["givenName"] as? String == Self.awkward)
        #expect(body["objectives"] as? String == Self.awkward)
        let image = try #require(body["image"] as? [String: Any])
        #expect(image["contentUrl"] as? String == "https://example.com/a\"b.png")
        let references = try #require(body["references"] as? [[String: Any]])
        #expect(references.first?["uri"] as? String == "https://example.com/?q=\"x\"&y=\\")

        #expect(try DRepMetadata.fromJSON(json) == metadata)
        #expect(try ImageObject.fromJSON(try #require(try metadata.image?.toJSON())) == metadata.image)
        #expect(try Reference.fromJSON(try #require(try metadata.references?.first?.toJSON())) == metadata.references?.first)
    }

    @Test func slashesAndUnicodeAreNotEscaped() throws {
        let metadata = DRepMetadata(
            paymentAddress: nil, givenName: "Zoë 🏝️", image: nil,
            objectives: "https://example.com/x", motivations: nil, qualifications: nil, references: nil
        )
        let json = try #require(try metadata.toJSON())
        #expect(json.contains(#""givenName": "Zoë 🏝️""#))
        #expect(json.contains(#""objectives": "https://example.com/x""#))
    }

    @Test func doNotListRoundTrips() throws {
        let listed = DRepMetadata(
            paymentAddress: nil, givenName: "A", image: nil,
            objectives: nil, motivations: nil, qualifications: nil, references: nil
        )
        var unlisted = listed
        unlisted.doNotList = true

        let unlistedJSON = try #require(try unlisted.toJSON())
        let body = try #require(try Self.parse(unlistedJSON)["body"] as? [String: Any])
        // A JSON boolean, not a string.
        #expect((body["doNotList"] as? NSNumber).map { String(cString: $0.objCType) } == "c")
        #expect(body["doNotList"] as? Bool == true)
        #expect(try DRepMetadata.fromJSON(unlistedJSON).doNotList == true)

        // false is CIP-119's default when the field is absent, so it isn't written.
        let listedJSON = try #require(try listed.toJSON())
        #expect(!listedJSON.contains("doNotList"))
        #expect(try DRepMetadata.fromJSON(listedJSON).doNotList == false)

        #expect(try listed.hash() != unlisted.hash())
        #expect(try unlisted.toDict() == DRepMetadata.fromJSON(unlistedJSON).toDict())
    }

    /// CIP-119's JSON schema types doNotList as the strings "true" / "false".
    @Test func doNotListAsStringDecodes() throws {
        let json = #"{"body": {"givenName": "A", "doNotList": "true"}}"#
        #expect(try DRepMetadata.fromJSON(json).doNotList == true)
        let falseJSON = #"{"body": {"givenName": "A", "doNotList": "false"}}"#
        #expect(try DRepMetadata.fromJSON(falseJSON).doNotList == false)
    }

    /// Unset optional fields are left out. Before, a missing image was written as
    /// `"image": {}`, which `fromJSON` then rejected for having no contentUrl.
    @Test func unsetFieldsAreOmittedAndRoundTrip() throws {
        let metadata = DRepMetadata(
            paymentAddress: nil, givenName: "Only a name", image: nil,
            objectives: nil, motivations: nil, qualifications: nil, references: nil
        )
        let json = try #require(try metadata.toJSON())
        let body = try #require(try Self.parse(json)["body"] as? [String: Any])
        #expect(Set(body.keys) == ["givenName"])
        #expect(try DRepMetadata.fromJSON(json) == metadata)

        var withEmpty = metadata
        withEmpty.references = []
        withEmpty.image = ImageObject(contentUrl: "https://example.com/i.png", sha256: nil)
        let emptyJSON = try #require(try withEmpty.toJSON())
        let emptyBody = try #require(try Self.parse(emptyJSON)["body"] as? [String: Any])
        #expect((emptyBody["references"] as? [Any])?.isEmpty == true)
        #expect((emptyBody["image"] as? [String: Any])?["sha256"] == nil)
        #expect(try DRepMetadata.fromJSON(emptyJSON) == withEmpty)
    }
}
