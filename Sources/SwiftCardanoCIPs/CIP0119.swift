import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import OrderedCollections
import SwiftNaCl
import SwiftCardanoCore

public enum CIP119Error: Error, Equatable, CustomStringConvertible {
    case deserialize(String)

    public var description: String {
        switch self {
        case .deserialize(let msg): return "CIP-119 deserialize error: \(msg)"
        }
    }
}

public struct ImageObject: JSONSerializable {
    public var type: String = "ImageObject"
    public var contentUrl: String
    public var sha256: String?

    enum CodingKeys: String, CodingKey {
        case type = "@type"
        case contentUrl = "contentUrl"
        case sha256 = "sha256"
    }

    public init(contentUrl: String, sha256: String?) {
        self.contentUrl = contentUrl
        self.sha256 = sha256
    }

    /// The image as a JSON object, laid out to sit inside ``DRepMetadata/toJSON()``'s
    /// `body`. Strings are escaped; an unset `sha256` is left out.
    public func toJSON() throws -> String? {
        var fields = [
            "\"@type\": \(try jsonString(type))",
            "\"contentUrl\": \(try jsonString(contentUrl))",
        ]
        if let sha256 {
            fields.append("\"sha256\": \(try jsonString(sha256))")
        }
        return "{\n" + fields.map { "            " + $0 }.joined(separator: ",\n") + "\n        }"
    }

    public func toDict() throws -> Primitive {
        var dict: OrderedDictionary<Primitive, Primitive> = [:]
        dict[.string("@type")] = .string(type)
        dict[.string("contentUrl")] = .string(contentUrl)
        if let sha256 {
            dict[.string("sha256")] = .string(sha256)
        }
        return .orderedDict(dict)
    }

    public static func fromDict(_ primitive: Primitive) throws -> ImageObject {
        let dict = try Self.unwrapDict(primitive, typeName: "ImageObject")
        guard
            let urlPrim = dict[.string("contentUrl")],
            case let .string(contentUrl) = urlPrim
        else {
            throw CIP119Error.deserialize("ImageObject: missing 'contentUrl'")
        }
        var sha256: String? = nil
        if let v = dict[.string("sha256")], case let .string(s) = v, !s.isEmpty {
            sha256 = s
        }
        return ImageObject(contentUrl: contentUrl, sha256: sha256)
    }
}

public struct Reference: JSONSerializable {
    public var type: String
    public var label: String
    public var uri: String

    enum CodingKeys: String, CodingKey {
        case type = "@type"
        case label = "label"
        case uri = "uri"
    }

    public init(type: String, label: String, uri: String) {
        self.type = type
        self.label = label
        self.uri = uri
    }

    /// The reference as a JSON object, laid out to sit inside ``DRepMetadata/toJSON()``'s
    /// `references` array. Strings are escaped.
    public func toJSON() throws -> String? {
        let fields = [
            "\"@type\": \(try jsonString(type))",
            "\"label\": \(try jsonString(label))",
            "\"uri\": \(try jsonString(uri))",
        ]
        return "{\n" + fields.map { "            " + $0 }.joined(separator: ",\n") + "\n          }"
    }

    public func toDict() throws -> Primitive {
        var dict: OrderedDictionary<Primitive, Primitive> = [:]
        dict[.string("@type")] = .string(type)
        dict[.string("label")] = .string(label)
        dict[.string("uri")] = .string(uri)
        return .orderedDict(dict)
    }

    public static func fromDict(_ primitive: Primitive) throws -> Reference {
        let dict = try Self.unwrapDict(primitive, typeName: "Reference")
        guard
            let typeVal = dict[.string("@type")], case let .string(type) = typeVal,
            let labelVal = dict[.string("label")], case let .string(label) = labelVal,
            let uriVal = dict[.string("uri")], case let .string(uri) = uriVal
        else {
            throw CIP119Error.deserialize("Reference: missing one of '@type' / 'label' / 'uri'")
        }
        return Reference(type: type, label: label, uri: uri)
    }
}

public struct DRepMetadata: JSONSerializable {
    public var paymentAddress: String?
    public var givenName: String
    public var image: ImageObject?
    public var objectives: String?
    public var motivations: String?
    public var qualifications: String?
    public var references: [Reference]?
    public var doNotList: Bool = false

    enum CodingKeys: String, CodingKey {
        case paymentAddress = "paymentAddress"
        case givenName = "givenName"
        case image = "image"
        case objectives = "objectives"
        case motivations = "motivations"
        case qualifications = "qualifications"
        case references = "references"
        case doNotList = "doNotList"
    }

    public init(
        paymentAddress: String?,
        givenName: String,
        image: ImageObject?,
        objectives: String?,
        motivations: String?,
        qualifications: String?,
        references: [Reference]?,
        doNotList: Bool = false
    ) {
        self.paymentAddress = paymentAddress
        self.givenName = givenName
        self.image = image
        self.objectives = objectives
        self.motivations = motivations
        self.qualifications = qualifications
        self.references = references
        self.doNotList = doNotList
    }

    /// The CIP-119 JSON-LD document: the CIP-119 `@context`, `hashAlgorithm` and the
    /// `body`. Strings are JSON-escaped; unset optional fields are left out, and
    /// `doNotList` is written only when `true`. A fully filled-in value keeps the
    /// layout of CIP-119's `examples/drep.jsonld`, so ``hash()`` matches that file.
    public func toJSON() throws -> String? {
        let jsonString = """
        {
            "@context": {
                "CIP100": "https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#",
                "CIP119": "https://github.com/cardano-foundation/CIPs/blob/master/CIP-0119/README.md#",
                "hashAlgorithm": "CIP100:hashAlgorithm",
                "body": {
                    "@id": "CIP119:body",
                    "@context": {
                        "references": {
                            "@id": "CIP119:references",
                            "@container": "@set",
                            "@context": {
                                "GovernanceMetadata": "CIP100:GovernanceMetadataReference",
                                "Other": "CIP100:OtherReference",
                                "label": "CIP100:reference-label",
                                "uri": "CIP100:reference-uri"
                            }
                        },
                        "paymentAddress": "CIP119:paymentAddress",
                        "givenName": "CIP119:givenName",
                        "image": {
                            "@id": "CIP119:image",
                            "@context": {
                                "ImageObject": "https://schema.org/ImageObject"
                            }
                        },
                        "objectives": "CIP119:objectives",
                        "motivations": "CIP119:motivations",
                        "qualifications": "CIP119:qualifications"
                    }
                }
            },
            "hashAlgorithm": "blake2b-256",
            "body": {
        \(try bodyFields().joined(separator: ",\n"))
            }
        }

        """
        return jsonString
    }

    /// The `body` members of ``toJSON()``, each already indented, in CIP-119 order.
    ///
    /// Unset optional fields are left out rather than written as `""`, `{}` or `[]`,
    /// so the document only states what the DRep gave. `doNotList` is written only
    /// when `true`: CIP-119 says a missing `doNotList` means `false`, and leaving it
    /// out keeps the bytes (and so the anchor hash) of existing documents unchanged.
    private func bodyFields() throws -> [String] {
        let indent = "        "
        var fields: [String] = []
        if let paymentAddress {
            fields.append("\"paymentAddress\": \(try jsonString(paymentAddress))")
        }
        fields.append("\"givenName\": \(try jsonString(givenName))")
        if let image, let imageJSON = try image.toJSON() {
            fields.append("\"image\": \(imageJSON)")
        }
        if let objectives {
            fields.append("\"objectives\": \(try jsonString(objectives))")
        }
        if let motivations {
            fields.append("\"motivations\": \(try jsonString(motivations))")
        }
        if let qualifications {
            fields.append("\"qualifications\": \(try jsonString(qualifications))")
        }
        if let references {
            if references.isEmpty {
                fields.append("\"references\": []")
            } else {
                let items = try references.compactMap { try $0.toJSON() }
                fields.append("\"references\": [\n          " + items.joined(separator: ",\n          ") + "\n        ]")
            }
        }
        if doNotList {
            fields.append("\"doNotList\": true")
        }
        return fields.map { indent + $0 }
    }

    public func toDict() throws -> Primitive {
        var body: OrderedDictionary<Primitive, Primitive> = [:]
        if let paymentAddress {
            body[.string("paymentAddress")] = .string(paymentAddress)
        }
        body[.string("givenName")] = .string(givenName)
        if let image = image {
            body[.string("image")] = try image.toDict()
        }
        if let objectives {
            body[.string("objectives")] = .string(objectives)
        }
        if let motivations {
            body[.string("motivations")] = .string(motivations)
        }
        if let qualifications {
            body[.string("qualifications")] = .string(qualifications)
        }
        if let references = references {
            body[.string("references")] = .list(try references.map { try $0.toDict() })
        }
        if doNotList {
            body[.string("doNotList")] = .bool(true)
        }

        var top: OrderedDictionary<Primitive, Primitive> = [:]
        top[.string("body")] = .orderedDict(body)
        return .orderedDict(top)
    }

    public static func fromDict(_ primitive: Primitive) throws -> DRepMetadata {
        let top = try Self.unwrapDict(primitive, typeName: "DRepMetadata")
        guard
            let bodyVal = top[.string("body")],
            case let .orderedDict(body) = bodyVal
        else {
            throw CIP119Error.deserialize("DRepMetadata: missing 'body'")
        }

        func optionalString(_ key: String) -> String? {
            if let v = body[.string(key)], case let .string(s) = v, !s.isEmpty { return s }
            return nil
        }

        let paymentAddress = optionalString("paymentAddress")
        guard let givenName = optionalString("givenName") else {
            throw CIP119Error.deserialize("DRepMetadata: missing 'givenName'")
        }

        var image: ImageObject? = nil
        if let imageVal = body[.string("image")] {
            if case .orderedDict = imageVal {
                image = try ImageObject.fromDict(imageVal)
            }
        }

        let objectives = optionalString("objectives")
        let motivations = optionalString("motivations")
        let qualifications = optionalString("qualifications")

        var references: [Reference]? = nil
        if let refsVal = body[.string("references")], case let .list(refs) = refsVal {
            references = try refs.map { try Reference.fromDict($0) }
        }

        var doNotList = false
        // CIP-119's README makes doNotList a boolean; its JSON schema has the strings
        // "true" / "false". Read both.
        switch body[.string("doNotList")] {
        case .bool(let b)?:
            doNotList = b
        case .string(let s)?:
            doNotList = s == "true"
        default:
            break
        }

        return DRepMetadata(
            paymentAddress: paymentAddress,
            givenName: givenName,
            image: image,
            objectives: objectives,
            motivations: motivations,
            qualifications: qualifications,
            references: references,
            doNotList: doNotList
        )
    }

    public func hash() throws -> String {
        guard let json = try toJSON() else {
            throw CIP119Error.deserialize("DRepMetadata: could not build the JSON document")
        }
        let jsonData = Data(json.utf8)

        let hash = try SwiftNaCl.Hash().blake2b(
            data: jsonData,
            digestSize: DREP_METADATA_HASH_SIZE,
            encoder: RawEncoder.self
        )

        return hash.toHex
    }
}

// MARK: - Internal helpers

/// `value` as a quoted, escaped JSON string. Quotes, backslashes and control
/// characters are escaped; `/` and non-ASCII text are written as they are, so URLs
/// and names read the same as in hand-written CIP-119 documents.
private func jsonString(_ value: String) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    let data = try encoder.encode(value)
    return String(decoding: data, as: UTF8.self)
}

private extension JSONSerializable {
    static func unwrapDict(_ primitive: Primitive, typeName: String) throws
    -> OrderedDictionary<Primitive, Primitive>
    {
        switch primitive {
        case .orderedDict(let d): return d
        case .indefiniteDictionary(let d): return d
        default:
            throw CIP119Error.deserialize("\(typeName): expected dictionary primitive, got \(primitive)")
        }
    }
}

// MARK: - Bounded JSON parsing

/// Runs core's `fromJSON` only after the nesting depth is checked on the raw
/// bytes. DRep metadata comes from third parties, and Apple's JSONSerialization
/// can overflow a 512 KiB cooperative-thread stack on deeply nested input before
/// its own limit applies.
private func boundedFromJSON<T: JSONSerializable>(_ type: T.Type, _ json: String) throws -> T {
    do {
        try CIP100.checkRawNestingDepth(Data(json.utf8))
    } catch {
        throw CIP119Error.deserialize("\(T.self): \(error)")
    }
    return try T.fromJSON(json)
}

extension DRepMetadata {
    /// Parses DRep metadata JSON, refusing input nested deeper than
    /// 64 levels before the recursive parser runs.
    public static func fromJSON(_ json: String) throws -> DRepMetadata {
        try boundedFromJSON(DRepMetadata.self, json)
    }
}

extension ImageObject {
    /// Parses image JSON with the same depth bound as ``DRepMetadata/fromJSON(_:)``.
    public static func fromJSON(_ json: String) throws -> ImageObject {
        try boundedFromJSON(ImageObject.self, json)
    }
}

extension Reference {
    /// Parses reference JSON with the same depth bound as ``DRepMetadata/fromJSON(_:)``.
    public static func fromJSON(_ json: String) throws -> Reference {
        try boundedFromJSON(Reference.self, json)
    }
}
