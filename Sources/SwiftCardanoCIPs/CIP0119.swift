import Foundation
import CryptoKit
import OrderedCollections
import PotentCBOR
import SwiftNcal
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

    public func toJSON() throws -> String? {
        let jsonString = """
        {
                    "@type": "\(type)",
                    "contentUrl": "\(contentUrl)",
                    "sha256": "\(sha256 ?? "")"
                }
        """
        return jsonString
    }

    public func toDict() throws -> Primitive {
        var dict: OrderedDictionary<Primitive, Primitive> = [:]
        dict[.string("@type")] = .string(type)
        dict[.string("contentUrl")] = .string(contentUrl)
        dict[.string("sha256")] = .string(sha256 ?? "")
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

    public func toJSON() throws -> String? {
        let jsonString = """
        {
                    "@type": "\(type)",
                    "label": "\(label)",
                    "uri": "\(uri)"
                  }
        """
        return jsonString
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
                "paymentAddress": "\(paymentAddress ?? "")",
                "givenName": "\(givenName)",
                "image": \(try image?.toJSON() ?? "{}"),
                "objectives": "\(objectives ?? "")",
                "motivations": "\(motivations ?? "")",
                "qualifications": "\(qualifications ?? "")",
                "references": [
                  \(try references?.compactMap { try $0.toJSON() }.joined(separator: ",\n          ") ?? "")
                ]
            }
        }

        """
        return jsonString
    }

    public func toDict() throws -> Primitive {
        var body: OrderedDictionary<Primitive, Primitive> = [:]
        body[.string("paymentAddress")] = .string(paymentAddress ?? "")
        body[.string("givenName")] = .string(givenName)
        if let image = image {
            body[.string("image")] = try image.toDict()
        }
        body[.string("objectives")] = .string(objectives ?? "")
        body[.string("motivations")] = .string(motivations ?? "")
        body[.string("qualifications")] = .string(qualifications ?? "")
        if let references = references {
            body[.string("references")] = .list(try references.map { try $0.toDict() })
        } else {
            body[.string("references")] = .list([])
        }
        body[.string("doNotList")] = .bool(doNotList)

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
        if let dnlVal = body[.string("doNotList")], case let .bool(b) = dnlVal {
            doNotList = b
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
        let json = try toJSON()!
        let jsonData = json.data(using: .utf8)!

        let hash = try SwiftNcal.Hash().blake2b(
            data: jsonData,
            digestSize: DREP_METADATA_HASH_SIZE,
            encoder: RawEncoder.self
        )

        return hash.toHex
    }
}

// MARK: - Internal helpers

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
