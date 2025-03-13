import Foundation
import CryptoKit
import PotentCBOR
import OrderedCollections
import SwiftNcal
import SwiftCardanoCore

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

    public static func fromDict(_ dict: Dictionary<AnyHashable, Any>) throws -> ImageObject {
        let contentUrl = dict["contentUrl"] as! String
        let sha256 = dict["sha256"] as? String
        
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

    public static func fromDict(_ dict: Dictionary<AnyHashable, Any>) throws -> Reference {
        let type = dict["@type"] as? String
        let label = dict["label"] as? String
        let uri = dict["uri"] as? String
        
        return Reference(type: type!, label: label!, uri: uri!)
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

    public static func fromDict(_ dict: Dictionary<AnyHashable, Any>) throws -> DRepMetadata {
        let body = dict["body"] as! [AnyHashable: Any]
        
        let paymentAddress = body["paymentAddress"] as? String
        let givenName = body["givenName"] as! String
        let image = try ImageObject.fromDict(body["image"] as! [AnyHashable: Any])
        let objectives = body["objectives"] as? String
        let motivations = body["motivations"] as? String
        let qualifications = body["qualifications"] as? String
        let references = try (body["references"] as! [[AnyHashable: Any]]).map { try Reference.fromDict($0) }
        let doNotList = body["doNotList"] as? Bool
        
        return DRepMetadata(
            paymentAddress: paymentAddress,
            givenName: givenName,
            image: image,
            objectives: objectives,
            motivations: motivations,
            qualifications: qualifications,
            references: references,
            doNotList: doNotList ?? false
        )
    }
    
    public func hash() throws -> String {
        let json = try toJSON()!
        let jsonData = json.data(using: .utf8)!
        
        let hash =  try SwiftNcal.Hash().blake2b(
            data: jsonData,
            digestSize: DREP_METADATA_HASH_SIZE,
            encoder: RawEncoder.self
        )
        
        return hash.toHex
    }
}
