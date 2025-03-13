import Foundation
import Testing
@testable import SwiftCardanoCIPs

let drepMetadataFilePath = (
    forResource: "drep",
    ofType: "jsonld",
    inDirectory: "data"
)
let drepMetadataHashFilePath = (
    forResource: "drepMetadataHash",
    ofType: "txt",
    inDirectory: "data"
)

func getFilePath(forResource: String, ofType: String, inDirectory: String) throws -> String? {
    guard let filePath = Bundle.module.path(
        forResource: forResource,
        ofType: ofType,
        inDirectory: inDirectory) else {
        Issue.record("File not found: \(forResource).\(ofType)")
        try #require(Bool(false))
        return nil
    }
    return filePath
}

var drepMetadata: DRepMetadata? {
    do {
        let filePath = try getFilePath(
            forResource: drepMetadataFilePath.forResource,
            ofType: drepMetadataFilePath.ofType,
            inDirectory: drepMetadataFilePath.inDirectory
        )
        return try DRepMetadata.load(from: filePath!)
    } catch {
        return nil
    }
}

var drepMetadataHash: String? {
    do {
        let filePath = try getFilePath(
            forResource: drepMetadataHashFilePath.forResource,
            ofType: drepMetadataHashFilePath.ofType,
            inDirectory: drepMetadataHashFilePath.inDirectory
        )
        return try String(contentsOfFile: filePath!).trimmingCharacters(in: .newlines)
    } catch {
        return nil
    }
}
