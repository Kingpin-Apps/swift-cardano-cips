import CryptoKit
import SwiftCardanoCore
import SwiftNcal
import Foundation

/// Size of the asset hash
let ASSET_HASH_SIZE = 20

/// Type for policy IDs
public enum PolicyIdType {
    case policyId(PolicyID)
    case data(Data)
    case hexString(String)
}

/// Type for asset names
public enum AssetNameType {
    case assetName(AssetName)
    case data(Data)
    case hexString(String)
}

/// Errors that can occur during CIP14 operations
public enum CIP14Error: Error {
    case invalidHexString(String)
    case invalidInput(String)
}

public struct CIP14 {
    /// Implementation of CIP14 asset fingerprinting
    ///
    /// This function encodes the asset policy and name into an asset fingerprint, which is
    /// bech32 compliant.
    ///
    /// For more information:
    /// https://developers.cardano.org/docs/governance/cardano-improvement-proposals/cip-0014/
    ///
    /// - Parameters:
    ///   - policyId: The asset policy as Data or a hex String or a ``PolicyId``
    ///   - assetName: The asset name as Data or a hex String or a ``AssetName``
    /// - Returns: A bech32 encoded asset fingerprint
    /// - Throws: Error if the input conversion fails
    public static func encodeAsset(policyId: PolicyIdType, assetName: AssetNameType) throws -> String? {
        // Convert policyId to Data
        let policyIdData: Data
        switch policyId {
            case .policyId(let policyId):
                policyIdData = policyId.payload
            case .data(let data):
                policyIdData = data
            case .hexString(let hexString):
                policyIdData = Data(hex: hexString)
        }
        
        // Convert assetName to Data
        let assetNameData: Data
        switch assetName {
            case .assetName(let assetName):
                assetNameData = assetName.payload
            case .data(let data):
                assetNameData = data
            case .hexString(let hexString):
                assetNameData = Data(hex: hexString)
        }
        
        // Calculate BLAKE2b hash
        let asset_hash = try SwiftNcal.Hash().blake2b(
            data: policyIdData + assetNameData,
            digestSize: ASSET_HASH_SIZE,
            encoder: RawEncoder.self
        )
        
        // Encode using bech32
        return Bech32().encode(hrp: "asset", witprog: asset_hash)
    }
}
