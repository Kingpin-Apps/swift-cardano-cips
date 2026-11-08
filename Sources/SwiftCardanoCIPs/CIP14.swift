#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import SwiftCardanoCore
import SwiftNaCl
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
    ///   - policyId: The asset policy as `Data`, a hex `String`, or a `SwiftCardanoCore.PolicyID`.
    ///   - assetName: The asset name as `Data`, a hex `String`, or a `SwiftCardanoCore.AssetName`.
    /// - Returns: A bech32 encoded asset fingerprint
    /// - Throws: ``CIP14Error/invalidHexString(_:)`` for a hex string that is not an even
    ///   number of hex digits, and ``CIP14Error/invalidInput(_:)`` when the policy id is
    ///   not 28 bytes or the asset name is longer than 32 bytes.
    public static func encodeAsset(policyId: PolicyIdType, assetName: AssetNameType) throws -> String? {
        // Convert policyId to Data
        let policyIdData: Data
        switch policyId {
            case .policyId(let policyId):
                policyIdData = policyId.payload
            case .data(let data):
                policyIdData = data
            case .hexString(let hexString):
                policyIdData = try strictHex(hexString)
        }
        
        // Convert assetName to Data
        let assetNameData: Data
        switch assetName {
            case .assetName(let assetName):
                assetNameData = assetName.payload
            case .data(let data):
                assetNameData = data
            case .hexString(let hexString):
                assetNameData = try strictHex(hexString)
        }
        
        // A fixed 28-byte policy id keeps policy || name unambiguous.
        guard policyIdData.count == 28 else {
            throw CIP14Error.invalidInput("A policy id is 28 bytes, not \(policyIdData.count)")
        }
        guard assetNameData.count <= 32 else {
            throw CIP14Error.invalidInput("An asset name is at most 32 bytes, not \(assetNameData.count)")
        }

        // Calculate BLAKE2b hash
        let asset_hash = try SwiftNaCl.Hash().blake2b(
            data: policyIdData + assetNameData,
            digestSize: ASSET_HASH_SIZE,
            encoder: RawEncoder.self
        )
        
        // Encode using bech32
        return Bech32().encode(hrp: "asset", witprog: asset_hash)
    }

    /// Decode hex strictly: an even number of `[0-9a-fA-F]` digits, no prefix.
    static func strictHex(_ string: String) throws -> Data {
        let digits = Array(string.utf8)
        guard digits.count.isMultiple(of: 2) else { throw CIP14Error.invalidHexString(string) }
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case 48...57: return c - 48
            case 65...70: return c - 55
            case 97...102: return c - 87
            default: return nil
            }
        }
        var data = Data(capacity: digits.count / 2)
        var index = 0
        while index < digits.count {
            guard let high = nibble(digits[index]), let low = nibble(digits[index + 1]) else {
                throw CIP14Error.invalidHexString(string)
            }
            data.append(high << 4 | low)
            index += 2
        }
        return data
    }
}
