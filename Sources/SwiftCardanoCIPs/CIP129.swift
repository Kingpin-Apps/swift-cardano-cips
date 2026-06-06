import Foundation
import SwiftCardanoCore

/// Errors thrown by ``CIP129`` encode / decode operations.
public enum CIP129Error: Error, Equatable {
    /// The key hash was the wrong length for the credential type (must be 28
    /// bytes — Blake2b-224).
    case invalidKeyHashLength(Int)
    /// The bech32 string failed checksum / character / length validation.
    case malformedBech32(String)
    /// The decoded HRP doesn't match any known CIP-129 / CIP-151 prefix.
    case unknownPrefix(String)
    /// The decoded header byte doesn't match the HRP (e.g. `drep1…` payload
    /// encoded with a `cc_hot` header byte).
    case headerHRPMismatch(String)
    /// The decoded payload was the wrong length after the header byte was
    /// stripped (must be 29 bytes total: 1 header + 28 key-hash).
    case invalidPayloadLength(Int)
}

/// Bech32-prefixed identifiers for Conway-era governance credentials, per
/// [CIP-0129](https://cips.cardano.org/cip/CIP-0129) and the calidus
/// prefix used by [CIP-0151](https://cips.cardano.org/cip/CIP-0151).
///
/// Each ID is `<header byte> || <28-byte Blake2b-224 key hash>` encoded as
/// bech32 under one of the canonical human-readable prefixes:
///
/// | Prefix     | HRP         | Header byte (key / script)         |
/// |------------|-------------|------------------------------------|
/// | `drep`     | `drep`      | `0x22` / `0x23`                    |
/// | `ccCold`   | `cc_cold`   | `0x12` / `0x13`                    |
/// | `ccHot`    | `cc_hot`    | `0x02` / `0x03`                    |
/// | `calidus`  | `calidus`   | `0xa1` (key only; no script form)  |
///
/// The header byte's upper nibble carries the credential type and the
/// lower nibble carries the key/script discriminator (`0x2` = key,
/// `0x3` = script). Calidus does not have a script form in the current
/// CIP-151 draft.
public enum CIP129 {

    /// One of the four CIP-129 / CIP-151 governance bech32 prefixes.
    public enum Prefix: String, Sendable, CaseIterable, Equatable {
        case drep
        case ccCold
        case ccHot
        case calidus

        /// The bech32 human-readable part.
        public var hrp: String {
            switch self {
            case .drep:    return "drep"
            case .ccCold:  return "cc_cold"
            case .ccHot:   return "cc_hot"
            case .calidus: return "calidus"
            }
        }

        /// The CIP-129 header byte for this prefix in either key or script
        /// form.
        ///
        /// - Returns: The 1-byte header, or `nil` if the requested form is
        ///   not defined for this prefix (calidus has no script form).
        public func headerByte(isScript: Bool) -> UInt8? {
            switch (self, isScript) {
            case (.ccHot,   false): return 0x02
            case (.ccHot,   true):  return 0x03
            case (.ccCold,  false): return 0x12
            case (.ccCold,  true):  return 0x13
            case (.drep,    false): return 0x22
            case (.drep,    true):  return 0x23
            case (.calidus, false): return 0xa1
            case (.calidus, true):  return nil
            }
        }

        /// Reverse-lookup: which (Prefix, isScript) pair does this header
        /// byte correspond to, if any?
        static func fromHeaderByte(_ byte: UInt8) -> (Prefix, Bool)? {
            switch byte {
            case 0x02: return (.ccHot,   false)
            case 0x03: return (.ccHot,   true)
            case 0x12: return (.ccCold,  false)
            case 0x13: return (.ccCold,  true)
            case 0x22: return (.drep,    false)
            case 0x23: return (.drep,    true)
            case 0xa1: return (.calidus, false)
            default:   return nil
            }
        }
    }

    // MARK: - Encode

    /// Encode a 28-byte Blake2b-224 key hash as a CIP-129 bech32 ID.
    ///
    /// - Parameters:
    ///   - keyHash: 28 bytes — the Blake2b-224 hash of a verification key
    ///     (or script). Shorter or longer payloads throw
    ///     ``CIP129Error/invalidKeyHashLength(_:)``.
    ///   - prefix: One of the four governance prefixes.
    ///   - isScript: Whether the hash represents a script (encodes the
    ///     script-form header byte). Calidus does not define a script form;
    ///     passing `isScript: true` for `.calidus` throws.
    /// - Returns: A bech32 string, e.g. `drep1…`.
    public static func encode(
        keyHash: Data,
        as prefix: Prefix,
        isScript: Bool = false
    ) throws -> String {
        guard keyHash.count == 28 else {
            throw CIP129Error.invalidKeyHashLength(keyHash.count)
        }
        guard let header = prefix.headerByte(isScript: isScript) else {
            throw CIP129Error.headerHRPMismatch(
                "Prefix \(prefix.hrp) has no \(isScript ? "script" : "key") form"
            )
        }
        var payload = Data()
        payload.append(header)
        payload.append(keyHash)

        guard let encoded = Bech32().encode(hrp: prefix.hrp, witprog: payload) else {
            throw CIP129Error.malformedBech32("Bech32 encoder rejected payload")
        }
        return encoded
    }

    // MARK: - Decode

    /// Decode a CIP-129 bech32 ID into its prefix, key hash, and script
    /// flag.
    ///
    /// - Parameter bech32: A bech32 string with a known CIP-129 / CIP-151
    ///   prefix (`drep1…`, `cc_cold1…`, `cc_hot1…`, or `calidus1…`).
    /// - Returns: A tuple of the matched ``Prefix``, the 28-byte key hash,
    ///   and whether the encoded header byte signalled a script form.
    /// - Throws: ``CIP129Error`` cases for bech32 corruption, unknown
    ///   prefix, header / HRP mismatch, or wrong payload length.
    public static func decode(
        _ bech32: String
    ) throws -> (prefix: Prefix, keyHash: Data, isScript: Bool) {
        let decoder = Bech32()
        let hrp: String
        do {
            hrp = try decoder.bech32Decode(bech32).hrp
        } catch {
            throw CIP129Error.malformedBech32(String(describing: error))
        }

        guard let prefix = Prefix.allCases.first(where: { $0.hrp == hrp }) else {
            throw CIP129Error.unknownPrefix(hrp)
        }

        guard let payload = decoder.decode(addr: bech32) else {
            throw CIP129Error.malformedBech32(
                "Bech32 payload bit-conversion failed for \(bech32)"
            )
        }

        guard payload.count == 29 else {
            throw CIP129Error.invalidPayloadLength(payload.count)
        }

        let header = payload[0]
        guard let (decodedPrefix, isScript) = Prefix.fromHeaderByte(header) else {
            throw CIP129Error.headerHRPMismatch(
                "Unknown header byte 0x\(String(header, radix: 16, uppercase: false)) for HRP \(hrp)"
            )
        }
        guard decodedPrefix == prefix else {
            throw CIP129Error.headerHRPMismatch(
                "Header byte 0x\(String(header, radix: 16)) indicates \(decodedPrefix.hrp) but HRP was \(hrp)"
            )
        }

        let keyHash = payload.subdata(in: 1..<29)
        return (prefix, keyHash, isScript)
    }
}
