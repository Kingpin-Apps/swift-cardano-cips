import Foundation
import JSONLD
import SwiftCardanoCore
import SwiftNaCl

/// Errors thrown by ``CIP100`` sign / verify.
public enum CIP100Error: Error, Equatable {
    /// The supplied document bytes were not valid JSON.
    case invalidJSON(String)
    /// The top-level JSON value was not an object.
    case notAnObject
    /// The signing key produced a verification key of the wrong length.
    case invalidVerificationKey(Int)
    /// The supplied document was missing a required field.
    case missingField(String)
    /// A witness signature had the wrong length (must be 64-byte Ed25519).
    case invalidSignatureLength(Int)
    /// A witness public key had the wrong length (must be 32-byte Ed25519).
    case invalidPublicKeyLength(Int)
    /// An unsupported `witnessAlgorithm` value was encountered.
    case unsupportedWitnessAlgorithm(String)
    /// The hex-encoded witness key or signature could not be decoded.
    case malformedHex(String)
    /// JSON-LD canonicalization failed.
    case canonicalizationFailed(String)
    /// Re-serializing the modified document to JSON failed.
    case serializationFailed(String)
}

/// CIP-100 governance-metadata sign + verify, built on top of swift-jsonld's
/// RDFC-1.0 / URDNA2015 canonicalization and the Ed25519 primitives in
/// swift-cardano-core / SwiftNaCl.
///
/// See [CIP-0100](https://cips.cardano.org/cip/CIP-0100) for the wire
/// format. Adjacent CIPs CIP-0108 (governance actions) and CIP-0119
/// (dRep metadata) reuse this signing scheme — the same code path
/// handles all three because they share the `body` + `authors[].witness`
/// shape.
///
/// ### Signing algorithm
///
/// 1. Strip the document's `authors` field (signing happens before
///    witnesses are attached, so previously-attached signatures don't
///    contribute to the canonical form).
/// 2. Canonicalize the resulting document with RDFC-1.0 / URDNA2015 via
///    `JSONLD.canonize(_:options:)`.
/// 3. Take the UTF-8 bytes of the canonical N-Quads (already terminated
///    by a trailing newline per the canonical N-Quads serialization).
/// 4. Hash with Blake2b-256.
/// 5. Sign the 32-byte hash with the author's Ed25519 signing key.
///
/// Verification re-canonicalizes the same way and checks each author's
/// witness signature in parallel.
public enum CIP100 {

    /// The single witness algorithm CIP-100 defines.
    public static let witnessAlgorithmEd25519 = "ed25519"

    // MARK: - Models

    /// A single author's signature attachment, mirroring the JSON-LD shape:
    /// `{witnessAlgorithm, publicKey, signature}`.
    public struct Witness: Sendable, Equatable {
        public let witnessAlgorithm: String
        public let publicKey: Data
        public let signature: Data

        public init(witnessAlgorithm: String, publicKey: Data, signature: Data) {
            self.witnessAlgorithm = witnessAlgorithm
            self.publicKey = publicKey
            self.signature = signature
        }
    }

    /// An author entry. `name` is optional; `witness` is required for
    /// any author that has signed.
    public struct Author: Sendable, Equatable {
        public let name: String?
        public let witness: Witness

        public init(name: String?, witness: Witness) {
            self.name = name
            self.witness = witness
        }
    }

    /// The result of verifying every author signature in a document.
    public struct VerificationResult: Sendable, Equatable {
        /// Conjunction of every author result. `false` if at least one
        /// witness failed to verify, or if there are no authors.
        public let allValid: Bool
        /// Per-author result, in document order.
        public let authorResults: [AuthorResult]
        /// The Blake2b-256 hash of the canonicalized body — the same
        /// payload every witness was expected to sign over.
        public let canonicalBodyHash: Data

        public struct AuthorResult: Sendable, Equatable {
            public let name: String?
            public let publicKey: Data
            public let valid: Bool
        }
    }

    // MARK: - Sign

    /// Sign a CIP-100 governance-metadata document and append the
    /// signer's author entry to the `authors` array.
    ///
    /// - Parameters:
    ///   - document: JSON-LD document bytes (UTF-8 JSON). If the document
    ///     has no `authors` field, one is created.
    ///   - signingKey: The author's Ed25519 signing key (regular or
    ///     extended). Must produce a 32-byte verification key.
    ///   - authorName: Optional display name to attach to the author
    ///     entry.
    /// - Returns: The document bytes with the new author entry appended.
    ///   Output is UTF-8 JSON.
    public static func signMetadata(
        document: Data,
        signingKey: SigningKeyType,
        authorName: String? = nil
    ) async throws -> Data {
        // 1. Parse the document.
        var rootObject = try parseAsObject(document)

        // 2. Compute the signing payload.
        let hash = try await canonicalBodyHash(of: rootObject)

        // 3. Sign with Ed25519.
        let signature: Data
        do {
            signature = try signingKey.sign(data: hash)
        } catch {
            throw CIP100Error.canonicalizationFailed("signing failed: \(error)")
        }

        // 4. Recover the verification key (chain code stripped for
        //    extended keys).
        let vk: Data
        do {
            let vkType = try signingKey.toVerificationKeyType()
            switch vkType {
            case .verificationKey(let k):
                vk = k.payload
            case .extendedVerificationKey(let k):
                vk = k.payload.prefix(32)
            }
        } catch {
            throw CIP100Error.invalidVerificationKey(0)
        }
        guard vk.count == 32 else {
            throw CIP100Error.invalidVerificationKey(vk.count)
        }

        // 5. Build the new author entry.
        let witnessObject: [String: Any] = [
            "witnessAlgorithm": witnessAlgorithmEd25519,
            "publicKey": hexString(vk),
            "signature": hexString(signature),
        ]
        var authorEntry: [String: Any] = ["witness": witnessObject]
        if let name = authorName {
            authorEntry["name"] = name
        }

        // 6. Append to the authors array.
        var authors = (rootObject["authors"] as? [Any]) ?? []
        authors.append(authorEntry)
        rootObject["authors"] = authors

        return try serialize(rootObject)
    }

    // MARK: - Verify

    /// Verify every author signature in a CIP-100 governance-metadata
    /// document.
    ///
    /// - Parameter document: JSON-LD document bytes (UTF-8 JSON) including
    ///   the `authors` array with attached witnesses.
    /// - Returns: A ``VerificationResult`` reporting which witnesses
    ///   verified successfully against the document's canonical body
    ///   hash. `allValid` is `false` if there are no authors.
    public static func verifyMetadata(
        _ document: Data
    ) async throws -> VerificationResult {
        let rootObject = try parseAsObject(document)

        let hash = try await canonicalBodyHash(of: rootObject)

        let authors = (rootObject["authors"] as? [Any]) ?? []
        var results: [VerificationResult.AuthorResult] = []
        for raw in authors {
            guard let entry = raw as? [String: Any] else { continue }
            let name = entry["name"] as? String
            guard let witnessObject = entry["witness"] as? [String: Any],
                  let alg = witnessObject["witnessAlgorithm"] as? String,
                  let pubHex = witnessObject["publicKey"] as? String,
                  let sigHex = witnessObject["signature"] as? String else {
                continue
            }
            guard alg == witnessAlgorithmEd25519 else {
                throw CIP100Error.unsupportedWitnessAlgorithm(alg)
            }

            guard let pubKey = Data(hexLowercase: pubHex) else {
                throw CIP100Error.malformedHex(pubHex)
            }
            guard pubKey.count == 32 else {
                throw CIP100Error.invalidPublicKeyLength(pubKey.count)
            }
            guard let signature = Data(hexLowercase: sigHex) else {
                throw CIP100Error.malformedHex(sigHex)
            }
            guard signature.count == 64 else {
                throw CIP100Error.invalidSignatureLength(signature.count)
            }

            let verifyKey: VerifyKey
            do {
                verifyKey = try VerifyKey(key: pubKey)
            } catch {
                results.append(.init(name: name, publicKey: pubKey, valid: false))
                continue
            }

            let valid: Bool
            do {
                _ = try verifyKey.verify(smessage: hash, signature: signature)
                valid = true
            } catch {
                valid = false
            }
            results.append(.init(name: name, publicKey: pubKey, valid: valid))
        }

        let allValid = !results.isEmpty && results.allSatisfy { $0.valid }
        return VerificationResult(
            allValid: allValid,
            authorResults: results,
            canonicalBodyHash: hash
        )
    }

    // MARK: - Canonical body hash (exposed)

    /// Compute the Blake2b-256 of the canonical N-Quads form of the
    /// document with `authors` stripped — i.e. the payload every CIP-100
    /// author witness signs.
    ///
    /// Exposed so callers can pre-compute the hash (e.g. for an external
    /// HSM-backed signer) without going through ``signMetadata(document:signingKey:authorName:)``.
    public static func canonicalBodyHash(of document: Data) async throws -> Data {
        let rootObject = try parseAsObject(document)
        return try await canonicalBodyHash(of: rootObject)
    }

    private static func canonicalBodyHash(of rootObject: [String: Any]) async throws -> Data {
        // Strip authors before canonicalizing.
        var stripped = rootObject
        stripped.removeValue(forKey: "authors")

        // Bridge into the JSONLD.JSON type and canonicalize.
        let jsonValue = JSONLD.JSON.fromFoundation(stripped)
        let canonical: String
        do {
            canonical = try await JSONLD.canonize(jsonValue)
        } catch {
            throw CIP100Error.canonicalizationFailed(String(describing: error))
        }

        // The canonical N-Quads serialization terminates each line with
        // "\n"; the spec calls for a trailing newline. JSONLD.canonize
        // already returns a newline-terminated string.
        let bytes = Data(canonical.utf8)
        do {
            return try SwiftNaCl.Hash().blake2b(
                data: bytes,
                digestSize: 32,
                encoder: RawEncoder.self
            )
        } catch {
            throw CIP100Error.canonicalizationFailed("blake2b-256 failed: \(error)")
        }
    }

    // MARK: - JSON helpers

    private static func parseAsObject(_ data: Data) throws -> [String: Any] {
        let parsed: Any
        do {
            parsed = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            throw CIP100Error.invalidJSON(String(describing: error))
        }
        guard let dict = parsed as? [String: Any] else {
            throw CIP100Error.notAnObject
        }
        return dict
    }

    private static func serialize(_ object: [String: Any]) throws -> Data {
        do {
            // `.sortedKeys` keeps output reproducible for downstream
            // hashing / diff workflows, even though CIP-100's signing
            // hash is over the *canonicalized* N-Quads, not the raw
            // JSON bytes — so key order in the serialized output doesn't
            // affect signature validity either way.
            return try JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys]
            )
        } catch {
            throw CIP100Error.serializationFailed(String(describing: error))
        }
    }

    private static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - JSON ↔ Foundation bridge

private extension JSONLD.JSON {
    /// Convert a Foundation-typed JSON value (`[String: Any]`, `[Any]`,
    /// `NSNumber`, etc., as produced by `JSONSerialization`) into the
    /// `JSONLD.JSON` enum.
    ///
    /// NSNumber's `Bool` distinction needs care: `NSNumber` wraps both
    /// `Bool` and integer/float numerics, and on Foundation both forms
    /// satisfy `is NSNumber`. We disambiguate by checking `CFGetTypeID`
    /// against `CFBooleanGetTypeID()`.
    static func fromFoundation(_ value: Any) -> JSONLD.JSON {
        if value is NSNull {
            return .null
        }
        if let s = value as? String {
            return .string(s)
        }
        if let arr = value as? [Any] {
            return .array(arr.map { JSONLD.JSON.fromFoundation($0) })
        }
        if let dict = value as? [String: Any] {
            return .object(
                Dictionary(
                    uniqueKeysWithValues:
                        dict.map { ($0.key, JSONLD.JSON.fromFoundation($0.value)) }
                )
            )
        }
        if let num = value as? NSNumber {
            #if canImport(Darwin)
            if CFGetTypeID(num) == CFBooleanGetTypeID() {
                return .bool(num.boolValue)
            }
            // Distinguish ints from floats by checking objCType:
            // 'q' / 'i' / 'l' / 's' / 'c' / 'B' etc. for integers,
            // 'd' / 'f' for floats. CFNumberGetType is the canonical
            // discriminator.
            let cfType = CFNumberGetType(num)
            switch cfType {
            case .float32Type, .float64Type, .cgFloatType, .floatType, .doubleType:
                return .double(num.doubleValue)
            default:
                return .int(num.int64Value)
            }
            #else
            // swift-corelibs-foundation (Linux/Windows) doesn't expose the
            // CFNumber bridging APIs, but NSNumber.objCType returns the same
            // Objective-C type encodings. JSONSerialization wraps booleans
            // with 'c' (or 'B'), floats with 'f'/'d', and everything else is
            // an integer.
            switch num.objCType.pointee {
            case 0x63 /* 'c' */, 0x42 /* 'B' */:
                return .bool(num.boolValue)
            case 0x66 /* 'f' */, 0x64 /* 'd' */:
                return .double(num.doubleValue)
            default:
                return .int(num.int64Value)
            }
            #endif
        }
        // Fallback for anything else — represent as string so we don't
        // silently drop data, but it should never trigger for output of
        // JSONSerialization.
        return .string(String(describing: value))
    }
}

// MARK: - Hex decoder

private extension Data {
    /// Decode a lowercase (or mixed-case) hex string. `nil` on any
    /// invalid character or odd length.
    init?(hexLowercase: String) {
        let chars = hexLowercase.unicodeScalars
        guard chars.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        var iter = chars.makeIterator()
        while let hi = iter.next(), let lo = iter.next() {
            guard let h = UInt8(String(hi), radix: 16),
                  let l = UInt8(String(lo), radix: 16) else {
                return nil
            }
            bytes.append(h << 4 | l)
        }
        self.init(bytes)
    }
}
