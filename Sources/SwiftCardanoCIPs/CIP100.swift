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
    ///
    /// The associated string is the offending hex value truncated to a
    /// safe prefix (≤ 80 chars + ellipsis) — never the full input.
    /// Witness fields are attacker-controlled in CIP-100 documents; a
    /// multi-megabyte garbage string would otherwise amplify into log /
    /// error sinks.
    case malformedHex(String)
    /// JSON-LD canonicalization failed.
    case canonicalizationFailed(String)
    /// Ed25519 signing of the canonical body hash failed.
    ///
    /// Distinct from ``canonicalizationFailed(_:)`` so callers can
    /// tell a broken signing key from a broken JSON-LD document —
    /// matching the shape of `CIP36Error` and `CIP88Error`.
    case signingError(String)
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
/// 1. Keep only the document's `@context` and `body` (CIP-100 witnesses
///    sign the `body`; test-vector.md removes every other top-level field,
///    so `authors` and `hashAlgorithm` don't contribute). A document with
///    no `body` throws ``CIP100Error/missingField(_:)``.
/// 2. Canonicalize the resulting document with RDFC-1.0 / URDNA2015 via
///    `JSONLD.canonize(_:options:)`.
/// 3. Take the UTF-8 bytes of the canonical N-Quads (already terminated
///    by a trailing newline per the canonical N-Quads serialization).
/// 4. Hash with Blake2b-256.
/// 5. Sign the 32-byte hash with the author's Ed25519 signing key.
///
/// Verification re-canonicalizes the same way and checks each author's
/// witness signature, in document order, against that one hash.
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
        authorName: String? = nil,
        strict: Bool = true
    ) async throws -> Data {
        // 1. Parse the document.
        var rootObject = try parseAsObject(document)

        // 2. Compute the signing payload.
        let hash = try await canonicalBodyHash(of: rootObject, strict: strict)

        // 3. Sign with Ed25519.
        let signature: Data
        do {
            signature = try signingKey.sign(data: hash)
        } catch {
            throw CIP100Error.signingError(String(describing: error))
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

        // 7. The returned bytes must hash to what was signed, or the new
        //    witness would not verify for anyone reading them.
        let output = try serialize(rootObject)
        guard try await canonicalBodyHash(of: parseAsObject(output), strict: strict) == hash else {
            throw CIP100Error.serializationFailed("the serialized document does not hash to the signed body hash")
        }
        return output
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
        _ document: Data,
        strict: Bool = true
    ) async throws -> VerificationResult {
        let rootObject = try parseAsObject(document)

        let hash = try await canonicalBodyHash(of: rootObject, strict: strict)

        let authors: [Any]
        switch rootObject["authors"] {
        case nil: authors = []
        case let list as [Any]: authors = list
        default: throw CIP100Error.invalidJSON("authors is not an array")
        }
        var results: [VerificationResult.AuthorResult] = []
        for raw in authors {
            // Every listed author counts. An entry that cannot be read
            // as a witness is recorded as invalid, so allValid can never
            // be true while the document lists an author who did not sign.
            guard let entry = raw as? [String: Any] else {
                results.append(.init(name: nil, publicKey: Data(), valid: false))
                continue
            }
            let name = entry["name"] as? String
            guard let witnessObject = entry["witness"] as? [String: Any],
                  let alg = witnessObject["witnessAlgorithm"] as? String,
                  let pubHex = witnessObject["publicKey"] as? String,
                  let sigHex = witnessObject["signature"] as? String else {
                let listedKey = ((entry["witness"] as? [String: Any])?["publicKey"] as? String)
                    .flatMap { Data(hexLowercase: $0) } ?? Data()
                results.append(.init(name: name, publicKey: listedKey, valid: false))
                continue
            }
            guard alg == witnessAlgorithmEd25519 else {
                throw CIP100Error.unsupportedWitnessAlgorithm(alg)
            }

            guard let pubKey = Data(hexLowercase: pubHex) else {
                throw CIP100Error.malformedHex(Self.truncatedForError(pubHex))
            }
            guard pubKey.count == 32 else {
                throw CIP100Error.invalidPublicKeyLength(pubKey.count)
            }
            guard let signature = Data(hexLowercase: sigHex) else {
                throw CIP100Error.malformedHex(Self.truncatedForError(sigHex))
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
    /// document's `@context` and `body` (every other top-level field
    /// dropped) — i.e. the payload every CIP-100 author witness signs.
    ///
    /// - Throws: ``CIP100Error/missingField(_:)`` when there is no `body`.
    ///
    /// Exposed so callers can pre-compute the hash (e.g. for an external
    /// HSM-backed signer) without going through ``signMetadata(document:signingKey:authorName:)``.
    public static func canonicalBodyHash(of document: Data, strict: Bool = true) async throws -> Data {
        let rootObject = try parseAsObject(document)
        return try await canonicalBodyHash(of: rootObject, strict: strict)
    }

    /// RDF canonicalization work factor for documents from other parties.
    /// Real governance documents have few indistinguishable blank nodes;
    /// poison graphs fail fast instead of running for hours.
    static let canonicalizationWorkFactor = 2

    /// Deepest array/object nesting accepted. Real documents are a few
    /// levels deep; the limit keeps conversion within a small thread stack.
    static let maxNestingDepth = 64

    private static func canonicalBodyHash(of rootObject: [String: Any], strict: Bool) async throws -> Data {
        // Witnesses sign the `body` only (CIP-100 "Hashing and Signatures";
        // test-vector.md step 1: "remove any top-level fields that are not
        // `@context` or `body`"). Other top-level fields such as
        // `hashAlgorithm` must not reach the canonical form.
        guard let body = rootObject["body"] else {
            throw CIP100Error.missingField("body")
        }
        var stripped: [String: Any] = ["body": body]
        if let context = rootObject["@context"] {
            stripped["@context"] = context
        }

        // Bridge into the JSONLD.JSON type and canonicalize.
        let jsonValue = try JSONLD.JSON.fromFoundation(stripped)
        var options = JSONLD.Options()
        // Strict mode refuses keys that JSON-LD expansion would drop, so
        // every key a reader sees in `body` is covered by the hash.
        // cardano-signer.js hashes with jsonld.js `safe: false`; pass
        // `strict: false` only to accept such documents as it does.
        options.safeMode = strict
        options.canonicalizationWorkFactor = canonicalizationWorkFactor
        options.maxNestingDepth = maxNestingDepth
        let canonical: String
        do {
            canonical = try await JSONLD.canonize(jsonValue, options: options)
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
        // Apple's JSONSerialization recurses per nesting level and overflows a
        // 512 KiB cooperative-thread stack at about 500 levels, so the depth
        // is checked on the raw bytes before it runs.
        try checkRawNestingDepth(data)
        let parsed: Any
        do {
            parsed = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            throw CIP100Error.invalidJSON(String(describing: error))
        }
        try checkNestingDepth(parsed)
        guard let dict = parsed as? [String: Any] else {
            throw CIP100Error.notAnObject
        }
        return dict
    }

    /// Iterative depth check on parsed Foundation JSON, run before any
    /// recursive conversion touches it.
    private static func checkNestingDepth(_ root: Any) throws {
        var stack: [(Any, Int)] = [(root, 1)]
        while let (value, depth) = stack.popLast() {
            if let array = value as? [Any] {
                guard depth <= maxNestingDepth else { throw nestingError }
                for item in array { stack.append((item, depth + 1)) }
            } else if let object = value as? [String: Any] {
                guard depth <= maxNestingDepth else { throw nestingError }
                for item in object.values { stack.append((item, depth + 1)) }
            }
        }
    }

    /// Counts `[`/`{` nesting in raw JSON bytes, skipping string contents.
    /// Malformed input is left for JSONSerialization to reject.
    ///
    /// The count only means something for UTF-8, so other encodings are
    /// refused first: JSONSerialization also reads UTF-16 and UTF-32, whose
    /// bytes this scanner would misread. Those encodings always contain a
    /// zero byte, which valid JSON in UTF-8 never does.
    static func checkRawNestingDepth(_ data: Data) throws {
        guard !data.contains(0), String(decoding: data, as: UTF8.self).utf8.elementsEqual(data) else {
            throw CIP100Error.invalidJSON("document is not UTF-8")
        }
        var depth = 0
        var inString = false
        var escaped = false
        for byte in data {
            if inString {
                if escaped { escaped = false }
                else if byte == UInt8(ascii: "\\") { escaped = true }
                else if byte == UInt8(ascii: "\"") { inString = false }
                continue
            }
            switch byte {
            case UInt8(ascii: "\""): inString = true
            case UInt8(ascii: "["), UInt8(ascii: "{"):
                depth += 1
                guard depth <= maxNestingDepth else { throw nestingError }
            case UInt8(ascii: "]"), UInt8(ascii: "}"):
                depth -= 1
                guard depth >= 0 else { throw CIP100Error.invalidJSON("unbalanced brackets") }
            default: break
            }
        }
    }

    private static var nestingError: CIP100Error {
        .invalidJSON("document nests arrays or objects deeper than \(maxNestingDepth) levels")
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

    /// Truncate an attacker-controlled string before placing it into a
    /// `CIP100Error` payload, so a malicious document with a multi-MB
    /// `signature` or `publicKey` field doesn't amplify into the
    /// caller's log / error pipeline. Internal helper used by the
    /// witness-decoding error sites.
    ///
    /// Cap at 80 characters — enough to identify the offending value at
    /// a glance for debugging (a well-formed Ed25519 signature is 128
    /// hex chars; 80 is plenty to spot a malformed prefix), but bounded
    /// so the error payload is always a constant-size string.
    static func truncatedForError(_ input: String, maxLength: Int = 80) -> String {
        guard input.count > maxLength else { return input }
        return String(input.prefix(maxLength)) + "…"
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
    static func fromFoundation(_ value: Any) throws -> JSONLD.JSON {
        if value is NSNull {
            return .null
        }
        if let s = value as? String {
            return .string(s)
        }
        if let arr = value as? [Any] {
            return .array(try arr.map { try JSONLD.JSON.fromFoundation($0) })
        }
        if let dict = value as? [String: Any] {
            // Keys that differ only in Unicode normalization compare equal
            // as Swift Strings. Reject such a document instead of letting
            // a dictionary initializer trap on the duplicate.
            var object: [String: JSONLD.JSON] = [:]
            for (key, item) in dict {
                guard object[key] == nil else {
                    throw CIP100Error.invalidJSON("duplicate or canonically equivalent key '\(CIP100.truncatedForError(key))'")
                }
                object[key] = try JSONLD.JSON.fromFoundation(item)
            }
            return .object(object)
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
                return try exactInteger(num)
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
                return try exactInteger(num)
            }
            #endif
        }
        throw CIP100Error.invalidJSON("unsupported JSON value of type \(type(of: value))")
    }

    /// An integer that Int64 holds exactly. A larger one (for example
    /// 2^64 - 1, which `int64Value` would wrap to -1) is rejected, so two
    /// different documents can never share a canonical form.
    private static func exactInteger(_ num: NSNumber) throws -> JSONLD.JSON {
        let value = num.int64Value
        guard String(value) == num.stringValue else {
            throw CIP100Error.invalidJSON("integer out of the Int64 range: \(CIP100.truncatedForError(num.stringValue))")
        }
        return .int(value)
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
