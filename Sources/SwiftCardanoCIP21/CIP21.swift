import Foundation

/// CIP-21: what hardware wallets (Ledger, Trezor, Keystone) ask of a
/// transaction before they will sign it.
///
/// Two things, kept apart on purpose:
///
/// - ``report(_:)`` says whether a transaction is compatible and what stands
///   in the way: encoding that is not canonical, empty collections, sets
///   tagged some ways but not others, and what the transaction does that
///   hardware wallets refuse, such as some certificates, or a pool
///   registration that is not alone.
/// - ``compatibleBody(_:)`` writes a transaction body in the form CIP-21
///   asks for. It changes how the body is written, never what it does, but
///   the bytes change, and with them the transaction id and the size the fee
///   is charged on. It is meant for a transaction builder, before it works
///   out the fee: rewriting the body of a transaction that is already built
///   leaves its fee sized for the old bytes, and the node refuses it.
///
/// Nothing here needs anything but Foundation: the rules read CBOR as it is
/// written, so they see what a decoder would smooth over.
public enum CIP21 {
    /// What CIP-21 asks of `transaction` (the whole transaction's CBOR) for
    /// hardware wallets to sign it.
    public static func report(_ transaction: Data) throws -> CIP21Report {
        try CIP21Check.report(transaction)
    }

    /// `body` (a transaction body's CBOR) as CIP-21 asks for it to be written:
    /// empty optional collections left out, every set tagged 258 as the
    /// Conway ledger writes them, and canonical CBOR throughout (shortest
    /// lengths, definite lengths, map keys in canonical order).
    ///
    /// Byte strings keep their content, so inline datums and reference
    /// scripts, which are written inside byte strings, keep their bytes and
    /// their hashes. Writing a body that is already in this form again
    /// changes nothing.
    public static func compatibleBody(_ body: Data) throws -> Data {
        var item = try RawCBOR.read(body)
        guard case .map(var entries) = item.kind else {
            throw CIP21ReadError(description: "That is not a transaction body: a body is a map.")
        }
        entries.removeAll { entry in
            guard let key = entry.key.unsigned, CIP21Check.optionalCollections[key] != nil else { return false }
            return (entry.value.array?.isEmpty ?? false) || (entry.value.entries?.isEmpty ?? false)
        }
        item.kind = .map(entries)
        return tagSets(item).canonical()
    }

    /// Every non-empty set in the body wrapped in tag 258: the set fields,
    /// and the owners of each pool registration.
    static func tagSets(_ body: RawCBOR) -> RawCBOR {
        guard case .map(var entries) = body.kind else { return body }
        func tagged(_ item: RawCBOR) -> RawCBOR {
            if case .array(let items) = item.kind, !items.isEmpty {
                return RawCBOR(kind: .tag(258, item), range: item.range)
            }
            return item
        }
        for index in entries.indices {
            guard let key = entries[index].key.unsigned else { continue }
            if key == 4, let certificates = entries[index].value.array {
                let rewritten = certificates.map { certificate -> RawCBOR in
                    guard case .array(var fields) = certificate.kind, fields.first?.unsigned == 3, fields.count > 7 else { return certificate }
                    fields[7] = tagged(fields[7])
                    return RawCBOR(kind: .array(fields), range: certificate.range)
                }
                entries[index].value = tagged(RawCBOR(kind: .array(rewritten), range: entries[index].value.range))
            } else if CIP21Check.setFields.contains(key) {
                entries[index].value = tagged(entries[index].value)
            }
        }
        return RawCBOR(kind: .map(entries), range: body.range)
    }
}

/// CBOR that cannot be read, or is not the shape asked for.
public struct CIP21ReadError: Error, Sendable, Equatable, CustomStringConvertible {
    public let description: String

    public init(description: String) {
        self.description = description
    }
}
