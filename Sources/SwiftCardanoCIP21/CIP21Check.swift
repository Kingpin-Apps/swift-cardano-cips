import Foundation

/// How a hardware wallet would sign a transaction, by what it contains
/// (CIP-21, "signing modes").
public enum CIP21SigningMode: String, Sendable, Equatable {
    /// A stake pool registration, signed on its own.
    case poolRegistration
    /// Key credentials only.
    case ordinary
    /// Native-script credentials only.
    case multisig
    /// Plutus elements (script data hash, collateral, redeemers).
    case plutus
}

/// One way a transaction falls short of CIP-21.
public struct CIP21Finding: Sendable, Equatable, Identifiable {
    public init(rule: String, message: String, path: String?, fixable: Bool) {
        self.rule = rule
        self.message = message
        self.path = path
        self.fixable = fixable
    }

    /// A short name for the rule: `canonical-sorting`, `prohibited-certificate` …
    public let rule: String
    public let message: String
    /// Where, as body field names: `outputs[2].amount`.
    public let path: String?
    /// Whether writing the body in CIP-21 form (``CIP21/compatibleBody(_:)``)
    /// fixes it. What it cannot fix is in what the transaction does.
    public let fixable: Bool

    public var id: String { "\(rule)|\(path ?? "")|\(message)" }
}

/// What CIP-21 asks of a transaction for hardware wallets to sign it.
public struct CIP21Report: Sendable, Equatable {
    public let mode: CIP21SigningMode
    public let findings: [CIP21Finding]
    public var isCompatible: Bool { findings.isEmpty }
    public var fixable: [CIP21Finding] { findings.filter(\.fixable) }
}

enum CIP21Check {
    static let maxCount = 65_535
    /// Body fields a transaction leaves out rather than writing empty.
    static let optionalCollections: [UInt64: String] = [
        4: "certificates", 5: "withdrawals", 9: "mint", 13: "collateral", 14: "required_signers",
        18: "reference_inputs", 19: "voting_procedures", 20: "proposal_procedures",
    ]
    /// Body fields that hold sets (tag 258 in Conway).
    static let setFields: [UInt64] = [0, 4, 13, 14, 18, 20]
    static let fieldNames: [UInt64: String] = [
        0: "inputs", 1: "outputs", 2: "fee", 3: "ttl", 4: "certificates", 5: "withdrawals", 6: "update",
        7: "auxiliary_data_hash", 8: "validity_start", 9: "mint", 11: "script_data_hash", 13: "collateral",
        14: "required_signers", 15: "network_id", 16: "collateral_return", 17: "total_collateral",
        18: "reference_inputs", 19: "voting_procedures", 20: "proposal_procedures", 21: "treasury", 22: "donation",
    ]

    /// Checks transaction `bytes` against CIP-21.
    public static func report(_ bytes: Data) throws -> CIP21Report {
        let transaction = try RawCBOR.read(bytes)
        guard let parts = transaction.array, parts.count >= 2, parts[0].entries != nil else {
            throw RawCBOR.ReadError(description: "That is not a transaction: an array holding a body map.")
        }
        var findings: [CIP21Finding] = []
        func add(_ rule: String, _ message: String, _ path: String?, fixable: Bool = false) {
            findings.append(CIP21Finding(rule: rule, message: message, path: path, fixable: fixable))
        }
        let body = parts[0]
        let witnesses = parts[1]

        encoding(body, path: "body", add: add)
        fields(body, add: add)
        sets(body, add: add)
        outputs(body, add: add)
        let mode = signingMode(body, witnesses: witnesses)
        certificates(body, mode: mode, add: add)
        counts(body, witnesses: witnesses, add: add)
        return CIP21Report(mode: mode, findings: findings)
    }

    // MARK: - Encoding

    /// Canonical CBOR: shortest heads, definite lengths, sorted map keys, no
    /// duplicate keys.
    static func encoding(_ item: RawCBOR, path: String, add: (String, String, String?, Bool) -> Void) {
        if item.overlong { add("canonical-length", "An integer or length is written longer than it needs to be.", path, true) }
        if item.indefinite { add("canonical-definite", "Written with indefinite length.", path, true) }
        switch item.kind {
        case .array(let items):
            for (index, child) in items.enumerated() { encoding(child, path: "\(path)[\(index)]", add: add) }
        case .map(let entries):
            let keys = entries.map { $0.key.canonical() }
            if Set(keys).count < keys.count {
                add("duplicate-keys", "The same key appears twice.", path, false)
            }
            if keys != keys.sorted(by: RawCBOR.canonicalOrder) {
                add("canonical-sorting", "The keys are not in canonical order.", path, true)
            }
            for entry in entries {
                let name = path == "body" ? (entry.key.unsigned.flatMap { fieldNames[$0] } ?? "?") : Self.keyLabel(entry.key)
                encoding(entry.key, path: "\(path).\(name)", add: add)
                encoding(entry.value, path: path == "body" ? name : "\(path).\(name)", add: add)
            }
        case .tag(_, let inner):
            encoding(inner, path: path, add: add)
        default:
            break
        }
    }

    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    static func keyLabel(_ key: RawCBOR) -> String {
        switch key.kind {
        case .unsigned(let value): "\(value)"
        case .bytes(let data): data.count > 8 ? hex(data.prefix(8)) + "…" : hex(data)
        default: "key"
        }
    }

    // MARK: - Body fields

    static func fields(_ body: RawCBOR, add: (String, String, String?, Bool) -> Void) {
        if body[6] != nil { add("prohibited-field", "Protocol parameter updates (field 6) are not supported.", "update", false) }
        if body[20] != nil { add("prohibited-field", "Proposal procedures (field 20) are not supported.", "proposal_procedures", false) }
        for (key, name) in optionalCollections.sorted(by: { $0.key < $1.key }) {
            guard let value = body[key] else { continue }
            let isEmpty = (value.array?.isEmpty ?? false) || (value.entries?.isEmpty ?? false)
            if isEmpty { add("empty-collection", "An empty \(name) is written; leave it out.", name, true) }
        }
        if let votes = body[19]?.entries {
            if votes.count > 1 || votes.contains(where: { ($0.value.entries?.count ?? 0) > 1 }) {
                add("voting", "Only a single voter with a single vote is supported.", "voting_procedures", false)
            }
        }
        if let withdrawals = body[5]?.entries, Set(withdrawals.map { $0.key.canonical() }).count < withdrawals.count {
            add("duplicate-withdrawal", "A reward account is withdrawn from twice.", "withdrawals", false)
        }
    }

    /// Sets are tagged 258 everywhere or nowhere.
    static func sets(_ body: RawCBOR, add: (String, String, String?, Bool) -> Void) {
        var tagged: [Bool] = []
        for key in setFields {
            if let value = body[key], !(value.array?.isEmpty ?? true) { tagged.append(value.isTaggedSet) }
        }
        for certificate in body[4]?.array ?? [] {
            if let fields = certificate.array, fields.first?.unsigned == 3, fields.count > 7, !(fields[7].array?.isEmpty ?? true) {
                tagged.append(fields[7].isTaggedSet)
            }
        }
        if Set(tagged).count > 1 {
            add("set-tags", "Some sets are written with tag 258 and some without; use one way throughout.", nil, true)
        }
    }

    // MARK: - Outputs

    static func outputs(_ body: RawCBOR, add: (String, String, String?, Bool) -> Void) {
        for (index, output) in (body[1]?.array ?? []).enumerated() {
            let path = "outputs[\(index)]"
            if let fields = output.entries {
                if let datum = output[2]?.array, datum.count == 2, case .tag(24, let inner) = datum[1].kind, case .bytes(let data) = inner.kind, data.isEmpty {
                    add("empty-datum", "The inline datum is empty.", path, false)
                }
                if let script = output[3], case .tag(24, let inner) = script.kind, case .bytes(let data) = inner.kind, data.isEmpty {
                    add("empty-script", "The reference script is empty.", path, false)
                }
                _ = fields
                assets(output[1], path: path, add: add)
            } else if let fields = output.array, fields.count > 1 {
                assets(fields[1], path: path, add: add)
            }
        }
        if let mint = body[9]?.entries {
            assetGroups(mint, path: "mint", add: add)
        }
    }

    static func assets(_ amount: RawCBOR?, path: String, add: (String, String, String?, Bool) -> Void) {
        guard let parts = amount?.array, parts.count == 2, let groups = parts[1].entries else { return }
        assetGroups(groups, path: path, add: add)
    }

    static func assetGroups(_ groups: [RawCBOR.Entry], path: String, add: (String, String, String?, Bool) -> Void) {
        if groups.count > maxCount { add("count", "More than \(maxCount) policies.", path, false) }
        for group in groups where (group.value.entries?.count ?? 0) > maxCount {
            add("count", "More than \(maxCount) assets under one policy.", path, false)
        }
    }

    // MARK: - Certificates

    static let prohibitedCertificates: [UInt64: String] = [
        5: "genesis key delegation", 6: "move instantaneous rewards", 10: "stake and vote delegation",
        11: "stake registration and delegation", 12: "vote registration and delegation",
        13: "stake and vote registration and delegation",
    ]

    static func certificates(_ body: RawCBOR, mode: CIP21SigningMode, add: (String, String, String?, Bool) -> Void) {
        let certificates = body[4]?.array ?? []
        for (index, certificate) in certificates.enumerated() {
            guard let kind = certificate.array?.first?.unsigned else { continue }
            if let name = prohibitedCertificates[kind] {
                add("prohibited-certificate", "A \(name) certificate is not supported by hardware wallets.", "certificates[\(index)]", false)
            }
        }
        guard mode == .poolRegistration else { return }
        if certificates.count > 1 {
            add("pool-registration", "A pool registration must be the only certificate.", "certificates", false)
        }
        let alone: [UInt64: String] = [
            5: "withdrawals", 9: "mint", 11: "a script data hash", 13: "collateral", 14: "required signers",
            16: "a collateral return", 17: "total collateral", 18: "reference inputs", 19: "votes", 21: "a treasury amount", 22: "a donation",
        ]
        for (key, name) in alone.sorted(by: { $0.key < $1.key }) where body[key] != nil {
            add("pool-registration", "A pool registration cannot carry \(name).", fieldNames[key], false)
        }
        for (index, output) in (body[1]?.array ?? []).enumerated() {
            if output[2] != nil || output[3] != nil || (output.array?.count ?? 0) > 2 {
                add("pool-registration", "A pool registration's outputs cannot carry datums or reference scripts.", "outputs[\(index)]", false)
            }
        }
    }

    // MARK: - Counts

    static func counts(_ body: RawCBOR, witnesses: RawCBOR, add: (String, String, String?, Bool) -> Void) {
        for key: UInt64 in [0, 1, 4, 13, 14, 18] {
            if let count = body[key]?.array?.count, count > maxCount {
                add("count", "More than \(maxCount) \(fieldNames[key] ?? "items").", fieldNames[key], false)
            }
        }
        if let count = body[5]?.entries?.count, count > maxCount { add("count", "More than \(maxCount) withdrawals.", "withdrawals", false) }
        for (index, certificate) in (body[4]?.array ?? []).enumerated() {
            guard let fields = certificate.array, fields.first?.unsigned == 3, fields.count > 8 else { continue }
            if (fields[7].array?.count ?? 0) > maxCount || (fields[8].array?.count ?? 0) > maxCount {
                add("count", "More than \(maxCount) pool owners or relays.", "certificates[\(index)]", false)
            }
        }
        let witnessCount = (witnesses.entries ?? []).reduce(0) { $0 + ($1.value.array?.count ?? 0) }
        if witnessCount > maxCount { add("count", "More than \(maxCount) witnesses.", "witnesses", false) }
    }

    // MARK: - Signing mode

    static func signingMode(_ body: RawCBOR, witnesses: RawCBOR) -> CIP21SigningMode {
        let certificates = body[4]?.array ?? []
        if certificates.contains(where: { $0.array?.first?.unsigned == 3 }) { return .poolRegistration }
        if body[11] != nil || body[13] != nil || witnesses[5] != nil { return .plutus }
        // Native scripts in the witness set, or script credentials in
        // certificates or withdrawals, sign as multisig.
        if witnesses[1] != nil { return .multisig }
        let scriptCredential = certificates.contains { certificate in
            guard let fields = certificate.array, fields.count > 1, let credential = fields[1].array, credential.count == 2 else { return false }
            return credential[0].unsigned == 1
        }
        let scriptWithdrawal = (body[5]?.entries ?? []).contains { entry in
            if case .bytes(let account) = entry.key.kind, let header = account.first { return header & 0x10 != 0 }
            return false
        }
        return scriptCredential || scriptWithdrawal ? .multisig : .ordinary
    }
}
