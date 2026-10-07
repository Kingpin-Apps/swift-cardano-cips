import Foundation

/// CBOR read closely enough to judge its encoding: each item keeps where it
/// sits in the bytes, whether its head was longer than it needed to be, and
/// whether it was written with indefinite length. It can then be written
/// back canonically (RFC 7049 §3.9), as CIP-21 asks.
struct RawCBOR: Sendable, Equatable {
    indirect enum Kind: Sendable, Equatable {
        case unsigned(UInt64)
        /// The value is `-1 - n`.
        case negative(UInt64)
        case bytes(Data)
        case text(String)
        case array([RawCBOR])
        case map([Entry])
        case tag(UInt64, RawCBOR)
        /// A simple value or float, kept as its bytes.
        case simple(Data)
    }

    struct Entry: Sendable, Equatable {
        var key: RawCBOR
        var value: RawCBOR
    }

    var kind: Kind
    /// Where the item was in the bytes it was read from.
    var range: Range<Int>
    /// Its head (or a string chunk's) used more bytes than its value needed.
    var overlong = false
    var indefinite = false

    // MARK: - Reading

    typealias ReadError = CIP21ReadError

    static func read(_ data: Data) throws -> RawCBOR {
        var reader = Reader(bytes: [UInt8](data))
        let item = try reader.item(depth: 0)
        guard reader.offset == reader.bytes.count else { throw ReadError(description: "Bytes follow the item.") }
        return item
    }

    struct Reader {
        let bytes: [UInt8]
        var offset = 0

        mutating func byte() throws -> UInt8 {
            guard offset < bytes.count else { throw ReadError(description: "The bytes end early.") }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func take(_ count: Int) throws -> [UInt8] {
            guard count >= 0, offset + count <= bytes.count else { throw ReadError(description: "The bytes end early.") }
            defer { offset += count }
            return Array(bytes[offset..<offset + count])
        }

        /// A head: its major type, its argument (nil when indefinite) and
        /// whether the argument was written longer than needed.
        mutating func head() throws -> (major: UInt8, info: UInt8, argument: UInt64?, overlong: Bool) {
            let initial = try byte()
            let major = initial >> 5
            let info = initial & 0x1f
            switch info {
            case 0..<24: return (major, info, UInt64(info), false)
            case 24:
                let value = UInt64(try byte())
                return (major, info, value, major != 7 && value < 24)
            case 25:
                let value = try take(2).reduce(0) { $0 << 8 | UInt64($1) }
                return (major, info, value, major != 7 && value < 0x100)
            case 26:
                let value = try take(4).reduce(0) { $0 << 8 | UInt64($1) }
                return (major, info, value, major != 7 && value < 0x1_0000)
            case 27:
                let value = try take(8).reduce(0) { $0 << 8 | UInt64($1) }
                return (major, info, value, major != 7 && value < 0x1_0000_0000)
            case 31: return (major, info, nil, false)
            default: throw ReadError(description: "A reserved head at byte \(offset - 1).")
            }
        }

        mutating func item(depth: Int) throws -> RawCBOR {
            guard depth < 512 else { throw ReadError(description: "Nested too deep.") }
            let start = offset
            let (major, info, argument, overlong) = try head()
            func done(_ kind: Kind, overlong: Bool = overlong, indefinite: Bool = false) -> RawCBOR {
                RawCBOR(kind: kind, range: start..<offset, overlong: overlong, indefinite: indefinite)
            }
            switch major {
            case 0:
                guard let argument else { throw ReadError(description: "An indefinite integer at byte \(start).") }
                return done(.unsigned(argument))
            case 1:
                guard let argument else { throw ReadError(description: "An indefinite integer at byte \(start).") }
                return done(.negative(argument))
            case 2, 3:
                var content: [UInt8] = []
                var chunkOverlong = overlong
                if let argument {
                    content = try take(Int(argument))
                } else {
                    while true {
                        guard offset < bytes.count else { throw ReadError(description: "The bytes end early.") }
                        if bytes[offset] == 0xff {
                            offset += 1
                            break
                        }
                        let chunk = try head()
                        guard chunk.major == major, let length = chunk.argument else {
                            throw ReadError(description: "A bad string chunk at byte \(offset).")
                        }
                        chunkOverlong = chunkOverlong || chunk.overlong
                        content += try take(Int(length))
                    }
                }
                if major == 2 { return done(.bytes(Data(content)), overlong: chunkOverlong, indefinite: argument == nil) }
                return done(.text(String(decoding: content, as: UTF8.self)), overlong: chunkOverlong, indefinite: argument == nil)
            case 4:
                var items: [RawCBOR] = []
                if let argument {
                    for _ in 0..<argument { items.append(try item(depth: depth + 1)) }
                } else {
                    while try peekBreak() == false { items.append(try item(depth: depth + 1)) }
                }
                return done(.array(items), indefinite: argument == nil)
            case 5:
                var entries: [Entry] = []
                if let argument {
                    for _ in 0..<argument { entries.append(Entry(key: try item(depth: depth + 1), value: try item(depth: depth + 1))) }
                } else {
                    while try peekBreak() == false {
                        entries.append(Entry(key: try item(depth: depth + 1), value: try item(depth: depth + 1)))
                    }
                }
                return done(.map(entries), indefinite: argument == nil)
            case 6:
                guard let argument else { throw ReadError(description: "An indefinite tag at byte \(start).") }
                return done(.tag(argument, try item(depth: depth + 1)))
            default:
                _ = info
                return done(.simple(Data(bytes[start..<offset])))
            }
        }

        /// Whether a break byte is next; consumes it when it is.
        mutating func peekBreak() throws -> Bool {
            guard offset < bytes.count else { throw ReadError(description: "The bytes end early.") }
            if bytes[offset] == 0xff {
                offset += 1
                return true
            }
            return false
        }
    }

    // MARK: - Writing

    /// The item written canonically: shortest heads, definite lengths, and
    /// map keys in RFC 7049 order (shorter encoded keys first, then by bytes).
    func canonical() -> Data {
        var out = Data()
        write(into: &out)
        return out
    }

    private func write(into out: inout Data) {
        switch kind {
        case .unsigned(let value): Self.head(0, value, into: &out)
        case .negative(let value): Self.head(1, value, into: &out)
        case .bytes(let data):
            Self.head(2, UInt64(data.count), into: &out)
            out += data
        case .text(let text):
            let data = Data(text.utf8)
            Self.head(3, UInt64(data.count), into: &out)
            out += data
        case .array(let items):
            Self.head(4, UInt64(items.count), into: &out)
            for item in items { item.write(into: &out) }
        case .map(let entries):
            Self.head(5, UInt64(entries.count), into: &out)
            let written = entries.map { ($0.key.canonical(), $0.value.canonical()) }
            for (key, value) in written.sorted(by: { Self.canonicalOrder($0.0, $1.0) }) {
                out += key
                out += value
            }
        case .tag(let tag, let item):
            Self.head(6, tag, into: &out)
            item.write(into: &out)
        case .simple(let raw):
            out += raw
        }
    }

    /// RFC 7049 §3.9: the shorter encoding first; equal lengths by their bytes.
    static func canonicalOrder(_ a: Data, _ b: Data) -> Bool {
        if a.count != b.count { return a.count < b.count }
        return a.lexicographicallyPrecedes(b)
    }

    static func head(_ major: UInt8, _ value: UInt64, into out: inout Data) {
        let type = major << 5
        switch value {
        case 0..<24: out.append(type | UInt8(value))
        case 24..<0x100: out += [type | 24, UInt8(value)]
        case 0x100..<0x1_0000: out += [type | 25, UInt8(value >> 8), UInt8(value & 0xff)]
        case 0x1_0000..<0x1_0000_0000:
            out.append(type | 26)
            for shift in stride(from: 24, through: 0, by: -8) { out.append(UInt8(value >> UInt64(shift) & 0xff)) }
        default:
            out.append(type | 27)
            for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8(value >> UInt64(shift) & 0xff)) }
        }
    }

    // MARK: - Helpers

    var array: [RawCBOR]? {
        if case .array(let items) = kind { return items }
        if case .tag(258, let inner) = kind, case .array(let items) = inner.kind { return items }
        return nil
    }

    var entries: [Entry]? {
        if case .map(let entries) = kind { return entries }
        return nil
    }

    var unsigned: UInt64? {
        if case .unsigned(let value) = kind { return value }
        return nil
    }

    /// The value at integer key `key` of a map.
    subscript(key: UInt64) -> RawCBOR? {
        entries?.first { $0.key.unsigned == key }?.value
    }

    /// Whether this is a set written with tag 258.
    var isTaggedSet: Bool {
        if case .tag(258, _) = kind { return true }
        return false
    }
}
