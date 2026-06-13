import Foundation

/// Minimal decoder for `kseal.v1.RequestProofResult` protobuf bytes.
///
/// The message has exactly two fields — `decision` (field 1, enum/varint) and
/// `reason` (field 2, string) — so a focused wire-format reader avoids pulling a
/// full protobuf runtime into the SDK. Unknown fields are skipped per the
/// protobuf spec, keeping forward compatibility if the server adds fields.
struct RequestProofResultProto {
    let decision: TrustDecision
    let reason: String

    static func decode(_ data: Data) throws -> RequestProofResultProto {
        var reader = ProtoReader(data)
        var decisionCode: Int = 0
        var reason = ""

        while reader.hasMore {
            let tag = try reader.readVarint()
            let field = tag >> 3
            let wireType = tag & 0x7
            switch (field, wireType) {
            case (1, 0): // decision (varint)
                decisionCode = Int(try reader.readVarint())
            case (2, 2): // reason (length-delimited string)
                reason = try reader.readString()
            default:
                try reader.skip(wireType: wireType)
            }
        }

        return RequestProofResultProto(decision: Self.decision(decisionCode), reason: reason)
    }

    private static func decision(_ code: Int) -> TrustDecision {
        switch code {
        case 1: return .allow
        case 2: return .stepUp
        case 3: return .deny
        default: return .unspecified
        }
    }
}

/// A minimal, bounds-checked protobuf wire-format reader.
struct ProtoReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ data: Data) { self.bytes = [UInt8](data) }

    var hasMore: Bool { offset < bytes.count }

    mutating func readVarint() throws -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            guard offset < bytes.count else {
                throw TrustSessionError(message: "malformed protobuf: truncated varint")
            }
            let byte = bytes[offset]
            offset += 1
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { break }
            shift += 7
            guard shift < 64 else {
                throw TrustSessionError(message: "malformed protobuf: varint too long")
            }
        }
        return result
    }

    mutating func readString() throws -> String {
        let length = Int(try readVarint())
        guard length >= 0, offset + length <= bytes.count else {
            throw TrustSessionError(message: "malformed protobuf: string overruns buffer")
        }
        let slice = bytes[offset..<(offset + length)]
        offset += length
        return String(decoding: slice, as: UTF8.self)
    }

    /// Skips a field of the given wire type (for forward compatibility).
    mutating func skip(wireType: UInt64) throws {
        switch wireType {
        case 0: _ = try readVarint()
        case 1: try advance(by: 8)            // 64-bit
        case 2: try advance(by: Int(try readVarint())) // length-delimited
        case 5: try advance(by: 4)            // 32-bit
        default:
            throw TrustSessionError(message: "malformed protobuf: unsupported wire type \(wireType)")
        }
    }

    private mutating func advance(by count: Int) throws {
        guard count >= 0, offset + count <= bytes.count else {
            throw TrustSessionError(message: "malformed protobuf: field overruns buffer")
        }
        offset += count
    }
}
