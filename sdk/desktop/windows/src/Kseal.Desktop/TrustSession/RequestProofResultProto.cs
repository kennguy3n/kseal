using System.Text;

namespace Kseal.Desktop;

/// <summary>
/// Minimal decoder for <c>kseal.v1.RequestProofResult</c> protobuf bytes.
///
/// The message has exactly two fields — <c>decision</c> (field 1, enum/varint)
/// and <c>reason</c> (field 2, string) — so a focused wire-format reader avoids
/// pulling a full protobuf runtime into the SDK. Unknown fields are skipped per
/// the protobuf spec, keeping forward compatibility if the server adds fields.
/// </summary>
internal static class RequestProofResultProto
{
    public static RequestProofDecision Decode(byte[] data)
    {
        var reader = new ProtoReader(data);
        int decisionCode = 0;
        string reason = "";

        while (reader.HasMore)
        {
            ulong tag = reader.ReadVarint();
            ulong field = tag >> 3;
            ulong wireType = tag & 0x7;
            switch (field, wireType)
            {
                case (1, 0): // decision (varint)
                    decisionCode = (int)reader.ReadVarint();
                    break;
                case (2, 2): // reason (length-delimited string)
                    reason = reader.ReadString();
                    break;
                default:
                    reader.Skip(wireType);
                    break;
            }
        }

        return new RequestProofDecision(Decision(decisionCode), reason);
    }

    private static TrustDecision Decision(int code) => code switch
    {
        1 => TrustDecision.Allow,
        2 => TrustDecision.StepUp,
        3 => TrustDecision.Deny,
        _ => TrustDecision.Unspecified,
    };
}

/// <summary>A minimal, bounds-checked protobuf wire-format reader.</summary>
internal struct ProtoReader(byte[] bytes)
{
    private int _offset = 0;

    public readonly bool HasMore => _offset < bytes.Length;

    public ulong ReadVarint()
    {
        ulong result = 0;
        int shift = 0;
        while (true)
        {
            if (_offset >= bytes.Length)
            {
                throw new TrustSessionException("malformed protobuf: truncated varint");
            }
            byte b = bytes[_offset++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (shift >= 64)
            {
                throw new TrustSessionException("malformed protobuf: varint too long");
            }
        }
        return result;
    }

    public string ReadString()
    {
        int length = (int)ReadVarint();
        if (length < 0 || _offset + length > bytes.Length)
        {
            throw new TrustSessionException("malformed protobuf: string overruns buffer");
        }
        string value = Encoding.UTF8.GetString(bytes, _offset, length);
        _offset += length;
        return value;
    }

    public void Skip(ulong wireType)
    {
        switch (wireType)
        {
            case 0: ReadVarint(); break;
            case 1: Advance(8); break;                 // 64-bit
            case 2: Advance((int)ReadVarint()); break; // length-delimited
            case 5: Advance(4); break;                 // 32-bit
            default:
                throw new TrustSessionException($"malformed protobuf: unsupported wire type {wireType}");
        }
    }

    private void Advance(int count)
    {
        if (count < 0 || _offset + count > bytes.Length)
        {
            throw new TrustSessionException("malformed protobuf: field overruns buffer");
        }
        _offset += count;
    }
}
