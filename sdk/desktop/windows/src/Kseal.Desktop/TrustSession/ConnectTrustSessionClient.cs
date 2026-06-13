using System.Text.Json;

namespace Kseal.Desktop;

/// <summary>Connection settings for the trust-session client.</summary>
public sealed record TrustSessionConfig(Uri BaseUrl, string TenantId, string AppId, Platform Platform = Platform.Unspecified);

/// <summary>
/// <see cref="ITrustSessionClient"/> over the Connect protocol
/// (https://connectrpc.com). Unary calls are plain HTTP POSTs to
/// <c>/&lt;package&gt;.&lt;Service&gt;/&lt;Method&gt;</c>:
/// <list type="bullet">
/// <item><c>GetNonce</c> / <c>VerifyAttestation</c> use Connect's JSON codec
/// (proto3 JSON mapping: int64/uint64 as strings, bytes as base64, enums as
/// names).</item>
/// <item><c>ValidateRequestProof</c> forwards the core-produced
/// <c>RequestProof</c> protobuf bytes verbatim using the binary codec, so the
/// server validates exactly the signature the core computed.</item>
/// </list>
/// </summary>
public sealed class ConnectTrustSessionClient(TrustSessionConfig config, IHttpTransport transport) : ITrustSessionClient
{
    private const string TrustService = "kseal.v1.TrustService";

    public byte[] GetNonce()
    {
        var body = new Dictionary<string, object>
        {
            ["tenantId"] = config.TenantId,
            ["appId"] = config.AppId,
            ["platform"] = ProtoJson.PlatformName(config.Platform),
        };
        using JsonDocument doc = CallJson("GetNonce", body);
        if (!doc.RootElement.TryGetProperty("nonce", out var nonceEl) ||
            nonceEl.GetString() is not { Length: > 0 } b64)
        {
            throw new TrustSessionException("GetNonce response missing nonce");
        }
        return Convert.FromBase64String(b64);
    }

    public TrustSession VerifyAttestation(
        byte[] nonce, ulong riskBitset, string buildHash, string policyHash, string instanceId, byte[] attestationToken)
    {
        var body = new Dictionary<string, object>
        {
            ["tenantId"] = config.TenantId,
            ["appId"] = config.AppId,
            ["buildHash"] = buildHash,
            ["policyHash"] = policyHash,
            // proto3 JSON encodes 64-bit integers as strings.
            ["riskBitset"] = riskBitset.ToString(),
            ["nonce"] = Convert.ToBase64String(nonce),
            ["platform"] = ProtoJson.PlatformName(config.Platform),
            ["instanceId"] = instanceId,
        };
        if (attestationToken.Length > 0)
        {
            body["platformAttestationToken"] = Convert.ToBase64String(attestationToken);
        }

        using JsonDocument doc = CallJson("VerifyAttestation", body);
        JsonElement root = doc.RootElement;
        JsonElement token = root.TryGetProperty("trustToken", out var t) ? t : default;

        return new TrustSession(
            TokenId: ProtoJson.String(token, "tokenId"),
            SignedToken: ProtoJson.Base64(root, "signedToken"),
            Accepted: root.TryGetProperty("accepted", out var a) && a.GetBoolean(),
            RejectionReason: ProtoJson.String(root, "rejectionReason"),
            ExpiresAt: ProtoJson.Int64(token, "expiresAt"),
            RiskLevel: ProtoJson.TrustLevel(token, "riskLevel"),
            CapabilityScopes: ProtoJson.StringArray(token, "capabilityScope"));
    }

    public RequestProofDecision ValidateRequestProof(RequestProof proof)
    {
        HttpTransportResponse response = Post("ValidateRequestProof", "application/proto", proof.ProofBytes);
        if (response.Status != 200)
        {
            throw new TrustSessionException($"ValidateRequestProof failed: HTTP {response.Status}");
        }
        return RequestProofResultProto.Decode(response.Body);
    }

    private JsonDocument CallJson(string method, Dictionary<string, object> body)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(body);
        HttpTransportResponse response = Post(method, "application/json", payload);
        if (response.Status != 200)
        {
            throw new TrustSessionException($"{method} failed: {ConnectError.Describe(response)}");
        }
        try
        {
            return JsonDocument.Parse(response.Body);
        }
        catch (JsonException ex)
        {
            throw new TrustSessionException($"{method} returned invalid JSON: {ex.Message}");
        }
    }

    private HttpTransportResponse Post(string method, string contentType, byte[] body)
    {
        var url = new Uri(config.BaseUrl, $"{TrustService}/{method}");
        var headers = new Dictionary<string, string>
        {
            ["Content-Type"] = contentType,
            ["Connect-Protocol-Version"] = "1",
            ["Accept"] = contentType,
        };
        return transport.Post(url, headers, body);
    }
}

/// <summary>proto3-JSON value helpers (lenient: tolerates omitted/zero defaults).</summary>
internal static class ProtoJson
{
    public static string PlatformName(Platform platform) => platform switch
    {
        Platform.Android => "PLATFORM_ANDROID",
        Platform.Ios => "PLATFORM_IOS",
        _ => "PLATFORM_UNSPECIFIED",
    };

    public static string String(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var el)
            ? el.GetString() ?? ""
            : "";

    public static byte[] Base64(JsonElement parent, string name)
    {
        if (parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var el) &&
            el.GetString() is { Length: > 0 } s)
        {
            try { return Convert.FromBase64String(s); }
            catch (FormatException) { return []; }
        }
        return [];
    }

    /// <summary>proto3 JSON encodes int64 as a quoted string (some encoders use a bare number).</summary>
    public static long Int64(JsonElement parent, string name)
    {
        if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(name, out var el)) return 0;
        return el.ValueKind switch
        {
            JsonValueKind.String => long.TryParse(el.GetString(), out var v) ? v : 0,
            JsonValueKind.Number => el.TryGetInt64(out var n) ? n : 0,
            _ => 0,
        };
    }

    public static TrustLevel TrustLevel(JsonElement parent, string name)
    {
        if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(name, out var el)) return Kseal.Desktop.TrustLevel.Unspecified;
        if (el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out var code))
        {
            return Enum.IsDefined((TrustLevel)code) ? (TrustLevel)code : Kseal.Desktop.TrustLevel.Unspecified;
        }
        return el.GetString() switch
        {
            "TRUST_LEVEL_TRUSTED" => Kseal.Desktop.TrustLevel.Trusted,
            "TRUST_LEVEL_LOW_RISK" => Kseal.Desktop.TrustLevel.LowRisk,
            "TRUST_LEVEL_MEDIUM_RISK" => Kseal.Desktop.TrustLevel.MediumRisk,
            "TRUST_LEVEL_HIGH_RISK" => Kseal.Desktop.TrustLevel.HighRisk,
            "TRUST_LEVEL_CRITICAL" => Kseal.Desktop.TrustLevel.Critical,
            _ => Kseal.Desktop.TrustLevel.Unspecified,
        };
    }

    public static IReadOnlyList<string> StringArray(JsonElement parent, string name)
    {
        if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(name, out var el) ||
            el.ValueKind != JsonValueKind.Array)
        {
            return [];
        }
        var list = new List<string>(el.GetArrayLength());
        foreach (var item in el.EnumerateArray())
        {
            if (item.GetString() is { } s) list.Add(s);
        }
        return list;
    }
}

/// <summary>Renders a Connect error body for diagnostics (no PII; codes/messages only).</summary>
internal static class ConnectError
{
    public static string Describe(HttpTransportResponse response)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(response.Body);
            if (doc.RootElement.TryGetProperty("code", out var code))
            {
                string message = doc.RootElement.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
                return $"HTTP {response.Status} [{code.GetString()}] {message}";
            }
        }
        catch (JsonException) { /* fall through */ }
        return $"HTTP {response.Status}";
    }
}
