namespace Kseal.Desktop;

/// <summary>A transport response: HTTP status code and raw body bytes.</summary>
public sealed record HttpTransportResponse(int Status, byte[] Body);

/// <summary>
/// Minimal synchronous HTTP POST seam used by the Connect trust client.
/// Abstracted so the trust flow can be unit-tested with a deterministic fake
/// (no sockets, no server) while production uses <see cref="HttpClientTransport"/>.
/// </summary>
public interface IHttpTransport
{
    HttpTransportResponse Post(Uri url, IReadOnlyDictionary<string, string> headers, byte[] body);
}

/// <summary>Production transport backed by a shared <see cref="HttpClient"/>.</summary>
public sealed class HttpClientTransport : IHttpTransport, IDisposable
{
    private readonly HttpClient _client;
    private readonly bool _ownsClient;

    public HttpClientTransport(HttpClient? client = null, TimeSpan? timeout = null)
    {
        _ownsClient = client is null;
        _client = client ?? new HttpClient();
        if (timeout is { } t) _client.Timeout = t;
    }

    public HttpTransportResponse Post(Uri url, IReadOnlyDictionary<string, string> headers, byte[] body)
    {
        using var content = new ByteArrayContent(body);
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        foreach (var (key, value) in headers)
        {
            if (key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(value);
            }
            else
            {
                request.Headers.TryAddWithoutValidation(key, value);
            }
        }

        // The trust flow runs off the launch hot path; a bounded synchronous call
        // keeps the public API simple. HttpClient.Timeout fails closed.
        using HttpResponseMessage response = _client.Send(request);
        byte[] payload = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        return new HttpTransportResponse((int)response.StatusCode, payload);
    }

    public void Dispose()
    {
        if (_ownsClient) _client.Dispose();
    }
}
