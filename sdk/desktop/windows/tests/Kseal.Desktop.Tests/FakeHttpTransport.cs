using Kseal.Desktop;

namespace Kseal.Desktop.Tests;

/// <summary>
/// Deterministic <see cref="IHttpTransport"/> for trust-flow tests: maps a
/// method name (last URL path segment) to a canned response and records the
/// requests it received. No sockets, no server.
/// </summary>
internal sealed class FakeHttpTransport : IHttpTransport
{
    public sealed record Request(Uri Url, IReadOnlyDictionary<string, string> Headers, byte[] Body);

    private readonly Dictionary<string, Func<Request, HttpTransportResponse>> _routes = new();
    public List<Request> Requests { get; } = [];

    public FakeHttpTransport On(string method, HttpTransportResponse response)
    {
        _routes[method] = _ => response;
        return this;
    }

    public FakeHttpTransport On(string method, Func<Request, HttpTransportResponse> handler)
    {
        _routes[method] = handler;
        return this;
    }

    public HttpTransportResponse Post(Uri url, IReadOnlyDictionary<string, string> headers, byte[] body)
    {
        var request = new Request(url, headers, body);
        Requests.Add(request);
        string method = url.Segments[^1];
        if (_routes.TryGetValue(method, out var handler)) return handler(request);
        return new HttpTransportResponse(404, []);
    }

    public static HttpTransportResponse Json(string json) =>
        new(200, System.Text.Encoding.UTF8.GetBytes(json));
}
