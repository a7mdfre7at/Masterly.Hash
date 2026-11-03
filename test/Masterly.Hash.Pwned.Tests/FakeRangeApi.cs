using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Pwned.Tests;

/// <summary>A captured outgoing request, copied before the request message is disposed.</summary>
internal sealed record CapturedRequest(HttpMethod Method, Uri Uri, IReadOnlyDictionary<string, string> Headers, bool HasContent)
{
    /// <summary>Everything that went on the wire, as one string, for "never sent" assertions.</summary>
    public string Wire => Method + " " + Uri + "\n" + string.Join("\n", Headers.Select(h => h.Key + ": " + h.Value));
}

/// <summary>In-process stand-in for the range API. Never touches the network.</summary>
internal sealed class FakeRangeApi : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond;
    private readonly ConcurrentQueue<CapturedRequest> _requests = new();

    public FakeRangeApi(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
    {
        _respond = respond;
    }

    /// <summary>Answers every request with 200 and <paramref name="body"/>.</summary>
    public static FakeRangeApi Ok(string body) => new((_, _) => Task.FromResult(Text(HttpStatusCode.OK, body)));

    /// <summary>Answers every request with <paramref name="status"/>.</summary>
    public static FakeRangeApi Status(HttpStatusCode status) => new((_, _) => Task.FromResult(Text(status, "error")));

    /// <summary>Never answers; completes only when the request is cancelled.</summary>
    public static FakeRangeApi Hang() => new(async (_, ct) =>
    {
        await Task.Delay(Timeout.Infinite, ct);
        throw new InvalidOperationException("unreachable");
    });

    public IReadOnlyList<CapturedRequest> Requests => _requests.ToArray();

    public int Count => _requests.Count;

    public HttpClient CreateClient() => new(this, disposeHandler: false);

    public static HttpResponseMessage Text(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.ASCII, "text/plain") };

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, IEnumerable<string>> h in request.Headers)
            headers[h.Key] = string.Equals(h.Key, "User-Agent", StringComparison.OrdinalIgnoreCase)
                ? string.Join(" ", h.Value) // product tokens are space-separated on the wire
                : string.Join(",", h.Value);
        _requests.Enqueue(new CapturedRequest(request.Method, request.RequestUri!, headers, request.Content != null));
        return _respond(request, cancellationToken);
    }
}

internal static class Sha1Hex
{
    /// <summary>Reference SHA-1 via the BCL, uppercase hex, for building fake ranges.</summary>
    public static string Of(string password) =>
        Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));

    public static string Prefix(string password) => Of(password)[..5];

    public static string Suffix(string password) => Of(password)[5..];

    /// <summary>A plausible padded range: <paramref name="lines"/> plus random zero-count padding lines.</summary>
    public static string Range(int padding, params string[] lines)
    {
        var rng = new Random(1234);
        var all = new List<string>(lines);
        for (int i = 0; i < padding; i++)
        {
            var bytes = new byte[18];
            rng.NextBytes(bytes);
            all.Add(Convert.ToHexString(bytes)[..35] + ":0");
        }
        return string.Join("\r\n", all.OrderBy(l => l, StringComparer.Ordinal));
    }
}
