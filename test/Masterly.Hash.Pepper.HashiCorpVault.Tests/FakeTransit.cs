using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.HashiCorpVault;

namespace Masterly.Hash.Pepper.HashiCorpVault.Tests;

/// <summary>Captured view of one request the pepper sent.</summary>
internal sealed record RecordedRequest(HttpMethod Method, Uri Uri, Dictionary<string, string> Headers, string? ContentType, string Body);

/// <summary>
/// In-memory imitation of Vault's Transit <c>hmac</c> endpoint: HMAC-SHA256 of the decoded <c>input</c> under the
/// requested key version, answered as <c>{"data":{"hmac":"vault:vN:&lt;b64&gt;"}}</c>.
/// </summary>
internal sealed class FakeTransitHandler : HttpMessageHandler
{
    public const string Token = "hvs.test-token-0123456789";

    private readonly Dictionary<int, byte[]> _keys = new();

    public FakeTransitHandler(params int[] versions)
    {
        foreach (int v in versions)
            _keys[v] = SHA256.HashData(Encoding.UTF8.GetBytes("transit-key-v" + v));
    }

    public ConcurrentQueue<RecordedRequest> Requests { get; } = new();

    /// <summary>When set, replaces the normal Transit behaviour.</summary>
    public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? Override { get; set; }

    public bool Down { get; set; }

    public void SetKey(int version, byte[] key) => _keys[version] = key;

    public byte[] Expected(int version, byte[] input) => HMACSHA256.HashData(_keys[version], input);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string body = request.Content == null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in request.Headers)
            headers[h.Key] = string.Join(",", h.Value);
        Requests.Enqueue(new RecordedRequest(request.Method, request.RequestUri!, headers, request.Content?.Headers.ContentType?.MediaType, body));

        if (Override != null)
            return await Override(request, cancellationToken);
        if (Down)
            throw new HttpRequestException("Connection refused (vault.test:8200)");

        if (!headers.TryGetValue("X-Vault-Token", out string? token) || token != Token)
            return Json(HttpStatusCode.Forbidden, "{\"errors\":[\"permission denied\"]}");

        using JsonDocument doc = JsonDocument.Parse(body);
        byte[] input = Convert.FromBase64String(doc.RootElement.GetProperty("input").GetString()!);
        int version = doc.RootElement.GetProperty("key_version").GetInt32();
        if (!_keys.TryGetValue(version, out byte[]? key))
            return Json(HttpStatusCode.BadRequest, "{\"errors\":[\"invalid key version\"]}");

        string hmac = "vault:v" + version + ":" + Convert.ToBase64String(HMACSHA256.HashData(key, input));
        return Json(HttpStatusCode.OK, "{\"request_id\":\"4b2f\",\"lease_id\":\"\",\"renewable\":false,\"data\":{\"hmac\":\"" + hmac + "\"},\"warnings\":null}");
    }

    public static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
}

internal static class Vault
{
    public static readonly Uri Address = new("https://vault.test:8200");

    public static HashiCorpVaultPepperOptions Options(int current = 1, Action<HashiCorpVaultPepperOptions>? configure = null)
    {
        var o = new HashiCorpVaultPepperOptions
        {
            VaultAddress = Address,
            KeyName = "password-pepper",
            Token = FakeTransitHandler.Token,
            CurrentKeyVersion = current,
        };
        configure?.Invoke(o);
        return o;
    }

    public static HashiCorpVaultPepper Pepper(FakeTransitHandler handler, int current = 1, Action<HashiCorpVaultPepperOptions>? configure = null) =>
        new(new HttpClient(handler), Options(current, configure));

    public static PasswordHasher Hasher(IPasswordPepper pepper) =>
        new(new PasswordHasherOptions { DefaultProfile = HashProfile.Argon2id("test", 64, 1), AllowWeakProfiles = true, Pepper = pepper });
}
