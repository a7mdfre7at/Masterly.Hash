using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.HashiCorpVault;

namespace Masterly.Hash.Pepper.HashiCorpVault.Tests;

public class HashiCorpVaultPepperTests
{
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");

    [Fact]
    public async Task ApplyAsync_SendsTransitHmacRequest()
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler);

        byte[] mac = await pepper.ApplyAsync("v1", Input);

        Assert.Equal(handler.Expected(1, Input), mac);
        RecordedRequest req = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, req.Method);
        Assert.Equal("https://vault.test:8200/v1/transit/hmac/password-pepper/sha2-256", req.Uri.AbsoluteUri);
        Assert.Equal(FakeTransitHandler.Token, req.Headers["X-Vault-Token"]);
        Assert.False(req.Headers.ContainsKey("X-Vault-Namespace"));
        Assert.Equal("application/json", req.ContentType);

        using JsonDocument body = JsonDocument.Parse(req.Body);
        Assert.Equal(Convert.ToBase64String(Input), body.RootElement.GetProperty("input").GetString());
        Assert.Equal(1, body.RootElement.GetProperty("key_version").GetInt32());
        Assert.Equal(2, body.RootElement.EnumerateObject().Count());
    }

    [Fact]
    public async Task ApplyAsync_SendsNamespace_AndCustomMountPath()
    {
        var handler = new FakeTransitHandler(3);
        var pepper = Vault.Pepper(handler, 3, o =>
        {
            o.VaultAddress = new Uri("https://proxy.test/vault/");
            o.MountPath = "/team-a/transit/";
            o.Namespace = "admin/team-a";
        });

        await pepper.ApplyAsync("v3", Input);

        RecordedRequest req = Assert.Single(handler.Requests);
        Assert.Equal("https://proxy.test/vault/v1/team-a/transit/hmac/password-pepper/sha2-256", req.Uri.AbsoluteUri);
        Assert.Equal("admin/team-a", req.Headers["X-Vault-Namespace"]);
        Assert.Contains("\"key_version\":3", req.Body);
        Assert.Equal(pepper.Endpoint, req.Uri);
    }

    // RFC 4231, section 4.7 (test case 6): HMAC-SHA-256 with a 131-byte key of 0xaa.
    // Vault Transit computes plain HMAC-SHA256 over the decoded input, so the pepper must return exactly these bytes.
    [Fact]
    public async Task KnownAnswer_Rfc4231TestCase6_PassesThroughUnchanged()
    {
        var handler = new FakeTransitHandler();
        handler.SetKey(1, Enumerable.Repeat((byte)0xaa, 131).ToArray());
        var pepper = Vault.Pepper(handler);

        byte[] mac = await pepper.ApplyAsync("v1", Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First"));

        Assert.Equal(Convert.FromHexString("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"), mac);
    }

    // Response shape from the Vault Transit API docs, "Generate HMAC" sample response
    // (https://developer.hashicorp.com/vault/api-docs/secret/transit#generate-hmac).
    [Fact]
    public void ParseHmac_VaultDocsSampleResponse()
    {
        const string b64 = "UOK8E9ShFMXjwDmIXmJHQ3fOmd96RbfVIRXqLk2NCeg=";
        string json = "{\n  \"data\": {\n    \"hmac\": \"vault:v1:" + b64 + "\"\n  }\n}";

        byte[] mac = HashiCorpVaultPepper.ParseHmac(Encoding.UTF8.GetBytes(json), 1);

        Assert.Equal(Convert.FromBase64String(b64), mac);
    }

    [Fact]
    public void BuildBody_IsExactJson()
    {
        byte[] body = HashiCorpVaultPepper.BuildBody(new byte[] { 0xfb, 0xff, 0x00, 0x01 }, 12);
        Assert.Equal("{\"input\":\"+/8AAQ==\",\"key_version\":12}", Encoding.ASCII.GetString(body));
    }

    [Fact]
    public void Apply_Sync_MatchesAsync()
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler);
        Assert.Equal(handler.Expected(1, Input), pepper.Apply("v1", Input));
    }

    [Fact]
    public async Task VersionMismatchInResponse_IsUnavailable()
    {
        var handler = new FakeTransitHandler(1);
        handler.Override = (_, _) => Task.FromResult(Ok("vault:v2:" + Convert.ToBase64String(new byte[32])));
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
        Assert.Contains("key version", ex.Message);
    }

    public static IEnumerable<object[]> MalformedBodies()
    {
        string good32 = Convert.ToBase64String(new byte[32]);
        string[] bodies =
        {
            "", " ", "null", "[]", "{}", "\"vault:v1:x\"", "{\"data\":null}", "{\"data\":{}}", "{\"data\":[]}",
            "{\"hmac\":\"vault:v1:" + good32 + "\"}",
            "{\"data\":{\"hmac\":123}}",
            "{\"data\":{\"hmac\":null}}",
            "{\"data\":{\"hmac\":\"\"}}",
            "{\"data\":{\"hmac\":\"vault:v1:\"}}",
            "{\"data\":{\"hmac\":\"vault:v1\"}}",
            "{\"data\":{\"hmac\":\"vault:v:" + good32 + "\"}}",
            "{\"data\":{\"hmac\":\"vault:v01:" + good32 + "\"}}",
            "{\"data\":{\"hmac\":\"vault:vx:" + good32 + "\"}}",
            "{\"data\":{\"hmac\":\"vault:v99999999999:" + good32 + "\"}}",
            "{\"data\":{\"hmac\":\"VAULT:v1:" + good32 + "\"}}",
            "{\"data\":{\"hmac\":\"vault:v1:" + Convert.ToBase64String(new byte[16]) + "\"}}",
            "{\"data\":{\"hmac\":\"vault:v1:" + Convert.ToBase64String(new byte[64]) + "\"}}",
            "{\"data\":{\"hmac\":\"vault:v1:" + good32.Replace('A', '*') + "\"}}",
            "{\"data\":{\"hmac\":\"vault:v1:" + good32.TrimEnd('=') + "\"}}",
            "{\"data\":{\"hmac\":\"\\u0076ault:v1:" + good32 + "\"}}",
            "{\"data\":{\"hmac\":\"vault:v1:" + good32 + "\"",
            "{\"data\":{\"hmac\":\"vault:v1:" + good32 + "\"}}}",
            new string('[', 5000) + new string(']', 5000),
            "{\"data\":" + new string('[', 100) + new string(']', 100) + "}",
            "ÿþ garbage",
        };
        return bodies.Select(b => new object[] { b });
    }

    [Theory]
    [MemberData(nameof(MalformedBodies))]
    public async Task MalformedResponse_IsUnavailable_NeverOtherException(string body)
    {
        var handler = new FakeTransitHandler(1);
        handler.Override = (_, _) => Task.FromResult(FakeTransitHandler.Json(HttpStatusCode.OK, body));
        await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
    }

    [Fact]
    public void ParseHmac_IgnoresUnrelatedFieldsAndUsesData()
    {
        string good = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray());
        string json = "{\"hmac\":\"ignored\",\"x\":{\"data\":{\"hmac\":\"no\"}},\"data\":{\"other\":[1,{\"a\":2}],\"hmac\":\"vault:v7:" + good + "\"},\"warnings\":null}";
        Assert.Equal(Convert.FromBase64String(good), HashiCorpVaultPepper.ParseHmac(Encoding.UTF8.GetBytes(json), 7));
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.TemporaryRedirect)]
    public async Task HttpError_IsUnavailable_WithoutSecretsInMessage(HttpStatusCode status)
    {
        var handler = new FakeTransitHandler(1);
        handler.Override = (req, _) => Task.FromResult(FakeTransitHandler.Json(status,
            "{\"errors\":[\"echo " + FakeTransitHandler.Token + " " + Convert.ToBase64String(Input) + "\"]}"));

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());

        Assert.Contains(((int)status).ToString(), ex.Message);
        AssertNoSecrets(ex);
    }

    [Fact]
    public async Task WrongToken_IsUnavailable()
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler, configure: o => o.Token = "hvs.wrong");
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("v1", Input).AsTask());
        Assert.DoesNotContain("hvs.wrong", ex.ToString());
    }

    [Fact]
    public async Task NetworkFailure_IsUnavailable_WithInnerException()
    {
        var handler = new FakeTransitHandler(1) { Down = true };
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
        Assert.IsType<HttpRequestException>(ex.InnerException);
        AssertNoSecrets(ex);
    }

    [Fact]
    public async Task IOException_IsUnavailable()
    {
        var handler = new FakeTransitHandler(1);
        handler.Override = (_, _) => throw new System.IO.IOException("reset");
        await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
    }

    // Resilience handlers (Polly TimeoutRejectedException / BrokenCircuitException), custom DelegatingHandlers and a
    // disposed HttpClient throw types other than HttpRequestException; they must still surface as unavailable.
    public static IEnumerable<object[]> PipelineErrors() => new[]
    {
        new object[] { new InvalidOperationException("custom handler failure") },
        new object[] { new ObjectDisposedException("System.Net.Http.HttpClient") },
        new object[] { new TimeoutException("resilience timeout") },
        new object[] { new ResilienceRejectedLikeException() },
    };

    [Theory]
    [MemberData(nameof(PipelineErrors))]
    public async Task NonHttpPipelineException_IsUnavailable(Exception error)
    {
        var handler = new FakeTransitHandler(1);
        handler.Override = (_, _) => throw error;
        var pepper = Vault.Pepper(handler);

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("v1", Input).AsTask());
        Assert.Same(error, ex.InnerException);
        AssertNoSecrets(ex);
        Assert.Same(error, Assert.Throws<PepperUnavailableException>(() => pepper.Apply("v1", Input)).InnerException);
    }

    [Fact]
    public async Task NonHttpPipelineException_ThroughHasher_IsUnavailable()
    {
        var handler = new FakeTransitHandler(1);
        var hasher = Vault.Hasher(Vault.Pepper(handler));
        string hash = await hasher.HashAsync("correct horse battery staple");
        handler.Override = (_, _) => throw new InvalidOperationException("circuit open");
        await Assert.ThrowsAsync<PepperUnavailableException>(() => hasher.VerifyAsync("correct horse battery staple", hash).AsTask());
    }

    private sealed class ResilienceRejectedLikeException : Exception
    {
        public ResilienceRejectedLikeException() : base("The circuit is now open and is not allowing calls.") { }
    }

    [Fact]
    public async Task Timeout_IsUnavailable()
    {
        var handler = new FakeTransitHandler(1);
        handler.Override = async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            throw new InvalidOperationException("unreachable");
        };
        var pepper = Vault.Pepper(handler, configure: o => o.Timeout = TimeSpan.FromMilliseconds(100));

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("v1", Input).AsTask());
        Assert.Contains("timeout", ex.Message);
    }

    [Fact]
    public async Task Timeout_AlsoCoversSlowTokenProvider()
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler, configure: o =>
        {
            o.Token = null;
            o.TokenProvider = async ct => { await Task.Delay(Timeout.Infinite, ct); return "never"; };
            o.Timeout = TimeSpan.FromMilliseconds(100);
        });
        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("v1", Input).AsTask());
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task CallerCancellation_IsOperationCanceled_NotUnavailable()
    {
        var handler = new FakeTransitHandler(1);
        handler.Override = async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            throw new InvalidOperationException("unreachable");
        };
        var pepper = Vault.Pepper(handler);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        var ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pepper.ApplyAsync("v1", Input, cts.Token).AsTask());
        Assert.IsNotType<PepperUnavailableException>(ex);
    }

    [Fact]
    public async Task AlreadyCancelled_DoesNotCallVault()
    {
        var handler = new FakeTransitHandler(1);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input, new CancellationToken(true)).AsTask());
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task OversizedResponse_IsUnavailable()
    {
        var handler = new FakeTransitHandler(1);
        string huge = "{\"data\":{\"pad\":\"" + new string('a', HashiCorpVaultPepper.MaxResponseBytes) + "\"}}";
        handler.Override = (_, _) => Task.FromResult(FakeTransitHandler.Json(HttpStatusCode.OK, huge));
        await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
    }

    [Fact]
    public async Task OversizedResponse_WithoutContentLength_IsUnavailable()
    {
        var handler = new FakeTransitHandler(1);
        handler.Override = (_, _) =>
        {
            var content = new StreamContent(new EndlessStream());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        };
        await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
    }

    [Fact]
    public async Task ChunkedResponse_WithoutContentLength_Parses()
    {
        var handler = new FakeTransitHandler(1);
        byte[] mac = Enumerable.Range(100, 32).Select(i => (byte)i).ToArray();
        string json = "{\"data\":{\"pad\":\"" + new string(' ', 3000) + "\",\"hmac\":\"vault:v1:" + Convert.ToBase64String(mac) + "\"}}";
        handler.Override = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new TrickleStream(Encoding.UTF8.GetBytes(json))),
        });
        Assert.Equal(mac, await Vault.Pepper(handler).ApplyAsync("v1", Input));
    }

    [Fact]
    public async Task TokenProvider_IsCalledPerRequest()
    {
        var handler = new FakeTransitHandler(1);
        int calls = 0;
        var pepper = Vault.Pepper(handler, configure: o =>
        {
            o.Token = null;
            o.TokenProvider = _ => { Interlocked.Increment(ref calls); return Task.FromResult(FakeTransitHandler.Token); };
        });

        await pepper.ApplyAsync("v1", Input);
        await pepper.ApplyAsync("v1", Input);

        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task TokenProviderFailure_IsUnavailable()
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler, configure: o =>
        {
            o.Token = null;
            o.TokenProvider = _ => throw new InvalidOperationException("login failed");
        });
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("v1", Input).AsTask());
        Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("tok en")]
    [InlineData("tok\r\nX-Injected: 1")]
    public async Task TokenProviderInvalidToken_IsUnavailable(string? token)
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler, configure: o =>
        {
            o.Token = null;
            o.TokenProvider = _ => Task.FromResult(token!);
        });
        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("v1", Input).AsTask());
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public void IsKnownKey_ChecksConfiguredRange_WithoutNetwork()
    {
        var handler = new FakeTransitHandler();
        var pepper = Vault.Pepper(handler, 3, o => { o.MinKeyVersion = 2; o.MaxKeyVersion = 4; });

        Assert.Equal("v3", pepper.CurrentKeyId);
        Assert.False(pepper.IsKnownKey("v1"));
        Assert.True(pepper.IsKnownKey("v2"));
        Assert.True(pepper.IsKnownKey("v3"));
        Assert.True(pepper.IsKnownKey("v4"));
        Assert.False(pepper.IsKnownKey("v5"));
        foreach (string? bad in new[] { null, "", "v", "v0", "v03", "V3", "3", "v3 ", " v3", "v-3", "v+3", "v3a", "v99999999999", "v2147483648" })
            Assert.False(pepper.IsKnownKey(bad!), bad);
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData("v1", true, 1)]
    [InlineData("v2147483647", true, int.MaxValue)]
    [InlineData("v2147483648", false, 0)]
    [InlineData("v0", false, 0)]
    [InlineData("v007", false, 0)]
    [InlineData("w1", false, 0)]
    public void TryParseKeyId(string keyId, bool ok, int version)
    {
        Assert.Equal(ok, HashiCorpVaultPepper.TryParseKeyId(keyId, out int parsed));
        Assert.Equal(version, parsed);
    }

    [Fact]
    public void KeyIdFor_FormatsAndValidates()
    {
        Assert.Equal("v12", HashiCorpVaultPepper.KeyIdFor(12));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashiCorpVaultPepper.KeyIdFor(0));
    }

    [Fact]
    public async Task UnknownKey_ThrowsKeyNotFound_WithoutNetwork()
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => pepper.ApplyAsync("v2", Input).AsTask());
        await Assert.ThrowsAsync<KeyNotFoundException>(() => pepper.ApplyAsync(null!, Input).AsTask());
        Assert.Throws<KeyNotFoundException>(() => pepper.Apply("k1", Input));
        await Assert.ThrowsAsync<ArgumentNullException>(() => pepper.ApplyAsync("v1", null!).AsTask());
        Assert.Throws<ArgumentNullException>(() => pepper.Apply("v1", null!));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ConcurrentCalls_AreIndependent()
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler);
        byte[][] inputs = Enumerable.Range(0, 64).Select(i => Encoding.UTF8.GetBytes("pw-" + i)).ToArray();

        byte[][] macs = await Task.WhenAll(inputs.Select(i => pepper.ApplyAsync("v1", i).AsTask()));

        for (int i = 0; i < inputs.Length; i++)
            Assert.Equal(handler.Expected(1, inputs[i]), macs[i]);
    }

    [Fact]
    public void Constructor_RejectsNulls()
    {
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultPepper(null!, Vault.Options()));
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultPepper(new HttpClient(), null!));
    }

    public static IEnumerable<object[]> InvalidOptions()
    {
        var cases = new (string Name, Action<HashiCorpVaultPepperOptions> Configure)[]
        {
            ("no address", o => o.VaultAddress = null),
            ("relative address", o => o.VaultAddress = new Uri("/vault", UriKind.Relative)),
            ("http", o => o.VaultAddress = new Uri("http://vault.test:8200")),
            ("ftp", o => { o.VaultAddress = new Uri("ftp://vault.test"); o.AllowInsecureHttp = true; }),
            ("query", o => o.VaultAddress = new Uri("https://vault.test/?x=1")),
            ("fragment", o => o.VaultAddress = new Uri("https://vault.test/#x")),
            ("userinfo", o => o.VaultAddress = new Uri("https://user:pw@vault.test/")),
            ("empty mount", o => o.MountPath = ""),
            ("slash mount", o => o.MountPath = "/"),
            ("null mount", o => o.MountPath = null!),
            ("dotdot mount", o => o.MountPath = "../sys"),
            ("double slash mount", o => o.MountPath = "a//b"),
            ("query in mount", o => o.MountPath = "transit?x"),
            ("no key", o => o.KeyName = null),
            ("empty key", o => o.KeyName = ""),
            ("slash key", o => o.KeyName = "a/b"),
            ("dot key", o => o.KeyName = ".."),
            ("space key", o => o.KeyName = "a b"),
            ("no token", o => o.Token = null),
            ("both tokens", o => o.TokenProvider = _ => Task.FromResult("x")),
            ("empty token", o => o.Token = ""),
            ("token with newline", o => o.Token = "abc\r\nX-Evil: 1"),
            ("token with space", o => o.Token = "abc def"),
            ("token non-ascii", o => o.Token = "tökén"),
            ("namespace newline", o => o.Namespace = "ns\nX: 1"),
            ("empty namespace", o => o.Namespace = ""),
            ("long namespace", o => o.Namespace = new string('a', 257)),
            ("current zero", o => o.CurrentKeyVersion = 0),
            ("current negative", o => o.CurrentKeyVersion = -1),
            ("min zero", o => o.MinKeyVersion = 0),
            ("min above current", o => o.MinKeyVersion = 2),
            ("max below current", o => o.MaxKeyVersion = 0),
            ("zero timeout", o => o.Timeout = TimeSpan.Zero),
            ("negative timeout", o => o.Timeout = TimeSpan.FromSeconds(-1)),
            ("infinite timeout", o => o.Timeout = Timeout.InfiniteTimeSpan),
            ("huge timeout", o => o.Timeout = TimeSpan.FromHours(1)),
        };
        return cases.Select(c => new object[] { c.Name, c.Configure });
    }

    [Theory]
    [MemberData(nameof(InvalidOptions))]
    public void Constructor_RejectsInvalidOptions(string name, Action<HashiCorpVaultPepperOptions> configure)
    {
        var ex = Assert.Throws<ArgumentException>(() => new HashiCorpVaultPepper(new HttpClient(), Vault.Options(1, configure)));
        Assert.Equal("options", ex.ParamName);
        Assert.DoesNotContain(FakeTransitHandler.Token, ex.Message);
        _ = name;
    }

    [Fact]
    public void Constructor_AllowsHttpOnlyWhenOptedIn()
    {
        var pepper = new HashiCorpVaultPepper(new HttpClient(), Vault.Options(1, o =>
        {
            o.VaultAddress = new Uri("http://127.0.0.1:8200");
            o.AllowInsecureHttp = true;
        }));
        Assert.Equal("http://127.0.0.1:8200/v1/transit/hmac/password-pepper/sha2-256", pepper.Endpoint.AbsoluteUri);
    }

    [Fact]
    public async Task Constructor_CopiesOptions()
    {
        var handler = new FakeTransitHandler(1);
        var options = Vault.Options();
        var pepper = new HashiCorpVaultPepper(new HttpClient(handler), options);
        options.CurrentKeyVersion = 9;
        options.Token = "changed";
        options.KeyName = "other";

        Assert.Equal("v1", pepper.CurrentKeyId);
        Assert.Equal(handler.Expected(1, Input), await pepper.ApplyAsync("v1", Input));
    }

    private static void AssertNoSecrets(Exception ex)
    {
        string all = ex.ToString();
        Assert.DoesNotContain(FakeTransitHandler.Token, all);
        Assert.DoesNotContain(Convert.ToBase64String(Input), all);
        Assert.DoesNotContain("correct horse", all);
    }

    private static HttpResponseMessage Ok(string hmac) =>
        FakeTransitHandler.Json(HttpStatusCode.OK, "{\"data\":{\"hmac\":\"" + hmac + "\"}}");

    private sealed class EndlessStream : System.IO.Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) { Array.Fill(buffer, (byte)' ', offset, count); return count; }
        public override long Seek(long offset, System.IO.SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>Returns at most 7 bytes per read, to exercise buffer growth.</summary>
    private sealed class TrickleStream(byte[] data) : System.IO.MemoryStream(data)
    {
        public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, 7));
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            Task.FromResult(Read(buffer, offset, count));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, 7)], cancellationToken);
    }
}
