using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.HashiCorpVault;

namespace Masterly.Hash.Pepper.HashiCorpVault.Tests;

/// <summary>
/// Precise assertions on messages, boundaries, buffer handling and await behaviour, so that a wrong
/// implementation fails a test rather than just being executed by one.
/// </summary>
public class MutationTests
{
    private const string UnexpectedMessage = "HashiCorp Vault returned an unexpected Transit HMAC response.";
    private const string OversizedMessage = "HashiCorp Vault returned an oversized response.";
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");
    private static readonly byte[] Mac = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private static readonly string MacB64 = Convert.ToBase64String(Mac);

    private static string Response(string hmac) => "{\"data\":{\"hmac\":\"" + hmac + "\"}}";

    private static byte[] Parse(string json, int expectedVersion) =>
        HashiCorpVaultPepper.ParseHmac(Encoding.UTF8.GetBytes(json), expectedVersion);

    private static void AssertParseUnexpected(string json, int expectedVersion)
    {
        var ex = Assert.Throws<PepperUnavailableException>(() => Parse(json, expectedVersion));
        Assert.Equal(UnexpectedMessage, ex.Message);
    }

    // ---------------------------------------------------------------- constructor validation

    public static IEnumerable<object[]> InvalidOptionMessages()
    {
        var cases = new (string Expected, Action<HashiCorpVaultPepperOptions> Configure)[]
        {
            ("VaultAddress must be an absolute URI.", o => o.VaultAddress = null),
            ("VaultAddress must use https (set AllowInsecureHttp only for local development).", o => o.VaultAddress = new Uri("http://vault.test")),
            ("VaultAddress must not contain user info, a query or a fragment.", o => o.VaultAddress = new Uri("https://vault.test/?x=1")),
            ("MountPath is required.", o => o.MountPath = null!),
            ("MountPath is required.", o => o.MountPath = ""),
            ("MountPath is required.", o => o.MountPath = "//"),
            ("MountPath segments may contain only letters, digits, '.', '_' and '-'.", o => o.MountPath = "a b"),
            ("MountPath segments may contain only letters, digits, '.', '_' and '-'.", o => o.MountPath = "."),
            ("MountPath segments may contain only letters, digits, '.', '_' and '-'.", o => o.MountPath = "a/./b"),
            ("MountPath segments may contain only letters, digits, '.', '_' and '-'.", o => o.MountPath = new string('m', 129)),
            ("KeyName is required and may contain only letters, digits, '.', '_' and '-'.", o => o.KeyName = null),
            ("MountPath segments may contain only letters, digits, '.', '_' and '-'.", o => o.MountPath = "a/../b"),
            ("KeyName is required and may contain only letters, digits, '.', '_' and '-'.", o => o.KeyName = "."),
            ("KeyName is required and may contain only letters, digits, '.', '_' and '-'.", o => o.KeyName = ".."),
            ("KeyName is required and may contain only letters, digits, '.', '_' and '-'.", o => o.KeyName = new string('k', 129)),
            ("Set exactly one of Token and TokenProvider.", o => o.Token = null),
            ("Set exactly one of Token and TokenProvider.", o => o.TokenProvider = _ => Task.FromResult("x")),
            ("Token must be non-empty printable ASCII without spaces.", o => o.Token = "a b"),
            ("Token must be non-empty printable ASCII without spaces.", o => o.Token = new string('t', 8193)),
            ("Token must be non-empty printable ASCII without spaces.", o => o.Token = "a\u007fb"),
            ("Namespace must be 1-256 printable ASCII characters without spaces.", o => o.Namespace = new string('n', 257)),
            ("Namespace must be 1-256 printable ASCII characters without spaces.", o => o.Namespace = ""),
            ("CurrentKeyVersion must be at least 1.", o => o.CurrentKeyVersion = 0),
            ("CurrentKeyVersion must be at least 1.", o => o.CurrentKeyVersion = -1),
            ("MinKeyVersion must be between 1 and CurrentKeyVersion.", o => o.MinKeyVersion = 0),
            ("MinKeyVersion must be between 1 and CurrentKeyVersion.", o => o.MinKeyVersion = 2),
            ("MaxKeyVersion must not be below CurrentKeyVersion.", o => o.MaxKeyVersion = 0),
            ("Timeout must be greater than zero and at most 10 minutes.", o => o.Timeout = TimeSpan.Zero),
            ("Timeout must be greater than zero and at most 10 minutes.", o => o.Timeout = TimeSpan.FromMinutes(10) + TimeSpan.FromTicks(1)),
        };
        return cases.Select(c => new object[] { c.Expected, c.Configure });
    }

    [Theory]
    [MemberData(nameof(InvalidOptionMessages))]
    public void Constructor_RejectsInvalidOptions_WithTheSpecificMessage(string expected, Action<HashiCorpVaultPepperOptions> configure)
    {
        var ex = Assert.Throws<ArgumentException>(() => new HashiCorpVaultPepper(new HttpClient(), Vault.Options(1, configure)));
        Assert.Equal("options", ex.ParamName);
        Assert.Equal(expected + " (Parameter 'options')", ex.Message);
    }

    public static IEnumerable<object[]> BoundaryOptions()
    {
        var cases = new (string Name, Action<HashiCorpVaultPepperOptions> Configure)[]
        {
            ("namespace of exactly 256", o => o.Namespace = new string('n', 256)),
            ("timeout of exactly 10 minutes", o => o.Timeout = TimeSpan.FromMinutes(10)),
            ("timeout of one tick", o => o.Timeout = TimeSpan.FromTicks(1)),
            ("token of exactly 8192", o => o.Token = new string('t', 8192)),
            ("token with tilde and bang", o => o.Token = "!a~"),
            ("key name of exactly 128", o => o.KeyName = new string('k', 128)),
            ("mount segment of exactly 128", o => o.MountPath = new string('m', 128) + "/transit"),
            ("key name with digit zero", o => o.KeyName = "key0"),
            ("mount with digits zero and nine", o => o.MountPath = "t0/t9"),
            ("max equal to current", o => o.MaxKeyVersion = 1),
        };
        return cases.Select(c => new object[] { c.Name, c.Configure });
    }

    [Theory]
    [MemberData(nameof(BoundaryOptions))]
    public void Constructor_AcceptsValuesAtTheLimits(string name, Action<HashiCorpVaultPepperOptions> configure)
    {
        var pepper = new HashiCorpVaultPepper(new HttpClient(), Vault.Options(1, configure));
        Assert.Equal("v1", pepper.CurrentKeyId);
        _ = name;
    }

    [Fact]
    public void Constructor_LimitSizedSegments_AppearInEndpoint()
    {
        string key = new string('k', 128);
        string mount = new string('m', 128);
        var pepper = new HashiCorpVaultPepper(new HttpClient(), Vault.Options(1, o => { o.KeyName = key; o.MountPath = mount; }));
        Assert.Equal("https://vault.test:8200/v1/" + mount + "/hmac/" + key + "/sha2-256", pepper.Endpoint.AbsoluteUri);
    }

    [Fact]
    public void KeyIdFor_Zero_ThrowsWithParamNameValueAndMessage()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => HashiCorpVaultPepper.KeyIdFor(0));
        Assert.Equal("version", ex.ParamName);
        Assert.Equal(0, ex.ActualValue);
        Assert.StartsWith("Transit key versions start at 1.", ex.Message);
        Assert.Equal("v1", HashiCorpVaultPepper.KeyIdFor(1));
    }

    // ---------------------------------------------------------------- TryParseKeyId digits

    [Theory]
    [InlineData("v9", true, 9)]
    [InlineData("v10", true, 10)]
    [InlineData("v19", true, 19)]
    [InlineData("v90", true, 90)]
    [InlineData("v1234567890", true, 1234567890)]
    [InlineData("v1a", false, 0)]
    [InlineData("v1/", false, 0)]   // '/' is just below '0'
    [InlineData("v1:", false, 0)]   // ':' is just above '9'
    [InlineData("v12345678901", false, 0)]
    public void TryParseKeyId_DigitBoundaries(string keyId, bool ok, int version)
    {
        Assert.Equal(ok, HashiCorpVaultPepper.TryParseKeyId(keyId, out int parsed));
        Assert.Equal(version, parsed);
    }

    // ---------------------------------------------------------------- ApplyAsync key range and errors

    [Fact]
    public async Task ApplyAsync_VersionBelowMinimum_IsKeyNotFound_WithoutNetwork()
    {
        var handler = new FakeTransitHandler(1, 2, 3);
        var pepper = Vault.Pepper(handler, 3, o => o.MinKeyVersion = 2);

        var ex = await Assert.ThrowsAsync<KeyNotFoundException>(() => pepper.ApplyAsync("v1", Input).AsTask());
        Assert.Equal("Unknown pepper key 'v1'.", ex.Message);
        var above = await Assert.ThrowsAsync<KeyNotFoundException>(() => pepper.ApplyAsync("v4", Input).AsTask());
        Assert.Equal("Unknown pepper key 'v4'.", above.Message);
        Assert.Empty(handler.Requests);

        Assert.Equal(handler.Expected(2, Input), await pepper.ApplyAsync("v2", Input));
    }

    [Fact]
    public async Task NetworkFailure_HasReachabilityMessage()
    {
        var handler = new FakeTransitHandler(1) { Down = true };
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
        Assert.Equal("HashiCorp Vault could not be reached.", ex.Message);
    }

    [Fact]
    public async Task IOException_HasConnectionMessage_AndInnerException()
    {
        var io = new IOException("reset");
        var handler = new FakeTransitHandler(1) { Override = (_, _) => throw io };
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
        Assert.Equal("The connection to HashiCorp Vault failed.", ex.Message);
        Assert.Same(io, ex.InnerException);
    }

    [Fact]
    public async Task OtherPipelineException_HasRequestFailedMessage()
    {
        var handler = new FakeTransitHandler(1) { Override = (_, _) => throw new InvalidOperationException("x") };
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
        Assert.Equal("HashiCorp Vault request failed.", ex.Message);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, "403")]
    [InlineData(HttpStatusCode.InternalServerError, "500")]
    public async Task HttpError_HasExactMessage(HttpStatusCode status, string code)
    {
        var handler = new FakeTransitHandler(1) { Override = (_, _) => Task.FromResult(FakeTransitHandler.Json(status, "{}")) };
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
        Assert.Equal("HashiCorp Vault refused the Transit HMAC request with HTTP " + code + ".", ex.Message);
    }

    [Fact]
    public void Apply_NullInput_IsRejectedSynchronously_BeforeAnyAsyncWorkIsScheduled()
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler);

        var ex = Assert.Throws<ArgumentNullException>(() => pepper.Apply("v1", null!));

        Assert.Equal("input", ex.ParamName);
        // Thrown by Apply's own guard, not rethrown from ApplyAsync after a hop through Task.Run.
        Assert.NotNull(ex.StackTrace);
        Assert.DoesNotContain("ApplyAsync", ex.StackTrace, StringComparison.Ordinal);
        Assert.DoesNotContain("End of stack trace from previous location", ex.StackTrace, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }

    // ---------------------------------------------------------------- ParseHmac structure

    [Fact]
    public void ParseHmac_HmacOutsideData_IsIgnored()
    {
        AssertParseUnexpected("{\"x\":{\"hmac\":\"vault:v1:" + MacB64 + "\"}}", 1);
        AssertParseUnexpected("{\"x\":{\"hmac\":\"vault:v1:" + MacB64 + "\"},\"data\":{}}", 1);
    }

    [Fact]
    public void ParseHmac_OtherStringFieldsInData_DoNotReplaceHmac()
    {
        string json = "{\"data\":{\"hmac\":\"vault:v1:" + MacB64 + "\",\"note\":\"zzz\",\"key\":\"vault:v1:" + Convert.ToBase64String(new byte[32]) + "\"}}";
        Assert.Equal(Mac, Parse(json, 1));
    }

    [Fact]
    public void ParseHmac_DuplicateHmac_LastOneWins()
    {
        string json = "{\"data\":{\"hmac\":\"vault:v1:" + Convert.ToBase64String(new byte[32]) + "\",\"hmac\":\"vault:v1:" + MacB64 + "\"}}";
        Assert.Equal(Mac, Parse(json, 1));
    }

    private static string Nested(int arrays) =>
        "{\"x\":" + new string('[', arrays) + new string(']', arrays) + ",\"data\":{\"hmac\":\"vault:v1:" + MacB64 + "\"}}";

    [Fact]
    public void ParseHmac_NestingDepth_IsLimitedTo16()
    {
        // The root object is depth 1, so 15 nested arrays reach the limit of 16 and 16 arrays exceed it.
        Assert.Equal(Mac, Parse(Nested(15), 1));
        AssertParseUnexpected(Nested(16), 1);
        AssertParseUnexpected(Nested(30), 1);
    }

    // ---------------------------------------------------------------- ParseHmac version prefix

    [Theory]
    [InlineData(9)]
    [InlineData(10)]
    [InlineData(12)]
    [InlineData(19)]
    [InlineData(90)]
    [InlineData(1234567890)]
    [InlineData(int.MaxValue)]
    public void ParseHmac_AcceptsMultiDigitVersions(int version)
    {
        Assert.Equal(Mac, Parse(Response("vault:v" + version + ":" + MacB64), version));
    }

    [Theory]
    [InlineData("vault:v:", 0)]                  // no digits at all
    [InlineData("vault:v:", 1)]
    [InlineData("vault:v1", 1)]                  // no colon
    [InlineData("vault:v12345678901:", 1)]       // 11 digits
    [InlineData("vault:v1/:", 9)]                // '/' (just below '0') would compute 1*10-1 = 9
    [InlineData("vault:v1:x:", 1)]               // not a digit after the colon: base64 check
    [InlineData("vault:v1;:", 21)]               // ';' - '0' = 11 would compute 1*10+11 = 21
    [InlineData("vault:v1::", 1)]
    public void ParseHmac_MalformedVersion_IsUnexpected(string prefix, int expected)
    {
        AssertParseUnexpected(Response(prefix + MacB64), expected);
    }

    [Fact]
    public void ParseHmac_NonDigitThatWouldComputeTheExpectedVersion_IsUnexpected()
    {
        // '/' - '0' = -1, so "2/" would compute 2*10 - 1 = 19 if non-digits were not rejected.
        AssertParseUnexpected(Response("vault:v2/:" + MacB64), 19);
    }

    [Fact]
    public void ParseHmac_DifferentVersion_HasVersionMessage()
    {
        var ex = Assert.Throws<PepperUnavailableException>(() => Parse(Response("vault:v12:" + MacB64), 21));
        Assert.Equal("HashiCorp Vault answered with a different key version than requested.", ex.Message);
    }

    // ---------------------------------------------------------------- ParseHmac base64 payload

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void ParseHmac_Base64OfTheRightLengthButWrongByteCount_IsUnexpected(int bytes)
    {
        string b64 = Convert.ToBase64String(Enumerable.Range(1, bytes).Select(i => (byte)i).ToArray());
        Assert.Equal(44, b64.Length);
        AssertParseUnexpected(Response("vault:v1:" + b64), 1);
    }

    [Theory]
    [InlineData(" ", "")]
    [InlineData("", " ")]
    public void ParseHmac_Base64WithWhitespace_IsUnexpected(string before, string after)
    {
        AssertParseUnexpected(Response("vault:v1:" + before + MacB64 + after), 1);
        string split = MacB64.Substring(0, 20) + " " + MacB64.Substring(20);
        AssertParseUnexpected(Response("vault:v1:" + split), 1);
    }

    // ---------------------------------------------------------------- response size limit and buffers

    [Fact]
    public async Task DeclaredOversizedResponse_IsRejectedEvenWhenItContainsAValidHmac()
    {
        string prefix = "{\"data\":{\"hmac\":\"vault:v1:" + MacB64 + "\"},\"pad\":\"";
        string json = prefix + new string('a', HashiCorpVaultPepper.MaxResponseBytes + 1 - prefix.Length - 2) + "\"}";
        Assert.Equal(HashiCorpVaultPepper.MaxResponseBytes + 1, json.Length);
        var handler = new FakeTransitHandler(1) { Override = (_, _) => Task.FromResult(FakeTransitHandler.Json(HttpStatusCode.OK, json)) };

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());

        Assert.Equal(OversizedMessage, ex.Message);
    }

    [Fact]
    public async Task DeclaredLength_SizesTheBufferWithOneSpareByte()
    {
        byte[] body = Encoding.UTF8.GetBytes(Response("vault:v1:" + MacB64));
        var stream = new RecordingStream(body);
        var pepper = PepperReturning(new RecordingContent(stream, declaredLength: body.Length));

        Assert.Equal(Mac, await pepper.ApplyAsync("v1", Input));

        Assert.Equal(new[] { body.Length + 1, 1 }, stream.Counts);
    }

    [Fact]
    public async Task DeclaredZeroLength_UsesTheDefaultBuffer()
    {
        var stream = new RecordingStream(Array.Empty<byte>());
        var pepper = PepperReturning(new RecordingContent(stream, declaredLength: 0));

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("v1", Input).AsTask());

        Assert.Equal(UnexpectedMessage, ex.Message);
        Assert.Equal(new[] { 1024 }, stream.Counts);
    }

    [Fact]
    public async Task UnknownLength_GrowsTheBufferByDoubling_AndZeroesEveryBuffer()
    {
        string prefix = "{\"data\":{\"hmac\":\"vault:v1:" + MacB64 + "\"},\"pad\":\"";
        string json = prefix + new string('a', 1500 - prefix.Length - 2) + "\"}";
        byte[] body = Encoding.UTF8.GetBytes(json);
        Assert.Equal(1500, body.Length);
        var stream = new RecordingStream(body);
        var pepper = PepperReturning(new RecordingContent(stream, declaredLength: null));

        Assert.Equal(Mac, await pepper.ApplyAsync("v1", Input));

        Assert.Equal(new[] { 1024, 1024, 548 }, stream.Counts);
        Assert.Equal(new[] { 1024, 2048 }, stream.Buffers.Select(b => b.Length));
        Assert.All(stream.Buffers, AssertZeroed);
    }

    [Fact]
    public async Task DeclaredLength_ZeroesTheReadBuffer()
    {
        byte[] body = Encoding.UTF8.GetBytes(Response("vault:v1:" + MacB64));
        var stream = new RecordingStream(body);
        var pepper = PepperReturning(new RecordingContent(stream, declaredLength: body.Length));

        Assert.Equal(Mac, await pepper.ApplyAsync("v1", Input));

        byte[] buffer = Assert.Single(stream.Buffers);
        Assert.Equal(body.Length + 1, buffer.Length);
        AssertZeroed(buffer);
    }

    [Fact]
    public async Task OversizedUnknownLength_ZeroesEveryBufferBeforeThrowing()
    {
        var stream = new RecordingStream(null);
        var pepper = PepperReturning(new RecordingContent(stream, declaredLength: null));

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("v1", Input).AsTask());

        Assert.Equal(OversizedMessage, ex.Message);
        Assert.Equal(HashiCorpVaultPepper.MaxResponseBytes + 1, stream.Buffers[^1].Length);
        Assert.Equal(new[] { 1024, 2048, 4096, 8192, 16384, 32768, 65536, 65537 }, stream.Buffers.Select(b => b.Length));
        Assert.All(stream.Buffers, AssertZeroed);
    }

    [Fact]
    public async Task RequestBody_IsZeroedAfterTheCall()
    {
        var capture = new CapturingStream();
        var http = new HttpClient(new DelegateHandler(async (req, ct) =>
        {
            await req.Content!.CopyToAsync(capture, ct).ConfigureAwait(false);
            return FakeTransitHandler.Json(HttpStatusCode.OK, Response("vault:v1:" + MacB64));
        }));
        var pepper = new HashiCorpVaultPepper(http, Vault.Options());

        Assert.Equal(Mac, await pepper.ApplyAsync("v1", Input));

        string expected = "{\"input\":\"" + Convert.ToBase64String(Input) + "\",\"key_version\":1}";
        Assert.Equal(expected, Encoding.ASCII.GetString(capture.Snapshot!));
        Assert.NotNull(capture.Captured);
        Assert.Equal(expected.Length, capture.Captured!.Length);
        AssertZeroed(capture.Captured);
    }

    // ---------------------------------------------------------------- ConfigureAwait(false) throughout

    public enum AsyncPoint { TokenProvider, Send, OpenContent, ReadContent }

    [Theory]
    [InlineData(AsyncPoint.TokenProvider)]
    [InlineData(AsyncPoint.Send)]
    [InlineData(AsyncPoint.OpenContent)]
    [InlineData(AsyncPoint.ReadContent)]
    public async Task ApplyAsync_NeverResumesOnTheCallersSynchronizationContext(AsyncPoint point)
    {
        byte[] body = Encoding.UTF8.GetBytes(Response("vault:v1:" + MacB64));
        var http = new HttpClient(new DelegateHandler(async (_, ct) =>
        {
            if (point == AsyncPoint.Send)
                await Task.Delay(20, ct).ConfigureAwait(false);
            var stream = new RecordingStream(body, asyncRead: point == AsyncPoint.ReadContent);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new RecordingContent(stream, body.Length, asyncOpen: point == AsyncPoint.OpenContent),
            };
        }));
        var options = Vault.Options();
        if (point == AsyncPoint.TokenProvider)
        {
            options.Token = null;
            options.TokenProvider = async ct =>
            {
                await Task.Delay(20, ct).ConfigureAwait(false);
                return FakeTransitHandler.Token;
            };
        }
        var pepper = new HashiCorpVaultPepper(http, options);

        var context = new CountingSynchronizationContext();
        SynchronizationContext? previous = SynchronizationContext.Current;
        Task<byte[]> pending;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            pending = pepper.ApplyAsync("v1", Input).AsTask();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }

        Assert.False(pending.IsCompleted, "the configured async point should make the call asynchronous");
        Assert.Equal(Mac, await pending);
        Assert.Equal(0, context.Posts);
    }

    // ---------------------------------------------------------------- helpers

    private static void AssertZeroed(byte[] buffer) => Assert.DoesNotContain(buffer, x => x != 0);

    private static HashiCorpVaultPepper PepperReturning(HttpContent content) =>
        new(new HttpClient(new DelegateHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content }))),
            Vault.Options());

    private sealed class DelegateHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }

    private sealed class CountingSynchronizationContext : SynchronizationContext
    {
        private int _posts;

        public int Posts => Volatile.Read(ref _posts);

        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }

        public override void Send(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            d(state);
        }
    }

    /// <summary>Response content that hands the pepper a <see cref="RecordingStream"/> directly.</summary>
    private sealed class RecordingContent(Stream stream, long? declaredLength, bool asyncOpen = false) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream target, System.Net.TransportContext? context) => stream.CopyToAsync(target);

        protected override bool TryComputeLength(out long length)
        {
            length = declaredLength ?? 0;
            return declaredLength.HasValue;
        }

        protected override async Task<Stream> CreateContentReadStreamAsync()
        {
            if (asyncOpen)
                await Task.Delay(20).ConfigureAwait(false);
            return stream;
        }

        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken) => CreateContentReadStreamAsync();
    }

    /// <summary>
    /// Read-only stream over <c>data</c> (or endless 'a' bytes when null) that records the count requested by every
    /// read and every distinct buffer it was handed.
    /// </summary>
    private sealed class RecordingStream(byte[]? data, bool asyncRead = false) : Stream
    {
        private int _position;

        public List<int> Counts { get; } = new();

        public List<byte[]> Buffers { get; } = new();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            lock (Counts)
            {
                Counts.Add(count);
                if (!Buffers.Any(b => ReferenceEquals(b, buffer)))
                    Buffers.Add(buffer);
            }
            if (data == null)
            {
                Array.Fill(buffer, (byte)'a', offset, count);
                return count;
            }
            int n = Math.Min(count, data.Length - _position);
            Buffer.BlockCopy(data, _position, buffer, offset, n);
            _position += n;
            return n;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (asyncRead && Counts.Count == 0)
                await Task.Delay(20, cancellationToken).ConfigureAwait(false);
            return Read(buffer, offset, count);
        }
    }

    /// <summary>Write-only stream that keeps a reference to (and a copy of) the array it is written from.</summary>
    private sealed class CapturingStream : Stream
    {
        public byte[]? Captured { get; private set; }

        public byte[]? Snapshot { get; private set; }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            Captured = buffer;
            Snapshot = buffer.AsSpan(offset, count).ToArray();
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment))
                throw new NotSupportedException();
            Write(segment.Array!, segment.Offset, segment.Count);
            return ValueTask.CompletedTask;
        }
    }
}
