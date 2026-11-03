using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Masterly.Hash.Pwned.Internal;

namespace Masterly.Hash.Pwned.Tests;

/// <summary>
/// Tests written to kill specific Stryker mutants: exact boundaries, exact messages, LRU bookkeeping,
/// allocation bounds and ConfigureAwait(false) on every await.
/// </summary>
public class MutationTests
{
    private const string PasswordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private static PwnedPasswordsClient Create(FakeRangeApi api, Action<PwnedPasswordsOptions>? configure = null)
    {
        var options = new PwnedPasswordsOptions();
        configure?.Invoke(options);
        return new PwnedPasswordsClient(api.CreateClient(), options);
    }

    private static PwnedPasswordsClient Throwing(FakeRangeApi api) =>
        Create(api, o => o.FailureMode = PwnedPasswordsFailureMode.Throw);

    private static FakeRangeApi WithContent(Func<HttpContent> content) =>
        new((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content() }));

    // ---- PwnedHash.HexValue ----

    [Fact]
    public void Lowercase_hex_digits_a_to_f_parse_to_their_values()
    {
        // 'a' is the lower boundary of the lowercase range; the existing vectors never contain it.
        byte[] lower = Encoding.ASCII.GetBytes("abcdefabcdefabcdefabcdefabcdefabcde");
        byte[] upper = Encoding.ASCII.GetBytes("ABCDEFABCDEFABCDEFABCDEFABCDEFABCDE");
        var a = new byte[PwnedHash.SuffixBytes];
        var b = new byte[PwnedHash.SuffixBytes];

        Assert.True(PwnedHash.TryParseSuffix(lower, 0, lower.Length, a, 0));
        Assert.True(PwnedHash.TryParseSuffix(upper, 0, upper.Length, b, 0));
        Assert.Equal(b, a);
        Assert.Equal(0xAB, a[0]);
        Assert.Equal(0xE0, a[17]);

        byte[] single = Encoding.ASCII.GetBytes("a0000000000000000000000000000000000");
        var c = new byte[PwnedHash.SuffixBytes];
        Assert.True(PwnedHash.TryParseSuffix(single, 0, single.Length, c, 0));
        Assert.Equal(0xA0, c[0]);
    }

    [Theory]
    [InlineData('g')]
    [InlineData('z')]
    [InlineData('W')]
    [InlineData('Z')]
    [InlineData('`')]
    [InlineData('_')]
    [InlineData('@')]
    [InlineData('/')]
    [InlineData(':')]
    public void Non_hex_characters_around_the_letter_ranges_are_rejected(char bad)
    {
        byte[] source = Encoding.ASCII.GetBytes(bad + PasswordSuffix[1..]);
        Assert.False(PwnedHash.TryParseSuffix(source, 0, source.Length, new byte[PwnedHash.SuffixBytes], 0));
    }

    [Fact]
    public void Suffix_is_parsed_at_the_destination_offset()
    {
        byte[] source = Encoding.ASCII.GetBytes("xx" + PasswordSuffix);
        var destination = new byte[PwnedHash.SuffixBytes * 2];
        Assert.True(PwnedHash.TryParseSuffix(source, 2, PwnedHash.SuffixLength, destination, PwnedHash.SuffixBytes));
        Assert.All(destination.Take(PwnedHash.SuffixBytes), b => Assert.Equal(0, b));
        Assert.Equal(PwnedHashTests.Pack(PasswordSuffix), destination.Skip(PwnedHash.SuffixBytes).ToArray());
    }

    // ---- RangeResponse ----

    [Fact]
    public void Body_starting_with_a_bare_line_feed_is_accepted()
    {
        byte[] body = Encoding.ASCII.GetBytes("\n" + PasswordSuffix + ":3");
        Assert.True(RangeResponse.TryParse(body, body.Length, out RangeResponse? range));
        Assert.Equal(3, range!.Lookup(PwnedHashTests.Pack(PasswordSuffix)));
    }

    [Theory]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD:3")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FDG:3")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\nZZ:1")]
    public void Bad_suffix_makes_TryParse_return_false_with_no_response(string text)
    {
        byte[] body = Encoding.ASCII.GetBytes(text);
        Assert.False(RangeResponse.TryParse(body, body.Length, out RangeResponse? range));
        Assert.Null(range);
    }

    [Fact]
    public void Parse_allocates_no_more_than_the_capacity_estimate_requires()
    {
        // Densest valid layout: 35 hex + ':' + 1 digit, LF separated. The working arrays are sized from
        // length / 37 + 1 entries (about 26 bytes each) and then trimmed to the real entry count.
        const int entries = 10_000;
        byte[] body = Encoding.ASCII.GetBytes(string.Join("\n", Enumerable.Range(0, entries).Select(i => i.ToString("X35") + ":1")));
        Assert.True(RangeResponse.TryParse(body, body.Length, out _)); // warm up (JIT, type loading)

        long before = GC.GetAllocatedBytesForCurrentThread();
        Assert.True(RangeResponse.TryParse(body, body.Length, out RangeResponse? range));
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(entries, range!.Count);
        long capacity = body.Length / (PwnedHash.SuffixLength + 2) + 1;
        long expected = (capacity + entries) * (PwnedHash.SuffixBytes + sizeof(long));
        Assert.InRange(allocated, expected, expected + 8 * 1024);
    }

    // ---- RangeCache ----

    [Fact]
    public void Cache_of_one_entry_is_allowed_and_holds_the_latest()
    {
        var cache = new RangeCache(1, TimeSpan.FromHours(1));
        RangeResponse a = EmptyRange(), b = EmptyRange();
        cache.Set("00000", a);
        Assert.True(cache.TryGet("00000", out RangeResponse? hit));
        Assert.Same(a, hit);

        cache.Set("00001", b);
        Assert.Equal(1, cache.Count);
        Assert.False(cache.TryGet("00000", out _));
        Assert.True(cache.TryGet("00001", out hit));
        Assert.Same(b, hit);

        Assert.Equal("maxEntries", Assert.Throws<ArgumentOutOfRangeException>(() => new RangeCache(0, TimeSpan.FromHours(1))).ParamName);
        Assert.Equal("ttl", Assert.Throws<ArgumentOutOfRangeException>(() => new RangeCache(1, TimeSpan.Zero)).ParamName);
    }

    [Fact]
    public void Expired_entry_is_removed_from_the_lru_list_too()
    {
        // A stale list node left behind by an expired lookup would later evict the re-added live entry.
        TimeSpan now = TimeSpan.Zero;
        var cache = new RangeCache(2, TimeSpan.FromSeconds(30), () => now);
        cache.Set("AAAAA", EmptyRange());        // expires at 30
        now = TimeSpan.FromSeconds(10);
        cache.Set("BBBBB", EmptyRange());        // expires at 40
        now = TimeSpan.FromSeconds(35);
        Assert.False(cache.TryGet("AAAAA", out _));
        Assert.Equal(1, cache.Count);

        cache.Set("AAAAA", EmptyRange());        // most recent
        cache.Set("CCCCC", EmptyRange());        // evicts the least recently used live entry: BBBBB

        Assert.Equal(2, cache.Count);
        Assert.True(cache.TryGet("AAAAA", out _));
        Assert.True(cache.TryGet("CCCCC", out _));
        Assert.False(cache.TryGet("BBBBB", out _));
    }

    [Fact]
    public void Replacing_an_entry_makes_it_most_recent_and_does_not_evict_others()
    {
        var cache = new RangeCache(2, TimeSpan.FromHours(1));
        cache.Set("AAAAA", EmptyRange());
        cache.Set("BBBBB", EmptyRange());
        RangeResponse replacement = EmptyRange();
        cache.Set("AAAAA", replacement);   // replace: nothing else may be evicted

        Assert.Equal(2, cache.Count);
        Assert.True(cache.TryGet("BBBBB", out _));
        Assert.True(cache.TryGet("AAAAA", out RangeResponse? hit));
        Assert.Same(replacement, hit);
    }

    [Fact]
    public void Replaced_entry_is_evicted_by_recency_of_its_latest_set()
    {
        var cache = new RangeCache(2, TimeSpan.FromHours(1));
        cache.Set("AAAAA", EmptyRange());
        cache.Set("BBBBB", EmptyRange());
        cache.Set("AAAAA", EmptyRange());  // AAAAA is now the most recent
        cache.Set("CCCCC", EmptyRange());  // evicts BBBBB

        Assert.Equal(2, cache.Count);
        Assert.False(cache.TryGet("BBBBB", out _));
        Assert.True(cache.TryGet("AAAAA", out _));
        Assert.True(cache.TryGet("CCCCC", out _));
    }

    [Fact]
    public void Clear_also_forgets_recency_so_later_evictions_are_correct()
    {
        var cache = new RangeCache(2, TimeSpan.FromHours(1));
        cache.Set("AAAAA", EmptyRange());
        cache.Clear();
        cache.Set("BBBBB", EmptyRange());
        cache.Set("AAAAA", EmptyRange());  // most recent
        cache.Set("CCCCC", EmptyRange());  // evicts BBBBB

        Assert.Equal(2, cache.Count);
        Assert.False(cache.TryGet("BBBBB", out _));
        Assert.True(cache.TryGet("AAAAA", out _));
        Assert.True(cache.TryGet("CCCCC", out _));
    }

    [Fact]
    public void Default_clock_is_the_monotonic_stopwatch_time()
    {
        // On Windows Stopwatch.Frequency usually equals TimeSpan.TicksPerSecond, so the conversion factor is 1;
        // elsewhere (Linux: 1 GHz) a wrong conversion shows up immediately.
        MethodInfo now = typeof(RangeCache).GetMethod("MonotonicNow", BindingFlags.NonPublic | BindingFlags.Static)!;
        TimeSpan before = Stopwatch.GetElapsedTime(0);
        var value = (TimeSpan)now.Invoke(null, null)!;
        TimeSpan after = Stopwatch.GetElapsedTime(0);
        Assert.InRange(value, before - TimeSpan.FromTicks(1), after + TimeSpan.FromTicks(1));
    }

    private static RangeResponse EmptyRange()
    {
        Assert.True(RangeResponse.TryParse(Array.Empty<byte>(), 0, out RangeResponse? r));
        return r!;
    }

    // ---- PwnedPasswordsBreachChecker / internal constructor ----

    [Fact]
    public void Breach_checker_validates_options_at_construction()
    {
        var factory = new CountingFactory(FakeRangeApi.Ok(""));
        var ex = Assert.Throws<ArgumentException>(() => new PwnedPasswordsBreachChecker(factory, "n", new PwnedPasswordsOptions { Timeout = TimeSpan.Zero }, null));
        Assert.Equal("options", ex.ParamName);
        Assert.Equal(0, factory.Created);
    }

    [Fact]
    public void Internal_constructor_validates_options()
    {
        using var http = new HttpClient(FakeRangeApi.Ok(""));
        var ex = Assert.Throws<ArgumentException>(() => new PwnedPasswordsClient(http, new PwnedPasswordsOptions { MinimumOccurrences = 0 }, null));
        Assert.Equal("options", ex.ParamName);
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => new PwnedPasswordsClient(http, null!, null)).ParamName);
        Assert.Equal("httpClient", Assert.Throws<ArgumentNullException>(() => new PwnedPasswordsClient(null!, new PwnedPasswordsOptions(), null)).ParamName);
    }

    [Fact]
    public async Task Null_range_in_the_cache_is_treated_as_a_miss()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":4");
        var cache = new RangeCache(4, TimeSpan.FromHours(1));
        cache.Set("5BAA6", null!);
        var client = new PwnedPasswordsClient(api.CreateClient(), new PwnedPasswordsOptions(), cache);

        BreachCheckResult result = await client.CheckAsync("password");

        Assert.Equal(4, result.Occurrences);
        Assert.Equal(1, api.Count);
        Assert.True(cache.TryGet("5BAA6", out RangeResponse? stored));
        Assert.NotNull(stored);
    }

    // ---- exception messages (PwnedPasswordsUnavailableException is part of the public surface) ----

    [Fact]
    public void Empty_password_message_and_parameter()
    {
        PwnedPasswordsClient client = Create(FakeRangeApi.Ok(""));
        var ex = Assert.Throws<ArgumentException>(() => { _ = client.CheckAsync(""); });
        Assert.Equal("password", ex.ParamName);
        Assert.StartsWith("Password cannot be empty.", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Http_error_message_names_the_status_code()
    {
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(
            () => Throwing(FakeRangeApi.Status(HttpStatusCode.ServiceUnavailable)).CheckAsync("password").AsTask());
        Assert.Equal("The Pwned Passwords service answered with HTTP 503.", ex.Message);
        Assert.Null(ex.InnerException);
    }

    [Fact]
    public async Task Network_error_message()
    {
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(
            () => Throwing(new FakeRangeApi((_, _) => throw new HttpRequestException("refused"))).CheckAsync("password").AsTask());
        Assert.Equal("The Pwned Passwords service could not be reached.", ex.Message);
        Assert.IsType<HttpRequestException>(ex.InnerException);
    }

    [Fact]
    public async Task Connection_error_message()
    {
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(
            () => Throwing(new FakeRangeApi((_, _) => throw new IOException("reset"))).CheckAsync("password").AsTask());
        Assert.Equal("The connection to the Pwned Passwords service failed.", ex.Message);
        Assert.IsType<IOException>(ex.InnerException);
    }

    [Fact]
    public async Task Other_pipeline_failure_message()
    {
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(
            () => Throwing(new FakeRangeApi((_, _) => throw new InvalidOperationException("bug"))).CheckAsync("password").AsTask());
        Assert.Equal("The Pwned Passwords request failed.", ex.Message);
        Assert.IsType<InvalidOperationException>(ex.InnerException);
    }

    [Theory]
    [InlineData("<html></html>")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD:5")]
    [InlineData("")]
    public async Task Malformed_or_empty_range_message(string body)
    {
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(
            () => Throwing(FakeRangeApi.Ok(body)).CheckAsync("password").AsTask());
        Assert.Equal("The Pwned Passwords service returned a malformed range.", ex.Message);
        Assert.Null(ex.InnerException);
    }

    [Fact]
    public async Task Too_large_message_names_the_limit()
    {
        var api = WithContent(() =>
        {
            var content = new ByteArrayContent(Encoding.ASCII.GetBytes(PasswordSuffix + ":1"));
            content.Headers.ContentLength = PwnedPasswordsClient.MaxResponseBytes + 1L;
            return content;
        });
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => Throwing(api).CheckAsync("password").AsTask());
        Assert.Equal("The Pwned Passwords response exceeded 1048576 bytes.", ex.Message);
    }

    // ---- ReadLimitedAsync ----

    [Fact]
    public async Task Read_buffer_never_grows_past_the_limit_plus_one_byte()
    {
        var stream = new RecordingStream(WellFormedBody(PwnedPasswordsClient.MaxResponseBytes));
        BreachCheckResult result = await Create(WithContent(() => new StreamContent(stream))).CheckAsync("password");

        Assert.Equal(12, result.Occurrences);
        Assert.Equal(PwnedPasswordsClient.MaxResponseBytes + 1, stream.LargestRequestedEnd);
    }

    [Fact]
    public async Task Stream_that_over_reports_a_read_past_the_limit_is_rejected_as_too_large()
    {
        // A misbehaving stream claims a single read returned more than the limit. The per-read length check
        // must reject it right away; otherwise the loop carries on with an impossible length and the
        // failure is reported as a malformed range (or a generic request failure), not as too large.
        var stream = new OverReportingStream(PwnedPasswordsClient.MaxResponseBytes + 1);
        var api = WithContent(() => new DirectStreamContent(stream));

        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => Throwing(api).CheckAsync("password").AsTask());

        Assert.Equal("The Pwned Passwords response exceeded 1048576 bytes.", ex.Message);
        Assert.Null(ex.InnerException);
        Assert.Equal(1, stream.Reads);
    }

    [Fact]
    public async Task Read_error_without_cancellation_is_a_connection_failure_not_a_timeout()
    {
        var api = WithContent(() => new StreamContent(new FailingStream()));
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => Throwing(api).CheckAsync("password").AsTask());
        Assert.Equal("The connection to the Pwned Passwords service failed.", ex.Message);
        Assert.IsType<IOException>(ex.InnerException);
    }

    [Fact]
    public async Task Caller_cancellation_of_a_stalled_read_reports_the_read_was_cancelled()
    {
        var stream = new StallingStream();
        PwnedPasswordsClient client = Create(WithContent(() => new StreamContent(stream)), o => o.Timeout = TimeSpan.FromMinutes(1));
        using var cts = new CancellationTokenSource();

        Task<BreachCheckResult> lookup = client.CheckAsync("password", cts.Token).AsTask();
        await stream.ReadStarted;
        cts.Cancel();

        OperationCanceledException ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lookup);
        Assert.Equal("Reading the Pwned Passwords response was cancelled.", ex.Message);
        Assert.IsType<ObjectDisposedException>(ex.InnerException);
    }

    // ---- ConfigureAwait(false): no continuation may be posted to the caller's SynchronizationContext ----

    [Fact]
    public async Task Asynchronous_send_never_posts_to_the_callers_context()
    {
        var api = new FakeRangeApi((_, _) => Task.Run(() => FakeRangeApi.Text(HttpStatusCode.OK, PasswordSuffix + ":5")));
        await AssertNoPosts(Create(api), 5);
    }

    [Fact]
    public async Task Asynchronous_content_stream_never_posts_to_the_callers_context()
    {
        var api = WithContent(() => new DeferredStreamContent(Encoding.ASCII.GetBytes(PasswordSuffix + ":6")));
        await AssertNoPosts(Create(api), 6);
    }

    [Fact]
    public async Task Asynchronous_body_read_never_posts_to_the_callers_context()
    {
        var api = WithContent(() => new StreamContent(new AsyncReadStream(Encoding.ASCII.GetBytes(PasswordSuffix + ":7"))));
        await AssertNoPosts(Create(api), 7);
    }

    private static async Task AssertNoPosts(PwnedPasswordsClient client, long expected)
    {
        var context = new CountingContext();
        SynchronizationContext? previous = SynchronizationContext.Current;
        ValueTask<BreachCheckResult> pending;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            pending = client.CheckAsync("password");
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }

        BreachCheckResult result = await pending;
        Assert.Equal(expected, result.Occurrences);
        Assert.Equal(0, context.Posts);
    }

    // ---- Validate: boundaries and messages ----

    private static ArgumentException Invalid(Action<PwnedPasswordsOptions> configure)
    {
        var options = new PwnedPasswordsOptions();
        configure(options);
        var ex = Assert.Throws<ArgumentException>(() => PwnedPasswordsClient.Validate(options));
        Assert.Equal("options", ex.ParamName);
        return ex;
    }

    private static void Valid(Action<PwnedPasswordsOptions> configure)
    {
        var options = new PwnedPasswordsOptions();
        configure(options);
        PwnedPasswordsClient.Validate(options);
    }

    [Fact]
    public void Validation_messages()
    {
        Assert.StartsWith("BaseAddress must be an absolute URI.", Invalid(o => o.BaseAddress = null!).Message, StringComparison.Ordinal);
        Assert.StartsWith("BaseAddress must use https; set AllowInsecureHttp to permit http.",
            Invalid(o => o.BaseAddress = new Uri("http://mirror.example/")).Message, StringComparison.Ordinal);
        string other = Invalid(o => { o.BaseAddress = new Uri("ftp://mirror.example/"); o.AllowInsecureHttp = true; }).Message;
        Assert.StartsWith("BaseAddress must use https.", other, StringComparison.Ordinal);
        Assert.DoesNotContain("AllowInsecureHttp", other, StringComparison.Ordinal);
        Assert.StartsWith("BaseAddress must not contain user info, a query or a fragment.",
            Invalid(o => o.BaseAddress = new Uri("https://mirror.example/?q=1")).Message, StringComparison.Ordinal);
        Assert.StartsWith("Timeout must be greater than zero and at most 5 minutes.", Invalid(o => o.Timeout = TimeSpan.Zero).Message, StringComparison.Ordinal);
        Assert.StartsWith("UserAgent must be a non-empty, valid User-Agent header value.", Invalid(o => o.UserAgent = "").Message, StringComparison.Ordinal);
        Assert.StartsWith("FailureMode is not a defined value.", Invalid(o => o.FailureMode = (PwnedPasswordsFailureMode)7).Message, StringComparison.Ordinal);
        Assert.StartsWith("MinimumOccurrences must be at least 1.", Invalid(o => o.MinimumOccurrences = 0).Message, StringComparison.Ordinal);
        Assert.StartsWith("CacheDuration must be greater than zero and at most 7 days.",
            Invalid(o => { o.EnableCache = true; o.CacheDuration = TimeSpan.Zero; }).Message, StringComparison.Ordinal);
        Assert.StartsWith("CacheMaxEntries must be between 1 and 100000.",
            Invalid(o => { o.EnableCache = true; o.CacheMaxEntries = 0; }).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Timeout_boundaries()
    {
        Valid(o => o.Timeout = PwnedPasswordsOptions.MaxTimeout);
        Valid(o => o.Timeout = TimeSpan.FromTicks(1));
        Invalid(o => o.Timeout = PwnedPasswordsOptions.MaxTimeout + TimeSpan.FromTicks(1));
        Invalid(o => o.Timeout = TimeSpan.FromTicks(-1));
    }

    [Fact]
    public void Cache_duration_boundaries()
    {
        Valid(o => { o.EnableCache = true; o.CacheDuration = PwnedPasswordsOptions.MaxCacheDuration; });
        Valid(o => { o.EnableCache = true; o.CacheDuration = TimeSpan.FromTicks(1); });
        Invalid(o => { o.EnableCache = true; o.CacheDuration = PwnedPasswordsOptions.MaxCacheDuration + TimeSpan.FromTicks(1); });
    }

    [Fact]
    public void Cache_size_boundaries()
    {
        Valid(o => { o.EnableCache = true; o.CacheMaxEntries = 1; });
        Valid(o => { o.EnableCache = true; o.CacheMaxEntries = PwnedPasswordsOptions.MaxCacheEntriesLimit; });
        Invalid(o => { o.EnableCache = true; o.CacheMaxEntries = PwnedPasswordsOptions.MaxCacheEntriesLimit + 1; });
        Invalid(o => { o.EnableCache = true; o.CacheMaxEntries = 0; });
        Assert.NotNull(PwnedPasswordsClient.CreateCache(new PwnedPasswordsOptions { EnableCache = true, CacheMaxEntries = 1 }));
    }

    [Fact]
    public void User_agent_length_boundary_is_512()
    {
        string ua512 = "App/" + new string('1', 508);
        Assert.Equal(512, ua512.Length);
        Valid(o => o.UserAgent = ua512);
        Invalid(o => o.UserAgent = ua512 + "1");
    }

    [Fact]
    public void User_agent_may_contain_a_tilde()
    {
        Valid(o => o.UserAgent = "App~1/1.0");
    }

    [Theory]
    [InlineData("App/1.0\t(x)")]
    [InlineData("App/1.0 (café)")]
    [InlineData("App/1.0 (\u007f)")]
    public void User_agent_outside_printable_ascii_is_rejected_even_if_the_header_parser_accepts_it(string ua)
    {
        Invalid(o => o.UserAgent = ua);
    }

    // ---- helpers ----

    private static byte[] WellFormedBody(int length)
    {
        const string padding = "0000000000000000000000000000000000A:0\r\n";
        string tail = PasswordSuffix + ":12";
        int lines = (length - tail.Length) / padding.Length;
        int blanks = length - tail.Length - lines * padding.Length;
        byte[] body = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(padding, lines)) + new string('\n', blanks) + tail);
        Assert.Equal(length, body.Length);
        return body;
    }

    private sealed class CountingFactory : IHttpClientFactory
    {
        private readonly FakeRangeApi _api;

        public CountingFactory(FakeRangeApi api) => _api = api;

        public int Created { get; private set; }

        public HttpClient CreateClient(string name)
        {
            Created++;
            return _api.CreateClient();
        }
    }

    private sealed class CountingContext : SynchronizationContext
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

    /// <summary>Content whose stream is produced asynchronously, on the thread pool.</summary>
    private sealed class DeferredStreamContent : HttpContent
    {
        private readonly byte[] _body;

        public DeferredStreamContent(byte[] body) => _body = body;

        protected override Task<Stream> CreateContentReadStreamAsync() => Task.Run<Stream>(() => new MemoryStream(_body, writable: false));

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(_body, 0, _body.Length);

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    /// <summary>Base for non-seekable read-only test streams.</summary>
    private abstract class ReadOnlyTestStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <summary>Serves its data in reads that complete on the thread pool.</summary>
    private sealed class AsyncReadStream : ReadOnlyTestStream
    {
        private readonly byte[] _data;
        private int _position;

        public AsyncReadStream(byte[] data) => _data = data;

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            new(Task.Run(() =>
            {
                int n = Math.Min(buffer.Length, _data.Length - _position);
                _data.AsMemory(_position, n).CopyTo(buffer);
                _position += n;
                return n;
            }));
    }

    /// <summary>Serves its data synchronously and records the furthest buffer end any read asked for.</summary>
    private sealed class RecordingStream : ReadOnlyTestStream
    {
        private readonly byte[] _data;
        private int _position;

        public RecordingStream(byte[] data) => _data = data;

        public int LargestRequestedEnd { get; private set; }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Assert.True(MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out ArraySegment<byte> segment));
            LargestRequestedEnd = Math.Max(LargestRequestedEnd, segment.Offset + segment.Count);
            int n = Math.Min(buffer.Length, _data.Length - _position);
            _data.AsMemory(_position, n).CopyTo(buffer);
            _position += n;
            return new ValueTask<int>(n);
        }
    }

    /// <summary>Content that hands out the given stream as is (no wrapper, no buffering).</summary>
    private sealed class DirectStreamContent : HttpContent
    {
        private readonly Stream _stream;

        public DirectStreamContent(Stream stream) => _stream = stream;

        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult(_stream);

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => _stream.CopyToAsync(stream);

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    /// <summary>
    /// Breaks the Stream contract: its first read reports <c>claimed</c> bytes whatever the buffer size, then
    /// every later read reports end of stream. Arguments are never validated.
    /// </summary>
    private sealed class OverReportingStream : ReadOnlyTestStream
    {
        private readonly int _claimed;

        public OverReportingStream(int claimed) => _claimed = claimed;

        public int Reads { get; private set; }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            Task.FromResult(Reads++ == 0 ? _claimed : 0);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            new(Reads++ == 0 ? _claimed : 0);
    }

    /// <summary>Every read fails with an I/O error.</summary>
    private sealed class FailingStream : ReadOnlyTestStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(new IOException("connection reset while reading"));
    }

    /// <summary>A read that ignores its token and fails with <see cref="ObjectDisposedException"/> once disposed.</summary>
    private sealed class StallingStream : ReadOnlyTestStream
    {
        private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _disposed = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task ReadStarted => _started.Task;

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _started.TrySetResult();
            await _disposed.Task.ConfigureAwait(false);
            throw new ObjectDisposedException(nameof(StallingStream));
        }

        protected override void Dispose(bool disposing)
        {
            _disposed.TrySetResult();
            base.Dispose(disposing);
        }
    }
}
