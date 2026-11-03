using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Masterly.Hash.Pwned.Internal;

namespace Masterly.Hash.Pwned.Tests;

public class PwnedPasswordsClientTests
{
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8. This is the worked example in the Pwned Passwords
    // range API documentation (https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) and is
    // reproducible with any SHA-1 implementation (e.g. `printf password | sha1sum`).
    private const string PasswordPrefix = "5BAA6";
    private const string PasswordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private static PwnedPasswordsClient Create(FakeRangeApi api, Action<PwnedPasswordsOptions>? configure = null)
    {
        var options = new PwnedPasswordsOptions();
        configure?.Invoke(options);
        return new PwnedPasswordsClient(api.CreateClient(), options);
    }

    // ---- happy path and request shape ----

    [Fact]
    public async Task Breached_password_is_reported_with_its_count()
    {
        var api = FakeRangeApi.Ok(Sha1Hex.Range(50, PasswordSuffix + ":10434004", "003D68EB55068C33ACE09247EE4C639306B:3"));
        BreachCheckResult result = await Create(api).CheckAsync("password");

        Assert.Equal(BreachCheckStatus.Ok, result.Status);
        Assert.True(result.IsBreached);
        Assert.Equal(10434004, result.Occurrences);
    }

    [Fact]
    public async Task Only_the_five_character_prefix_is_sent_with_padding_and_user_agent()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":1");
        await Create(api).CheckAsync("password");

        CapturedRequest request = Assert.Single(api.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(new Uri("https://api.pwnedpasswords.com/range/" + PasswordPrefix), request.Uri);
        Assert.Equal("true", request.Headers["Add-Padding"]);
        Assert.Equal(PwnedPasswordsOptions.DefaultUserAgent, request.Headers["User-Agent"]);
        Assert.False(request.HasContent);

        // Neither the password, the full hash nor the suffix (or any 6+ character piece of it) may be on the wire.
        // (The host name "api.pwnedpasswords.com" itself contains "password", so it is removed first.)
        Assert.Equal("", request.Uri.Query);
        string wire = request.Wire.Replace("api.pwnedpasswords.com", "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Sha1Hex.Of("password"), wire, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(PasswordPrefix + PasswordSuffix[0], wire, StringComparison.OrdinalIgnoreCase);
        for (int i = 0; i + 6 <= PasswordSuffix.Length; i++)
            Assert.DoesNotContain(PasswordSuffix.Substring(i, 6), wire, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Prefix_is_computed_over_utf8_bytes()
    {
        const string password = "pässwörd-日本語-🔑";
        var api = FakeRangeApi.Ok(Sha1Hex.Suffix(password) + ":2");
        BreachCheckResult result = await Create(api).CheckAsync(password);

        Assert.True(result.IsBreached);
        Assert.EndsWith("/range/" + Sha1Hex.Prefix(password), api.Requests[0].Uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Custom_user_agent_and_base_address_with_path_are_used()
    {
        var api = FakeRangeApi.Ok("");
        await Create(api, o =>
        {
            o.UserAgent = "Contoso-SignUp/1.4";
            o.BaseAddress = new Uri("https://mirror.example/hibp");
        }).CheckAsync("password");

        CapturedRequest request = api.Requests[0];
        Assert.Equal(new Uri("https://mirror.example/hibp/range/5BAA6"), request.Uri);
        Assert.Equal("Contoso-SignUp/1.4", request.Headers["User-Agent"]);
    }

    [Fact]
    public async Task Suffix_match_ignores_case()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix.ToLowerInvariant() + ":7\r\n");
        BreachCheckResult result = await Create(api).CheckAsync("password");
        Assert.True(result.IsBreached);
        Assert.Equal(7, result.Occurrences);
    }

    [Fact]
    public async Task Absent_suffix_is_not_breached()
    {
        var api = FakeRangeApi.Ok(Sha1Hex.Range(100, "003D68EB55068C33ACE09247EE4C639306B:3"));
        BreachCheckResult result = await Create(api).CheckAsync("password");
        Assert.Same(BreachCheckResult.NotBreached, result);
    }

    [Fact]
    public async Task Padding_entry_with_count_zero_is_ignored_even_for_the_matching_suffix()
    {
        var api = FakeRangeApi.Ok(Sha1Hex.Range(20, PasswordSuffix + ":0", "003D68EB55068C33ACE09247EE4C639306B:3"));
        BreachCheckResult result = await Create(api).CheckAsync("password");
        Assert.Same(BreachCheckResult.NotBreached, result);
    }

    // A real range always holds hundreds of breached suffixes, so an answer without any comes from a proxy, a
    // fallback handler or a broken mirror. Treating it as "not breached" (and caching it) would be a false negative.
    [Theory]
    [InlineData("")]
    [InlineData("\r\n\r\n")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\r\n003D68EB55068C33ACE09247EE4C639306B:0")]
    public async Task Range_without_real_entries_is_unavailable_and_not_cached(string body)
    {
        var api = FakeRangeApi.Ok(body);
        PwnedPasswordsClient client = Create(api, o => o.EnableCache = true);

        Assert.Same(BreachCheckResult.Unavailable, await client.CheckAsync("password"));
        Assert.Same(BreachCheckResult.Unavailable, await client.CheckAsync("password"));
        Assert.Equal(2, api.Count);

        PwnedPasswordsClient throwing = Create(FakeRangeApi.Ok(body), o => o.FailureMode = PwnedPasswordsFailureMode.Throw);
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => throwing.CheckAsync("password").AsTask());
        AssertNoSecrets(ex);
    }

    [Fact]
    public async Task All_padding_range_is_unavailable()
    {
        BreachCheckResult result = await Create(FakeRangeApi.Ok(Sha1Hex.Range(800))).CheckAsync("password");
        Assert.Same(BreachCheckResult.Unavailable, result);
    }

    [Fact]
    public async Task No_content_204_is_unavailable()
    {
        var api = new FakeRangeApi((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent)));
        Assert.Same(BreachCheckResult.Unavailable, await Create(api).CheckAsync("password"));
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(5, true)]
    [InlineData(6, false)]
    [InlineData(int.MaxValue, false)]
    public async Task MinimumOccurrences_is_a_threshold(int minimum, bool breached)
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":5");
        BreachCheckResult result = await Create(api, o => o.MinimumOccurrences = minimum).CheckAsync("password");
        Assert.Equal(BreachCheckStatus.Ok, result.Status);
        Assert.Equal(breached, result.IsBreached);
        Assert.Equal(breached ? 5 : 0, result.Occurrences);
    }

    [Fact]
    public async Task SensitiveString_overload_checks_the_revealed_value()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":3");
        BreachCheckResult result = await Create(api).CheckAsync(new SensitiveString("password"));
        Assert.True(result.IsBreached);
        Assert.EndsWith("/range/5BAA6", api.Requests[0].Uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Works_through_the_IBreachedPasswordChecker_interface()
    {
        IBreachedPasswordChecker checker = Create(FakeRangeApi.Ok(PasswordSuffix + ":3"));
        BreachCheckResult result = await checker.CheckAsync("password", CancellationToken.None);
        Assert.True(result.IsBreached);
    }

    // ---- argument validation ----

    [Fact]
    public void Null_and_empty_passwords_throw_synchronously_without_a_request()
    {
        var api = FakeRangeApi.Ok("");
        PwnedPasswordsClient client = Create(api);

        Assert.Throws<ArgumentNullException>(() => { _ = client.CheckAsync((string)null!); });
        Assert.Throws<ArgumentNullException>(() => { _ = client.CheckAsync((SensitiveString)null!); });
        Assert.Throws<ArgumentException>(() => { _ = client.CheckAsync(""); });
        Assert.Throws<ArgumentException>(() => { _ = client.CheckAsync(new SensitiveString("")); });
        Assert.Equal(0, api.Count);
    }

    [Fact]
    public void Null_http_client_throws()
    {
        Assert.Throws<ArgumentNullException>(() => new PwnedPasswordsClient(null!));
    }

    // ---- caching ----

    [Fact]
    public async Task Cache_hit_avoids_a_second_request()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":9");
        PwnedPasswordsClient client = Create(api, o => o.EnableCache = true);

        BreachCheckResult first = await client.CheckAsync("password");
        BreachCheckResult second = await client.CheckAsync("password");

        Assert.Equal(1, api.Count);
        Assert.Equal(9, first.Occurrences);
        Assert.Equal(9, second.Occurrences);
    }

    [Fact]
    public async Task Cached_range_answers_other_passwords_with_the_same_prefix()
    {
        // The cache stores the whole range, so a different suffix under the same prefix is answered locally.
        var api = FakeRangeApi.Ok(PasswordSuffix + ":9");
        var cache = new RangeCache(16, TimeSpan.FromHours(1));
        var client = new PwnedPasswordsClient(api.CreateClient(), new PwnedPasswordsOptions(), cache);

        await client.CheckAsync("password");
        Assert.True(cache.TryGet(PasswordPrefix, out RangeResponse? range));
        Assert.Equal(1, range!.Count);
        Assert.Equal(1, api.Count);
    }

    [Fact]
    public async Task Without_cache_every_lookup_is_a_request()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":9");
        PwnedPasswordsClient client = Create(api);
        await client.CheckAsync("password");
        await client.CheckAsync("password");
        Assert.Equal(2, api.Count);
    }

    [Fact]
    public async Task Expired_cache_entry_triggers_a_new_request()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":9");
        TimeSpan now = TimeSpan.FromHours(10);
        var cache = new RangeCache(16, TimeSpan.FromMinutes(5), () => now);
        var client = new PwnedPasswordsClient(api.CreateClient(), new PwnedPasswordsOptions(), cache);

        await client.CheckAsync("password");
        now += TimeSpan.FromMinutes(4);
        await client.CheckAsync("password");
        Assert.Equal(1, api.Count);

        now += TimeSpan.FromMinutes(2);
        await client.CheckAsync("password");
        Assert.Equal(2, api.Count);
    }

    [Fact]
    public async Task ClearCache_forces_a_new_request()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":9");
        PwnedPasswordsClient client = Create(api, o => o.EnableCache = true);
        await client.CheckAsync("password");
        client.ClearCache();
        await client.CheckAsync("password");
        Assert.Equal(2, api.Count);

        Create(FakeRangeApi.Ok("")).ClearCache(); // no cache: no-op
    }

    [Fact]
    public async Task Failures_are_not_cached()
    {
        int calls = 0;
        var api = new FakeRangeApi((_, _) => Task.FromResult(++calls == 1
            ? FakeRangeApi.Text(HttpStatusCode.ServiceUnavailable, "down")
            : FakeRangeApi.Text(HttpStatusCode.OK, PasswordSuffix + ":4")));
        PwnedPasswordsClient client = Create(api, o => o.EnableCache = true);

        Assert.Same(BreachCheckResult.Unavailable, await client.CheckAsync("password"));
        Assert.True((await client.CheckAsync("password")).IsBreached);
        Assert.True((await client.CheckAsync("password")).IsBreached);
        Assert.Equal(2, api.Count);
    }

    [Fact]
    public async Task Concurrent_lookups_with_cache_are_safe()
    {
        var api = new FakeRangeApi(async (req, ct) =>
        {
            await Task.Yield();
            return FakeRangeApi.Text(HttpStatusCode.OK, PasswordSuffix + ":1");
        });
        PwnedPasswordsClient client = Create(api, o => { o.EnableCache = true; o.CacheMaxEntries = 4; });

        string[] passwords = Enumerable.Range(0, 64).Select(i => "pw-" + i).Append("password").ToArray();
        BreachCheckResult[] results = await Task.WhenAll(Enumerable.Range(0, 400).Select(i =>
            Task.Run(async () => await client.CheckAsync(passwords[i % passwords.Length]))));

        Assert.All(results, r => Assert.Equal(BreachCheckStatus.Ok, r.Status));
        Assert.All(results.Where((_, i) => passwords[i % passwords.Length] == "password"), r => Assert.True(r.IsBreached));
        Assert.All(results.Where((_, i) => passwords[i % passwords.Length] != "password"), r => Assert.False(r.IsBreached));
    }

    // ---- failure handling ----

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData((HttpStatusCode)429)]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task Error_status_is_unavailable_in_fail_open(HttpStatusCode status)
    {
        BreachCheckResult result = await Create(FakeRangeApi.Status(status)).CheckAsync("password");
        Assert.Same(BreachCheckResult.Unavailable, result);
        Assert.False(result.IsBreached);
    }

    [Fact]
    public async Task Error_status_throws_in_throw_mode_without_leaking_hash_material()
    {
        PwnedPasswordsClient client = Create(FakeRangeApi.Status(HttpStatusCode.ServiceUnavailable),
            o => o.FailureMode = PwnedPasswordsFailureMode.Throw);

        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => client.CheckAsync("password").AsTask());
        Assert.Contains("503", ex.Message, StringComparison.Ordinal);
        AssertNoSecrets(ex);
    }

    [Fact]
    public async Task Timeout_is_unavailable_in_fail_open()
    {
        PwnedPasswordsClient client = Create(FakeRangeApi.Hang(), o => o.Timeout = TimeSpan.FromMilliseconds(100));
        BreachCheckResult result = await client.CheckAsync("password");
        Assert.Same(BreachCheckResult.Unavailable, result);
    }

    [Fact]
    public async Task Timeout_throws_in_throw_mode()
    {
        PwnedPasswordsClient client = Create(FakeRangeApi.Hang(), o =>
        {
            o.Timeout = TimeSpan.FromMilliseconds(100);
            o.FailureMode = PwnedPasswordsFailureMode.Throw;
        });
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => client.CheckAsync("password").AsTask());
        Assert.Contains("timeout", ex.Message, StringComparison.OrdinalIgnoreCase);
        AssertNoSecrets(ex);
    }

    [Fact]
    public async Task Timeout_while_reading_the_body_is_unavailable()
    {
        var api = new FakeRangeApi((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new HangingStream()),
        }));
        PwnedPasswordsClient client = Create(api, o => o.Timeout = TimeSpan.FromMilliseconds(100));
        Assert.Same(BreachCheckResult.Unavailable, await client.CheckAsync("password"));
    }

    [Fact]
    public async Task Timeout_while_reading_the_body_throws_in_throw_mode()
    {
        var api = new FakeRangeApi((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new HangingStream()),
        }));
        PwnedPasswordsClient client = Create(api, o =>
        {
            o.Timeout = TimeSpan.FromMilliseconds(100);
            o.FailureMode = PwnedPasswordsFailureMode.Throw;
        });
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => client.CheckAsync("password").AsTask());
        AssertNoSecrets(ex);
    }

    // Some response streams (a custom handler's, for example) check the token only when a read starts.
    // TokenIgnoringStream models that: a pending read ignores the token and ends only on dispose.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Stalled_read_that_ignores_the_token_is_torn_down_by_the_timeout(bool throwsOnDispose)
    {
        var stream = new TokenIgnoringStream(Encoding.ASCII.GetBytes(PasswordSuffix + ":5\r\n"), throwsOnDispose);
        var api = new FakeRangeApi((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(stream),
        }));

        PwnedPasswordsClient client = Create(api, o => o.Timeout = TimeSpan.FromMilliseconds(150));
        Task<BreachCheckResult> lookup = client.CheckAsync("password").AsTask();
        Assert.Same(lookup, await Task.WhenAny(lookup, Task.Delay(TimeSpan.FromSeconds(10))));
        // Even when the torn-down read reports end of stream, the partial body is never parsed as a whole range.
        Assert.Same(BreachCheckResult.Unavailable, await lookup);
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task Stalled_read_that_ignores_the_token_throws_in_throw_mode_and_honours_caller_cancellation()
    {
        static FakeRangeApi Stalling() => new((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new TokenIgnoringStream(Encoding.ASCII.GetBytes(PasswordSuffix + ":5\r\n"), throwsOnDispose: true)),
        }));

        PwnedPasswordsClient throwing = Create(Stalling(), o =>
        {
            o.Timeout = TimeSpan.FromMilliseconds(150);
            o.FailureMode = PwnedPasswordsFailureMode.Throw;
        });
        Task<BreachCheckResult> thrown = throwing.CheckAsync("password").AsTask();
        Assert.Same(thrown, await Task.WhenAny(thrown, Task.Delay(TimeSpan.FromSeconds(10))));
        await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => thrown);

        PwnedPasswordsClient patient = Create(Stalling(), o => o.Timeout = TimeSpan.FromSeconds(30));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        Task<BreachCheckResult> cancelled = patient.CheckAsync("password", cts.Token).AsTask();
        Assert.Same(cancelled, await Task.WhenAny(cancelled, Task.Delay(TimeSpan.FromSeconds(10))));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
    }

    [Fact]
    public async Task HttpClient_timeout_counts_as_unavailable_not_cancellation()
    {
        var api = FakeRangeApi.Hang();
        var http = new HttpClient(api, disposeHandler: false) { Timeout = TimeSpan.FromMilliseconds(50) };
        var client = new PwnedPasswordsClient(http, new PwnedPasswordsOptions { Timeout = TimeSpan.FromSeconds(30) });
        Assert.Same(BreachCheckResult.Unavailable, await client.CheckAsync("password"));
    }

    [Fact]
    public async Task HttpClient_timeout_throws_in_throw_mode()
    {
        var api = FakeRangeApi.Hang();
        var http = new HttpClient(api, disposeHandler: false) { Timeout = TimeSpan.FromMilliseconds(50) };
        var client = new PwnedPasswordsClient(http, new PwnedPasswordsOptions
        {
            Timeout = TimeSpan.FromSeconds(30),
            FailureMode = PwnedPasswordsFailureMode.Throw,
        });
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => client.CheckAsync("password").AsTask());
        AssertNoSecrets(ex);
    }

    [Fact]
    public async Task Caller_cancellation_propagates_in_both_modes()
    {
        foreach (PwnedPasswordsFailureMode mode in new[] { PwnedPasswordsFailureMode.FailOpen, PwnedPasswordsFailureMode.Throw })
        {
            PwnedPasswordsClient client = Create(FakeRangeApi.Hang(), o => { o.FailureMode = mode; o.Timeout = TimeSpan.FromSeconds(30); });
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.CheckAsync("password", cts.Token).AsTask());
        }
    }

    [Fact]
    public void Already_cancelled_token_throws_without_a_request()
    {
        var api = FakeRangeApi.Ok("");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Throws<OperationCanceledException>(() => { _ = Create(api).CheckAsync("password", cts.Token); });
        Assert.Equal(0, api.Count);
    }

    [Fact]
    public async Task Network_error_is_unavailable_or_wrapped()
    {
        var failing = new FakeRangeApi((_, _) => throw new HttpRequestException("connection refused"));
        Assert.Same(BreachCheckResult.Unavailable, await Create(failing).CheckAsync("password"));

        PwnedPasswordsClient throwing = Create(failing, o => o.FailureMode = PwnedPasswordsFailureMode.Throw);
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => throwing.CheckAsync("password").AsTask());
        Assert.IsType<HttpRequestException>(ex.InnerException);
    }

    [Fact]
    public async Task Any_pipeline_exception_honours_the_failure_mode()
    {
        var failing = new FakeRangeApi((_, _) => throw new InvalidOperationException("custom handler bug"));
        Assert.Same(BreachCheckResult.Unavailable, await Create(failing).CheckAsync("password"));

        var io = new FakeRangeApi((_, _) => throw new IOException("reset"));
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(
            () => Create(io, o => o.FailureMode = PwnedPasswordsFailureMode.Throw).CheckAsync("password").AsTask());
        Assert.IsType<IOException>(ex.InnerException);
    }

    [Fact]
    public async Task Disposed_http_client_is_unavailable()
    {
        var http = new HttpClient(FakeRangeApi.Ok(""));
        var client = new PwnedPasswordsClient(http);
        http.Dispose();
        Assert.Same(BreachCheckResult.Unavailable, await client.CheckAsync("password"));
    }

    [Theory]
    [InlineData("<html><body>Service unavailable</body></html>")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD:5")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8X:5")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:-5")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\r\ngarbage")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:99999999999999999999")]
    public async Task Malformed_body_is_unavailable_never_a_false_negative(string body)
    {
        BreachCheckResult result = await Create(FakeRangeApi.Ok(body)).CheckAsync("password");
        Assert.Same(BreachCheckResult.Unavailable, result);

        PwnedPasswordsClient throwing = Create(FakeRangeApi.Ok(body), o => o.FailureMode = PwnedPasswordsFailureMode.Throw);
        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => throwing.CheckAsync("password").AsTask());
        AssertNoSecrets(ex);
    }

    /// <summary>
    /// A well-formed body of exactly <paramref name="length"/> bytes that reports "password" as breached 12 times:
    /// padding lines, blank lines to hit the exact length, then the matching line. A missing size limit would
    /// therefore show up as Breached rather than Unavailable.
    /// </summary>
    private static byte[] WellFormedBody(int length)
    {
        const string padding = "0000000000000000000000000000000000A:0\r\n";
        string tail = PasswordSuffix + ":12";
        int lines = (length - tail.Length) / padding.Length;
        int blanks = length - tail.Length - lines * padding.Length;
        byte[] body = Encoding.ASCII.GetBytes(
            string.Concat(Enumerable.Repeat(padding, lines)) + new string('\n', blanks) + tail);
        Assert.Equal(length, body.Length);
        return body;
    }

    private static FakeRangeApi Streaming(byte[] body) => new((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
    {
        // Non-seekable, so StreamContent cannot compute a Content-Length: only the streaming cap applies.
        Content = new StreamContent(new RepeatingStream(body, body.Length)),
    }));

    [Fact]
    public async Task Declared_length_over_the_limit_is_rejected_without_reading_the_body()
    {
        // A valid body that would report Breached; only the inflated Content-Length makes it unacceptable.
        byte[] valid = Encoding.ASCII.GetBytes(PasswordSuffix + ":12");
        var stream = new RepeatingStream(valid, valid.Length);
        var api = new FakeRangeApi((_, _) =>
        {
            var content = new StreamContent(stream);
            content.Headers.ContentLength = PwnedPasswordsClient.MaxResponseBytes + 1L;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        });
        Assert.Same(BreachCheckResult.Unavailable, await Create(api).CheckAsync("password"));
        Assert.Equal(0, stream.BytesRead);
    }

    [Fact]
    public async Task Streamed_body_one_byte_over_the_limit_is_rejected()
    {
        byte[] body = WellFormedBody(PwnedPasswordsClient.MaxResponseBytes + 1);
        Assert.Same(BreachCheckResult.Unavailable, await Create(Streaming(body)).CheckAsync("password"));
    }

    [Fact]
    public async Task Body_of_exactly_the_limit_is_accepted_streamed_or_declared()
    {
        byte[] body = WellFormedBody(PwnedPasswordsClient.MaxResponseBytes);

        BreachCheckResult streamed = await Create(Streaming(body)).CheckAsync("password");
        Assert.Equal(12, streamed.Occurrences);

        var declared = new FakeRangeApi((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(body),
        }));
        Assert.Equal(12, (await Create(declared).CheckAsync("password")).Occurrences);
    }

    [Fact]
    public async Task Response_without_content_is_unavailable_and_never_throws()
    {
        var api = new FakeRangeApi((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        Assert.Same(BreachCheckResult.Unavailable, await Create(api).CheckAsync("password"));
    }

    // ---- integration with PasswordPolicy ----

    [Fact]
    public async Task PasswordPolicy_reports_breached_passwords()
    {
        const string candidate = "violet kettle ocean 7193 lantern";
        var api = FakeRangeApi.Ok(Sha1Hex.Range(30, Sha1Hex.Suffix(candidate) + ":42"));
        var policy = new PasswordPolicy(new PasswordPolicyOptions(), Create(api));

        PasswordPolicyResult result = await policy.EvaluateAsync(candidate);

        Assert.True(result.HasViolation(PasswordViolationCode.Breached));
        Assert.NotNull(result.BreachCheck);
        Assert.Equal(42, result.BreachCheck!.Occurrences);
    }

    [Fact]
    public async Task PasswordPolicy_survives_an_outage()
    {
        const string candidate = "violet kettle ocean 7193 lantern";
        var policy = new PasswordPolicy(new PasswordPolicyOptions(), Create(FakeRangeApi.Status(HttpStatusCode.ServiceUnavailable)));

        PasswordPolicyResult result = await policy.EvaluateAsync(candidate);

        Assert.True(result.BreachCheckUnavailable);
        Assert.False(result.HasViolation(PasswordViolationCode.Breached));
    }

    [Fact]
    public async Task PasswordPolicy_absorbs_throw_mode_so_callers_must_check_BreachCheckUnavailable()
    {
        // Documents why the README says Throw does not make PasswordPolicy fail closed.
        const string candidate = "violet kettle ocean 7193 lantern";
        PwnedPasswordsClient client = Create(FakeRangeApi.Status(HttpStatusCode.ServiceUnavailable),
            o => o.FailureMode = PwnedPasswordsFailureMode.Throw);
        var policy = new PasswordPolicy(new PasswordPolicyOptions(), client);

        PasswordPolicyResult result = await policy.EvaluateAsync(candidate);

        Assert.True(result.BreachCheckUnavailable);
        Assert.True(result.IsAcceptable);
    }

    private static void AssertNoSecrets(Exception ex)
    {
        var text = new StringBuilder();
        for (Exception? e = ex; e != null; e = e.InnerException)
            text.AppendLine(e.Message);
        AssertNoSecrets(text.ToString());
    }

    private static void AssertNoSecrets(string text)
    {
        Assert.DoesNotContain("password", text.Replace("Pwned Passwords", "", StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.DoesNotContain(PasswordPrefix, text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(PasswordSuffix, text, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A body stream that never produces data until cancelled.</summary>
    private sealed class HangingStream : Stream
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

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }
    }

    /// <summary>
    /// Serves its data at once, then a read that ignores its token and ends only when the stream is disposed
    /// (returning 0, or throwing <see cref="ObjectDisposedException"/>).
    /// </summary>
    private sealed class TokenIgnoringStream : Stream
    {
        private readonly byte[] _data;
        private readonly bool _throwsOnDispose;
        private readonly TaskCompletionSource<bool> _disposed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private bool _served;

        public TokenIgnoringStream(byte[] data, bool throwsOnDispose)
        {
            _data = data;
            _throwsOnDispose = throwsOnDispose;
        }

        public bool Disposed => _disposed.Task.IsCompleted;

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

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_served)
            {
                _served = true;
                _data.CopyTo(buffer);
                return _data.Length;
            }
            await _disposed.Task.ConfigureAwait(false); // deliberately ignores cancellationToken
            if (_throwsOnDispose)
                throw new ObjectDisposedException(nameof(TokenIgnoringStream));
            return 0;
        }

        protected override void Dispose(bool disposing)
        {
            _disposed.TrySetResult(true);
            base.Dispose(disposing);
        }
    }

    /// <summary>Repeats a pattern up to a total length, with no known length.</summary>
    private sealed class RepeatingStream : Stream
    {
        private readonly byte[] _pattern;
        private readonly long _total;
        private long _position;

        public long BytesRead => _position;

        public RepeatingStream(byte[] pattern, long total)
        {
            _pattern = pattern;
            _total = total;
        }

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
            int n = (int)Math.Min(count, _total - _position);
            for (int i = 0; i < n; i++)
                buffer[offset + i] = _pattern[(_position + i) % _pattern.Length];
            _position += n;
            return n;
        }
    }
}
