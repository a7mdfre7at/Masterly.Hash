using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.AspNetCore.Tests;

public class PasswordLengthEndpointFilterTests
{
    private const int Limit = 64;

    public sealed class LoginRequest
    {
        public string? UserName { get; set; }
        public SensitiveString? Password { get; set; }
        public SensitiveString? NewPassword { get; set; }
    }

    public sealed record ChangeRequest(string UserName, SensitiveString Current, SensitiveString Next);

    public struct PasswordStruct
    {
        public SensitiveString? Password { get; set; }
    }

    public sealed class Hidden
    {
        internal SensitiveString? Password { get; set; } = new SensitiveString(new string('a', 1000));
    }

    private static async Task<(object? Result, bool NextCalled)> InvokeAsync(PasswordLengthEndpointFilter filter, params object?[] arguments)
    {
        bool called = false;
        var context = new DefaultEndpointFilterInvocationContext(new DefaultHttpContext(), arguments);
        object? result = await filter.InvokeAsync(context, _ =>
        {
            called = true;
            return new ValueTask<object?>("ok");
        });
        return (result, called);
    }

    private static void AssertRejected((object? Result, bool NextCalled) outcome)
    {
        Assert.False(outcome.NextCalled);
        ProblemHttpResult problem = Assert.IsType<ProblemHttpResult>(outcome.Result);
        Assert.Equal(400, problem.StatusCode);
    }

    private static void AssertPassed((object? Result, bool NextCalled) outcome)
    {
        Assert.True(outcome.NextCalled);
        Assert.Equal("ok", outcome.Result);
    }

    private static SensitiveString S(string value) => new SensitiveString(value);

    [Fact]
    public async Task DirectArgument_AtLimit_Passes_OverLimit_IsRejected()
    {
        var filter = new PasswordLengthEndpointFilter(Limit);
        AssertPassed(await InvokeAsync(filter, S(new string('a', Limit))));
        AssertRejected(await InvokeAsync(filter, S(new string('a', Limit + 1))));
    }

    [Fact]
    public async Task ModelProperties_AreChecked()
    {
        var filter = new PasswordLengthEndpointFilter(Limit);
        string longValue = new string('x', Limit + 1);

        AssertPassed(await InvokeAsync(filter, new LoginRequest { UserName = longValue, Password = S("short") }));
        AssertRejected(await InvokeAsync(filter, new LoginRequest { UserName = "u", Password = S(longValue) }));
        AssertRejected(await InvokeAsync(filter, new LoginRequest { Password = S("short"), NewPassword = S(longValue) }));
        AssertRejected(await InvokeAsync(filter, new ChangeRequest("u", S("short"), S(longValue))));
        AssertRejected(await InvokeAsync(filter, new PasswordStruct { Password = S(longValue) }));
        AssertPassed(await InvokeAsync(filter, new PasswordStruct()));
    }

    [Fact]
    public async Task UnrelatedArguments_AndNulls_Pass()
    {
        var filter = new PasswordLengthEndpointFilter(Limit);
        AssertPassed(await InvokeAsync(filter));
        AssertPassed(await InvokeAsync(filter, null, 42, "a plain string longer than the limit, which is not a SensitiveString at all", new LoginRequest(), DayOfWeek.Monday, new DefaultHttpContext()));
        AssertPassed(await InvokeAsync(filter, S("")));
    }

    [Fact]
    public async Task NonPublicProperties_AreIgnored()
    {
        AssertPassed(await InvokeAsync(new PasswordLengthEndpointFilter(Limit), new Hidden()));
    }

    [Fact]
    public async Task AnyOffendingArgument_Rejects()
    {
        var filter = new PasswordLengthEndpointFilter(Limit);
        AssertRejected(await InvokeAsync(filter, S("ok"), "x", S(new string('a', Limit * 10))));
    }

    [Theory]
    [InlineData("é", 32, false)]   // 2 UTF-8 bytes each: 64 bytes
    [InlineData("é", 33, true)]    // 66 bytes
    [InlineData("€", 21, false)]   // 3 bytes each: 63 bytes
    [InlineData("€", 22, true)]    // 66 bytes
    [InlineData("🔑", 16, false)] // 4 bytes each: 64 bytes
    [InlineData("🔑", 17, true)]
    [InlineData("ﷺ", 1, false)]    // NFKC expands U+FDFA to 18 Arabic letters: 33 bytes
    [InlineData("ﷺ", 2, true)]     // 6 raw bytes but 66 normalized bytes: measured like the hasher
    [InlineData("ﬁ", 32, false)]   // ligature "fi" -> "fi": 2 bytes each after NFKC
    [InlineData("ﬁ", 33, true)]
    public void NonAscii_IsMeasuredAfterNfkc(string unit, int count, bool expectedTooLong)
    {
        string value = string.Concat(System.Linq.Enumerable.Repeat(unit, count));
        Assert.Equal(expectedTooLong, new PasswordLengthEndpointFilter(Limit).IsTooLong(S(value)));
    }

    [Theory]
    [InlineData("plain ascii")]
    [InlineData("ﷺﷺ")]
    [InlineData("ﷺ")]
    [InlineData("éééééééééééééééééééééé")]
    [InlineData("각각각각각각각각")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("\ud800 lone surrogate")]
    public void AgreesWithTheHasher(string password)
    {
        var hasher = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestHashers.Fast, AllowWeakProfiles = true, MaxPasswordBytes = Limit });
        string stored = hasher.Hash("reference");

        bool hasherTooLong = hasher.Verify(password, stored).FailureReason == VerificationFailureReason.PasswordTooLong;

        Assert.Equal(hasherTooLong, new PasswordLengthEndpointFilter(Limit).IsTooLong(S(password)));
    }

    [Theory]
    [InlineData("각", 21, false)]       // Hangul L+V+T jamo (9 raw bytes) compose to one 3-byte syllable: 63 bytes
    [InlineData("각", 22, true)]        // 66 bytes
    [InlineData("ᾢ", 21, false)] // 4 code points compose to U+1FA2 (3 bytes): 84 chars, 63 bytes
    [InlineData("ᾢ", 22, true)]
    public void ComposingInput_ShorterAfterNfkc_IsMeasuredAfterNfkc(string unit, int count, bool expectedTooLong)
    {
        string value = string.Concat(System.Linq.Enumerable.Repeat(unit, count));
        Assert.True(Encoding.UTF8.GetByteCount(value) > Limit, "The raw input must exceed the limit for this test to mean anything.");
        Assert.Equal(expectedTooLong, new PasswordLengthEndpointFilter(Limit).IsTooLong(S(value)));
    }

    [Fact]
    public async Task HugeNfkcExpandingPassword_IsRejectedWithoutNormalizing()
    {
        // 4M x U+FDFA (12 MB of UTF-8, under Kestrel's 30 MB default) would normalize to 72M chars / 132 MB.
        var filter = new PasswordLengthEndpointFilter(1024);
        var argument = new LoginRequest { Password = S(new string('ﷺ', 4_000_000)) };

        long before = GC.GetAllocatedBytesForCurrentThread();
        (object? Result, bool NextCalled) outcome = await InvokeAsync(filter, argument);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        AssertRejected(outcome);
        Assert.True(allocated < 1_000_000, $"The guard allocated {allocated} bytes; it must reject from the length alone.");
    }

    [Fact]
    public void RawBound_IsEightTimesTheLimit_AndNeverStricterThanTheHasher()
    {
        var hasher = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestHashers.Fast, AllowWeakProfiles = true, MaxPasswordBytes = Limit });
        string stored = hasher.Hash("reference");
        var filter = new PasswordLengthEndpointFilter(Limit);

        // The most compressing inputs known (4 UTF-16 units -> 3 UTF-8 bytes), just past the raw bound.
        string greek = string.Concat(System.Linq.Enumerable.Repeat("ᾢ", 2 * Limit)) + "a";
        Assert.Equal(8 * Limit + 1, greek.Length);
        Assert.True(filter.IsTooLong(S(greek)));
        Assert.Equal(VerificationFailureReason.PasswordTooLong, hasher.Verify(greek, stored).FailureReason);
    }

    [Fact]
    public void LoneSurrogates_DoNotThrow()
    {
        var filter = new PasswordLengthEndpointFilter(Limit);
        Assert.False(filter.IsTooLong(S("\udc00\ud800")));
        Assert.True(filter.IsTooLong(S(new string('\ud800', Limit))));
    }

    [Fact]
    public void Constructors_ValidateArguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordLengthEndpointFilter(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordLengthEndpointFilter(-1));
        Assert.Throws<ArgumentNullException>(() => new PasswordLengthEndpointFilter((IOptions<PasswordHasherOptions>)null!));
        Assert.Throws<ArgumentNullException>(() => new PasswordLengthEndpointFilter(Limit).IsTooLong(null!));
        Assert.Equal(200, new PasswordLengthEndpointFilter(Options.Create(new PasswordHasherOptions { MaxPasswordBytes = 200 })).MaxPasswordBytes);
    }

    [Fact]
    public async Task Invoke_GuardsNulls()
    {
        var filter = new PasswordLengthEndpointFilter(Limit);
        await Assert.ThrowsAsync<ArgumentNullException>(() => filter.InvokeAsync(null!, _ => new ValueTask<object?>()).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(() => filter.InvokeAsync(new DefaultEndpointFilterInvocationContext(new DefaultHttpContext()), null!).AsTask());
    }

    [Fact]
    public async Task RejectionBody_StatesLimit_AndNeverEchoesThePassword()
    {
        const string secret = "SECRET-VALUE-THAT-MUST-NOT-LEAK-0123456789-0123456789-0123456789-0123456789";
        (object? result, _) = await InvokeAsync(new PasswordLengthEndpointFilter(Limit), new LoginRequest { Password = S(secret) });

        var services = new ServiceCollection();
        services.AddLogging();
        using ServiceProvider provider = services.BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Response.Body = new MemoryStream();
        await ((IResult)result!).ExecuteAsync(context);

        context.Response.Body.Position = 0;
        string body = await new StreamReader(context.Response.Body).ReadToEndAsync();
        Assert.Equal(400, context.Response.StatusCode);
        Assert.Contains("64 bytes", body, StringComparison.Ordinal);
        Assert.DoesNotContain("SECRET", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Pipeline_RejectsLongPasswordsBeforeTheHandler_OnEndpointsAndGroups()
    {
        int handlerCalls = 0;
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddMasterlyHash(o =>
        {
            TestHashers.Weak(o);
            o.MaxPasswordBytes = Limit;
        });
        await using WebApplication app = builder.Build();

        app.MapPost("/login", IResult (LoginRequest request, IPasswordHasher hasher) =>
        {
            handlerCalls++;
            return hasher.Hash(request.Password!.Reveal()).Length > 0 ? Results.Ok() : Results.BadRequest();
        }).WithPasswordLengthLimit();

        RouteGroupBuilder group = app.MapGroup("/account").WithPasswordLengthLimit();
        group.MapPost("/change", IResult (ChangeRequest request) =>
        {
            handlerCalls++;
            return Results.Ok();
        });

        await app.StartAsync();
        HttpClient client = app.GetTestClient();

        HttpResponseMessage ok = await client.PostAsJsonAsync("/login", new { userName = "a", password = "short password" });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(1, handlerCalls);

        HttpResponseMessage tooLong = await client.PostAsJsonAsync("/login", new { userName = "a", password = new string('p', Limit + 1) });
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
        Assert.Equal("application/problem+json", tooLong.Content.Headers.ContentType?.MediaType);
        Assert.Equal(1, handlerCalls);

        HttpResponseMessage groupTooLong = await client.PostAsJsonAsync("/account/change", new { userName = "a", current = "x", next = new string('n', 500) });
        Assert.Equal(HttpStatusCode.BadRequest, groupTooLong.StatusCode);
        HttpResponseMessage groupOk = await client.PostAsJsonAsync("/account/change", new { userName = "a", current = "x", next = "y" });
        Assert.Equal(HttpStatusCode.OK, groupOk.StatusCode);
        Assert.Equal(2, handlerCalls);

        using JsonDocument problem = JsonDocument.Parse(await tooLong.Content.ReadAsStringAsync());
        Assert.Equal(400, problem.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public void WithPasswordLengthLimit_NullBuilder_Throws() =>
        Assert.Throws<ArgumentNullException>(() => PasswordLengthEndpointConventionBuilderExtensions.WithPasswordLengthLimit<RouteHandlerBuilder>(null!));
}
