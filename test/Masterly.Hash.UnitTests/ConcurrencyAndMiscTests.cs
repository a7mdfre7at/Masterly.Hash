using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.UnitTests;

public class ConcurrencyTests
{
    [Fact]
    public async Task ConcurrencyLimit_RejectsWhenSaturated()
    {
        var blocker = new BlockingFormat();
        var hasher = TestHashers.Create(o =>
        {
            o.MaxConcurrency = 1;
            o.ConcurrencyTimeout = TimeSpan.FromMilliseconds(50);
            o.LegacyFormats.Add(blocker);
        });

        Task<PasswordVerificationResult> holder = Task.Run(() => hasher.Verify("pw", BlockingFormat.Marker));
        Assert.True(blocker.Entered.Wait(TimeSpan.FromSeconds(10)));

        Assert.Throws<PasswordHasherBusyException>(() => hasher.Hash("pw"));
        await Assert.ThrowsAsync<PasswordHasherBusyException>(async () => await hasher.HashAsync("pw"));

        blocker.Release.Set();
        await holder;
        Assert.StartsWith("$mh$", hasher.Hash("pw")); // slot freed
    }

    [Fact]
    public async Task ConcurrencyLimit_HonoursCancellation()
    {
        var blocker = new BlockingFormat();
        var hasher = TestHashers.Create(o =>
        {
            o.MaxConcurrency = 1;
            o.ConcurrencyTimeout = Timeout.InfiniteTimeSpan;
            o.LegacyFormats.Add(blocker);
        });

        Task holder = Task.Run(() => hasher.Verify("pw", BlockingFormat.Marker));
        Assert.True(blocker.Entered.Wait(TimeSpan.FromSeconds(10)));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await hasher.HashAsync("pw", cts.Token));

        blocker.Release.Set();
        await holder;
    }

    [Fact]
    public void ParallelUse_IsThreadSafe()
    {
        var hasher = TestHashers.Create(o => o.MaxConcurrency = 4);
        string[] passwords = Enumerable.Range(0, 32).Select(i => "pw-" + i).ToArray();

        string[] hashes = passwords.AsParallel().Select(hasher.Hash).ToArray();

        Assert.All(passwords.Zip(hashes), pair => Assert.True(hasher.Verify(pair.First, pair.Second).IsMatch));
    }

    [Fact]
    public void RehashInsideVerify_DoesNotDeadlockAtLimitOfOne()
    {
        var hasher = TestHashers.Create(o =>
        {
            o.MaxConcurrency = 1;
            o.ConcurrencyTimeout = TimeSpan.FromSeconds(5);
        });
        string legacy = TestHashers.Original1x("pw", new byte[8], V1Algorithm.SHA512);

        Assert.NotNull(hasher.Verify("pw", legacy).Rehash);
    }

    private sealed class BlockingFormat : ILegacyHashFormat
    {
        public const string Marker = "block-me";
        public readonly ManualResetEventSlim Entered = new ManualResetEventSlim();
        public readonly ManualResetEventSlim Release = new ManualResetEventSlim();

        public string Id => "blocking";
        public bool CanHandle(string storedHash) => storedHash == Marker;

        public bool Verify(string password, string storedHash)
        {
            Entered.Set();
            Release.Wait(TimeSpan.FromSeconds(30));
            return false;
        }

        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = parameter = Array.Empty<byte>();
            return false;
        }

        public byte[] ComputeWrapInput(string password, byte[] parameter) => throw new NotSupportedException();
    }
}

public class SensitiveStringTests
{
    private sealed record LoginRequest(string Email, SensitiveString Password);

    [Fact]
    public void NeverRevealsItself()
    {
        var secret = new SensitiveString("hunter2");

        Assert.Equal("***", secret.ToString());
        Assert.Equal("***", $"{secret}");
        Assert.Equal("hunter2", secret.Reveal());
        Assert.DoesNotContain("hunter2", new LoginRequest("a@b.c", secret).ToString());
    }

    [Fact]
    public void Json_ReadsRealValue_WritesRedacted()
    {
        var request = JsonSerializer.Deserialize<LoginRequest>("{\"Email\":\"a@b.c\",\"Password\":\"hunter2\"}")!;

        Assert.Equal("hunter2", request.Password.Reveal());
        Assert.Equal("{\"Email\":\"a@b.c\",\"Password\":\"***\"}", JsonSerializer.Serialize(request));
    }

    [Fact]
    public void Overloads_HashAndVerify()
    {
        IPasswordHasher hasher = TestHashers.Create();
        var secret = new SensitiveString("hunter2");
        Assert.True(hasher.Verify(secret, hasher.Hash(secret)).IsMatch);
        Assert.True(SensitiveString.TryParse("x", out var parsed) && parsed!.Reveal() == "x");
    }

    [Fact]
    public void LengthAndIsEmpty_DescribeTheValue()
    {
        var secret = new SensitiveString("päss");
        Assert.Equal(4, secret.Length);
        Assert.False(secret.IsEmpty);

        var empty = new SensitiveString(string.Empty);
        Assert.Equal(0, empty.Length);
        Assert.True(empty.IsEmpty);
    }

    [Fact]
    public void ExplicitConversion_WrapsTheString()
    {
        var secret = (SensitiveString)"hunter2";
        Assert.Equal("hunter2", secret.Reveal());
        Assert.Equal(SensitiveString.Redacted, secret.ToString());
        Assert.Equal("value", Assert.Throws<ArgumentNullException>(() => (SensitiveString)(string)null!).ParamName);
    }

    [Fact]
    public void Constructor_Null_Throws()
    {
        Assert.Equal("value", Assert.Throws<ArgumentNullException>(() => new SensitiveString(null!)).ParamName);
    }

    [Fact]
    public void TryParse_Null_ReturnsFalse()
    {
        Assert.False(SensitiveString.TryParse(null, out SensitiveString? result));
        Assert.Null(result);
    }

    [Fact]
    public void Json_NullProperty_DeserializesToNull()
    {
        var request = JsonSerializer.Deserialize<LoginRequest>("{\"Email\":\"a@b.c\",\"Password\":null}")!;
        Assert.Null(request.Password);
    }

    [Theory]
    [InlineData("123")]
    [InlineData("true")]
    [InlineData("{}")]
    [InlineData("[\"hunter2\"]")]
    public void Json_NonStringToken_Throws(string json)
    {
        var ex = Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<LoginRequest>("{\"Email\":\"a@b.c\",\"Password\":" + json + "}"));
        Assert.DoesNotContain("hunter2", ex.Message);
    }

    [Fact]
    public void Converter_ReadsNullTokenAsNull()
    {
        // The serializer short-circuits null for reference types; a direct caller of the converter still gets null back.
        var reader = new Utf8JsonReader("null"u8);
        Assert.True(reader.Read());

        SensitiveString? value = new SensitiveStringJsonConverter().Read(ref reader, typeof(SensitiveString), JsonSerializerOptions.Default);

        Assert.Null(value);
    }

    [Fact]
    public void Converter_ReadsStringAndRejectsOtherTokens()
    {
        var converter = new SensitiveStringJsonConverter();

        var reader = new Utf8JsonReader("\"hunter2\""u8);
        Assert.True(reader.Read());
        Assert.Equal("hunter2", converter.Read(ref reader, typeof(SensitiveString), JsonSerializerOptions.Default)!.Reveal());

        var number = new Utf8JsonReader("42"u8);
        Assert.True(number.Read());
        try
        {
            converter.Read(ref number, typeof(SensitiveString), JsonSerializerOptions.Default);
            Assert.Fail("Expected JsonException.");
        }
        catch (JsonException ex)
        {
            Assert.Equal("Expected a string.", ex.Message);
        }
    }

    [Fact]
    public void Json_TopLevelValue_WritesRedacted()
    {
        Assert.Equal("\"***\"", JsonSerializer.Serialize(new SensitiveString("hunter2")));
        Assert.Equal("hunter2", JsonSerializer.Deserialize<SensitiveString>("\"hunter2\"")!.Reveal());
    }
}

/// <summary>The real profiles, end to end. Slower (hundreds of ms each).</summary>
public class ProductionProfileTests
{
    [Fact]
    public void StaticApi_DefaultProfile_RoundTrips()
    {
        string stored = Password.Hash("hunter2");

        Assert.StartsWith("$mh$p=2026a$", stored);
        Assert.Equal(VerificationStatus.Success, Password.Verify("hunter2", stored).Status);
        Assert.False(Password.Verify("hunter3", stored).IsMatch);
    }

    [Fact]
    public void ConstrainedProfile_IsUpgradedToDefault()
    {
        string stored = Password.Hash("hunter2", HashProfile.Constrained2026a);

        Assert.StartsWith("$mh$p=2026c$", stored);
        var result = Password.Verify("hunter2", stored);
        Assert.Equal(RehashReason.OutdatedProfile, result.RehashReason);
        Assert.StartsWith("$mh$p=2026a$", result.Rehash);
    }

    [Fact]
    public void FipsProfile_RoundTrips()
    {
        var hasher = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = HashProfile.Fips2026a });
        string stored = hasher.Hash("hunter2");

        Assert.StartsWith("$mh$p=2026f$", stored);
        Assert.Equal(VerificationStatus.Success, hasher.Verify("hunter2", stored).Status);
    }
}
