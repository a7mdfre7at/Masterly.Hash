using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.UnitTests;

/// <summary>Less common paths through <see cref="PasswordHasher"/>: Inspect edge cases, wrapping, limits and guards.</summary>
public class PasswordHasherEdgeCaseTests
{
    private const string Pw = "hunter2";
    private const string ValidSalt = "AAAAAAAAAAAAAAAAAAAAAA";
    private const string ValidTag = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Inspect_NullOrEmpty_IsUnknown(string? stored)
    {
        HashInfo info = TestHashers.Create().Inspect(stored!);

        Assert.Equal(HashInfo.UnknownFormat, info.Format);
        Assert.False(info.IsRecognized);
        Assert.False(info.IsNative);
        Assert.Equal(RehashReason.None, info.RehashReason);
    }

    public static TheoryData<string> MalformedNative() => new TheoryData<string>
    {
        "$mh$garbage",
        "$mh$p$" + ValidSalt + "$" + ValidTag,                    // parameter without '='
        "$mh$=test-fast$" + ValidSalt + "$" + ValidTag,           // empty parameter name
        "$mh$p=test-fast$" + ValidSalt + "$" + new string('A', 1100), // longer than the format allows
    };

    [Theory]
    [MemberData(nameof(MalformedNative))]
    public void Inspect_MalformedNativeHash_IsNativeButUnrecognized(string stored)
    {
        PasswordHasher hasher = TestHashers.Create();

        HashInfo info = hasher.Inspect(stored);

        Assert.True(info.IsNative);
        Assert.False(info.IsRecognized);
        Assert.Null(info.ProfileId);
        Assert.Equal(RehashReason.None, info.RehashReason);
        Assert.Equal(VerificationFailureReason.MalformedHash, hasher.Verify(Pw, stored).FailureReason);
    }

    [Fact]
    public void Inspect_PepperedHash_ReportsKeyId_AndRecognizesOnlyKnownKeys()
    {
        PasswordHasher withK1 = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k1", "k1"));
        string stored = withK1.Hash(Pw);

        HashInfo current = withK1.Inspect(stored);
        Assert.Equal("k1", current.PepperKeyId);
        Assert.True(current.IsRecognized);
        Assert.Equal(RehashReason.None, current.RehashReason);

        HashInfo rotated = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k2", "k1", "k2")).Inspect(stored);
        Assert.True(rotated.IsRecognized);
        Assert.Equal(RehashReason.OutdatedPepperKey, rotated.RehashReason);

        HashInfo noPepper = TestHashers.Create().Inspect(stored);
        Assert.Equal("k1", noPepper.PepperKeyId);
        Assert.False(noPepper.IsRecognized);
        Assert.False(noPepper.NeedsRehash);

        HashInfo keyRetired = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k2", "k2")).Inspect(stored);
        Assert.False(keyRetired.IsRecognized);
    }

    [Fact]
    public void Wrap_FormatWithoutParameter_OmitsWp_AndVerifiesWithTheOriginalPassword()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.LegacyFormats.Add(new Sha256HexFormat()));
        string legacy = Sha256HexFormat.HashOf(Pw);

        Assert.True(hasher.TryWrap(legacy, out string wrapped));

        Assert.StartsWith("$mh$p=test-fast,w=sha256hex$", wrapped);
        Assert.DoesNotContain("wp=", wrapped);

        HashInfo info = hasher.Inspect(wrapped);
        Assert.True(info.IsRecognized);
        Assert.Equal("sha256hex", info.WrappedFormat);
        Assert.Null(info.PepperKeyId);
        Assert.Equal(RehashReason.Wrapped, info.RehashReason);

        PasswordVerificationResult ok = hasher.Verify(Pw, wrapped);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, ok.Status);
        Assert.Equal(RehashReason.Wrapped, ok.RehashReason);
        Assert.StartsWith("$mh$p=test-fast$", ok.Rehash);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(Pw + "x", wrapped).FailureReason);
    }

    [Fact]
    public void Inspect_WrappedHash_FormatNotRegistered_IsUnrecognized()
    {
        string wrapped = WrapWithSha256Hex(Pw);

        HashInfo info = TestHashers.Create().Inspect(wrapped);

        Assert.True(info.IsNative);
        Assert.False(info.IsRecognized);
        Assert.Equal("sha256hex", info.WrappedFormat);
        Assert.Equal(RehashReason.None, info.RehashReason);
    }

    [Fact]
    public void Wrapped_ComputeWrapInputThrows_FailsAsMalformedHash()
    {
        string wrapped = WrapWithSha256Hex(Pw);
        PasswordHasher hasher = TestHashers.Create(o => o.LegacyFormats.Add(new Sha256HexFormat(computeThrows: new InvalidOperationException("boom"))));

        Assert.Equal(VerificationFailureReason.MalformedHash, hasher.Verify(Pw, wrapped).FailureReason);
    }

    [Fact]
    public void Wrapped_ComputeWrapInputCancelled_Propagates()
    {
        string wrapped = WrapWithSha256Hex(Pw);
        PasswordHasher hasher = TestHashers.Create(o => o.LegacyFormats.Add(new Sha256HexFormat(computeThrows: new OperationCanceledException())));

        Assert.Throws<OperationCanceledException>(() => hasher.Verify(Pw, wrapped));
    }

    [Fact]
    public void Wrapped_PasswordOverLimit_FailsWithPasswordTooLong()
    {
        string longPassword = new string('a', 65);
        PasswordHasher hasher = TestHashers.Create(o =>
        {
            o.MaxPasswordBytes = 64;
            o.LegacyFormats.Add(new Sha256HexFormat());
        });
        Assert.True(hasher.TryWrap(Sha256HexFormat.HashOf(longPassword), out string wrapped));

        Assert.Equal(VerificationFailureReason.PasswordTooLong, hasher.Verify(longPassword, wrapped).FailureReason);
    }

    [Fact]
    public void Legacy_PasswordOverLimit_FailsWithPasswordTooLong()
    {
        string longPassword = new string('a', 65);
        string v1 = TestHashers.Original1x(longPassword, new byte[16], V1Algorithm.SHA512);
        PasswordHasher hasher = TestHashers.Create(o => o.MaxPasswordBytes = 64);

        Assert.Equal(VerificationFailureReason.PasswordTooLong, hasher.Verify(longPassword, v1).FailureReason);
    }

    [Fact]
    public void Legacy_ComputeRehashDisabled_FlagsButDoesNotHash()
    {
        string v1 = TestHashers.Original1x(Pw, new byte[16], V1Algorithm.SHA256);
        PasswordHasher hasher = TestHashers.Create(o => o.ComputeRehashOnVerify = false);

        PasswordVerificationResult result = hasher.Verify(Pw, v1);

        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.LegacyFormat, result.RehashReason);
        Assert.Null(result.Rehash);
    }

    [Fact]
    public void NeedsRehash_OnInstance_ReflectsInspect()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.AdditionalProfiles.Add(TestHashers.Fast2));
        string unregisteredProfile = TestHashers.Create(o => o.DefaultProfile = HashProfile.Argon2id("other", 64, 1)).Hash(Pw);

        Assert.False(hasher.NeedsRehash(hasher.Hash(Pw)));
        Assert.True(hasher.NeedsRehash(hasher.Hash(Pw, TestHashers.Fast2)));
        Assert.False(hasher.NeedsRehash(unregisteredProfile)); // unrecognized, so a login cannot replace it
        Assert.True(hasher.NeedsRehash(TestHashers.Original1x(Pw, new byte[8], V1Algorithm.SHA512)));
        Assert.False(hasher.NeedsRehash("garbage"));
    }

    [Fact]
    public async Task NoConcurrencyLimit_EveryOperationWorks()
    {
        PasswordHasher hasher = TestHashers.Create(o =>
        {
            o.MaxConcurrency = 0;
            o.LegacyFormats.Add(new Sha256HexFormat());
        });

        string stored = await hasher.HashAsync(Pw);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(Pw, stored).Status);
        Assert.Equal(VerificationStatus.Success, (await hasher.VerifyAsync(Pw, stored)).Status);

        PasswordVerificationResult legacy = hasher.Verify(Pw, TestHashers.Original1x(Pw, new byte[8], V1Algorithm.SHA384));
        Assert.Equal(RehashReason.LegacyFormat, legacy.RehashReason);
        Assert.NotNull(legacy.Rehash);

        Assert.True(hasher.TryWrap(Sha256HexFormat.HashOf(Pw), out string wrapped));
        Assert.True(hasher.Verify(Pw, wrapped).IsMatch);
    }

    [Theory]
    [InlineData(typeof(OperationCanceledException))]
    [InlineData(typeof(OutOfMemoryException))]
    public void LegacyFormat_FatalExceptions_AreNotSwallowed(Type exceptionType)
    {
        var format = new FatalFormat((Exception)Activator.CreateInstance(exceptionType)!);
        PasswordHasher hasher = TestHashers.Create(o => o.LegacyFormats.Insert(0, format));

        Exception ex = Assert.ThrowsAny<Exception>(() => hasher.Verify(Pw, FatalFormat.Marker));
        Assert.IsType(exceptionType, ex);
    }

    [Fact]
    public async Task NullArguments_Throw()
    {
        PasswordHasher hasher = TestHashers.Create();
        string stored = hasher.Hash(Pw);

        Assert.Equal("profile", Assert.Throws<ArgumentNullException>(() => hasher.Hash(Pw, null!)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => hasher.Hash(null!)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => hasher.Verify(null!, stored)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => hasher.VerifyOrDummy(null!, stored)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => hasher.VerifyOrDummy(null!, null)).ParamName);
        Assert.Equal("password", (await Assert.ThrowsAsync<ArgumentNullException>(async () => await hasher.VerifyOrDummyAsync(null!, null))).ParamName);
    }

    [Fact]
    public void TryWrap_RejectsNativeEmptyAndUnknownHashes()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.LegacyFormats.Add(new Sha256HexFormat()));

        Assert.False(hasher.TryWrap(hasher.Hash(Pw), out string wrapped));
        Assert.Equal(string.Empty, wrapped);
        Assert.False(hasher.TryWrap(string.Empty, out _));
        Assert.False(hasher.TryWrap(null!, out _));
        Assert.False(hasher.TryWrap("unknown-format", out _));
    }

    private static string WrapWithSha256Hex(string password)
    {
        PasswordHasher wrapper = TestHashers.Create(o => o.LegacyFormats.Add(new Sha256HexFormat()));
        Assert.True(wrapper.TryWrap(Sha256HexFormat.HashOf(password), out string wrapped));
        return wrapped;
    }

    /// <summary>A legacy format, <c>sha256:&lt;hex&gt;</c>, whose wrap input needs no parameter.</summary>
    private sealed class Sha256HexFormat : ILegacyHashFormat
    {
        private const string Prefix = "sha256:";
        private readonly Exception? _computeThrows;

        public Sha256HexFormat(Exception? computeThrows = null) => _computeThrows = computeThrows;

        public static string HashOf(string password) =>
            Prefix + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password)));

        public string Id => "sha256hex";
        public bool CanHandle(string storedHash) => storedHash.StartsWith(Prefix, StringComparison.Ordinal) && storedHash.Length == Prefix.Length + 64;
        public bool Verify(string password, string storedHash) => HashOf(password) == storedHash;

        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Convert.FromHexString(storedHash.Substring(Prefix.Length));
            parameter = Array.Empty<byte>();
            return true;
        }

        public byte[] ComputeWrapInput(string password, byte[] parameter)
        {
            if (_computeThrows != null)
                throw _computeThrows;
            Assert.Empty(parameter);
            return SHA256.HashData(Encoding.UTF8.GetBytes(password));
        }
    }

    private sealed class FatalFormat : ILegacyHashFormat
    {
        public const string Marker = "fatal-marker";
        private readonly Exception _exception;

        public FatalFormat(Exception exception) => _exception = exception;

        public string Id => "fatal";
        public bool CanHandle(string storedHash) => storedHash == Marker;
        public bool Verify(string password, string storedHash) => throw _exception;

        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = parameter = Array.Empty<byte>();
            return false;
        }

        public byte[] ComputeWrapInput(string password, byte[] parameter) => throw new NotSupportedException();
    }
}
