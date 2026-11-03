using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.UnitTests;

/// <summary>Regression tests for issues found by the satellite-package reviews and the property-based fuzzer.</summary>
public class HardeningTests
{
    [Fact]
    public void Parameters_MustBeInCanonicalOrder()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("key1", "key1"));
        string hash = hasher.Hash("hunter2");
        Assert.Contains("$mh$p=test-fast,k=key1$", hash);
        Assert.True(hasher.Verify("hunter2", hash).IsMatch);

        string reordered = hash.Replace("p=test-fast,k=key1", "k=key1,p=test-fast");
        PasswordVerificationResult result = hasher.Verify("hunter2", reordered);
        Assert.False(result.IsMatch);
        Assert.Equal(VerificationFailureReason.MalformedHash, result.FailureReason);
    }

    // xUnit serializes string test data and would turn lone surrogates into U+FFFD, so pass code units.
    [Theory]
    [InlineData(0xD800, false)]
    [InlineData(0xDC00, false)]
    [InlineData(0xDBFF, true)]
    public void UnpairedSurrogates_AreRejected_NotCollapsedToReplacementChar(int surrogate, bool prefix)
    {
        string password = prefix ? (char)surrogate + "pw" : "pw" + (char)surrogate;
        PasswordHasher hasher = TestHashers.Create();
        Assert.Throws<ArgumentException>(() => hasher.Hash(password));
        Assert.Throws<ArgumentException>(() => HashPrimitives.EncodePassword(password));
        Assert.False(HashPrimitives.IsWellFormedPassword(password));

        string replacement = hasher.Hash("pwFFFD");
        PasswordVerificationResult result = hasher.Verify(password, replacement);
        Assert.False(result.IsMatch);
        Assert.Equal(VerificationFailureReason.InvalidPassword, result.FailureReason);
        Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy(password, null).FailureReason);
    }

    [Fact]
    public void SurrogatePairs_AreFine()
    {
        PasswordHasher hasher = TestHashers.Create();
        string hash = hasher.Hash("pw😀"); // 😀
        Assert.True(hasher.Verify("pw😀", hash).IsMatch);
        Assert.False(hasher.Verify("pw😁", hash).IsMatch);
    }

    [Fact]
    public void TryFromB64_ClearsOutput_OnNonCanonicalInput()
    {
        Assert.False(HashPrimitives.TryFromB64("AB", out byte[] bytes)); // trailing bits set
        Assert.Empty(bytes);
        Assert.True(HashPrimitives.TryFromB64("AA", out bytes));
        Assert.Single(bytes);
    }

    [Fact]
    public void ThrowingThirdPartyFormat_NeverBreaksVerify()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.LegacyFormats.Insert(0, new ThrowingFormat()));
        PasswordVerificationResult result = hasher.Verify("pw", "throw-me");
        Assert.False(result.IsMatch);
        Assert.False(hasher.TryWrap("throw-me", out _));
        Assert.True(hasher.Inspect("throw-me").IsRecognized);
        Assert.False(hasher.Inspect("other").IsRecognized); // CanHandle throws
        Assert.Equal(VerificationFailureReason.UnknownFormat, hasher.Verify("pw", "other").FailureReason);
    }

    [Fact]
    public void V1_DoesNotClaimHexDigests()
    {
        string hex = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("pw"))).ToLowerInvariant();
        Assert.False(V1LegacyFormat.Instance.CanHandle(hex));
        Assert.Equal(HashInfo.UnknownFormat, PasswordHasher.Default.Inspect(hex).Format);

        string v1 = TestHashers.Original1x("pw", RandomNumberGenerator.GetBytes(16), V1Algorithm.SHA256);
        Assert.True(V1LegacyFormat.Instance.CanHandle(v1));
    }

    [Fact]
    public void PublicHelpers_MatchCoreRules()
    {
        Assert.Equal(new[] { "2026a", "2026c", "2026f" }, Array.ConvertAll(System.Linq.Enumerable.ToArray(HashProfile.BuiltIn), p => p.Id));
        Assert.True(HashProfile.TryGetBuiltIn("2026c", out HashProfile c));
        Assert.Same(HashProfile.Constrained2026a, c);
        Assert.False(HashProfile.TryGetBuiltIn("2025z", out _));

        Assert.True(HashPrimitives.IsValidProfileId("2026a"));
        Assert.False(HashPrimitives.IsValidProfileId("2026A"));
        Assert.True(HashPrimitives.IsValidKeyId("Key-1"));
        Assert.False(HashPrimitives.IsValidKeyId("key_1"));
        Assert.True(HashPrimitives.IsValidFormatId("aspnet-identity-v3"));
        Assert.False(HashPrimitives.IsValidFormatId("-bad"));

        Assert.True(HashPrimitives.FixedTimeEquals(new byte[] { 1, 2 }.AsSpan(), new byte[] { 1, 2 }.AsSpan()));
        Assert.False(HashPrimitives.FixedTimeEquals(new byte[] { 1, 2 }.AsSpan(), new byte[] { 1, 3 }.AsSpan()));
        Assert.False(HashPrimitives.FixedTimeEquals(new byte[] { 1 }.AsSpan(), new byte[] { 1, 2 }.AsSpan()));

        Assert.Equal(1024, PasswordHasher.Default.MaxPasswordBytes);
        HashInfo info = PasswordHasher.Default.Inspect(Password.Hash("x"));
        Assert.True(info.IsNative);
        Assert.Equal(HashInfo.NativeFormat, info.Format);
        Assert.False(new HashInfo("bcrypt", true, null, null, null, null, RehashReason.LegacyFormat).IsNative);
    }

    [Fact]
    public void NonNormalizableCodePoint_IsInvalidPassword_NotAnException()
    {
        string password = "a" + (char)0xFFFE; // .NET's NFKC throws on U+FFFE
        PasswordHasher hasher = TestHashers.Create();
        Assert.False(HashPrimitives.IsWellFormedPassword(password));
        Assert.Throws<ArgumentException>(() => hasher.Hash(password));
        Assert.Equal(VerificationFailureReason.InvalidPassword, hasher.Verify(password, hasher.Hash("a")).FailureReason);
        Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy(password, null).FailureReason);
    }

    [Fact]
    public void LegacyPassword_ThatExpandsPastTheCapUnderNfkc_LogsIn_WithoutRehash()
    {
        string password = new string('ﷺ', 100); // 300 UTF-8 bytes raw, 3300 after NFKC
        string v1 = TestHashers.Original1x(password, RandomNumberGenerator.GetBytes(16), V1Algorithm.SHA512);
        PasswordHasher hasher = TestHashers.Create();

        PasswordVerificationResult result = hasher.Verify(password, v1);
        Assert.True(result.IsMatch);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Null(result.Rehash);
        Assert.Throws<ArgumentException>(() => hasher.Hash(password));
    }

    private sealed class ThrowingFormat : ILegacyHashFormat
    {
        public string Id => "throwing";
        public bool CanHandle(string storedHash) => storedHash == "throw-me" ? true : throw new InvalidOperationException();
        public bool Verify(string password, string storedHash) => throw new InvalidOperationException("boom");
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter) => throw new NullReferenceException();
        public byte[] ComputeWrapInput(string password, byte[] parameter) => throw new InvalidOperationException();
    }
}
