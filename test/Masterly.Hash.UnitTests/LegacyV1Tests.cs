using System;
using System.Text;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.UnitTests;

public class LegacyV1Tests
{
    private const string Pw = "SomePaswword!@#";

    public static TheoryData<V1Algorithm, int> Cases()
    {
        var data = new TheoryData<V1Algorithm, int>();
        foreach (V1Algorithm alg in Enum.GetValues<V1Algorithm>())
            foreach (int saltLength in new[] { 0, 4, 11, 15, 40 })
                data.Add(alg, saltLength);
        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Original1xHashes_VerifyWithoutKnowingTheAlgorithm(V1Algorithm algorithm, int saltLength)
    {
        byte[] salt = new byte[saltLength];
        new Random(saltLength).NextBytes(salt);
        string legacy = TestHashers.Original1x(Pw, salt, algorithm);
        var hasher = TestHashers.Create();

        var ok = hasher.Verify(Pw, legacy);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, ok.Status);
        Assert.Equal(RehashReason.LegacyFormat, ok.RehashReason);
        Assert.StartsWith("$mh$p=test-fast$", ok.Rehash);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(Pw, ok.Rehash!).Status);

        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(Pw + "x", legacy).FailureReason);
    }

    [Fact]
    public void StringSaltFrom1xReadme_Verifies()
    {
        string legacy = TestHashers.Original1x(Pw, Encoding.UTF8.GetBytes("SomeSalt#$%"), V1Algorithm.SHA256);
        Assert.True(Password.Verify(Pw, legacy).IsMatch);
    }

    [Fact]
    public void ObsoleteApi_StillWorks_AndNoLongerThrowsOnWrongAlgorithm()
    {
        var hash = new Hash();
        string sha256 = hash.ComputeHash(Pw, SupportedHash.SHA256);

        Assert.True(hash.Verify(Pw, sha256, SupportedHash.SHA256));
        // 1.x threw OverflowException here (negative salt length).
        Assert.False(hash.Verify(Pw, sha256, SupportedHash.SHA512));
        Assert.True(Password.Verify(Pw, sha256).IsMatch);
    }

    [Fact]
    public void LegacyDisabled_V1HashesAreUnknown()
    {
        var hasher = TestHashers.Create(o => o.LegacyFormats.Clear());
        string legacy = TestHashers.Original1x(Pw, new byte[8], V1Algorithm.SHA512);
        Assert.Equal(VerificationFailureReason.UnknownFormat, hasher.Verify(Pw, legacy).FailureReason);
    }

    [Theory]
    [InlineData("QUJD")]                    // too short
    [InlineData("not base64 at all!!")]
    [InlineData(" AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")] // whitespace
    public void V1_RejectsNonHashes(string value)
    {
        Assert.False(V1LegacyFormat.Instance.CanHandle(value));
    }

    [Fact]
    public void Wrap_V1WithKnownAlgorithm_VerifiesWithOriginalPassword()
    {
        var hasher = TestHashers.Create(o =>
        {
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA512));
        });
        string legacy = TestHashers.Original1x(Pw, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }, V1Algorithm.SHA512);

        Assert.True(hasher.TryWrap(legacy, out string wrapped));
        Assert.StartsWith("$mh$p=test-fast,w=v1,wp=", wrapped);

        var result = hasher.Verify(Pw, wrapped);
        Assert.Equal(RehashReason.Wrapped, result.RehashReason);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(Pw, result.Rehash!).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify("nope", wrapped).FailureReason);
    }

    [Fact]
    public void Wrap_WithPepper_IncludesKeyAndVerifies()
    {
        var hasher = TestHashers.Create(o =>
        {
            o.Pepper = TestHashers.Pepper("k1", "k1");
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA256));
        });
        string legacy = TestHashers.Original1x(Pw, new byte[12], V1Algorithm.SHA256);

        Assert.True(hasher.TryWrap(legacy, out string wrapped));
        Assert.Contains(",k=k1,", wrapped);
        Assert.True(hasher.Verify(Pw, wrapped).IsMatch);
    }

    [Fact]
    public void Wrap_AmbiguousV1_IsRefused()
    {
        var hasher = TestHashers.Create();
        Assert.False(hasher.TryWrap(TestHashers.Original1x(Pw, new byte[8], V1Algorithm.SHA512), out _));
        Assert.False(hasher.TryWrap(hasher.Hash(Pw), out _));
    }

    [Fact]
    public void Wrapped_FormatNoLongerRegistered_FailsWithUnknownFormat()
    {
        var wrapping = TestHashers.Create(o => o.LegacyFormats.Add(new WrappableAlias()));
        Assert.True(wrapping.TryWrap(TestHashers.Original1x(Pw, new byte[8], V1Algorithm.SHA512), out string wrapped));

        Assert.Equal(VerificationFailureReason.UnknownFormat, TestHashers.Create().Verify(Pw, wrapped).FailureReason);
    }

    public static TheoryData<string> NotV1() => new TheoryData<string>
    {
        "!" + new string('Q', 43),                       // 44 characters, one outside the base64 alphabet
        new string('Q', 20) + " " + new string('Q', 23), // embedded space
        "QQQQ=QQQ" + new string('Q', 36),                // padding in the middle: not decodable
        new string('Q', 42) + "==",                      // decodes to 31 bytes, below the 32-byte minimum
        new string('Q', 42) + "R=",                      // unused trailing bits set: not canonical
        new string('Q', 1028),                           // longer than any stored 1.x hash
        new string('Q', 45),                             // not a multiple of 4
    };

    [Theory]
    [MemberData(nameof(NotV1))]
    public void V1_RejectsNearMisses(string value)
    {
        Assert.False(V1LegacyFormat.Instance.CanHandle(value));
        Assert.False(V1LegacyFormat.Instance.Verify(Pw, value));
        Assert.False(new V1LegacyFormat(V1Algorithm.SHA256).TryExtractWrapInput(value, out byte[] digest, out byte[] parameter));
        Assert.Empty(digest);
        Assert.Empty(parameter);
    }

    [Fact]
    public void V1_Verify_NullStoredHash_IsFalse_NullPassword_Throws()
    {
        string legacy = TestHashers.Original1x(Pw, new byte[8], V1Algorithm.SHA256);

        Assert.False(V1LegacyFormat.Instance.Verify(Pw, null!));
        Assert.False(V1LegacyFormat.Instance.CanHandle(null!));
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => V1LegacyFormat.Instance.Verify(null!, legacy)).ParamName);
    }

    [Fact]
    public void V1_TryExtractWrapInput_HashShorterThanTheDigest_IsRefused()
    {
        // A SHA-256 hash with no salt is 32 bytes, shorter than a SHA-512 digest.
        string sha256 = TestHashers.Original1x(Pw, Array.Empty<byte>(), V1Algorithm.SHA256);

        Assert.True(new V1LegacyFormat(V1Algorithm.SHA256).TryExtractWrapInput(sha256, out byte[] digest, out byte[] parameter));
        Assert.Equal(32, digest.Length);
        Assert.Equal(new byte[] { (byte)V1Algorithm.SHA256 }, parameter);

        Assert.False(new V1LegacyFormat(V1Algorithm.SHA512).TryExtractWrapInput(sha256, out digest, out parameter));
        Assert.Empty(digest);
        Assert.Empty(parameter);
        Assert.False(new V1LegacyFormat(V1Algorithm.SHA512).Verify(Pw, sha256));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 3 })]
    [InlineData(new byte[] { 255, 1, 2 })]
    public void V1_ComputeWrapInput_InvalidParameter_Throws(byte[]? parameter)
    {
        Assert.Throws<FormatException>(() => V1LegacyFormat.Instance.ComputeWrapInput(Pw, parameter!));
    }

    [Fact]
    public void V1_ComputeWrapInput_NullPassword_Throws()
    {
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => V1LegacyFormat.Instance.ComputeWrapInput(null!, new byte[] { 0 })).ParamName);
    }

    [Theory]
    [InlineData(V1Algorithm.SHA256)]
    [InlineData(V1Algorithm.SHA384)]
    [InlineData(V1Algorithm.SHA512)]
    public void V1_ComputeWrapInput_ReproducesTheExtractedDigest(V1Algorithm algorithm)
    {
        byte[] salt = { 1, 2, 3, 4, 5 };
        var format = new V1LegacyFormat(algorithm);
        string legacy = TestHashers.Original1x(Pw, salt, algorithm);

        Assert.True(format.TryExtractWrapInput(legacy, out byte[] digest, out byte[] parameter));

        Assert.Equal(digest, format.ComputeWrapInput(Pw, parameter));
        Assert.NotEqual(digest, format.ComputeWrapInput(Pw + "x", parameter));
    }

    [Fact]
    public void Wrapped_TamperedWrapParameter_FailsAsMalformedHash()
    {
        var hasher = TestHashers.Create(o =>
        {
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA256));
        });
        Assert.True(hasher.TryWrap(TestHashers.Original1x(Pw, new byte[3], V1Algorithm.SHA256), out string wrapped));
        string[] parts = wrapped.Split('$');
        // Replace wp (algorithm byte 0 + 3 salt bytes) with an unknown algorithm byte.
        string tampered = "$mh$p=test-fast,w=v1,wp=BwAAAA$" + parts[3] + "$" + parts[4];

        Assert.StartsWith("$mh$p=test-fast,w=v1,wp=AAAAAA$", wrapped);
        Assert.Equal(VerificationFailureReason.MalformedHash, hasher.Verify(Pw, tampered).FailureReason);
    }

    /// <summary>A v1 variant under another id, to test unregistered wrap formats.</summary>
    private sealed class WrappableAlias : ILegacyHashFormat
    {
        private readonly V1LegacyFormat _inner = new V1LegacyFormat(V1Algorithm.SHA512);
        public string Id => "alias";
        public bool CanHandle(string storedHash) => _inner.CanHandle(storedHash);
        public bool Verify(string password, string storedHash) => _inner.Verify(password, storedHash);
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter) => _inner.TryExtractWrapInput(storedHash, out digest, out parameter);
        public byte[] ComputeWrapInput(string password, byte[] parameter) => _inner.ComputeWrapInput(password, parameter);
    }
}
