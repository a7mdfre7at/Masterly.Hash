using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Legacy.Internal;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

/// <summary>Edge paths not reached by the scenario tests.</summary>
public class CoverageGapTests
{
    public static IEnumerable<object[]> AllFormatIds()
    {
        foreach (ILegacyHashFormat format in LegacyFormats.All)
            yield return new object[] { format.Id };
    }

    [Theory]
    [MemberData(nameof(AllFormatIds))]
    public void Verify_and_ComputeWrapInput_reject_a_null_password(string id)
    {
        ILegacyHashFormat format = Format(id);

        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => format.Verify(null!, "anything")).ParamName);
        if (format is ExternalArgon2Format)
            Assert.Throws<FormatException>(() => format.ComputeWrapInput(null!, new byte[64])); // never wrapped
        else
            Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => format.ComputeWrapInput(null!, new byte[64])).ParamName);
    }

    // ---------- bcrypt internals: BCrypt.Net failures are reported as null, never thrown ----------

    [Theory]
    [InlineData("garbage")]                           // SaltParseException: no rounds
    [InlineData("$2b$32$CCCCCCCCCCCCCCCCCCCCC.")]     // SaltParseException: rounds out of range
    [InlineData("$2b$03$CCCCCCCCCCCCCCCCCCCCC.")]     // ArgumentException: bad number of rounds
    [InlineData("$2b$05$CCCCCCCCCCCCCCCCCCCCC")]      // ArgumentOutOfRangeException: salt one character short
    public void BCrypt_Compute_returns_null_when_BCryptNet_rejects_the_salt(string salt)
    {
        Assert.Null(BCryptFormat.Compute("pw", salt));
    }

    [Fact]
    public void BCrypt_Compute_returns_null_for_a_null_salt()
    {
        // BCrypt.Net throws ArgumentNullException, an ArgumentException.
        Assert.Null(BCryptFormat.Compute("pw", null!));
    }

    [Fact]
    public void BCrypt_Compute_returns_the_31_character_digest_for_a_valid_prefix()
    {
        // Known answer from the OpenBSD/BCrypt.Net test vectors: "U*U" with cost 5.
        byte[]? digest = BCryptFormat.Compute("U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.");
        Assert.NotNull(digest);
        Assert.Equal("E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", System.Text.Encoding.ASCII.GetString(digest!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("$2b$10$")]
    [InlineData("$2b$10$CCCCCCCCCCCCCCCCCCCCC")] // one salt character short
    public void BCrypt_TryParsePrefix_rejects_short_values(string value)
    {
        Assert.False(BCryptFormat.TryParsePrefix(value, out int cost));
        Assert.Equal(0, cost);
    }

    // ---------- HashAudit.IsWeak: unparseable PBKDF2 hashes are not "weak", they are unknown ----------

    [Theory]
    [InlineData("django-pbkdf2", "pbkdf2_sha256$abc$salt$hash")]
    [InlineData("django-pbkdf2", "garbage")]
    [InlineData("aspnet-identity-v3", "AQAAAA==")]
    [InlineData("aspnet-identity-v3", "garbage")]
    [InlineData("bcrypt", "garbage")]
    [InlineData("wordpress-bcrypt", "garbage")]
    [InlineData("custom-format", "anything")]
    public void IsWeak_is_false_for_unparseable_or_unknown_hashes(string format, string hash)
    {
        Assert.False(HashAudit.IsWeak(format, hash));
    }

    [Fact]
    public void IsWeak_compares_Django_iterations_with_the_threshold()
    {
        Assert.True(HashAudit.IsWeak("django-pbkdf2", "pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY="));
        string strong = $"pbkdf2_sha256${HashAudit.WeakPbkdf2IterationsBelow}$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=";
        Assert.False(HashAudit.IsWeak("django-pbkdf2", strong));
    }

    [Fact]
    public void IsWeak_rejects_a_null_stored_hash()
    {
        Assert.Equal("storedHash", Assert.Throws<ArgumentNullException>(() => HashAudit.IsWeak("bcrypt", null!)).ParamName);
        Assert.Equal("formatId", Assert.Throws<ArgumentNullException>(() => HashAudit.IsWeak(null!, "x")).ParamName);
    }

    // ---------- report escaping ----------

    [Fact]
    public void Markdown_escapes_pipes_backslashes_backticks_and_control_characters_in_custom_format_ids()
    {
        var hasher = new FixedInfoHasher(new HashInfo("a|b\\c`d\ne\u007Ff\tg", true, "p\\1", null, null, null, RehashReason.None));

        HashAuditReport report = HashAudit.Audit(hasher, new[] { "h1", "h2" });
        string md = report.ToMarkdown();

        Assert.Equal(2, report.ByFormat["a|b\\c`d\ne\u007Ff\tg"]);
        Assert.Contains("| a\\|b\\\\c\\`d e f g | 2 | 100.0% | 0 |", md);
        Assert.Contains("| p\\\\1 | 2 | 100.0% |", md);
        // Ordinal: under culture-sensitive comparison DEL is ignorable and "found" everywhere.
        Assert.DoesNotContain("\u007F", md, StringComparison.Ordinal);
        Assert.DoesNotContain("\t", md, StringComparison.Ordinal);
    }

    // ---------- LegacyEncoding.TryFromHex: callers pre-validate, so its own rejections are checked directly ----------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abc")]  // odd length
    [InlineData("0g")]   // bad low nibble
    [InlineData("g0")]   // bad high nibble
    [InlineData("zz")]
    public void TryFromHex_rejects_invalid_input(string? value)
    {
        Assert.False(LegacyEncoding.TryFromHex(value!, out byte[] bytes));
        Assert.Empty(bytes);
    }

    [Fact]
    public void TryFromHex_rejects_input_longer_than_the_stored_limit()
    {
        Assert.False(LegacyEncoding.TryFromHex(new string('a', LegacyEncoding.MaxStoredLength + 2), out _));
        Assert.True(LegacyEncoding.TryFromHex(new string('a', LegacyEncoding.MaxStoredLength), out byte[] max));
        Assert.Equal(LegacyEncoding.MaxStoredLength / 2, max.Length);
    }

    [Fact]
    public void TryFromHex_decodes_either_case()
    {
        Assert.True(LegacyEncoding.TryFromHex("00aBcDeF", out byte[] bytes));
        Assert.Equal(new byte[] { 0x00, 0xAB, 0xCD, 0xEF }, bytes);
    }

    /// <summary>A hasher whose <see cref="Inspect"/> always reports the same info.</summary>
    private sealed class FixedInfoHasher : IPasswordHasher
    {
        private readonly HashInfo _info;

        public FixedInfoHasher(HashInfo info) => _info = info;

        public HashInfo Inspect(string storedHash) => _info;

        public string Hash(string password) => throw new NotSupportedException();
        public string Hash(string password, HashProfile profile) => throw new NotSupportedException();
        public PasswordVerificationResult Verify(string password, string storedHash) => throw new NotSupportedException();
        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) => throw new NotSupportedException();
        public ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public bool NeedsRehash(string storedHash) => throw new NotSupportedException();
        public bool TryWrap(string legacyHash, out string wrappedHash) => throw new NotSupportedException();
    }
}
