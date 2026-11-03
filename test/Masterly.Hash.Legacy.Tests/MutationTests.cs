using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Legacy.Internal;
using Masterly.Hash.Primitives;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

/// <summary>
/// Exact-boundary and exact-output tests: each one fails if a comparison, a guard or an output string in the
/// legacy formats is changed, not just if the code stops running.
/// </summary>
public class MutationTests
{
    private const string BCryptSalt = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.";
    private const string BCryptDigest = "E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    private const string PhpassVector = "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0";
    private const string PhpassPassword = "test12345";

    // ---------- FormatException messages are part of the diagnostics surface ----------

    [Fact]
    public void Wrap_parameter_errors_have_precise_messages()
    {
        Assert.Equal("Invalid ASP.NET Identity v2 wrap parameter.",
            Assert.Throws<FormatException>(() => AspNetIdentityV2Format.Instance.ComputeWrapInput("pw", new byte[15])).Message);

        Assert.Equal("Invalid ASP.NET Identity v3 wrap parameter.",
            Assert.Throws<FormatException>(() => AspNetIdentityV3Format.Default.ComputeWrapInput("pw", new byte[5])).Message);
        byte[] badPrf = new byte[13 + 8 + 1];
        badPrf[0] = 0x01;
        badPrf[4] = 9; // PRF 9 does not exist
        badPrf[^1] = 32;
        Assert.Equal("Invalid ASP.NET Identity v3 wrap parameter.",
            Assert.Throws<FormatException>(() => AspNetIdentityV3Format.Default.ComputeWrapInput("pw", badPrf)).Message);

        Assert.Equal("Invalid md5 wrap parameter.",
            Assert.Throws<FormatException>(() => UnsaltedDigestFormat.Md5.ComputeWrapInput("pw", new byte[1])).Message);
        Assert.Equal("Invalid sha512 wrap parameter.",
            Assert.Throws<FormatException>(() => UnsaltedDigestFormat.Sha512.ComputeWrapInput("pw", null!)).Message);

        Assert.Equal("argon2-phc hashes are not onion-wrapped.",
            Assert.Throws<FormatException>(() => ExternalArgon2Format.Default.ComputeWrapInput("pw", new byte[8])).Message);
    }

    // ---------- bcrypt ----------

    [Fact]
    public void BCrypt_null_wrap_parameter_is_a_format_error()
    {
        FormatException ex = Assert.Throws<FormatException>(() => BCryptFormat.Default.ComputeWrapInput("U*U", null!));
        Assert.Equal("Invalid bcrypt wrap parameter.", ex.Message);
        Assert.Equal("Invalid bcrypt wrap parameter.",
            Assert.Throws<FormatException>(() => BCryptFormat.Default.ComputeWrapInput("U*U", new byte[28])).Message);
    }

    [Fact]
    public void BCrypt_wrap_parameter_at_exactly_the_cost_cap_is_computed()
    {
        var format = new BCryptFormat(5);
        byte[] digest = format.ComputeWrapInput("U*U", Encoding.ASCII.GetBytes(BCryptSalt));
        Assert.Equal(BCryptDigest, Encoding.ASCII.GetString(digest));

        // One above the cap: refused, with the parameter message.
        FormatException ex = Assert.Throws<FormatException>(() =>
            format.ComputeWrapInput("U*U", Encoding.ASCII.GetBytes("$2a$06$CCCCCCCCCCCCCCCCCCCCC.")));
        Assert.Equal("Invalid bcrypt wrap parameter.", ex.Message);
    }

    [Theory]
    [InlineData("$2a$2$$CCCCCCCCCCCCCCCCCCCCC.")] // second cost digit below '0' ('$' - '0' = -12, so 2$ would read as 8)
    [InlineData("$2a$1.$CCCCCCCCCCCCCCCCCCCCC.")] // '.' below '0'
    [InlineData("$2a$1:$CCCCCCCCCCCCCCCCCCCCC.")] // second cost digit above '9' (1: would read as 20)
    [InlineData("$2a$0A$CCCCCCCCCCCCCCCCCCCCC.")] // 'A' above '9' (0A would read as 17)
    [InlineData("$2a$32$CCCCCCCCCCCCCCCCCCCCC.")] // one above the hard maximum
    [InlineData("$2a$03$CCCCCCCCCCCCCCCCCCCCC.")] // one below the minimum
    public void BCrypt_prefix_rejects_non_digit_and_out_of_range_costs(string prefix)
    {
        Assert.False(BCryptFormat.TryParsePrefix(prefix, out _));
        Assert.False(BCryptFormat.Default.CanHandle(prefix + BCryptDigest));
        Assert.False(new BCryptFormat(BCryptFormat.HardMaxCost).CanHandle(prefix + BCryptDigest));
    }

    [Theory]
    [InlineData("$2b$04$CCCCCCCCCCCCCCCCCCCCC.", 4)]
    [InlineData("$2b$31$CCCCCCCCCCCCCCCCCCCCC.", 31)]
    [InlineData("$2y$19$CCCCCCCCCCCCCCCCCCCCC.", 19)]
    public void BCrypt_prefix_accepts_costs_at_both_limits(string prefix, int expected)
    {
        Assert.True(BCryptFormat.TryParsePrefix(prefix, out int cost));
        Assert.Equal(expected, cost);
        Assert.True(BCryptFormat.TryReadCost(prefix + BCryptDigest, out int read));
        Assert.Equal(expected, read);
        // Syntax only: no hashing happens, so even cost 31 is free to recognize.
        Assert.True(new BCryptFormat(BCryptFormat.HardMaxCost).CanHandle(prefix + BCryptDigest));
    }

    [Fact]
    public void BCrypt_password_BCrypt_Net_cannot_encode_never_verifies_and_cannot_be_wrapped()
    {
        // A lone surrogate is not valid UTF-16: BCrypt.Net's strict UTF-8 encoder throws (an ArgumentException),
        // which Compute turns into null. Verify must then say "no match" and ComputeWrapInput must refuse.
        const string loneSurrogate = "\uD800";
        string hash = BCryptSalt + BCryptDigest;
        Assert.True(BCryptFormat.Default.CanHandle(hash));

        Assert.Null(BCryptFormat.Compute(loneSurrogate, BCryptSalt));
        Assert.False(BCryptFormat.Default.Verify(loneSurrogate, hash));

        FormatException ex = Assert.Throws<FormatException>(() =>
            BCryptFormat.Default.ComputeWrapInput(loneSurrogate, Encoding.ASCII.GetBytes(BCryptSalt)));
        Assert.Equal("Invalid bcrypt wrap parameter.", ex.Message);
    }

    // ---------- WordPress bcrypt ----------

    [Fact]
    public void WordPress_null_wrap_parameter_is_a_format_error()
    {
        FormatException ex = Assert.Throws<FormatException>(() => WordPressBcryptFormat.Default.ComputeWrapInput("password", null!));
        Assert.Equal("Invalid WordPress bcrypt wrap parameter.", ex.Message);
        Assert.Equal("Invalid WordPress bcrypt wrap parameter.",
            Assert.Throws<FormatException>(() => WordPressBcryptFormat.Default.ComputeWrapInput("password", new byte[30])).Message);
    }

    [Fact]
    public void WordPress_cost_exactly_at_the_cap_is_accepted()
    {
        string hash = WordPressBcryptFormatTests.WordPressHash("password"); // cost 05
        var format = new WordPressBcryptFormat(5);

        Assert.True(format.CanHandle(hash));
        Assert.True(format.Verify("password", hash));
        Assert.True(format.TryExtractWrapInput(hash, out byte[] digest, out byte[] parameter));
        Assert.Equal(digest, format.ComputeWrapInput("password", parameter));

        var tighter = new WordPressBcryptFormat(4);
        Assert.False(tighter.CanHandle(hash));
        FormatException ex = Assert.Throws<FormatException>(() => tighter.ComputeWrapInput("password", parameter));
        Assert.Equal("Invalid WordPress bcrypt wrap parameter.", ex.Message);
    }

    [Fact]
    public void WordPress_too_long_password_has_its_own_message()
    {
        string hash = WordPressBcryptFormatTests.WordPressHash("password");
        Assert.True(WordPressBcryptFormat.Default.TryExtractWrapInput(hash, out _, out byte[] parameter));
        FormatException ex = Assert.Throws<FormatException>(() => WordPressBcryptFormat.Default.ComputeWrapInput(new string('p', 4097), parameter));
        Assert.Equal("Password is too long for WordPress.", ex.Message);
    }

    // ---------- phpass ----------

    [Fact]
    public void Phpass_rejects_a_character_outside_the_alphabet_inside_the_hash_part()
    {
        // Setting and the last character are valid; only a middle hash character is not in itoa64.
        string hash = "$P$9IQRaTwmf" + "e+o7ud9Fh4E2PdI0S3r.L0";
        Assert.Equal(34, hash.Length);
        Assert.False(PhpassFormat.Default.CanHandle(hash));
        Assert.False(PhpassFormat.Default.TryExtractWrapInput(hash, out _, out _));
    }

    [Fact]
    public void Phpass_last_character_must_be_one_of_the_first_four_itoa64_characters()
    {
        string stem = PhpassVector.Substring(0, 33);
        Assert.True(PhpassFormat.Default.CanHandle(stem + "1"));  // index 3: allowed
        Assert.False(PhpassFormat.Default.CanHandle(stem + "2")); // index 4: low bits set
    }

    [Theory]
    [InlineData("#P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0")]
    [InlineData("$P#9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0")]
    public void Phpass_requires_the_dollar_delimiters(string hash)
    {
        Assert.False(PhpassFormat.Default.CanHandle(hash));
        Assert.Throws<FormatException>(() => PhpassFormat.Default.ComputeWrapInput(PhpassPassword, Encoding.ASCII.GetBytes(hash.Substring(0, 12))));
    }

    [Fact]
    public void Phpass_accepts_the_minimum_count_and_matches_a_reference_implementation()
    {
        const string setting = "$P$5IQRaTwmf"; // '5' is itoa64 index 7, the phpass minimum
        byte[] computed = PhpassFormat.Default.ComputeWrapInput(PhpassPassword, Encoding.ASCII.GetBytes(setting));
        string expected = ReferencePhpass(PhpassPassword, setting);
        Assert.Equal(expected, Encoding.ASCII.GetString(computed));

        string hash = setting + expected;
        Assert.True(new PhpassFormat(PhpassFormat.MinCostLog2).CanHandle(hash));
        Assert.True(PhpassFormat.Default.Verify(PhpassPassword, hash));
        Assert.False(PhpassFormat.Default.Verify(PhpassPassword + "x", hash));

        // Count 6 ('4') is below the minimum.
        Assert.False(PhpassFormat.Default.CanHandle("$P$4" + hash.Substring(4)));
    }

    [Fact]
    public void Phpass_accepts_the_first_itoa64_character_in_the_salt()
    {
        const string setting = "$P$9.QRaTwmf"; // '.' is itoa64 index 0
        string expected = ReferencePhpass(PhpassPassword, setting);
        string hash = setting + expected;
        Assert.True(PhpassFormat.Default.CanHandle(hash));
        Assert.True(PhpassFormat.Default.Verify(PhpassPassword, hash));
        Assert.Equal(expected, Encoding.ASCII.GetString(PhpassFormat.Default.ComputeWrapInput(PhpassPassword, Encoding.ASCII.GetBytes(setting))));
    }

    [Fact]
    public void Reference_phpass_reproduces_the_openwall_vector()
    {
        Assert.Equal(PhpassVector, "$P$9IQRaTwmf" + ReferencePhpass(PhpassPassword, "$P$9IQRaTwmf"));
    }

    /// <summary>Independent crypt_private from phpass 0.3 (PasswordHash.php), for cross-checking.</summary>
    private static string ReferencePhpass(string password, string setting)
    {
        const string itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        int count = 1 << itoa64.IndexOf(setting[3]);
        byte[] pw = Encoding.UTF8.GetBytes(password);
        byte[] salt = Encoding.ASCII.GetBytes(setting.Substring(4, 8));
        byte[] hash = MD5.HashData(Concat(salt, pw));
        do
        {
            hash = MD5.HashData(Concat(hash, pw));
        }
        while (--count > 0);

        var output = new StringBuilder();
        int i = 0;
        do
        {
            int value = hash[i++];
            output.Append(itoa64[value & 0x3f]);
            if (i < 16)
                value |= hash[i] << 8;
            output.Append(itoa64[(value >> 6) & 0x3f]);
            if (i++ >= 16)
                break;
            if (i < 16)
                value |= hash[i] << 16;
            output.Append(itoa64[(value >> 12) & 0x3f]);
            if (i++ >= 16)
                break;
            output.Append(itoa64[(value >> 18) & 0x3f]);
        }
        while (i < 16);
        return output.ToString();
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    // ---------- Django PBKDF2 ----------

    private static string DjangoHash(int iterations, string salt, string password = "pw") =>
        $"pbkdf2_sha256${iterations}${salt}${Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), Encoding.ASCII.GetBytes(salt), iterations, HashAlgorithmName.SHA256, 32))}";

    private static byte[] DjangoParameter(byte algorithm, uint iterations, string salt)
    {
        byte[] parameter = new byte[5 + salt.Length];
        parameter[0] = algorithm;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(parameter.AsSpan(1, 4), iterations);
        Encoding.ASCII.GetBytes(salt).CopyTo(parameter, 5);
        return parameter;
    }

    [Fact]
    public void Django_accepts_one_iteration_and_a_one_character_salt()
    {
        string hash = DjangoHash(1, "s");
        Assert.True(DjangoPbkdf2Format.Default.CanHandle(hash));
        Assert.True(DjangoPbkdf2Format.Default.Verify("pw", hash));
        Assert.True(DjangoPbkdf2Format.TryReadIterations(hash, out int iterations));
        Assert.Equal(1, iterations);

        Assert.False(DjangoPbkdf2Format.Default.CanHandle(hash.Replace("$1$", "$0$", StringComparison.Ordinal)));
        Assert.False(DjangoPbkdf2Format.Default.CanHandle(hash.Replace("$s$", "$$", StringComparison.Ordinal)));
    }

    [Fact]
    public void Django_salt_may_use_the_first_and_last_printable_characters()
    {
        string hash = DjangoHash(1, "!~");
        Assert.True(DjangoPbkdf2Format.Default.CanHandle(hash));
        Assert.True(DjangoPbkdf2Format.Default.Verify("pw", hash));
        Assert.False(DjangoPbkdf2Format.Default.CanHandle(DjangoHash(1, "a b")));       // 0x20
        Assert.False(DjangoPbkdf2Format.Default.CanHandle(DjangoHash(1, "a\u007Fb"))); // 0x7F
    }

    [Fact]
    public void Django_wrap_parameter_accepts_the_smallest_and_largest_valid_shapes()
    {
        // 6 bytes: one iteration, one salt character.
        byte[] smallest = DjangoParameter(1, 1, "s");
        Assert.Equal(6, smallest.Length);
        Assert.Equal(Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes("pw"), "s"u8.ToArray(), 1, HashAlgorithmName.SHA256, 32),
            DjangoPbkdf2Format.Default.ComputeWrapInput("pw", smallest));

        // 133 bytes: a 128-character salt.
        string salt128 = new string('s', 128);
        byte[] largest = DjangoParameter(0, 1, salt128);
        Assert.Equal(133, largest.Length);
        Assert.Equal(Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes("pw"), Encoding.ASCII.GetBytes(salt128), 1, HashAlgorithmName.SHA1, 20),
            DjangoPbkdf2Format.Default.ComputeWrapInput("pw", largest));

        // Printable salt boundaries.
        Assert.Equal(32, DjangoPbkdf2Format.Default.ComputeWrapInput("pw", DjangoParameter(1, 1, "!~")).Length);

        Assert.Equal("Invalid Django PBKDF2 wrap parameter.",
            Assert.Throws<FormatException>(() => DjangoPbkdf2Format.Default.ComputeWrapInput("pw", DjangoParameter(1, 1, new string('s', 129)))).Message);
        Assert.Equal("Invalid Django PBKDF2 wrap parameter.",
            Assert.Throws<FormatException>(() => DjangoPbkdf2Format.Default.ComputeWrapInput("pw", DjangoParameter(1, 0, "s"))).Message);
        Assert.Equal("Invalid Django PBKDF2 wrap parameter.",
            Assert.Throws<FormatException>(() => DjangoPbkdf2Format.Default.ComputeWrapInput("pw", null!)).Message);
    }

    [Fact]
    public void Django_wrap_parameter_iterations_exactly_at_the_cap_are_accepted()
    {
        var format = new DjangoPbkdf2Format(3);
        Assert.Equal(Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes("pw"), "salt"u8.ToArray(), 3, HashAlgorithmName.SHA256, 32),
            format.ComputeWrapInput("pw", DjangoParameter(1, 3, "salt")));
        Assert.Throws<FormatException>(() => format.ComputeWrapInput("pw", DjangoParameter(1, 4, "salt")));
    }

    // ---------- external Argon2 ----------

    private static string Argon2Phc(string costs, int saltLength, int hashLength) =>
        $"$argon2id$v=19${costs}${HashPrimitives.ToB64(Bytes(saltLength, 1))}${HashPrimitives.ToB64(Bytes(hashLength, 2))}";

    [Fact]
    public void Argon2_memory_must_be_at_least_8_KiB_per_lane()
    {
        Assert.True(ExternalArgon2Format.Default.CanHandle(Argon2Phc("m=8,t=1,p=1", 16, 32)));
        Assert.False(ExternalArgon2Format.Default.CanHandle(Argon2Phc("m=7,t=1,p=1", 16, 32)));
        Assert.True(ExternalArgon2Format.Default.CanHandle(Argon2Phc("m=16,t=1,p=2", 16, 32)));
        Assert.False(ExternalArgon2Format.Default.CanHandle(Argon2Phc("m=15,t=1,p=2", 16, 32)));
        Assert.False(ExternalArgon2Format.Default.CanHandle(Argon2Phc("m=8,t=1,p=2", 16, 32)));
    }

    [Fact]
    public void Argon2_minimum_memory_hash_really_verifies()
    {
        byte[] salt = Bytes(16, 1);
        byte[] tag;
        using (var argon2 = new Konscious.Security.Cryptography.Argon2id(Encoding.UTF8.GetBytes("pw")) { Salt = salt, MemorySize = 8, Iterations = 1, DegreeOfParallelism = 1 })
            tag = argon2.GetBytes(16);
        string hash = $"$argon2id$v=19$m=8,t=1,p=1${HashPrimitives.ToB64(salt)}${HashPrimitives.ToB64(tag)}";
        Assert.True(ExternalArgon2Format.Default.Verify("pw", hash));
        Assert.False(ExternalArgon2Format.Default.Verify("pX", hash));
    }

    // Regression: Konscious surfaces the allocation failure as AggregateException(OutOfMemoryException).
    [Fact]
    public void Argon2_allocation_failure_is_a_non_match_not_an_exception()
    {
        // The test host's GC heap is capped at 1 GiB (System.GC.HeapHardLimit in the test csproj), so the single
        // 1 GiB block array an m=1 GiB, p=1 verify needs can never be allocated: Konscious throws
        // OutOfMemoryException up front, before any hashing, and Verify must turn it into "no match".
        long available = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        Assert.True(available <= 1L << 30, $"GC heap hard limit not applied (available: {available} bytes).");

        var format = new ExternalArgon2Format(HashProfile.MaxMemoryKiB, 1, 1);
        string hash = Argon2Phc($"m={HashProfile.MaxMemoryKiB},t=1,p=1", 16, 32);
        Assert.True(format.CanHandle(hash));
        AssertQuick(() => Assert.False(format.Verify("pw", hash)), 5000);
    }

    [Theory]
    [InlineData(8, 32, true)]
    [InlineData(7, 32, false)]
    [InlineData(64, 32, true)]
    [InlineData(65, 32, false)]
    [InlineData(16, 4, true)]
    [InlineData(16, 3, false)]
    [InlineData(16, 128, true)]
    [InlineData(16, 129, false)]
    public void Argon2_salt_and_hash_lengths_are_inclusive_ranges(int saltLength, int hashLength, bool accepted)
    {
        Assert.Equal(accepted, ExternalArgon2Format.Default.CanHandle(Argon2Phc("m=64,t=1,p=1", saltLength, hashLength)));
    }

    // ---------- LegacyEncoding ----------

    [Theory]
    [InlineData("0", 0L)]
    [InlineData("7", 7L)]
    [InlineData("10", 10L)]
    [InlineData("1234567890", 1234567890L)] // exactly 10 digits
    [InlineData("9999999999", 9999999999L)]
    public void TryParseDecimal_accepts_canonical_numbers(string value, long expected)
    {
        Assert.True(LegacyEncoding.TryParseDecimal(value, out long result));
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("01")]
    [InlineData("00")]
    [InlineData("12345678901")] // 11 digits
    [InlineData("1a")]
    [InlineData("a")]
    [InlineData("/")]           // just below '0'
    [InlineData(":")]           // just above '9'
    [InlineData("-1")]
    [InlineData(" 1")]
    public void TryParseDecimal_rejects_non_canonical_input(string? value)
    {
        Assert.False(LegacyEncoding.TryParseDecimal(value!, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("AAA")]  // not a multiple of 4
    [InlineData("AA*=")] // character outside the alphabet
    [InlineData("A===")] // valid characters, invalid base64
    [InlineData("AB==")] // non-canonical: unused bits set
    public void TryFromBase64Padded_rejects_invalid_input(string? value)
    {
        Assert.False(LegacyEncoding.TryFromBase64Padded(value!, out byte[] bytes));
        Assert.Empty(bytes);
    }

    [Fact]
    public void TryFromBase64Padded_enforces_the_stored_length_limit()
    {
        Assert.True(LegacyEncoding.TryFromBase64Padded(new string('A', LegacyEncoding.MaxStoredLength), out byte[] max));
        Assert.Equal(LegacyEncoding.MaxStoredLength / 4 * 3, max.Length);
        Assert.False(LegacyEncoding.TryFromBase64Padded(new string('A', LegacyEncoding.MaxStoredLength + 4), out byte[] over));
        Assert.Empty(over);
    }

    [Fact]
    public void TryFromBase64Padded_decodes_canonical_input()
    {
        Assert.True(LegacyEncoding.TryFromBase64Padded("AQID/w==", out byte[] bytes));
        Assert.Equal(new byte[] { 1, 2, 3, 0xFF }, bytes);
    }

    [Fact]
    public void WriteUInt32BigEndian_writes_every_byte()
    {
        byte[] buffer = new byte[6];
        LegacyEncoding.WriteUInt32BigEndian(buffer, 1, 0x8182_8384);
        Assert.Equal(new byte[] { 0, 0x81, 0x82, 0x83, 0x84, 0 }, buffer);
        Assert.Equal(0x8182_8384u, LegacyEncoding.ReadUInt32BigEndian(buffer, 1));
    }

    [Fact]
    public void FromPrintableAscii_accepts_exactly_0x20_to_0x7E()
    {
        Assert.Equal(" ~", LegacyEncoding.FromPrintableAscii(new byte[] { 0x41, 0x20, 0x7E, 0x41 }, 1, 2));
        Assert.Null(LegacyEncoding.FromPrintableAscii(new byte[] { 0x41, 0x1F }, 0, 2));
        Assert.Null(LegacyEncoding.FromPrintableAscii(new byte[] { 0x7F, 0x41 }, 0, 2));
        Assert.Null(LegacyEncoding.FromPrintableAscii(new byte[] { 0x80 }, 0, 1));
        Assert.Null(LegacyEncoding.FromPrintableAscii(new byte[] { 0x00 }, 0, 1));
    }

    // ---------- HashAudit ----------

    [Fact]
    public void Audit_counts_a_throwing_Inspect_as_unknown()
    {
        var hasher = new DelegateHasher(_ => throw new InvalidOperationException("boom"));
        HashAuditReport report = HashAudit.Audit(hasher, new[] { "a", "b" });

        Assert.Equal(2, report.Total);
        Assert.Equal(2, report.Unknown);
        Assert.Equal(0, report.Recognized);
        Assert.Equal(new KeyValuePair<string, long>("unknown", 2), Assert.Single(report.ByFormat));
    }

    [Fact]
    public void Audit_counts_an_empty_format_as_unknown()
    {
        var hasher = new DelegateHasher(_ => new HashInfo("", true, "p", null, null, null, RehashReason.LegacyFormat));
        HashAuditReport report = HashAudit.Audit(hasher, new[] { "a" });

        Assert.Equal(1, report.Unknown);
        Assert.Equal(0, report.Recognized);
        Assert.Equal(0, report.NeedsRehash);
        Assert.Empty(report.ByProfile);
        Assert.Equal(new KeyValuePair<string, long>("unknown", 1), Assert.Single(report.ByFormat));
    }

    [Fact]
    public void Audit_duplicates_need_the_whole_128_bit_fingerprint_to_match()
    {
        // Two different values whose SHA-256 bytes 8..15 (the fingerprint's low half, which alone decides the
        // HashSet bucket) are equal, while bytes 0..7 differ. Found offline with a parallel rho search
        // (distinguished points, about 6e9 SHA-256 evaluations). They are not duplicates.
        const string a = "9af61d128d7046a1";
        const string b = "99127298b4445524";
        byte[] da = SHA256.HashData(Encoding.UTF8.GetBytes(a));
        byte[] db = SHA256.HashData(Encoding.UTF8.GetBytes(b));
        Assert.Equal(0x97255c2f5edbcd53UL, BitConverter.ToUInt64(da, 8));
        Assert.Equal(0x97255c2f5edbcd53UL, BitConverter.ToUInt64(db, 8));
        Assert.NotEqual(BitConverter.ToUInt64(da, 0), BitConverter.ToUInt64(db, 0));

        PasswordHasher hasher = AllFormats();
        Assert.Equal(0, HashAudit.Audit(hasher, new[] { a, b }).Duplicates);
        Assert.Equal(0, HashAudit.Audit(hasher, new[] { b, a }).Duplicates);
        Assert.Equal(2, HashAudit.Audit(hasher, new[] { a, b, b, a }).Duplicates);
    }

    [Fact]
    public void Markdown_is_exact_and_sorted_by_count_then_ordinal_id()
    {
        PasswordHasher hasher = AllFormats();
        const string md5 = "5f4dcc3b5aa765d61d8327deb882cf99";
        const string bcrypt = BCryptSalt + BCryptDigest;
        // Insertion order (unknown, mh, md5, bcrypt) differs from both the count order and the ordinal order.
        string[] rows = { "garbage", hasher.Hash("pw"), md5, bcrypt, md5 };

        string md = HashAudit.Audit(hasher, rows).ToMarkdown();

        const string expected =
            "## Password hash audit\n\n" +
            "| Metric | Count | Share |\n" +
            "|---|---:|---:|\n" +
            "| Total | 5 | 100.0% |\n" +
            "| Recognized | 4 | 80.0% |\n" +
            "| Unknown | 1 | 20.0% |\n" +
            "| Needs rehash | 3 | 60.0% |\n" +
            "| Weak | 3 | 60.0% |\n" +
            "| Onion-wrapped | 0 | 0.0% |\n" +
            "| Duplicates | 1 | 20.0% |\n" +
            "\n### By format\n\n" +
            "| Format | Count | Share | Weak |\n" +
            "|---|---:|---:|---:|\n" +
            "| md5 | 2 | 40.0% | 2 |\n" +
            "| bcrypt | 1 | 20.0% | 1 |\n" +
            "| mh | 1 | 20.0% | 0 |\n" +
            "| unknown | 1 | 20.0% | 0 |\n" +
            "\n### By profile\n\n" +
            "| Profile | Count | Share |\n" +
            "|---|---:|---:|\n" +
            "| test | 1 | 20.0% |\n";
        Assert.Equal(expected, md);
    }

    [Fact]
    public void Markdown_onion_wrapped_row_counts_wrapped_hashes()
    {
        PasswordHasher hasher = AllFormats();
        Assert.True(hasher.TryWrap("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", out string wrapped));
        string md = HashAudit.Audit(hasher, new[] { wrapped, "garbage" }).ToMarkdown();
        Assert.Contains("\n| Onion-wrapped | 1 | 50.0% |\n", md, StringComparison.Ordinal);
    }

    /// <summary>A hasher whose <see cref="Inspect"/> is a delegate.</summary>
    private sealed class DelegateHasher : IPasswordHasher
    {
        private readonly Func<string, HashInfo> _inspect;

        public DelegateHasher(Func<string, HashInfo> inspect) => _inspect = inspect;

        public HashInfo Inspect(string storedHash) => _inspect(storedHash);

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
