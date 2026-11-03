using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

public class HashAuditTests
{
    private const string Md5Password = "5f4dcc3b5aa765d61d8327deb882cf99";
    private const string BCrypt5 = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    private const string BCrypt12 = "$2a$12$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"; // syntactically valid; never verified
    private const string Django10k = "pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=";
    private const string Django600k = "pbkdf2_sha256$600000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=";
    private const string Argon2 = "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8";
    private const string Phpass = "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0";

    private static string V1Hash()
    {
        byte[] salt = Bytes(16, 9);
        byte[] data = Encoding.UTF8.GetBytes("pw").Concat(salt).ToArray();
        return Convert.ToBase64String(SHA512.HashData(data).Concat(salt).ToArray());
    }

    [Fact]
    public void Classifies_a_mixed_table()
    {
        PasswordHasher hasher = AllFormats();
        Assert.True(hasher.TryWrap("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", out string wrappedSha1));
        string current = hasher.Hash("pw");
        string outdated = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = HashProfile.Argon2id("test-old", 64, 1), AllowWeakProfiles = true }).Hash("pw");
        var auditor = new PasswordHasher(new PasswordHasherOptions
        {
            DefaultProfile = Fast,
            AllowWeakProfiles = true,
            AdditionalProfiles = { HashProfile.Argon2id("test-old", 64, 1) },
        }.AddAllLegacyFormats());

        string?[] rows =
        {
            current,                                        // mh, current
            outdated,                                       // mh, outdated profile -> needs rehash
            "$mh$p=gone$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // unregistered profile
            wrappedSha1,                                    // wrapped
            Md5Password, Md5Password, Md5Password.ToUpperInvariant(), // weak, 1 exact duplicate
            BCrypt5,                                        // weak (cost 5)
            BCrypt12,                                       // not weak
            Django10k,                                      // weak (< 100k)
            Django600k,                                     // not weak
            IdentityV3(2, 100_000, Bytes(16, 1), Bytes(32, 2)), // not weak
            IdentityV3(1, 10_000, Bytes(16, 1), Bytes(32, 2)),  // weak
            Convert.ToBase64String(new byte[49]),           // identity v2: weak
            Argon2,                                         // strong, needs rehash
            Phpass,                                         // weak
            V1Hash(),                                       // weak
            "garbage", "", null, "$2b$31$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", // unknown (last one: over the cost cap)
        };

        HashAuditReport report = HashAudit.Audit(auditor, rows);

        Assert.Equal(rows.Length, report.Total);
        Assert.Equal(5, report.Unknown);
        Assert.Equal(rows.Length - 5, report.Recognized);
        Assert.Equal(report.Recognized - 1, report.NeedsRehash); // everything recognized except `current`
        Assert.Equal(9, report.Weak);
        Assert.Equal(1, report.Wrapped);
        Assert.Equal(1, report.Duplicates);
        Assert.Equal(rows.Length, report.ByFormat.Values.Sum());

        Assert.Equal(4, report.ByFormat["mh"]);       // current, outdated, unregistered profile, wrapped
        Assert.Equal(3, report.ByFormat["md5"]);
        Assert.Equal(2, report.ByFormat["bcrypt"]);
        Assert.Equal(2, report.ByFormat["django-pbkdf2"]);
        Assert.Equal(2, report.ByFormat["aspnet-identity-v3"]);
        Assert.Equal(1, report.ByFormat["aspnet-identity-v2"]);
        Assert.Equal(1, report.ByFormat["argon2-phc"]);
        Assert.Equal(1, report.ByFormat["phpass"]);
        Assert.Equal(1, report.ByFormat["v1"]);
        Assert.Equal(4, report.ByFormat["unknown"]);

        Assert.Equal(2, report.ByProfile["test"]);    // current + wrapped
        Assert.Equal(1, report.ByProfile["test-old"]);
        Assert.Equal(1, report.ByProfile["gone"]);

        Assert.Equal(3, report.WeakByFormat["md5"]);
        Assert.Equal(1, report.WeakByFormat["bcrypt"]);
        Assert.Equal(1, report.WeakByFormat["django-pbkdf2"]);
        Assert.Equal(1, report.WeakByFormat["aspnet-identity-v3"]);
        Assert.False(report.WeakByFormat.ContainsKey("argon2-phc"));
        Assert.False(report.WeakByFormat.ContainsKey("mh"));

        Assert.Equal(100.0 * 9 / rows.Length, report.WeakPercent, 9);
        Assert.Equal(100.0 * 5 / rows.Length, report.UnknownPercent, 9);
        Assert.Equal(100.0 / rows.Length, report.DuplicatePercent, 9);
        Assert.Equal(100.0 / rows.Length, report.WrappedPercent, 9);
        Assert.Equal(100.0, report.RecognizedPercent + report.UnknownPercent, 9);
        Assert.Equal(100.0 * report.NeedsRehash / rows.Length, report.NeedsRehashPercent, 9);
    }

    [Fact]
    public void Markdown_contains_tables()
    {
        HashAuditReport report = HashAudit.Audit(AllFormats(), new[] { Md5Password, Md5Password, BCrypt5, "garbage" });
        string md = report.ToMarkdown();

        Assert.Contains("| Metric | Count | Share |", md);
        Assert.Contains("| Total | 4 | 100.0% |", md);
        Assert.Contains("| Weak | 3 | 75.0% |", md);
        Assert.Contains("| Duplicates | 1 | 25.0% |", md);
        Assert.Contains("| Format | Count | Share | Weak |", md);
        Assert.Contains("| md5 | 2 | 50.0% | 2 |", md);
        Assert.Contains("| bcrypt | 1 | 25.0% | 1 |", md);
        Assert.Contains("| unknown | 1 | 25.0% | 0 |", md);
        Assert.DoesNotContain("By profile", md);
        Assert.True(md.IndexOf("| md5 |", StringComparison.Ordinal) < md.IndexOf("| bcrypt |", StringComparison.Ordinal), "sorted by count");
        Assert.DoesNotContain(Md5Password, md); // the report never echoes stored hashes

        Assert.Contains("4 hashes", report.ToString());
    }

    [Fact]
    public void Markdown_is_culture_invariant()
    {
        CultureInfoScope.Run("de-DE", () =>
        {
            string md = HashAudit.Audit(AllFormats(), new[] { Md5Password, "x", "y" }).ToMarkdown();
            Assert.Contains("33.3%", md);
        });
    }

    [Fact]
    public void Lists_profiles_when_present()
    {
        PasswordHasher hasher = AllFormats();
        string md = HashAudit.Audit(hasher, new[] { hasher.Hash("pw") }).ToMarkdown();
        Assert.Contains("### By profile", md);
        Assert.Contains("| test | 1 | 100.0% |", md);
    }

    [Fact]
    public void Empty_input()
    {
        HashAuditReport report = HashAudit.Audit(AllFormats(), Array.Empty<string>());
        Assert.Equal(0, report.Total);
        Assert.Equal(0, report.WeakPercent);
        Assert.Equal(0, report.Percent(5));
        Assert.Empty(report.ByFormat);
        Assert.Contains("| Total | 0 | 0.0% |", report.ToMarkdown());
    }

    [Fact]
    public void Enumerates_once_and_streams()
    {
        var source = new OnceEnumerable(Enumerable.Range(0, 20_000).Select(i => TestSupport.Hex(MD5.HashData(BitConverter.GetBytes(i % 15_000)))));
        HashAuditReport report = HashAudit.Audit(AllFormats(), source);
        Assert.Equal(1, source.Enumerations);
        Assert.Equal(20_000, report.Total);
        Assert.Equal(20_000, report.Weak);
        Assert.Equal(5_000, report.Duplicates);
    }

    [Fact]
    public void Survives_garbage_and_a_throwing_hasher()
    {
        var hasher = new ThrowingHasher(AllFormats(), "boom");
        var rows = Garbage().Concat(new[] { "boom", Md5Password }).ToArray();
        HashAuditReport report = HashAudit.Audit(hasher, rows);
        Assert.Equal(rows.Length, report.Total);
        Assert.Equal(1, report.Recognized);
        Assert.Equal(rows.Length - 1, report.Unknown);
    }

    [Fact]
    public void Guards()
    {
        Assert.Throws<ArgumentNullException>(() => HashAudit.Audit(null!, new string[0]));
        Assert.Throws<ArgumentNullException>(() => HashAudit.Audit(AllFormats(), null!));
        Assert.Throws<ArgumentNullException>(() => HashAudit.IsWeak(null!, "x"));
        Assert.Throws<ArgumentNullException>(() => HashAudit.IsWeak("md5", null!));
    }

    [Theory]
    [InlineData("bcrypt", "$2a$09$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", true)]
    [InlineData("bcrypt", "$2a$10$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", false)]
    [InlineData("wordpress-bcrypt", "$wp$2y$09$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", true)]
    [InlineData("wordpress-bcrypt", "$wp$2y$10$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", false)]
    [InlineData("wordpress-bcrypt", "$2y$09$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", false)]
    [InlineData("django-pbkdf2", "pbkdf2_sha256$99999$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=", true)]
    [InlineData("django-pbkdf2", "pbkdf2_sha256$100000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=", false)]
    [InlineData("v1", "anything", true)]
    [InlineData("phpass", "anything", true)]
    [InlineData("aspnet-identity-v2", "anything", true)]
    [InlineData("sha512", "anything", true)]
    [InlineData("argon2-phc", "anything", false)]
    [InlineData("mh", "anything", false)]
    [InlineData("bcrypt", "garbage", false)]
    public void Weakness_rules(string format, string hash, bool weak) => Assert.Equal(weak, HashAudit.IsWeak(format, hash));

    [Fact]
    public void Pbkdf2_threshold_for_identity_v3()
    {
        Assert.True(HashAudit.IsWeak("aspnet-identity-v3", IdentityV3(2, 99_999, Bytes(16, 1), Bytes(32, 2))));
        Assert.False(HashAudit.IsWeak("aspnet-identity-v3", IdentityV3(2, 100_000, Bytes(16, 1), Bytes(32, 2))));
        // Classified even when above the verification cap (it is not weak, merely unverifiable).
        Assert.False(HashAudit.IsWeak("aspnet-identity-v3", IdentityV3(2, 50_000_000, Bytes(16, 1), Bytes(32, 2))));
    }

    private sealed class OnceEnumerable : IEnumerable<string>
    {
        private readonly IEnumerable<string> _inner;

        public OnceEnumerable(IEnumerable<string> inner) => _inner = inner;

        public int Enumerations { get; private set; }

        public IEnumerator<string> GetEnumerator()
        {
            if (++Enumerations > 1)
                throw new InvalidOperationException("Enumerated twice.");
            return _inner.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class ThrowingHasher : IPasswordHasher
    {
        private readonly IPasswordHasher _inner;
        private readonly string _trigger;

        public ThrowingHasher(IPasswordHasher inner, string trigger)
        {
            _inner = inner;
            _trigger = trigger;
        }

        public HashInfo Inspect(string storedHash) =>
            storedHash == _trigger ? throw new InvalidOperationException("custom hasher failure") : _inner.Inspect(storedHash);

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

    private static class CultureInfoScope
    {
        public static void Run(string culture, Action action)
        {
            var previous = System.Globalization.CultureInfo.CurrentCulture;
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo(culture);
            try
            {
                action();
            }
            finally
            {
                System.Globalization.CultureInfo.CurrentCulture = previous;
            }
        }
    }
}
