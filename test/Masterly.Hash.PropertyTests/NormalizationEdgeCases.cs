using System;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// Normalization edge cases found by this suite and fixed in core: U+FFFE (which .NET's NFKC rejects) is an
/// InvalidPassword, and a legacy password that only exceeds MaxPasswordBytes after NFKC still logs in, with a null
/// Rehash instead of an exception.
/// </summary>
[Properties(Arbitrary = new[] { typeof(Arbitraries) }, QuietOnSuccess = true)]
public class NormalizationEdgeCases
{
    // ---- U+FFFE ----------------------------------------------------------------------------------------------------

    /// <summary>
    /// "a" + U+FFFE is well-formed UTF-16 and <see cref="Primitives.HashPrimitives.IsWellFormedPassword"/> says the
    /// hasher accepts it, but string.Normalize(FormKC) throws "String contains invalid Unicode code points" on
    /// U+FFFE (it is the only code point that does), and core calls it unguarded: Hash and EncodePassword throw an
    /// undocumented ArgumentException, and Verify / VerifyOrDummy throw instead of returning a result. Any fix
    /// (accept and hash it, or reject it as InvalidPassword and make IsWellFormedPassword false) passes. The
    /// generators map U+FFFE to U+FFFF until then.
    /// </summary>
    [Fact]
    public void A_password_containing_U_FFFE_is_either_hashable_or_rejected_cleanly()
    {
        foreach (string password in new[] { "a\uFFFE", "\uFFFE", "pass\uFFFEword", "\uFEFF\uFFFE" })
        {
            string context = Fixtures.Show(password);
            bool accepted = Primitives.HashPrimitives.IsWellFormedPassword(password);
            foreach (PasswordHasher hasher in Fixtures.AllHashersWithUnpepperedWrap())
            {
                string stored = hasher.Hash("a");
                PasswordVerificationResult result = hasher.Verify(password, stored);
                Assertions.Consistent(result, context);
                Assert.False(result.IsMatch, context);
                Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy(password, null).FailureReason);
                if (accepted)
                {
                    Assert.True(hasher.Verify(password, hasher.Hash(password)).IsMatch, context);
                }
                else
                {
                    Assert.Equal(VerificationFailureReason.InvalidPassword, result.FailureReason);
                    Assert.Throws<ArgumentException>(() => hasher.Hash(password));
                }
            }
        }
    }

    // ---- Legacy rehash length gap --------------------------------------------------------------------------------

    /// <summary>
    /// 100 x U+FDFA is 300 raw UTF-8 bytes (the legacy length check passes) but 3300 bytes after NFKC, so the
    /// rehash after a successful 1.x verify calls Hash, which throws ArgumentException out of Verify. Any fix
    /// (Success with a null Rehash, or PasswordTooLong) must not throw and must keep the result consistent.
    /// </summary>
    [Fact]
    public void Verify_does_not_throw_when_a_legacy_password_expands_past_the_cap()
    {
        string password = new string('ﷺ', 100);
        string v1 = Fixtures.BuildLegacyHash(0, password, Fixtures.Bytes(16, 7));
        AssertNeverThrowsAndStaysConsistent(Fixtures.Plain, password, v1);
        AssertNeverThrowsAndStaysConsistent(Fixtures.Wrapping, password, v1);

        Assert.True(Fixtures.Wrapping.TryWrap(v1, out string wrapped));
        AssertNeverThrowsAndStaysConsistent(Fixtures.Wrapping, password, wrapped);
    }

    /// <summary>Generalization of the Fact above over every legacy kind.</summary>
    [Property(MaxTest = 100)]
    public Property Verify_does_not_throw_in_the_legacy_rehash_length_gap() =>
        Prop.ForAll(Arbitraries.LegacyGapCases().ToArbitrary(), c =>
        {
            string legacy = Fixtures.BuildLegacyHash(c.Kind, c.Password, c.Salt);
            foreach (PasswordHasher hasher in Fixtures.AllHashersWithUnpepperedWrap())
            {
                AssertNeverThrowsAndStaysConsistent(hasher, c.Password, legacy);
                if (hasher.TryWrap(legacy, out string wrapped))
                    AssertNeverThrowsAndStaysConsistent(hasher, c.Password, wrapped);
            }
        });

    private static void AssertNeverThrowsAndStaysConsistent(PasswordHasher hasher, string password, string stored)
    {
        string context = $"{Fixtures.Name(hasher)}: {Assertions.Context(password, stored)}";
        PasswordVerificationResult sync = hasher.Verify(password, stored);
        PasswordVerificationResult async = hasher.VerifyAsync(password, stored).AsTask().GetAwaiter().GetResult();
        PasswordVerificationResult dummy = hasher.VerifyOrDummy(password, stored);
        foreach (PasswordVerificationResult r in new[] { sync, async, dummy })
        {
            Assertions.Consistent(r, context);
            Assert.Equal(sync.Status, r.Status);
            if (r.Rehash != null)
                Assert.True(hasher.Verify(password, r.Rehash).IsMatch, context);
        }
    }
}
