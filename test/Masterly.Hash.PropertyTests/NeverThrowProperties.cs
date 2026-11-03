using System;
using System.Linq;
using System.Text;
using FsCheck.Xunit;
using Masterly.Hash.Legacy;
using Masterly.Hash.Primitives;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// No stored value, however broken, may make the hasher or a legacy format throw. The stored hash is attacker- or
/// corruption-controlled data; an exception there is a denial of service or an information leak.
/// </summary>
[Properties(Arbitrary = new[] { typeof(Arbitraries) }, QuietOnSuccess = true)]
public class NeverThrowProperties
{
    private static readonly ILegacyHashFormat[] AllFormats = Fixtures.FuzzFormats.Concat(LegacyFormats.All).ToArray();

    [Property(MaxTest = 3000)]
    public void Verify_never_throws_for_any_stored_hash(AnyString stored, AnyPassword password)
    {
        string context = Assertions.Context(password.Value, stored.Value);
        foreach (PasswordHasher hasher in Fixtures.AllHashers())
        {
            PasswordVerificationResult sync = hasher.Verify(password.Value, stored.Value);
            Assertions.Consistent(sync, context);

            PasswordVerificationResult async = hasher.VerifyAsync(password.Value, stored.Value).AsTask().GetAwaiter().GetResult();
            Assertions.Consistent(async, context);
            Assert.Equal(sync.Status, async.Status);
            Assert.Equal(sync.FailureReason, async.FailureReason);

            PasswordVerificationResult dummy = hasher.VerifyOrDummy(password.Value, stored.Value);
            Assertions.Consistent(dummy, context);
            Assert.Equal(sync.FailureReason, dummy.FailureReason);

            if (password.Value.Length == 0 && stored.Value.Length > 0)
                Assert.Equal(VerificationFailureReason.EmptyPassword, sync.FailureReason);

            // An ill-formed password is rejected before the stored hash is even parsed, whatever it holds.
            if (password.Value.Length > 0 && stored.Value.Length > 0 && !Fixtures.IsWellFormedUtf16(password.Value))
                Assert.True(sync.FailureReason == VerificationFailureReason.InvalidPassword, $"{context}: {sync}");
            else
                Assert.NotEqual(VerificationFailureReason.InvalidPassword, sync.FailureReason);

            // Unknown user: always NoStoredHash, whatever the password.
            Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy(password.Value, null).FailureReason);
        }
    }

    /// <summary>
    /// The password contract on any input: a password is hashable iff it is non-empty, well-formed UTF-16 and fits
    /// the cap after NFKC. Well-formedness is checked against an independent oracle, the encoding against
    /// string.Normalize + UTF-8, and every rejection is an ArgumentException (never anything else).
    /// </summary>
    [Property(MaxTest = 1500)]
    public void Hash_accepts_exactly_the_non_empty_well_formed_passwords_that_fit(AnyPassword password)
    {
        string p = password.Value;
        string context = Fixtures.Show(p);
        bool wellFormed = Fixtures.IsWellFormedUtf16(p);
        Assert.Equal(wellFormed, HashPrimitives.IsWellFormedPassword(p));

        if (!wellFormed)
        {
            Assert.Throws<ArgumentException>(() => HashPrimitives.EncodePassword(p));
            ArgumentException ex = Assert.Throws<ArgumentException>(() => Fixtures.Plain.Hash(p));
            Assert.Contains("invalid UTF-16", ex.Message, StringComparison.Ordinal);
            Assert.Throws<ArgumentException>(() => Fixtures.Plain.HashAsync(p).AsTask().GetAwaiter().GetResult());
            return;
        }

        byte[] encoded = HashPrimitives.EncodePassword(p);
        Assert.Equal(Encoding.UTF8.GetBytes(p.Normalize(NormalizationForm.FormKC)), encoded);
        if (p.Length == 0 || encoded.Length > Arbitraries.MaxPasswordBytes)
        {
            Assert.Throws<ArgumentException>(() => Fixtures.Plain.Hash(p));
            return;
        }

        string hash = Fixtures.Plain.Hash(p);
        Assert.Equal(VerificationStatus.Success, Fixtures.Plain.Verify(p, hash).Status);
        string wrong = Fixtures.WrongPassword(p);
        PasswordVerificationResult other = Fixtures.Plain.Verify(wrong, hash);
        if (Fixtures.NfkcEqual(p, wrong))
            Assert.True(other.IsMatch, context); // e.g. a leading fullwidth '!'
        else if (Fixtures.NfkcByteCount(wrong) <= Arbitraries.MaxPasswordBytes)
            Assert.True(other.FailureReason == VerificationFailureReason.Mismatch, $"{context}: {other}");
    }

    [Property(MaxTest = 3000)]
    public void Inspect_and_NeedsRehash_never_throw_and_agree_with_Verify(AnyString stored)
    {
        foreach (PasswordHasher hasher in Fixtures.AllHashers())
        {
            HashInfo info = hasher.Inspect(stored.Value);
            Assert.NotNull(info.Format);
            Assert.Equal(info.NeedsRehash, hasher.NeedsRehash(stored.Value));

            PasswordVerificationResult result = hasher.Verify("pw", stored.Value);
            string context = $"{Fixtures.Show(stored.Value)} info={info.Format}/{info.IsRecognized} result={result}";
            if (info.IsRecognized)
            {
                // A wrong password on a usable hash is a mismatch; MalformedHash only if a wrap parameter is bad.
                Assert.True(result.IsMatch
                    || result.FailureReason == VerificationFailureReason.Mismatch
                    || (result.FailureReason == VerificationFailureReason.MalformedHash && info.WrappedFormat != null), context);
            }
            else
            {
                Assert.False(info.NeedsRehash, context);
                Assert.False(result.IsMatch, context);
                Assert.Contains(result.FailureReason, Assertions.Unusable);
            }
        }
    }

    [Property(MaxTest = 3000)]
    public void TryWrap_never_throws_and_only_emits_usable_hashes(AnyString stored)
    {
        foreach (PasswordHasher hasher in Fixtures.AllHashers())
        {
            if (hasher.TryWrap(stored.Value, out string wrapped))
            {
                HashInfo info = hasher.Inspect(wrapped);
                Assert.True(info.IsRecognized, Fixtures.Show(wrapped));
                Assert.NotNull(info.WrappedFormat);
                Assert.Equal(RehashReason.Wrapped, info.RehashReason);
                // Arbitrary stored strings almost never accept "pw", so this is only a smoke check; the real
                // both-directions wrap equivalence is LegacyRoundTripProperties, on hashes of the actual password.
                Assert.True(hasher.Verify("pw", wrapped).IsMatch == hasher.Verify("pw", stored.Value).IsMatch,
                    $"wrapping changed whether \"pw\" verifies: {Fixtures.Show(stored.Value)}");
            }
            else
            {
                Assert.Equal(string.Empty, wrapped);
            }
        }
    }

    [Property(MaxTest = 2000)]
    public void Legacy_formats_never_throw_on_arbitrary_input(AnyString stored, AnyPassword password)
    {
        foreach (ILegacyHashFormat format in AllFormats)
        {
            string context = $"{format.Id}: {Assertions.Context(password.Value, stored.Value)}";
            bool handled = format.CanHandle(stored.Value);
            bool verified = format.Verify(password.Value, stored.Value);
            Assert.True(handled || !verified, context);

            if (format.TryExtractWrapInput(stored.Value, out byte[] digest, out byte[] parameter))
            {
                Assert.True(handled, context);
                Assert.NotNull(digest);
                Assert.NotNull(parameter);
                byte[] recomputed;
                try
                {
                    recomputed = format.ComputeWrapInput(password.Value, parameter);
                }
                catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
                {
                    // The documented failure signal, which the hasher maps to MalformedHash. It is only acceptable
                    // when the password does not verify: a format that verifies a password but rejects its own
                    // extracted parameter would make TryWrap emit a hash that locks the user out.
                    Assert.False(verified, $"ComputeWrapInput rejected its own parameter for a verifying password: {context}");
                    continue;
                }
                Assert.Equal(verified, recomputed.AsSpan().SequenceEqual(digest));
            }
        }
    }

    [Fact]
    public void Null_and_empty_stored_hashes_are_rejected()
    {
        foreach (PasswordHasher hasher in Fixtures.AllHashers())
        {
            Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.Verify("pw", null!).FailureReason);
            Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.Verify("pw", "").FailureReason);
            Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy("pw", null).FailureReason);
            Assert.False(hasher.Inspect(null!).IsRecognized);
            Assert.False(hasher.NeedsRehash(null!));
            Assert.False(hasher.TryWrap(null!, out _));
        }

        foreach (ILegacyHashFormat format in AllFormats)
        {
            Assert.False(format.CanHandle(null!));
            Assert.False(format.CanHandle(""));
            Assert.False(format.Verify("pw", ""));
        }
    }

    [Fact]
    public void A_null_password_is_a_programming_error_not_a_stored_hash_problem()
    {
        Assert.Throws<ArgumentNullException>(() => Fixtures.Plain.Verify(null!, "$mh$p=test$AAAA$AAAA"));
    }
}
