using System.Text;
using FsCheck.Xunit;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// Legacy and onion-wrapped hashes paired with the password they were made from, so the success path (and the
/// rehash that runs after it) is fuzzed, not just the rejection paths. The legacy hashes are built from each
/// system's published algorithm with BCL primitives (<see cref="Fixtures.BuildLegacyHash"/>), not by the formats
/// under test.
/// </summary>
[Properties(Arbitrary = new[] { typeof(Arbitraries) }, QuietOnSuccess = true)]
public class LegacyRoundTripProperties
{
    [Property(MaxTest = 500)]
    public void Legacy_hashes_of_any_password_verify_rehash_and_wrap_consistently(LegacyCase c)
    {
        string legacy = Fixtures.BuildLegacyHash(c.Kind, c.Password, c.Salt);
        string wrong = Fixtures.WrongPassword(c.Password);
        bool tooLong = Encoding.UTF8.GetByteCount(c.Password) > Arbitraries.MaxPasswordBytes;

        foreach (PasswordHasher hasher in Fixtures.AllHashersWithUnpepperedWrap())
        {
            string context = $"{c} hasher={Fixtures.Name(hasher)}";
            bool supported = Fixtures.Supports(hasher, c.Kind);

            PasswordVerificationResult sync = hasher.Verify(c.Password, legacy);
            PasswordVerificationResult async = hasher.VerifyAsync(c.Password, legacy).AsTask().GetAwaiter().GetResult();
            PasswordVerificationResult dummy = hasher.VerifyOrDummy(c.Password, legacy);
            foreach (PasswordVerificationResult r in new[] { sync, async, dummy })
            {
                Assertions.Consistent(r, context);
                Assert.Equal(sync.Status, r.Status);
                Assert.Equal(sync.FailureReason, r.FailureReason);
            }

            if (tooLong)
            {
                Assert.False(sync.IsMatch, context);
                Assert.True(sync.FailureReason == VerificationFailureReason.PasswordTooLong
                    || sync.FailureReason == VerificationFailureReason.UnknownFormat, $"{context}: {sync}");
            }
            else if (supported)
            {
                Assert.Equal(VerificationStatus.SuccessRehashNeeded, sync.Status);
                Assert.Equal(RehashReason.LegacyFormat, sync.RehashReason);
                AssertRehashIsCurrent(hasher, c.Password, sync, context);
                AssertRehashIsCurrent(hasher, c.Password, async, context);
            }
            else
            {
                Assert.False(sync.IsMatch, context);
            }

            Assert.False(hasher.Verify(wrong, legacy).IsMatch, $"wrong password verified: {context}");

            if (hasher.TryWrap(legacy, out string wrapped))
            {
                // Both directions: the wrapped hash accepts the password iff the original does, and never a wrong one.
                PasswordVerificationResult viaWrap = hasher.Verify(c.Password, wrapped);
                Assertions.Consistent(viaWrap, context);
                Assert.True(sync.IsMatch == viaWrap.IsMatch, $"wrap changed the outcome: {context}: {sync} vs {viaWrap}");
                if (viaWrap.IsMatch)
                {
                    Assert.Equal(RehashReason.Wrapped, viaWrap.RehashReason);
                    AssertRehashIsCurrent(hasher, c.Password, viaWrap, context);
                }

                PasswordVerificationResult viaWrapAsync = hasher.VerifyAsync(c.Password, wrapped).AsTask().GetAwaiter().GetResult();
                Assert.Equal(viaWrap.Status, viaWrapAsync.Status);
                Assert.False(hasher.Verify(wrong, wrapped).IsMatch, $"wrong password verified via wrap: {context}");
            }
            else
            {
                Assert.False(Fixtures.CanWrap(hasher, c.Kind), $"expected a wrap: {context}");
            }
        }
    }

    /// <summary>
    /// A 128-character hex string is both an unsalted SHA-512 digest and valid base64 of the shape a SHA-512 1.x hash
    /// has (64-byte digest + 32-byte salt). The 1.x format leaves hex-only strings to the hex formats, so it never
    /// claims one, and the hasher verifies and wraps it as sha512 whatever the registration order.
    /// </summary>
    [Fact]
    public void An_unsalted_sha512_hex_hash_is_left_to_the_sha512_format()
    {
        const string password = "password";
        string sha512 = Fixtures.BuildLegacyHash(5, password, System.Array.Empty<byte>());
        Assert.Equal(128, sha512.Length);
        Assert.Equal(96, System.Convert.FromBase64String(sha512).Length); // it does parse as base64
        foreach (string hex in new[] { sha512, sha512.ToUpperInvariant() })
        {
            Assert.False(new Masterly.Hash.Legacy.V1LegacyFormat(Masterly.Hash.Legacy.V1Algorithm.SHA512).CanHandle(hex));
            Assert.False(Masterly.Hash.Legacy.V1LegacyFormat.Instance.CanHandle(hex));
            Assert.False(Masterly.Hash.Legacy.V1LegacyFormat.Instance.Verify(password, hex));
        }

        // Even with 1.x registered first, nothing but sha512 claims the digest.
        PasswordHasher v1First = Fixtures.Create(o =>
        {
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(new Masterly.Hash.Legacy.V1LegacyFormat(Masterly.Hash.Legacy.V1Algorithm.SHA512));
            o.LegacyFormats.Add(Masterly.Hash.Legacy.UnsaltedDigestFormat.Sha512);
        });

        foreach (PasswordHasher hasher in new[] { Fixtures.Wrapping, Fixtures.WrappingNoPepper, v1First })
        {
            Assert.Equal("sha512", hasher.Inspect(sha512).Format);
            Assert.True(hasher.Verify(password, sha512).IsMatch);
            Assert.True(hasher.TryWrap(sha512, out string wrapped));
            Assert.Equal("sha512", hasher.Inspect(wrapped).WrappedFormat);
            Assert.True(hasher.Verify(password, wrapped).IsMatch, wrapped);
            Assert.False(hasher.Verify("Password", wrapped).IsMatch);
        }
    }

    private static void AssertRehashIsCurrent(PasswordHasher hasher, string password, PasswordVerificationResult result, string context)
    {
        Assert.True(result.IsMatch, $"{context}: {result}");
        Assert.NotNull(result.Rehash);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(password, result.Rehash!).Status);
    }
}
