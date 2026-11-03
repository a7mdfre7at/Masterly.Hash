using System;
using System.Security.Cryptography;
using System.Text;
using FsCheck.Xunit;
using Masterly.Hash.Legacy;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// Edits of a valid hash string never verify and never throw. For <c>$mh$</c> hashes this is strict: any string
/// other than the one the hasher produced must fail, whatever was flipped, inserted, deleted, re-cased, truncated,
/// duplicated, swapped, unwrapped or un-peppered.
/// </summary>
[Properties(Arbitrary = new[] { typeof(Arbitraries) }, QuietOnSuccess = true)]
public class MutationProperties
{
    private static readonly PasswordHasher[] Verifiers = { Fixtures.Wrapping, Fixtures.Everything, Fixtures.Plain };

    [Property(MaxTest = 3000)]
    public void Mutated_mh_hashes_never_match_and_never_throw(MhMutation m)
    {
        string original = BuildOriginal(m);
        Assert.True(Fixtures.Wrapping.Verify(m.Password, original).IsMatch, "seed must verify: " + Fixtures.Show(original));

        string mutated = Mutator.Apply(original, m.Ops);
        string context = $"{Fixtures.Show(original)} -> {Fixtures.Show(mutated)}";

        foreach (PasswordHasher hasher in Verifiers)
        {
            PasswordVerificationResult result = hasher.Verify(m.Password, mutated);
            Assertions.Consistent(result, context);
            if (!string.Equals(mutated, original, StringComparison.Ordinal))
                Assert.False(result.IsMatch, $"mutation verified: {context} ({result})");

            _ = hasher.Inspect(mutated);
            _ = hasher.NeedsRehash(mutated);
            _ = hasher.VerifyOrDummy(m.Password, mutated);
            if (hasher.TryWrap(mutated, out string wrapped))
                Assert.False(hasher.Verify(m.Password, wrapped).IsMatch, context);
        }

        if (string.Equals(mutated, original, StringComparison.Ordinal))
            Assert.True(Fixtures.Wrapping.Verify(m.Password, mutated).IsMatch);
    }

    [Property(MaxTest = 1500)]
    public void Mutated_legacy_hashes_never_throw(LegacyMutation m)
    {
        (ILegacyHashFormat format, string password, string seed) = Fixtures.LegacySeeds[m.SeedIndex];
        Assert.True(format.CanHandle(seed), $"{format.Id} seed must parse");
        Assert.True(format.Verify(password, seed), $"{format.Id} seed must verify");

        string mutated = Mutator.Apply(seed, m.Ops);
        string context = $"{format.Id}: {Fixtures.Show(seed)} -> {Fixtures.Show(mutated)}";

        bool handled = format.CanHandle(mutated);
        bool verified = format.Verify(password, mutated);
        Assert.True(handled || !verified, context);
        if (format.TryExtractWrapInput(mutated, out byte[] digest, out byte[] parameter))
        {
            Assert.True(handled, context);
            byte[] recomputed = format.ComputeWrapInput(password, parameter);
            Assert.Equal(verified, recomputed.AsSpan().SequenceEqual(digest));
        }

        PasswordVerificationResult result = Fixtures.Everything.Verify(password, mutated);
        Assertions.Consistent(result, context);
        if (result.IsMatch)
        {
            Assert.True(Fixtures.Everything.Inspect(mutated).IsRecognized, context);
            Assert.Equal(RehashReason.LegacyFormat, result.RehashReason);
            Assert.True(Fixtures.Everything.Verify(password, result.Rehash!).IsMatch, context);
        }

        if (Fixtures.Wrapping.TryWrap(mutated, out string wrapped))
        {
            // Onion wrapping must preserve exactly which password the hash accepts.
            bool originalAccepts = Fixtures.Wrapping.Verify(password, mutated).IsMatch;
            Assert.Equal(originalAccepts, Fixtures.Wrapping.Verify(password, wrapped).IsMatch);
        }
    }

    [Fact]
    public void Every_legacy_seed_verifies_through_the_hasher_and_wraps_where_supported()
    {
        foreach ((ILegacyHashFormat format, string password, string seed) in Fixtures.LegacySeeds)
        {
            Assert.True(Fixtures.Everything.Verify(password, seed).IsMatch, format.Id);
            Assert.False(Fixtures.Everything.Verify(password + "x", seed).IsMatch, format.Id);
            if (Fixtures.Wrapping.TryWrap(seed, out string wrapped))
            {
                Assert.True(Fixtures.Wrapping.Verify(password, wrapped).IsMatch, format.Id);
                Assert.False(Fixtures.Wrapping.Verify(password + "x", wrapped).IsMatch, format.Id);
            }
        }
    }

    internal static string BuildOriginal(MhMutation m)
    {
        switch (m.BaseKind)
        {
            case 0: return Fixtures.WrappingNoPepper.Hash(m.Password);                        // $mh$p=test$
            case 1: return Fixtures.Wrapping.Hash(m.Password);                                // $mh$p=test,k=key1$
            case 2: return Wrap(Fixtures.WrappingNoPepper, m);                                // $mh$p=test,w=v1,wp=...$
            case 3: return Wrap(Fixtures.Wrapping, m);                                        // $mh$p=test,k=key1,w=v1,wp=...$
            default: return Fixtures.WrappingNoPepper.Hash(m.Password, Fixtures.Fast2);       // $mh$p=test2$
        }
    }

    private static string Wrap(PasswordHasher hasher, MhMutation m)
    {
        // Masterly.Hash 1.x: base64(SHA-512(utf8(password) || salt) || salt).
        byte[] plain = Encoding.UTF8.GetBytes(m.Password);
        byte[] digest = SHA512.HashData(Fixtures.Concat(plain, m.LegacySalt));
        string v1 = Convert.ToBase64String(Fixtures.Concat(digest, m.LegacySalt));
        Assert.True(hasher.TryWrap(v1, out string wrapped), "v1 hash must wrap");
        return wrapped;
    }
}
