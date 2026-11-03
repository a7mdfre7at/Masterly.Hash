using System;
using System.Collections.Generic;
using System.Linq;
using FsCheck.Xunit;
using Masterly.Hash.Pepper;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// Pepper rotation: a hash made under key set K keeps verifying under any superset of K, is flagged for rehash
/// exactly when its key is no longer current, and fails cleanly (never throws, never matches) when its key is gone.
/// </summary>
[Properties(Arbitrary = new[] { typeof(Arbitraries) }, QuietOnSuccess = true)]
public class PepperRotationProperties
{
    [Property(MaxTest = 600)]
    public void A_hash_made_under_K_verifies_under_any_superset_of_K(KeyRotation k)
    {
        PasswordHasher before = HasherFor(k.OriginalCurrent, k.Original);
        PasswordHasher after = HasherFor(k.SupersetCurrent, k.Superset);

        string hash = before.Hash(k.Password);
        Assert.Equal(k.OriginalCurrent, before.Inspect(hash).PepperKeyId);

        PasswordVerificationResult result = after.Verify(k.Password, hash);
        Assert.True(result.IsMatch, $"{k} {result}");

        RehashReason expected = k.OriginalCurrent == k.SupersetCurrent ? RehashReason.None : RehashReason.OutdatedPepperKey;
        Assert.Equal(expected, result.RehashReason);
        Assert.Equal(expected != RehashReason.None, after.NeedsRehash(hash));

        HashInfo info = after.Inspect(hash);
        Assert.True(info.IsRecognized);
        Assert.Equal(k.OriginalCurrent, info.PepperKeyId);

        Assert.Equal(result.Status, after.VerifyAsync(k.Password, hash).AsTask().GetAwaiter().GetResult().Status);
        Assert.Equal(VerificationFailureReason.Mismatch, after.Verify(k.Password + "x", hash).FailureReason);

        if (result.Rehash != null)
        {
            // The upgrade lands on the current key and is itself current.
            Assert.Equal(VerificationStatus.Success, after.Verify(k.Password, result.Rehash).Status);
            Assert.Equal(k.SupersetCurrent, after.Inspect(result.Rehash).PepperKeyId);

            // Rolling back to K only works if K already knew the new key.
            PasswordVerificationResult rollback = before.Verify(k.Password, result.Rehash);
            if (k.Original.Contains(k.SupersetCurrent))
                Assert.True(rollback.IsMatch);
            else
                Assert.Equal(VerificationFailureReason.UnknownPepperKey, rollback.FailureReason);
        }
    }

    [Property(MaxTest = 300)]
    public void Removing_the_key_fails_cleanly(KeyRotation k)
    {
        if (k.OriginalCurrent == null)
            return; // unpeppered hashes verify under every key set; covered above

        string hash = HasherFor(k.OriginalCurrent, k.Original).Hash(k.Password);
        string[] remaining = k.Superset.Where(id => id != k.OriginalCurrent).ToArray();
        PasswordHasher without = remaining.Length == 0 ? Fixtures.Create() : HasherFor(remaining[0], remaining);

        PasswordVerificationResult result = without.Verify(k.Password, hash);
        Assert.False(result.IsMatch);
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, result.FailureReason);
        Assert.False(without.Inspect(hash).IsRecognized);
        Assert.False(without.NeedsRehash(hash));
    }

    [Property(MaxTest = 300)]
    public void The_same_key_id_with_different_key_material_never_matches(KeyRotation k)
    {
        if (k.OriginalCurrent == null)
            return;

        string hash = HasherFor(k.OriginalCurrent, k.Original).Hash(k.Password);
        var keys = k.Superset.ToDictionary(id => id, Fixtures.KeyFor, StringComparer.Ordinal);
        keys[k.OriginalCurrent] = Fixtures.KeyFor(k.OriginalCurrent + "-replaced");
        PasswordHasher impostor = Fixtures.Create(o => o.Pepper = new HmacPepper(k.SupersetCurrent, keys));

        PasswordVerificationResult result = impostor.Verify(k.Password, hash);
        Assert.Equal(VerificationFailureReason.Mismatch, result.FailureReason);
    }

    private static PasswordHasher HasherFor(string? current, IReadOnlyCollection<string> keyIds) =>
        current == null
            ? Fixtures.Create()
            : Fixtures.Create(o => o.Pepper = Fixtures.Pepper(current, keyIds.ToArray()));
}
