using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Testing.Tests;

public class FakePepperTests
{
    private const string Pw = "pepper-me-please";

    [Fact]
    public void Defaults()
    {
        var pepper = new FakePepper();
        Assert.Equal("test-key", pepper.CurrentKeyId);
        Assert.True(pepper.IsKnownKey("test-key"));
        Assert.False(pepper.IsKnownKey("other"));
        Assert.False(pepper.IsKnownKey(null!));
        Assert.Equal(new[] { "test-key" }, pepper.KeyIds);
    }

    [Fact]
    public void Apply_IsHmacSha256WithDerivedKey()
    {
        byte[] input = Encoding.UTF8.GetBytes(Pw);
        byte[] expectedKey = SHA256.HashData(Encoding.UTF8.GetBytes("Masterly.Hash.Testing.FakePepper/k1"));

        Assert.Equal(expectedKey, FakePepper.KeyFor("k1"));
        Assert.Equal(HMACSHA256.HashData(expectedKey, input), new FakePepper("k1").Apply("k1", input));
    }

    [Fact]
    public void IsDeterministic_AcrossInstances()
    {
        byte[] input = Encoding.UTF8.GetBytes(Pw);
        Assert.Equal(new FakePepper("k1").Apply("k1", input), new FakePepper("k1").Apply("k1", input));
        Assert.NotEqual(new FakePepper("k1", "k2").Apply("k1", input), new FakePepper("k1", "k2").Apply("k2", input));

        string stored = new FastPasswordHasher(o => o.Pepper = new FakePepper("k1")).Hash(Pw);
        Assert.True(new FastPasswordHasher(o => o.Pepper = new FakePepper("k1")).Verify(Pw, stored).IsMatch);
    }

    [Fact]
    public void Apply_UnknownKey_Throws()
    {
        var pepper = new FakePepper("k1");
        Assert.Throws<KeyNotFoundException>(() => pepper.Apply("nope", new byte[1]));
        Assert.Throws<ArgumentNullException>(() => pepper.Apply("k1", null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("under_score")]
    [InlineData("this-key-id-is-much-too-long-for-the-format")]
    [InlineData("k1\n")]
    public void InvalidKeyIds_AreRejected(string keyId)
    {
        Assert.Throws<ArgumentException>(() => new FakePepper(keyId));
        Assert.Throws<ArgumentException>(() => new FakePepper("ok", keyId));
        Assert.Throws<ArgumentException>(() => new FakePepper().AddKey(keyId));
        Assert.Throws<ArgumentException>(() => new FakePepper().RotateTo(keyId));
    }

    [Fact]
    public void NullKeyIds_AreRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new FakePepper(null!));
        Assert.Throws<ArgumentNullException>(() => new FakePepper().RetireKey(null!));
        Assert.Throws<ArgumentNullException>(() => FakePepper.KeyFor(null!));
    }

    [Fact]
    public async Task Counts_SyncAndAsyncPathsSeparately()
    {
        var pepper = new FakePepper("k1");
        var hasher = new FastPasswordHasher(o => o.Pepper = pepper);

        string stored = hasher.Hash(Pw);
        Assert.Equal(1, pepper.ApplyCount);
        Assert.Equal(0, pepper.ApplyAsyncCount);

        Assert.True((await hasher.VerifyAsync(Pw, stored)).IsMatch);
        Assert.Equal(1, pepper.ApplyCount);
        Assert.Equal(1, pepper.ApplyAsyncCount);
        Assert.Equal(new[] { "k1", "k1" }, pepper.KeyIdsUsed);

        pepper.ResetCounters();
        Assert.Equal(0, pepper.ApplyCount);
        Assert.Equal(0, pepper.ApplyAsyncCount);
        Assert.Empty(pepper.KeyIdsUsed);
    }

    [Fact]
    public async Task ForceAsynchronous_CompletesAsynchronously_AndStillVerifies()
    {
        var pepper = new FakePepper("k1") { ForceAsynchronous = true };
        ValueTask<byte[]> pending = pepper.ApplyAsync("k1", new byte[] { 1, 2, 3 });
        Assert.False(pending.IsCompleted);
        byte[] result = await pending;
        Assert.Equal(pepper.Apply("k1", new byte[] { 1, 2, 3 }), result);

        var hasher = new FastPasswordHasher(o => o.Pepper = pepper);
        string stored = await hasher.HashAsync(Pw);
        Assert.True((await hasher.VerifyAsync(Pw, stored)).IsMatch);
    }

    [Fact]
    public async Task AsyncDelay_IsObserved_AndHonoursCancellation()
    {
        var pepper = new FakePepper("k1") { AsyncDelay = TimeSpan.FromSeconds(30) };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pepper.ApplyAsync("k1", new byte[1], cts.Token).AsTask());

        var hasher = new FastPasswordHasher(o => o.Pepper = pepper);
        using var cts2 = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => hasher.HashAsync(Pw, cts2.Token).AsTask());
    }

    [Fact]
    public async Task AlreadyCancelledToken_Throws()
    {
        var pepper = new FakePepper("k1");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pepper.ApplyAsync("k1", new byte[1], new CancellationToken(true)).AsTask());
        Assert.Equal(1, pepper.ApplyAsyncCount);
    }

    [Fact]
    public async Task ThrowOnApply_SimulatesOutage()
    {
        var outage = new TimeoutException("vault down");
        var pepper = new FakePepper("k1") { ThrowOnApply = outage };
        var hasher = new FastPasswordHasher(o => o.Pepper = pepper);

        Assert.Same(outage, Assert.Throws<TimeoutException>(() => hasher.Hash(Pw)));
        Assert.Same(outage, await Assert.ThrowsAsync<TimeoutException>(() => hasher.HashAsync(Pw).AsTask()));

        pepper.ThrowOnApply = null;
        Assert.StartsWith("$mh$p=test-fast,k=k1$", hasher.Hash(Pw));
    }

    [Fact]
    public void RotateTo_OldHashesNeedRehash_NewHashesUseNewKey()
    {
        var pepper = new FakePepper("k1");
        var hasher = new FastPasswordHasher(o => o.Pepper = pepper);
        string old = hasher.Hash(Pw);

        pepper.RotateTo("k2");
        Assert.Equal("k2", pepper.CurrentKeyId);
        Assert.True(pepper.IsKnownKey("k1"));

        PasswordVerificationResult result = hasher.Verify(Pw, old);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        MasterlyHashAssert.IsPeppered(result.Rehash, "k2");
        MasterlyHashAssert.IsPeppered(hasher.Hash(Pw), "k2");
    }

    [Fact]
    public void RetireKey_OldHashesFailWithUnknownPepperKey()
    {
        var pepper = new FakePepper("k1");
        var hasher = new FastPasswordHasher(o => o.Pepper = pepper);
        string old = hasher.Hash(Pw);
        pepper.RotateTo("k2");

        Assert.True(pepper.RetireKey("k1"));
        Assert.False(pepper.RetireKey("k1"));
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, hasher.Verify(Pw, old).FailureReason);
        Assert.Throws<InvalidOperationException>(() => pepper.RetireKey("k2"));
    }

    [Fact]
    public void AddKey_AcceptsHashesFromOtherInstance()
    {
        string fromK9 = new FastPasswordHasher(o => o.Pepper = new FakePepper("k9")).Hash(Pw);
        var pepper = new FakePepper("k1");
        var hasher = new FastPasswordHasher(o => o.Pepper = pepper);
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, hasher.Verify(Pw, fromK9).FailureReason);

        pepper.AddKey("k9");
        Assert.Equal(RehashReason.OutdatedPepperKey, hasher.Verify(Pw, fromK9).RehashReason);
    }

    [Fact]
    public void IsThreadSafe()
    {
        var pepper = new FakePepper("k1");
        Parallel.For(0, 200, i =>
        {
            if (i % 50 == 0)
                pepper.AddKey("x" + i);
            pepper.Apply("k1", new byte[] { (byte)i });
        });
        Assert.Equal(200, pepper.ApplyCount);
        Assert.Equal(200, pepper.KeyIdsUsed.Count);
    }
}
