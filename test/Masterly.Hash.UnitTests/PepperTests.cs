using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper;

namespace Masterly.Hash.UnitTests;

public class PepperTests
{
    private const string Pw = "hunter2";

    [Fact]
    public void PepperedHash_RecordsKeyId_AndVerifies()
    {
        var hasher = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k1", "k1"));
        string stored = hasher.Hash(Pw);

        Assert.StartsWith("$mh$p=test-fast,k=k1$", stored);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(Pw, stored).Status);
    }

    [Fact]
    public void PepperedHash_WithoutPepper_FailsWithUnknownKey()
    {
        string stored = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k1", "k1")).Hash(Pw);
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, TestHashers.Create().Verify(Pw, stored).FailureReason);
    }

    [Fact]
    public void PepperedHash_WithDifferentKeyMaterial_Mismatches()
    {
        string stored = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k1", "k1")).Hash(Pw);
        var otherKey = new HmacPepper("k1", new byte[32]);
        Assert.Equal(VerificationFailureReason.Mismatch, TestHashers.Create(o => o.Pepper = otherKey).Verify(Pw, stored).FailureReason);
    }

    [Fact]
    public void KeyRotation_OldKeyVerifies_AndRehashesToNewKey()
    {
        string stored = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k1", "k1")).Hash(Pw);
        var rotated = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k2", "k1", "k2"));

        var result = rotated.Verify(Pw, stored);

        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        Assert.StartsWith("$mh$p=test-fast,k=k2$", result.Rehash);
    }

    [Fact]
    public void AddingPepper_UpgradesUnpepperedHashes()
    {
        string stored = TestHashers.Create().Hash(Pw);
        var result = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k1", "k1")).Verify(Pw, stored);

        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        Assert.Contains(",k=k1$", result.Rehash);
    }

    [Fact]
    public async Task AsyncApi_UsesAsyncPepper()
    {
        var pepper = new RecordingPepper();
        var hasher = TestHashers.Create(o => o.Pepper = pepper);

        string stored = await hasher.HashAsync(Pw);
        Assert.True((await hasher.VerifyAsync(Pw, stored)).IsMatch);

        Assert.Equal(2, pepper.AsyncCalls);
        Assert.Equal(0, pepper.SyncCalls);
    }

    [Fact]
    public void HmacPepper_RejectsShortKeysAndBadIds()
    {
        Assert.Throws<ArgumentException>(() => new HmacPepper("k1", new byte[16]));
        Assert.Throws<ArgumentException>(() => new HmacPepper("bad id", new byte[32]));
        Assert.Throws<ArgumentException>(() => new HmacPepper("k2", new Dictionary<string, byte[]> { ["k1"] = new byte[32] }));
    }

    [Fact]
    public void HmacPepper_FromBase64_RoundTrips()
    {
        byte[] key = HmacPepper.GenerateKey();
        var pepper = HmacPepper.FromBase64("k1", new Dictionary<string, string> { ["k1"] = Convert.ToBase64String(key) });
        Assert.True(pepper.IsKnownKey("k1"));
        Assert.Equal(32, pepper.Apply("k1", new byte[] { 1 }).Length);
    }

    [Theory]
    [InlineData("bad id")]
    [InlineData("key_1")]
    [InlineData("")]
    [InlineData("abcdefghijklmnopqrstuvwxyz0123456")] // 33 characters
    public void HmacPepper_InvalidKeyIdInRing_Throws(string badId)
    {
        var keys = new Dictionary<string, byte[]> { ["k1"] = new byte[32], [badId] = new byte[32] };

        var ex = Assert.Throws<ArgumentException>(() => new HmacPepper("k1", keys));

        Assert.Equal("keys", ex.ParamName);
        Assert.Contains($"'{badId}'", ex.Message);
    }

    [Fact]
    public void HmacPepper_NullOrShortKeyInRing_Throws()
    {
        Assert.Equal("keys", Assert.Throws<ArgumentException>(() => new HmacPepper("k1", new Dictionary<string, byte[]> { ["k1"] = null! })).ParamName);
        Assert.Equal("keys", Assert.Throws<ArgumentException>(() => new HmacPepper("k1", new byte[31])).ParamName);
    }

    [Fact]
    public void HmacPepper_NullArguments_Throw()
    {
        Assert.Equal("keys", Assert.Throws<ArgumentNullException>(() => new HmacPepper("k1", (IReadOnlyDictionary<string, byte[]>)null!)).ParamName);
        Assert.Equal("base64Keys", Assert.Throws<ArgumentNullException>(() => HmacPepper.FromBase64("k1", null!)).ParamName);
        Assert.Equal("currentKeyId", Assert.Throws<ArgumentException>(() => new HmacPepper(null!, new Dictionary<string, byte[]>())).ParamName);

        var pepper = new HmacPepper("k1", new byte[32]);
        Assert.Equal("input", Assert.Throws<ArgumentNullException>(() => pepper.Apply("k1", null!)).ParamName);
    }

    [Fact]
    public void HmacPepper_UnknownKey_IsNotKnown_AndCannotBeApplied()
    {
        var pepper = new HmacPepper("k1", new byte[32]);

        Assert.False(pepper.IsKnownKey("k2"));
        Assert.False(pepper.IsKnownKey(null!));
        Assert.Contains("'k2'", Assert.Throws<KeyNotFoundException>(() => pepper.Apply("k2", new byte[] { 1 })).Message);
        Assert.Throws<KeyNotFoundException>(() => pepper.Apply(null!, new byte[] { 1 }));
    }

    [Fact]
    public async Task HmacPepper_ApplyAsync_MatchesApply_AndIsHmacSha256()
    {
        byte[] key = HmacPepper.GenerateKey();
        var pepper = new HmacPepper("k1", key);
        byte[] input = { 1, 2, 3 };

        byte[] sync = pepper.Apply("k1", input);
        byte[] async = await pepper.ApplyAsync("k1", input);

        Assert.Equal(sync, async);
        Assert.Equal(System.Security.Cryptography.HMACSHA256.HashData(key, input), sync);
        await Assert.ThrowsAsync<KeyNotFoundException>(async () => await pepper.ApplyAsync("k2", input));
    }

    [Fact]
    public void HmacPepper_CopiesKeys_SoLaterChangesHaveNoEffect()
    {
        byte[] key = HmacPepper.GenerateKey();
        var pepper = new HmacPepper("k1", key);
        byte[] before = pepper.Apply("k1", new byte[] { 1 });

        Array.Clear(key);

        Assert.Equal(before, pepper.Apply("k1", new byte[] { 1 }));
    }

    private sealed class RecordingPepper : IPasswordPepper
    {
        private readonly HmacPepper _inner = new HmacPepper("r1", new byte[32]);
        public int SyncCalls;
        public int AsyncCalls;

        public string CurrentKeyId => _inner.CurrentKeyId;
        public bool IsKnownKey(string keyId) => _inner.IsKnownKey(keyId);

        public byte[] Apply(string keyId, byte[] input)
        {
            Interlocked.Increment(ref SyncCalls);
            return _inner.Apply(keyId, input);
        }

        public async ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref AsyncCalls);
            await Task.Yield();
            return _inner.Apply(keyId, input);
        }
    }
}
