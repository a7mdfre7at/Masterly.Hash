using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Detection.Internal;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Detection.Tests;

/// <summary>Edge paths not reached by the scenario tests.</summary>
public class CoverageGapTests
{
    // ---------- HoneywordService ----------

    [Fact]
    public void Pepper_with_an_invalid_current_key_id_is_rejected()
    {
        var ex = Assert.Throws<ArgumentException>(() => TestSupport.Service(configure: o => o.Pepper = new CountingPepper("bad id")));
        Assert.Equal("options", ex.ParamName);
        Assert.StartsWith("Pepper.CurrentKeyId must match ^[A-Za-z0-9-]{1,32}$.", ex.Message);
    }

    [Fact]
    public void Null_profile_in_the_allowlist_is_rejected()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new HoneywordService(TestSupport.Fast, new HashProfile[] { null! }, new HoneywordServiceOptions { AllowWeakProfiles = true }));
        Assert.StartsWith("Profiles cannot contain null.", ex.Message);
    }

    [Fact]
    public void Generator_returning_a_decoy_longer_than_MaxPasswordBytes_is_rejected()
    {
        var generator = new FixedGenerator((_, n) => Enumerable.Range(0, n).Select(i => new string('x', 65) + i).ToList());
        HoneywordService service = TestSupport.Service(generator, o => o.MaxPasswordBytes = 64);

        var ex = Assert.Throws<InvalidOperationException>(() => service.Create("pw", 3));
        Assert.Equal("The honeyword generator returned a decoy longer than MaxPasswordBytes.", ex.Message);
    }

    [Fact]
    public async Task VerifyOrDummy_for_an_unknown_user_applies_the_pepper_like_a_real_verify()
    {
        var pepper = new CountingPepper("k1");
        HoneywordService service = TestSupport.Service(configure: o => o.Pepper = pepper);
        TestSupport.StrongBox derivations = TestSupport.Count(service);

        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, service.VerifyOrDummy("password", null).Status);
        Assert.Equal(1, pepper.SyncCalls);
        Assert.Equal(1, derivations.Value);

        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, (await service.VerifyOrDummyAsync("password", null)).Status);
        Assert.Equal(1, pepper.AsyncCalls);
        Assert.Equal(2, derivations.Value);
        Assert.Equal(new[] { "k1", "k1" }, pepper.KeyIds);
    }

    [Fact]
    public async Task Without_a_concurrency_limit_create_and_verify_still_work()
    {
        HoneywordService service = TestSupport.Service(configure: o => o.MaxConcurrency = 0);
        HoneywordRecord record = service.Create("ungated", 3);

        Assert.Equal(record.RealIndex, service.Verify("ungated", record.StoredHash));
        Assert.Equal(record.RealIndex, (await service.VerifyDetailedAsync("ungated", record.StoredHash)).Index);
        Assert.Equal(-1, service.Verify("other", record.StoredHash));
    }

    [Fact]
    public async Task Busy_gate_throws_PasswordHasherBusyException_sync_and_async()
    {
        HoneywordService service = TestSupport.Service(configure: o =>
        {
            o.MaxConcurrency = 1;
            o.ConcurrencyTimeout = TimeSpan.FromMilliseconds(50);
        });
        HoneywordRecord record = service.Create("busy", 3);

        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        service.Derive = (profile, input, salt) =>
        {
            entered.Set();
            release.Wait(TimeSpan.FromSeconds(30));
            return HashPrimitives.DeriveKey(profile, input, salt);
        };

        Task<int> holder = Task.Run(() => service.Verify("busy", record.StoredHash));
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(30)), "the first verify never reached the KDF");

            Assert.Throws<PasswordHasherBusyException>(() => service.Verify("busy", record.StoredHash));
            await Assert.ThrowsAsync<PasswordHasherBusyException>(() => service.VerifyDetailedAsync("busy", record.StoredHash).AsTask());
        }
        finally
        {
            release.Set();
        }

        Assert.Equal(record.RealIndex, await holder);
        // The gate was released: a later verify gets in.
        Assert.Equal(record.RealIndex, service.Verify("busy", record.StoredHash));
    }

    [Fact]
    public void HoneywordRecord_rejects_a_null_stored_hash()
    {
        Assert.Equal("storedHash", Assert.Throws<ArgumentNullException>(() => new HoneywordRecord(null!, 0, 2)).ParamName);
    }

    [Fact]
    public void HoneywordHash_key_id_validation()
    {
        Assert.False(HoneywordHash.IsValidKeyId(null));
        Assert.False(HoneywordHash.IsValidKeyId(""));
        Assert.False(HoneywordHash.IsValidKeyId("bad id"));
        Assert.True(HoneywordHash.IsValidKeyId("k-1"));
    }

    // ---------- generators and their helpers ----------

    [Fact]
    public void Letters_alone_in_their_block_are_kept_verbatim()
    {
        // U+0294 (glottal stop, Lo) and U+2132 (turned F, Lu) are the only NFKC-stable letters of their category in their
        // 128-code-point block, so there is nothing to replace them with.
        Assert.Null(ScriptAlphabets.For('ʔ'));
        Assert.Null(ScriptAlphabets.For('Ⅎ'));
        Assert.NotNull(ScriptAlphabets.For('а')); // Cyrillic, for contrast

        IReadOnlyList<string> decoys = TweakingHoneywordGenerator.Default.GenerateDecoys("passʔ", 5);

        Assert.Equal(5, decoys.Count);
        Assert.All(decoys, d =>
        {
            Assert.Equal(5, d.Length);
            Assert.StartsWith("pa", d, StringComparison.Ordinal);
            Assert.Equal('ʔ', d[4]);
        });
        Assert.Equal(5, decoys.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void CharClasses_Alphabet_per_class()
    {
        Assert.Equal(CharClasses.Lower, CharClasses.Alphabet(CharClass.Lower));
        Assert.Equal(CharClasses.Upper, CharClasses.Alphabet(CharClass.Upper));
        Assert.Equal(CharClasses.Digits, CharClasses.Alphabet(CharClass.Digit));
        Assert.Equal(CharClasses.Symbols, CharClasses.Alphabet(CharClass.Symbol));
        Assert.Null(CharClasses.Alphabet(CharClass.Other));
    }

    [Fact]
    public void TypoSafety_rejects_null_arguments()
    {
        Assert.Equal("a", Assert.Throws<ArgumentNullException>(() => TypoSafety.WithinOneEdit(null!, "x")).ParamName);
        Assert.Equal("b", Assert.Throws<ArgumentNullException>(() => TypoSafety.WithinOneEdit("x", null!)).ParamName);
    }

    // ---------- honey accounts ----------

    [Fact]
    public void CheckLogin_without_subscribers_still_reports_the_honey_account()
    {
        var registry = new HoneyAccountRegistry(new[] { "decoy" });
        Assert.True(registry.CheckLogin("decoy", "10.0.0.1"));
        Assert.False(registry.CheckLogin("alice"));
    }

    // ---------- credential stuffing ----------

    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    [Fact]
    public void Snapshot_reports_flagged_fingerprints()
    {
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 2, Clock = () => T0 });
        detector.RecordFailedLogin("a", "Winter2026!");
        detector.RecordFailedLogin("b", "Winter2026!");
        detector.RecordFailedLogin("a", "Summer2026!");

        IReadOnlyList<FingerprintStatistics> snapshot = detector.GetSnapshot();

        Assert.Equal(2, snapshot.Count);
        Assert.False(snapshot[0].IsFlagged); // most recently seen first
        Assert.Equal(1, snapshot[0].DistinctAccountCount);
        Assert.True(snapshot[1].IsFlagged);
        Assert.Equal(2, snapshot[1].DistinctAccountCount);
    }

    [Fact]
    public void RecordFailedLogin_retries_when_the_window_rotates_while_hashing()
    {
        var clock = new JumpingClock(T0);
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 2, Window = Window, Clock = clock.Now });
        Assert.False(detector.RecordFailedLogin("a", "Winter2026!"));

        // The window ends between the first generation read and the locked update: the failure lands in the new window.
        clock.JumpAfterNextCall(Window + TimeSpan.FromSeconds(1));
        Assert.False(detector.RecordFailedLogin("b", "Winter2026!"));

        FingerprintStatistics only = Assert.Single(detector.GetSnapshot());
        Assert.Equal(1, only.DistinctAccountCount);
        Assert.False(only.IsFlagged);
    }

    [Fact]
    public void IsFlagged_retries_when_the_window_rotates_while_hashing()
    {
        var clock = new JumpingClock(T0);
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 2, Window = Window, Clock = clock.Now });
        detector.RecordFailedLogin("a", "Winter2026!");
        Assert.True(detector.RecordFailedLogin("b", "Winter2026!"));
        Assert.True(detector.IsFlagged("Winter2026!"));

        clock.JumpAfterNextCall(Window + TimeSpan.FromSeconds(1));

        Assert.False(detector.IsFlagged("Winter2026!"));
        Assert.Empty(detector.GetSnapshot());
    }

    /// <summary>A clock that moves forward right after it is read once, simulating time passing mid-call.</summary>
    private sealed class JumpingClock
    {
        private DateTimeOffset _now;
        private TimeSpan? _pending;

        public JumpingClock(DateTimeOffset start) => _now = start;

        public Func<DateTimeOffset> Now => Read;

        public void JumpAfterNextCall(TimeSpan by) => _pending = by;

        private DateTimeOffset Read()
        {
            DateTimeOffset value = _now;
            if (_pending is TimeSpan by)
            {
                _now += by;
                _pending = null;
            }
            return value;
        }
    }

    /// <summary>A pepper with any current key id that records how it is called.</summary>
    private sealed class CountingPepper : IPasswordPepper
    {
        private readonly HmacPepper _inner = new("k1", HmacPepper.GenerateKey());

        public CountingPepper(string currentKeyId) => CurrentKeyId = currentKeyId;

        public string CurrentKeyId { get; }

        public int SyncCalls { get; private set; }

        public int AsyncCalls { get; private set; }

        public List<string> KeyIds { get; } = new();

        public bool IsKnownKey(string keyId) => keyId == CurrentKeyId;

        public byte[] Apply(string keyId, byte[] input)
        {
            SyncCalls++;
            KeyIds.Add(keyId);
            return _inner.Apply("k1", input);
        }

        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)
        {
            AsyncCalls++;
            KeyIds.Add(keyId);
            return new ValueTask<byte[]>(_inner.Apply("k1", input));
        }
    }
}
