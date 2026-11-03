using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Detection.Tests;

public class CredentialStuffingDetectorTests
{
    private static readonly DateTimeOffset T0 = new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private static (CredentialStuffingDetector Detector, FakeClock Clock, List<CredentialStuffingDetectedEventArgs> Events) Create(
        int threshold = 5, int maxFingerprints = 1000, TimeSpan? window = null)
    {
        var clock = new FakeClock(T0);
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions
        {
            DistinctAccountThreshold = threshold,
            MaxTrackedFingerprints = maxFingerprints,
            Window = window ?? TimeSpan.FromMinutes(10),
            Clock = clock.Func,
        });
        var events = new List<CredentialStuffingDetectedEventArgs>();
        detector.StuffingDetected += (_, e) => events.Add(e);
        return (detector, clock, events);
    }

    [Fact]
    public void Threshold_RaisesOnce_WhenReached()
    {
        var (detector, clock, events) = Create(threshold: 5);

        for (int i = 0; i < 4; i++)
            Assert.False(detector.RecordFailedLogin("user" + i, "Winter2026!"));
        Assert.Empty(events);

        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.True(detector.RecordFailedLogin("user4", "Winter2026!"));
        CredentialStuffingDetectedEventArgs e = Assert.Single(events);
        Assert.Equal(5, e.DistinctAccountCount);
        Assert.Equal(T0, e.WindowStart);
        Assert.Equal(T0.AddMinutes(10), e.WindowEnd);
        Assert.Equal(T0.AddMinutes(1), e.DetectedAt);
        Assert.Matches("^[0-9a-f]{32}$", e.FingerprintId);

        // Further failures in the same window keep returning true but do not re-raise.
        for (int i = 5; i < 20; i++)
            Assert.True(detector.RecordFailedLogin("user" + i, "Winter2026!"));
        Assert.Single(events);
        Assert.True(detector.IsFlagged("Winter2026!"));
    }

    [Fact]
    public void SameAccount_CountsOnce_CaseInsensitively()
    {
        var (detector, _, events) = Create(threshold: 3);
        for (int i = 0; i < 50; i++)
            detector.RecordFailedLogin(i % 2 == 0 ? "alice" : "ALICE", "pw");
        detector.RecordFailedLogin("ａｌｉｃｅ", "pw"); // full-width alice
        detector.RecordFailedLogin("bob", "pw");
        Assert.Empty(events);
        Assert.Equal(2, detector.GetSnapshot().Single().DistinctAccountCount);

        detector.RecordFailedLogin("carol", "pw");
        Assert.Single(events);
    }

    [Fact]
    public void DifferentPasswords_AreTrackedSeparately()
    {
        var (detector, _, events) = Create(threshold: 3);
        detector.RecordFailedLogin("a", "pw1");
        detector.RecordFailedLogin("b", "pw2");
        detector.RecordFailedLogin("c", "pw3");
        Assert.Empty(events);
        Assert.Equal(3, detector.TrackedFingerprintCount);
        Assert.False(detector.IsFlagged("pw1"));
    }

    [Fact]
    public void PasswordsAreNfkcNormalized()
    {
        var (detector, _, events) = Create(threshold: 2);
        detector.RecordFailedLogin("a", "pass");
        detector.RecordFailedLogin("b", "ｐａｓｓ");
        Assert.Single(events);
    }

    [Fact]
    public void WindowRotation_ResetsCounts_AndChangesFingerprints()
    {
        var (detector, clock, events) = Create(threshold: 3);
        detector.RecordFailedLogin("a", "pw");
        detector.RecordFailedLogin("b", "pw");
        string before = detector.GetSnapshot().Single().FingerprintId;

        clock.Advance(TimeSpan.FromMinutes(10)); // exactly at End: a new window
        Assert.Equal(0, detector.TrackedFingerprintCount);
        Assert.Equal(clock.Now, detector.WindowStart);

        detector.RecordFailedLogin("c", "pw");
        Assert.Empty(events);
        string after = detector.GetSnapshot().Single().FingerprintId;
        Assert.NotEqual(before, after); // the key changed: fingerprints cannot be correlated across windows
        Assert.Equal(1, detector.GetSnapshot().Single().DistinctAccountCount);
    }

    [Fact]
    public void WithinWindow_FingerprintIsStable()
    {
        var (detector, clock, events) = Create(threshold: 2);
        detector.RecordFailedLogin("a", "pw");
        string first = detector.GetSnapshot().Single().FingerprintId;
        clock.Advance(TimeSpan.FromMinutes(9.99));
        detector.RecordFailedLogin("b", "pw");
        Assert.Equal(first, Assert.Single(events).FingerprintId);
    }

    [Fact]
    public void Detection_IsOncePerFingerprintPerWindow_AndRepeatsInNextWindow()
    {
        var (detector, clock, events) = Create(threshold: 2);
        detector.RecordFailedLogin("a", "pw");
        detector.RecordFailedLogin("b", "pw");
        detector.RecordFailedLogin("c", "pw");
        Assert.Single(events);

        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.False(detector.IsFlagged("pw"));
        detector.RecordFailedLogin("a", "pw");
        detector.RecordFailedLogin("b", "pw");
        Assert.Equal(2, events.Count);
        Assert.NotEqual(events[0].FingerprintId, events[1].FingerprintId);
        Assert.Equal(T0.AddMinutes(11), events[1].WindowStart);
    }

    [Fact]
    public void Eviction_IsLeastRecentlyUsed_AndBounded()
    {
        var (detector, _, _) = Create(threshold: 3, maxFingerprints: 2);
        detector.RecordFailedLogin("a", "p1");
        detector.RecordFailedLogin("a", "p2");
        detector.RecordFailedLogin("b", "p1"); // p1 is now most recent
        detector.RecordFailedLogin("a", "p3"); // evicts p2

        Assert.Equal(2, detector.TrackedFingerprintCount);
        Assert.Equal(1, detector.EvictedCount);
        IReadOnlyList<FingerprintStatistics> snapshot = detector.GetSnapshot();
        Assert.Equal(new[] { 1, 2 }, snapshot.Select(s => s.DistinctAccountCount)); // p3 then p1

        // p1 kept its count, so one more account flags it.
        Assert.True(detector.RecordFailedLogin("c", "p1"));

        // p2 was evicted: it starts again from zero.
        detector.RecordFailedLogin("b", "p2");
        Assert.Equal(1, detector.GetSnapshot().First().DistinctAccountCount);
        Assert.Equal(2, detector.EvictedCount);
    }

    [Fact]
    public void Flood_OfUniquePasswords_StaysWithinMemoryCap()
    {
        var (detector, _, events) = Create(threshold: 2, maxFingerprints: 100);
        for (int i = 0; i < 10_000; i++)
            detector.RecordFailedLogin("victim", "garbage" + i);
        Assert.Equal(100, detector.TrackedFingerprintCount);
        Assert.Equal(9_900, detector.EvictedCount);
        Assert.Empty(events);
    }

    [Fact]
    public void PublicApi_ExposesOnlyFingerprints_NeverPasswordsOrAccounts()
    {
        var (detector, _, events) = Create(threshold: 2);
        const string password = "MySecretPassword123";
        detector.RecordFailedLogin("victim-one", password);
        detector.RecordFailedLogin("victim-two", password);

        var texts = new List<string>();
        foreach (FingerprintStatistics s in detector.GetSnapshot())
        {
            texts.Add(s.FingerprintId);
            texts.Add(s.ToString()!);
        }
        CredentialStuffingDetectedEventArgs e = Assert.Single(events);
        texts.Add(e.FingerprintId);
        texts.Add(e.ToString()!);
        texts.Add(detector.ToString()!);

        foreach (string text in texts)
        {
            Assert.DoesNotContain(password, text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("victim", text, StringComparison.OrdinalIgnoreCase);
        }
        Assert.All(detector.GetSnapshot(), s => Assert.Matches(new Regex("^[0-9a-f]{32}$"), s.FingerprintId));

        // The fingerprint is not a plain (unkeyed) hash of the password.
        string sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
        Assert.DoesNotContain(e.FingerprintId, sha);

        // Two detectors (two random keys) give unrelated fingerprints for the same password.
        var (other, _, _) = Create(threshold: 2);
        other.RecordFailedLogin("x", password);
        Assert.NotEqual(e.FingerprintId, other.GetSnapshot().Single().FingerprintId);
    }

    [Fact]
    public void OverlongPasswords_AreIgnored()
    {
        var clock = new FakeClock(T0);
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { MaxPasswordLength = 10, Clock = clock.Func, DistinctAccountThreshold = 2 });
        Assert.False(detector.RecordFailedLogin("a", new string('x', 11)));
        Assert.Equal(0, detector.TrackedFingerprintCount);
        Assert.False(detector.IsFlagged(new string('x', 11)));
    }

    [Fact]
    public void SensitiveStringOverload_MatchesStringOverload()
    {
        var (detector, _, events) = Create(threshold: 2);
        detector.RecordFailedLogin("a", new SensitiveString("pw"));
        detector.RecordFailedLogin("b", "pw");
        Assert.Single(events);
        Assert.Throws<ArgumentNullException>(() => detector.RecordFailedLogin("a", (SensitiveString)null!));
    }

    [Fact]
    public void ResetAndDispose()
    {
        var (detector, _, _) = Create(threshold: 2);
        detector.RecordFailedLogin("a", "pw");
        detector.Reset();
        Assert.Equal(0, detector.TrackedFingerprintCount);
        Assert.False(detector.RecordFailedLogin("b", "pw"));

        detector.Dispose();
        detector.Dispose(); // idempotent
        Assert.Throws<ObjectDisposedException>(() => detector.RecordFailedLogin("a", "pw"));
        Assert.Throws<ObjectDisposedException>(() => detector.IsFlagged("pw"));
        Assert.Throws<ObjectDisposedException>(() => detector.GetSnapshot());
        Assert.Throws<ObjectDisposedException>(() => detector.Reset());
    }

    [Fact]
    public void Arguments_AndOptions_AreValidated()
    {
        var (detector, _, _) = Create();
        Assert.Throws<ArgumentNullException>(() => detector.RecordFailedLogin(null!, "pw"));
        Assert.Throws<ArgumentNullException>(() => detector.RecordFailedLogin("a", (string)null!));
        Assert.Throws<ArgumentNullException>(() => detector.IsFlagged(null!));
        Assert.Throws<ArgumentNullException>(() => new CredentialStuffingDetector(null!));

        Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { Window = TimeSpan.Zero }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { Window = TimeSpan.FromDays(2) }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { MaxTrackedFingerprints = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { MaxPasswordLength = 0 }));

        using var defaults = new CredentialStuffingDetector();
        Assert.Equal(20, defaults.DistinctAccountThreshold);
        Assert.Equal(TimeSpan.FromMinutes(10), defaults.Window);
    }

    [Fact]
    public void EmptyStrings_AreAccepted()
    {
        var (detector, _, events) = Create(threshold: 2);
        detector.RecordFailedLogin("", "");
        detector.RecordFailedLogin("x", "");
        Assert.Single(events);
    }

    [Fact]
    public void Concurrent_Recording_RaisesExactlyOnce()
    {
        var clock = new FakeClock(T0);
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 50, Clock = clock.Func });
        int raised = 0;
        detector.StuffingDetected += (_, _) => Interlocked.Increment(ref raised);

        Parallel.For(0, 2000, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
        {
            detector.RecordFailedLogin("user" + (i % 500), "sprayed");
            detector.RecordFailedLogin("user" + i, "noise" + i);
        });

        Assert.Equal(1, raised);
        Assert.True(detector.IsFlagged("sprayed"));
        Assert.Equal(2001, detector.TrackedFingerprintCount);
    }

    [Fact]
    public void HandlerException_PropagatesToCaller_StateStaysConsistent()
    {
        var clock = new FakeClock(T0);
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 2, Clock = clock.Func });
        detector.StuffingDetected += (_, _) => throw new InvalidOperationException("handler");
        detector.RecordFailedLogin("a", "pw");
        Assert.Throws<InvalidOperationException>(() => detector.RecordFailedLogin("b", "pw"));
        Assert.True(detector.IsFlagged("pw"));
        Assert.True(detector.RecordFailedLogin("c", "pw")); // already flagged, no re-raise
    }
}
