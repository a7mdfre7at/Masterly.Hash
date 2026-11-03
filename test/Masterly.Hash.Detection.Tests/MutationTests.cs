using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Detection.Internal;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Detection.Tests;

/// <summary>
/// Tests written to kill surviving Stryker.NET mutants: exact boundaries, exact messages, internal invariants and
/// the library's async hygiene (no captured synchronization context, buffers zeroed after use).
/// </summary>
public class MutationTests
{
    // =====================================================================================================
    // HoneywordService: options boundaries and messages
    // =====================================================================================================

    [Fact]
    public void Options_accept_their_exact_limits()
    {
        Assert.NotNull(TestSupport.Service(configure: o => o.MaxSweetwordCount = HoneywordService.MinSweetwordCount));
        Assert.NotNull(TestSupport.Service(configure: o => o.MaxSweetwordCount = HoneywordService.MaxSweetwordLimit));
        Assert.NotNull(TestSupport.Service(configure: o => o.MaxPasswordBytes = 1024 * 1024));
        Assert.NotNull(TestSupport.Service(configure: o => o.MaxPasswordBytes = 64));

        Assert.Equal("options", Assert.Throws<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxSweetwordCount = 1)).ParamName);
        Assert.Equal("options", Assert.Throws<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxSweetwordCount = 1001)).ParamName);
        Assert.Equal("options", Assert.Throws<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxPasswordBytes = 1024 * 1024 + 1)).ParamName);
    }

    [Fact]
    public void Create_accepts_exactly_MaxSweetwordCount()
    {
        HoneywordService service = TestSupport.Service(new FixedGenerator(), o => o.MaxSweetwordCount = 3);

        HoneywordRecord record = service.Create("limit", 3);

        Assert.Equal(3, record.SweetwordCount);
        Assert.Equal(record.RealIndex, service.Verify("limit", record.StoredHash));
        Assert.Equal("sweetwordCount", Assert.Throws<ArgumentOutOfRangeException>(() => service.Create("limit", 4)).ParamName);
    }

    [Fact]
    public void Weak_and_conflicting_profiles_are_rejected_with_their_messages()
    {
        var weak = Assert.Throws<ArgumentException>(() =>
            new HoneywordService(TestSupport.Fast, Array.Empty<HashProfile>(), new HoneywordServiceOptions()));
        Assert.StartsWith("Profile ", weak.Message);
        Assert.EndsWith(" is below the OWASP minimum. Set AllowWeakProfiles only in tests.", weak.Message);

        HashProfile other = HashProfile.Argon2id("test", memoryKiB: 128, iterations: 1);
        var twice = Assert.Throws<ArgumentException>(() =>
            new HoneywordService(TestSupport.Fast, new[] { other }, new HoneywordServiceOptions { AllowWeakProfiles = true }));
        Assert.Equal("Profile id 'test' is listed twice with different parameters.", twice.Message);
    }

    [Fact]
    public void Bad_generator_output_is_reported_with_a_specific_message()
    {
        Assert.Equal(
            "The honeyword generator returned the wrong number of decoys.",
            Assert.Throws<InvalidOperationException>(() => TestSupport.Service(new FixedGenerator((_, _) => new[] { "only-one" })).Create("pw", 4)).Message);
        Assert.Equal(
            "The honeyword generator returned an empty decoy.",
            Assert.Throws<InvalidOperationException>(() => TestSupport.Service(new FixedGenerator((_, _) => new[] { "", "x" })).Create("pw", 3)).Message);
        Assert.Equal(
            "The honeyword generator returned duplicate decoys or the real password.",
            Assert.Throws<InvalidOperationException>(() => TestSupport.Service(new FixedGenerator((real, _) => new[] { real, "x" })).Create("pw", 3)).Message);
    }

    [Fact]
    public void Empty_password_is_rejected_before_the_generator_runs()
    {
        int generatorCalls = 0;
        HoneywordService service = TestSupport.Service(new FixedGenerator((_, n) =>
        {
            generatorCalls++;
            return Enumerable.Range(0, n).Select(FixedGenerator.Decoy).ToList();
        }));

        Assert.Equal("password", Assert.Throws<ArgumentException>(() => service.Create("", 3)).ParamName);
        Assert.Equal(0, generatorCalls);
    }

    [Fact]
    public async Task Dummy_derivation_is_skipped_for_an_empty_password()
    {
        HoneywordService service = TestSupport.Service();
        TestSupport.StrongBox derivations = TestSupport.Count(service);

        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, service.VerifyOrDummy("", null).Status);
        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, (await service.VerifyOrDummyAsync("", null)).Status);
        Assert.Equal(0, derivations.Value);

        // Contrast: a non-empty password does pay for one derivation.
        service.VerifyOrDummy("x", null);
        Assert.Equal(1, derivations.Value);
    }

    [Fact]
    public async Task VerifyDetailed_without_a_stored_hash_never_derives()
    {
        HoneywordService service = TestSupport.Service();
        TestSupport.StrongBox derivations = TestSupport.Count(service);

        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, service.VerifyDetailed("password", null).Status);
        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, (await service.VerifyDetailedAsync("password", null)).Status);
        Assert.Equal(0, derivations.Value);
    }

    [Fact]
    public async Task Sync_apis_use_the_sync_pepper_and_async_apis_the_async_pepper()
    {
        var pepper = new RecordingPepper();
        HoneywordService service = TestSupport.Service(new FixedGenerator(), o => o.Pepper = pepper);

        HoneywordRecord record = service.Create("pw", 3);
        Assert.Equal((3, 0), (pepper.SyncCalls, pepper.AsyncCalls));

        HoneywordRecord asyncRecord = await service.CreateAsync("pw", 3);
        Assert.Equal((3, 3), (pepper.SyncCalls, pepper.AsyncCalls));

        Assert.Equal(record.RealIndex, service.VerifyDetailed("pw", record.StoredHash).Index);
        Assert.Equal((4, 3), (pepper.SyncCalls, pepper.AsyncCalls));

        Assert.Equal(asyncRecord.RealIndex, (await service.VerifyDetailedAsync("pw", asyncRecord.StoredHash)).Index);
        Assert.Equal((4, 4), (pepper.SyncCalls, pepper.AsyncCalls));

        service.VerifyOrDummy("pw", null);
        Assert.Equal((5, 4), (pepper.SyncCalls, pepper.AsyncCalls));
        await service.VerifyOrDummyAsync("pw", null);
        Assert.Equal((5, 5), (pepper.SyncCalls, pepper.AsyncCalls));
    }

    // ---------- buffers are zeroed ----------

    [Fact]
    public void Create_and_verify_zero_every_derivation_input_and_output_and_pepper_input()
    {
        var pepper = new RecordingPepper();
        HoneywordService service = TestSupport.Service(new FixedGenerator(), o => o.Pepper = pepper);
        var inputs = new List<byte[]>();
        var outputs = new List<byte[]>();
        service.Derive = (profile, input, salt) =>
        {
            Assert.Contains(input, b => b != 0);
            inputs.Add(input);
            byte[] tag = HashPrimitives.DeriveKey(profile, input, salt);
            Assert.Contains(tag, b => b != 0);
            outputs.Add(tag);
            return tag;
        };

        HoneywordRecord record = service.Create("zero me", 3);
        Assert.Equal(3, inputs.Count);
        AssertAllZero(inputs);
        AssertAllZero(outputs); // the tags, once encoded into the stored string
        Assert.Equal(3, pepper.Inputs.Count);
        AssertAllZero(pepper.Inputs);

        inputs.Clear();
        outputs.Clear();
        pepper.Inputs.Clear();
        Assert.Equal(record.RealIndex, service.Verify("zero me", record.StoredHash));
        Assert.Single(outputs);
        AssertAllZero(inputs);
        AssertAllZero(outputs); // the computed tag, once compared
        AssertAllZero(pepper.Inputs);
    }

    private static void AssertAllZero(IEnumerable<byte[]> buffers)
    {
        foreach (byte[] buffer in buffers)
        {
            Assert.NotEmpty(buffer);
            Assert.All(buffer, b => Assert.Equal(0, b));
        }
    }

    // ---------- concurrency gate: sync waits on the calling thread, async never blocks ----------

    [Fact]
    public async Task Sync_verify_under_contention_waits_on_the_calling_thread()
    {
        HoneywordService service = TestSupport.Service(new FixedGenerator(), o =>
        {
            o.MaxConcurrency = 1;
            o.ConcurrencyTimeout = TimeSpan.FromSeconds(30);
        });
        HoneywordRecord record = service.Create("gate", 2);

        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        int block = 1;
        int deriveThread = 0;
        service.Derive = (profile, input, salt) =>
        {
            if (Interlocked.Exchange(ref block, 0) == 1)
            {
                entered.Set();
                release.Wait(TimeSpan.FromSeconds(30));
            }
            else
            {
                Interlocked.CompareExchange(ref deriveThread, Environment.CurrentManagedThreadId, 0);
            }
            return HashPrimitives.DeriveKey(profile, input, salt);
        };

        Task<int> holder = Task.Run(() => service.Verify("gate", record.StoredHash));
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(30)), "the holder never reached the KDF");

            int callerThread = 0;
            int result = -2;
            var waiter = new Thread(() =>
            {
                callerThread = Environment.CurrentManagedThreadId;
                result = service.Verify("gate", record.StoredHash);
            });
            waiter.Start();
            SpinWait.SpinUntil(() => (waiter.ThreadState & ThreadState.WaitSleepJoin) != 0, TimeSpan.FromSeconds(10));
            release.Set();
            Assert.True(waiter.Join(TimeSpan.FromSeconds(30)));

            Assert.Equal(record.RealIndex, result);
            Assert.Equal(callerThread, deriveThread);
        }
        finally
        {
            release.Set();
        }
        Assert.Equal(record.RealIndex, await holder);
    }

    public static IEnumerable<object[]> GatedOperations() =>
        new[] { "create", "verify", "dummy", "register", "login" }.Select(s => new object[] { s });

    /// <summary>
    /// While another call holds the only derivation slot, an async call must return a pending task (not block the
    /// caller), and its continuations must not be posted back to the caller's synchronization context.
    /// </summary>
    [Theory]
    [MemberData(nameof(GatedOperations))]
    public async Task Async_calls_waiting_for_a_derivation_slot_do_not_block_or_capture_the_context(string operation)
    {
        HoneywordService service = TestSupport.Service(new FixedGenerator(), o =>
        {
            o.MaxConcurrency = 1;
            o.ConcurrencyTimeout = TimeSpan.FromSeconds(5);
        });
        var login = new HoneywordLoginService(service, new InMemoryHoneychecker());
        string stored = await login.RegisterAsync("user", "gate-pw", 2);

        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        int block = 1;
        service.Derive = (profile, input, salt) =>
        {
            if (Interlocked.Exchange(ref block, 0) == 1)
            {
                entered.Set();
                release.Wait(TimeSpan.FromSeconds(30));
            }
            return HashPrimitives.DeriveKey(profile, input, salt);
        };

        Task<int> holder = Task.Run(() => service.Verify("gate-pw", stored));
        int posts;
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(30)), "the holder never reached the KDF");
            Func<Task> start = operation switch
            {
                "create" => () => service.CreateAsync("other", 3).AsTask(),
                "verify" => () => service.VerifyDetailedAsync("gate-pw", stored).AsTask(),
                "dummy" => () => service.VerifyOrDummyAsync("gate-pw", null).AsTask(),
                "register" => () => login.RegisterAsync("other", "other-pw", 2),
                _ => () => login.LoginAsync("user", "gate-pw", stored),
            };
            posts = await SyncContextProbe.PostsDuring(start, () => release.Set());
        }
        finally
        {
            release.Set();
        }

        Assert.Equal(0, posts);
        Assert.True((await holder) >= 0);
    }

    public static IEnumerable<object[]> PepperedOperations() =>
        new[] { "create", "verify", "dummy", "register", "login" }.Select(s => new object[] { s });

    /// <summary>An async pepper that completes later must not get its continuations posted to the caller's context.</summary>
    [Theory]
    [MemberData(nameof(PepperedOperations))]
    public async Task Awaiting_an_async_pepper_does_not_capture_the_context(string operation)
    {
        var pepper = new RecordingPepper();
        HoneywordService service = TestSupport.Service(new FixedGenerator(), o => o.Pepper = pepper);
        var checker = new InMemoryHoneychecker();
        var login = new HoneywordLoginService(service, checker);
        string stored = await login.RegisterAsync("user", "pepper-pw", 3);

        pepper.DeferNextAsyncCall();
        Func<Task> start = operation switch
        {
            "create" => () => service.CreateAsync("other", 3).AsTask(),
            "verify" => () => service.VerifyDetailedAsync("pepper-pw", stored).AsTask(),
            "dummy" => () => service.VerifyOrDummyAsync("pepper-pw", null).AsTask(),
            "register" => () => login.RegisterAsync("other", "other-pw", 3),
            _ => () => login.LoginAsync("user", "pepper-pw", stored),
        };

        Assert.Equal(0, await SyncContextProbe.PostsDuring(start, pepper.Release));
        Assert.Equal(HoneywordLoginOutcome.Success, (await login.LoginAsync("user", "pepper-pw", stored)).Outcome);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Awaiting_the_honeychecker_does_not_capture_the_context(bool register)
    {
        var checker = new DeferredHoneychecker();
        var login = new HoneywordLoginService(TestSupport.Service(new FixedGenerator()), checker);
        string stored = await login.RegisterAsync("user", "checker-pw", 3);

        checker.DeferNextCall();
        Func<Task> start = register
            ? () => login.RegisterAsync("other", "other-pw", 3)
            : () => login.LoginAsync("user", "checker-pw", stored);

        Assert.Equal(0, await SyncContextProbe.PostsDuring(start, checker.Release));
        Assert.Equal(HoneywordLoginOutcome.Success, (await login.LoginAsync("user", "checker-pw", stored)).Outcome);
    }

    // =====================================================================================================
    // HoneywordLoginService, HoneywordVerification, InMemoryHoneychecker
    // =====================================================================================================

    [Fact]
    public async Task RegisterAsync_rejects_a_null_user_before_any_work()
    {
        var checker = new PermissiveHoneychecker();
        HoneywordService service = TestSupport.Service(new FixedGenerator());
        TestSupport.StrongBox derivations = TestSupport.Count(service);
        var login = new HoneywordLoginService(service, checker);

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => login.RegisterAsync(null!, "pw"));
        Assert.Equal("userId", ex.ParamName);
        Assert.Equal(0, checker.Calls);
        Assert.Equal(0, derivations.Value);
    }

    [Fact]
    public void Verification_keeps_an_index_only_for_a_sweetword_match()
    {
        Assert.Equal(-1, new HoneywordVerification(HoneywordVerificationStatus.Mismatch, 3).Index);
        Assert.Equal(-1, new HoneywordVerification(HoneywordVerificationStatus.MalformedHash, 0).Index);
        Assert.Equal(-1, new HoneywordVerification(HoneywordVerificationStatus.SweetwordMatch, -1).Index);
        Assert.Equal(0, new HoneywordVerification(HoneywordVerificationStatus.SweetwordMatch, 0).Index);
        Assert.Equal(5, new HoneywordVerification(HoneywordVerificationStatus.SweetwordMatch, 5).Index);

        HoneywordVerification fail = HoneywordVerification.Fail(HoneywordVerificationStatus.SweetwordMatch);
        Assert.Equal(-1, fail.Index);
        Assert.Equal(-1, HoneywordVerification.Fail(HoneywordVerificationStatus.Mismatch).Index);
    }

    [Fact]
    public async Task InMemoryHoneychecker_validates_with_its_own_parameter_names()
    {
        var checker = new InMemoryHoneychecker();
        Assert.Equal("userId", (await Assert.ThrowsAsync<ArgumentNullException>(() => checker.SetAsync(null!, 1))).ParamName);
        Assert.Equal("userId", (await Assert.ThrowsAsync<ArgumentNullException>(() => checker.IsRealAsync(null!, 1))).ParamName);
        Assert.Equal("userId", Assert.Throws<ArgumentNullException>(() => checker.Remove(null!)).ParamName);
        Assert.Equal("index", (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => checker.SetAsync("u", -1))).ParamName);
    }

    [Fact]
    public async Task InMemoryHoneychecker_index_zero_is_real_and_cancellation_is_honoured()
    {
        var checker = new InMemoryHoneychecker();
        await checker.SetAsync("u", 0);
        Assert.True(await checker.IsRealAsync("u", 0));
        Assert.False(await checker.IsRealAsync("u", 1));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => checker.IsRealAsync("u", 0, cts.Token));
    }

    // =====================================================================================================
    // HoneywordHash.TryParse
    // =====================================================================================================

    private const string Salt = "AAAAAAAAAAAAAAAAAAAAAA";

    [Theory]
    [InlineData("$mhw$p=test$" + Salt + "$AAAA,AAAA", 2, null)]
    [InlineData("$mhw$p=test,k=key-1$" + Salt + "$AAAA,AAAA", 2, "key-1")]
    [InlineData("$mhw$p=test$" + Salt + "$AAAA,AAAA,AAAA", 3, null)]
    public void TryParse_accepts_well_formed_hashes(string value, int maxTags, string? keyId)
    {
        Assert.True(HoneywordHash.TryParse(value, maxTags, out HoneywordHash? hash));
        Assert.NotNull(hash);
        Assert.Equal("test", hash!.ProfileId);
        Assert.Equal(keyId, hash.PepperKeyId);
        Assert.Equal(16, hash.Salt.Length);
        Assert.Equal(maxTags, hash.Tags.Length);
    }

    [Theory]
    [InlineData("$mhx$p=test$" + Salt + "$AAAA,AAAA")] // wrong prefix
    [InlineData("$mhw$p=test$" + Salt)] // two parts
    [InlineData("$mhw$p=test$" + Salt + "$AAAA,AAAA$AAAA")] // four parts
    [InlineData("$mhw$p=test,k=a,k=b$" + Salt + "$AAAA,AAAA")] // three parameters
    [InlineData("$mhw$q=test$" + Salt + "$AAAA,AAAA")] // not p=
    [InlineData("$mhw$p=TEST$" + Salt + "$AAAA,AAAA")] // bad profile id
    [InlineData("$mhw$p=test,x=abc$" + Salt + "$AAAA,AAAA")] // second parameter is not k=
    [InlineData("$mhw$p=test,k=$" + Salt + "$AAAA,AAAA")] // empty key id
    [InlineData("$mhw$p=test,k=bad id$" + Salt + "$AAAA,AAAA")] // bad key id
    [InlineData("$mhw$p=test$$AAAA,AAAA")] // empty salt
    [InlineData("$mhw$p=test$!!!!$AAAA,AAAA")] // bad salt
    [InlineData("$mhw$p=test$" + Salt + "$AAAA")] // one tag
    [InlineData("$mhw$p=test$" + Salt + "$AAAA,AAAA,AAAA")] // three tags, max two
    [InlineData("$mhw$p=test$" + Salt + "$AAAA,")] // empty tag
    [InlineData("$mhw$p=test$" + Salt + "$AAAA,!!!!")] // bad tag
    public void TryParse_rejects_malformed_hashes(string value)
    {
        Assert.False(HoneywordHash.TryParse(value, 2, out HoneywordHash? hash));
        Assert.Null(hash);
    }

    [Fact]
    public void TryParse_rejects_null_and_accepts_exactly_MaxLength()
    {
        Assert.False(HoneywordHash.TryParse(null!, 2, out HoneywordHash? none));
        Assert.Null(none);

        int max = HoneywordHash.MaxLength(2);
        string atLimit = "$mhw$p=a$" + new string('A', max - 19) + "$AAAA,AAAA";
        Assert.Equal(max, atLimit.Length);
        Assert.True(HoneywordHash.TryParse(atLimit, 2, out HoneywordHash? hash));
        Assert.NotNull(hash);

        string overLimit = "$mhw$p=a$" + new string('A', max - 18) + "$AAAA,AAAA";
        Assert.Equal(max + 1, overLimit.Length);
        Assert.True(HashPrimitives.TryFromB64(new string('A', max - 18), out _)); // only the length is wrong
        Assert.False(HoneywordHash.TryParse(overLimit, 2, out _));
    }

    // =====================================================================================================
    // CharClasses, TypoSafety, SecureRandom
    // =====================================================================================================

    [Theory]
    [InlineData('!', "Symbol")]
    [InlineData('~', "Symbol")]
    [InlineData(' ', "Other")]
    [InlineData('\u001F', "Other")]
    [InlineData('\t', "Other")]
    [InlineData('\u007F', "Other")]
    [InlineData('\u0080', "Other")]
    public void CharClasses_symbol_range_is_exactly_printable_ascii_punctuation(char c, string expected)
    {
        Assert.Equal(expected, CharClasses.Of(c).ToString());
    }

    [Theory]
    [InlineData("xaby", "xcay")] // a[p] == b[p+1] but a[p+1] != b[p]: not a transposition
    [InlineData("ab", "bc")] // a[p+1] == b[p] but a[p] != b[p+1]: not a transposition
    [InlineData("abcd", "acbe")]
    public void TypoSafety_half_transpositions_are_not_one_edit(string a, string b)
    {
        Assert.False(TypoSafety.WithinOneEdit(a, b));
        Assert.False(TypoSafety.WithinOneEdit(b, a));
    }

    [Fact]
    public void SecureRandom_uses_all_four_bytes()
    {
        int[] small = Enumerable.Range(0, 64).Select(_ => SecureRandom.Next(1 << 24)).ToArray();
        Assert.All(small, v => Assert.InRange(v, 0, (1 << 24) - 1));
        Assert.Contains(small, v => ((v >> 8) & 0xFF) != 0);
        Assert.Contains(small, v => ((v >> 16) & 0xFF) != 0);

        int[] large = Enumerable.Range(0, 64).Select(_ => SecureRandom.Next(int.MaxValue)).ToArray();
        Assert.Contains(large, v => v >= 1 << 24);
    }

    [Fact]
    public void SecureRandom_range_and_chance_bounds()
    {
        int[] values = Enumerable.Range(0, 200).Select(_ => SecureRandom.Next(10, 20)).ToArray();
        Assert.All(values, v => Assert.InRange(v, 10, 19));

        Assert.All(Enumerable.Range(0, 200), _ => Assert.False(SecureRandom.Chance(0, 2)));
        Assert.All(Enumerable.Range(0, 200), _ => Assert.True(SecureRandom.Chance(2, 2)));
    }

    // =====================================================================================================
    // ScriptAlphabets: full sweep against a reference model of the documented rules
    // =====================================================================================================

    private static readonly (int First, int Last, (int First, int Last)[] Parts)[] CuratedScripts =
    {
        (0x0430, 0x044F, new[] { (0x0430, 0x044F) }),
        (0x0410, 0x042F, new[] { (0x0410, 0x042F) }),
        (0x03B1, 0x03C9, new[] { (0x03B1, 0x03C9) }),
        (0x0391, 0x03A9, new[] { (0x0391, 0x03A9) }),
        (0x05D0, 0x05EA, new[] { (0x05D0, 0x05EA) }),
        (0x0621, 0x064A, new[] { (0x0621, 0x063A), (0x0641, 0x064A) }),
        (0x0660, 0x0669, new[] { (0x0660, 0x0669) }),
        (0x06F0, 0x06F9, new[] { (0x06F0, 0x06F9) }),
        (0x0905, 0x0939, new[] { (0x0905, 0x0939) }),
        (0x0966, 0x096F, new[] { (0x0966, 0x096F) }),
        (0x0E01, 0x0E2E, new[] { (0x0E01, 0x0E2E) }),
        (0x00DF, 0x00FF, new[] { (0x00DF, 0x00FF) }),
        (0x00C0, 0x00DE, new[] { (0x00C0, 0x00DE) }),
        (0x3041, 0x3093, new[] { (0x3041, 0x3093) }),
        (0x30A1, 0x30F3, new[] { (0x30A1, 0x30F3) }),
        (0xAC00, 0xD7A3, new[] { (0xAC00, 0xD7A3) }),
        (0x4E00, 0x9FFF, new[] { (0x4E00, 0x9FFF) }),
    };

    [Fact]
    public void ScriptAlphabets_For_matches_the_reference_model_for_every_BMP_code_unit()
    {
        var curated = CuratedScripts
            .Select(s =>
            {
                string alphabet = string.Concat(s.Parts.Select(p => ReferenceBuild(p.First, p.Last, null)));
                return (s.First, s.Last, Alphabet: alphabet, Members: new HashSet<char>(alphabet));
            })
            .ToArray();
        var generic = new Dictionary<int, string>();
        var verified = new Dictionary<string, string>(ReferenceEqualityComparer.Instance);
        var mismatches = new List<string>();

        for (int code = 0; code <= 0xFFFF; code++)
        {
            char c = (char)code;
            string? expected = ReferenceFor(c, curated, generic);
            string? actual = ScriptAlphabets.For(c);
            if (expected == null || actual == null)
            {
                if (!ReferenceEquals(expected, actual))
                    mismatches.Add($"U+{code:X4}: expected {(expected == null ? "null" : "an alphabet")}, got {(actual == null ? "null" : "an alphabet")}");
                continue;
            }
            if (verified.TryGetValue(expected, out string? seen) && ReferenceEquals(seen, actual))
                continue;
            if (!string.Equals(expected, actual, StringComparison.Ordinal))
                mismatches.Add($"U+{code:X4}: alphabet differs");
            else
                verified[expected] = actual;
            if (mismatches.Count > 20)
                break;
        }

        Assert.Empty(mismatches);
        // Letters missing from an incomplete curated range are not taken for members of it.
        Assert.Null(ScriptAlphabets.For('×'));
        Assert.Null(ScriptAlphabets.For('÷'));
        Assert.Equal(ScriptAlphabets.For('б'), ScriptAlphabets.For('а'));
        Assert.Equal(ScriptAlphabets.For('б'), ScriptAlphabets.For('я'));
        Assert.Equal(ScriptAlphabets.For('Β'), ScriptAlphabets.For('Α'));
    }

    private static string? ReferenceFor(char c, (int First, int Last, string Alphabet, HashSet<char> Members)[] curated, Dictionary<int, string> generic)
    {
        if (c < 0x80 || char.IsSurrogate(c))
            return null;
        foreach (var script in curated)
        {
            if (c >= script.First && c <= script.Last && script.Members.Contains(c))
                return script.Alphabet;
        }
        UnicodeCategory category = CharUnicodeInfo.GetUnicodeCategory(c);
        if (category != UnicodeCategory.LowercaseLetter && category != UnicodeCategory.UppercaseLetter &&
            category != UnicodeCategory.OtherLetter && category != UnicodeCategory.DecimalDigitNumber)
        {
            return null;
        }
        int block = c & 0xFF80;
        int key = block * 64 + (int)category;
        if (!generic.TryGetValue(key, out string? alphabet))
        {
            alphabet = ReferenceBuild(block, block + 0x7F, category);
            generic[key] = alphabet;
        }
        return alphabet.Length >= 2 ? alphabet : null;
    }

    private static string ReferenceBuild(int first, int last, UnicodeCategory? category)
    {
        var sb = new StringBuilder();
        for (int code = first; code <= last; code++)
        {
            char c = (char)code;
            if (char.IsSurrogate(c))
                continue;
            bool usable = category.HasValue ? CharUnicodeInfo.GetUnicodeCategory(c) == category.Value : char.IsLetterOrDigit(c);
            if (usable && IsNfkcStable(c))
                sb.Append(c);
        }
        return sb.ToString();
    }

    private static bool IsNfkcStable(char c)
    {
        string s = c.ToString();
        try
        {
            return s.Normalize(NormalizationForm.FormKC) == s;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    // =====================================================================================================
    // TweakingHoneywordGenerator
    // =====================================================================================================

    [Fact]
    public void Tweaking_accepts_a_tail_of_16_and_validates_count_by_name()
    {
        Assert.Equal(16, new TweakingHoneywordGenerator(16).TailLength);
        Assert.Equal("tailLength", Assert.Throws<ArgumentOutOfRangeException>(() => new TweakingHoneywordGenerator(17)).ParamName);
        Assert.Equal("count", Assert.Throws<ArgumentOutOfRangeException>(() => TweakingHoneywordGenerator.Default.GenerateDecoys("pw", -1)).ParamName);
        Assert.Equal("realPassword", Assert.Throws<ArgumentException>(() => TweakingHoneywordGenerator.Default.GenerateDecoys("", 1)).ParamName);
    }

    [Fact]
    public void Tweaking_widens_a_short_tail_into_the_password()
    {
        // A one-character tail of "ab" offers only typo neighbours, so the tail must grow to cover both letters.
        IReadOnlyList<string> decoys = new TweakingHoneywordGenerator(1).GenerateDecoys("ab", 3);

        Assert.Equal(3, decoys.Count);
        Assert.All(decoys, d =>
        {
            Assert.Equal(2, d.Length);
            Assert.All(d, c => Assert.InRange(c, 'a', 'z'));
            Assert.NotEqual('a', d[0]);
            Assert.NotEqual('b', d[1]);
        });
    }

    [Theory]
    [InlineData(29, 2)] // space 100 == 2 * (1 seen + 29 needed + 20 neighbours): two digits are just enough
    [InlineData(30, 3)] // one more decoy tips it over: a third digit is appended
    public void Tweaking_appends_digits_exactly_when_the_space_is_too_small(int count, int expectedLength)
    {
        IReadOnlyList<string> decoys = TweakingHoneywordGenerator.Default.GenerateDecoys("7", count);

        Assert.Equal(count, decoys.Count);
        Assert.All(decoys, d =>
        {
            Assert.Equal(expectedLength, d.Length);
            Assert.All(d, c => Assert.InRange(c, '0', '9'));
        });
    }

    [Fact]
    public void Tweaking_keeps_the_whole_password_in_the_tail_after_appending_a_digit()
    {
        // U+0370 (Greek capital heta) is outside the curated Greek range; its generic alphabet is the four
        // NFKC-stable upper-case letters of block U+0300-U+037F. For "Ͱ5" the full tail offers 4 * 10 = 40
        // variations, less than 2 * (1 seen + 6 needed + 14 neighbours) = 42, so a digit is appended and the tail
        // must grow with it to all three characters (400 variations). If the tail did not grow with the appended
        // digit it would cover only "50" (100 >= 2 * (7 + 20) = 54) and the heta would never be tweaked.
        const char heta = 'Ͱ';
        Assert.Equal("ͰͲͶͿ", ScriptAlphabets.For(heta));

        var firstChars = new HashSet<char>();
        for (int run = 0; run < 20; run++)
        {
            string real = heta + "5";
            IReadOnlyList<string> decoys = TweakingHoneywordGenerator.Default.GenerateDecoys(real, 6);

            Assert.Equal(6, decoys.Count);
            Assert.Equal(6, decoys.Distinct(StringComparer.Ordinal).Count());
            Assert.All(decoys, d =>
            {
                Assert.Equal(3, d.Length);
                Assert.Contains(d[0], "ͰͲͶͿ");
                Assert.InRange(d[1], '0', '9');
                Assert.InRange(d[2], '0', '9');
                Assert.False(TypoSafety.WithinOneEdit(d, real));
                firstChars.Add(d[0]);
            });
        }

        // The first character is drawn from all four letters (heta itself least often, about 81 of 381 accepted
        // candidates, because "Ͱ5d" and "Ͱd5" are one insertion away). Missing any of the four in 120 decoys has
        // probability below 1e-12; both mutants never change the heta at all.
        Assert.Equal("ͰͲͶͿ", new string(firstChars.OrderBy(c => c).ToArray()));
    }

    // =====================================================================================================
    // PasswordModelHoneywordGenerator
    // =====================================================================================================

    [Fact]
    public void Model_word_list_accepts_32_letter_words_and_the_letter_z()
    {
        Assert.Equal(1, new PasswordModelHoneywordGenerator(new[] { new string('q', 32) }).WordCount);
        Assert.Equal(1, new PasswordModelHoneywordGenerator(new[] { "zz", new string('q', 33) }).WordCount);
        Assert.Equal(2, new PasswordModelHoneywordGenerator(new[] { "Zebra", "fizz" }).WordCount);
    }

    [Fact]
    public void Model_validates_count_by_name()
    {
        Assert.Equal("count", Assert.Throws<ArgumentOutOfRangeException>(() => PasswordModelHoneywordGenerator.Default.GenerateDecoys("pw", -1)).ParamName);
        Assert.Equal("realPassword", Assert.Throws<ArgumentException>(() => PasswordModelHoneywordGenerator.Default.GenerateDecoys("", 1)).ParamName);
    }

    [Fact]
    public void Model_fallback_counts_the_real_password_as_already_seen()
    {
        // "7" has no model decoys (every digit is one typo away); the fallback sees {"7"} and needs 30 more,
        // which no longer fits in two digits.
        IReadOnlyList<string> decoys = PasswordModelHoneywordGenerator.Default.GenerateDecoys("7", 30);

        Assert.Equal(30, decoys.Count);
        Assert.All(decoys, d => Assert.Equal(3, d.Length));
    }

    [Fact]
    public void Model_tries_the_model_before_falling_back()
    {
        var generator = new PasswordModelHoneywordGenerator(new[] { "dog", "sun" });
        for (int i = 0; i < 20; i++)
            Assert.Contains(Assert.Single(generator.GenerateDecoys("Abc", 1)), new[] { "Dog", "Sun" });
    }

    [Fact]
    public void Model_composes_runs_from_a_shorter_word_and_an_exact_word()
    {
        var generator = new PasswordModelHoneywordGenerator(new[] { "orange", "cat", "dog" });
        string[] all = { "orange", "catcat", "catdog", "dogcat", "dogdog" };

        for (int i = 0; i < 5; i++)
        {
            IReadOnlyList<string> decoys = generator.GenerateDecoys("qwerty", 5);
            Assert.Equal(all.OrderBy(s => s, StringComparer.Ordinal), decoys.OrderBy(s => s, StringComparer.Ordinal));
        }
    }

    [Fact]
    public void Model_composition_finishes_with_an_exact_word_once_started()
    {
        // No six-letter word: every decoy is one two-letter and one four-letter word, never three two-letter words.
        var generator = new PasswordModelHoneywordGenerator(new[] { "go", "up", "ship", "boat" });
        string[] two = { "go", "up" };
        string[] four = { "ship", "boat" };
        var allowed = new HashSet<string>(
            two.SelectMany(a => four.Select(b => a + b)).Concat(four.SelectMany(a => two.Select(b => a + b))),
            StringComparer.Ordinal);

        for (int i = 0; i < 10; i++)
        {
            IReadOnlyList<string> decoys = generator.GenerateDecoys("qwerty", 8);
            Assert.Equal(8, decoys.Count);
            Assert.All(decoys, d => Assert.Contains(d, allowed));
        }
    }

    [Fact]
    public void Model_exact_word_is_chosen_three_times_in_four_when_a_composition_is_possible()
    {
        var generator = new PasswordModelHoneywordGenerator(new[] { "orange", "cat", "dog" });
        const int n = 2000;
        int exact = 0;
        for (int i = 0; i < n; i++)
        {
            if (Assert.Single(generator.GenerateDecoys("qwerty", 1)) == "orange")
                exact++;
        }

        // Expected 0.75; a composition that may also pick the exact length would give 0.875.
        Assert.InRange(exact / (double)n, 0.69, 0.8125);
    }

    [Fact]
    public void Model_two_letter_run_without_a_two_letter_word_is_random_not_composed()
    {
        var generator = new PasswordModelHoneywordGenerator(new[] { "x" });
        int composed = 0;
        for (int i = 0; i < 50; i++)
        {
            string decoy = Assert.Single(generator.GenerateDecoys("qw", 1));
            Assert.Equal(2, decoy.Length);
            if (decoy == "xx")
                composed++;
        }
        Assert.InRange(composed, 0, 10);
    }

    [Fact]
    public void Model_symbols_are_mostly_but_not_only_common_ones()
    {
        IReadOnlyList<string> decoys = PasswordModelHoneywordGenerator.Default.GenerateDecoys("!!!!!!!!!!", 100);
        string symbols = string.Concat(decoys);

        Assert.Equal(1000, symbols.Length);
        Assert.All(symbols, c => Assert.Contains(c, CharClasses.Symbols));
        Assert.Contains(symbols, c => !CharClasses.CommonSymbols.Contains(c));
        double common = symbols.Count(c => CharClasses.CommonSymbols.Contains(c)) / (double)symbols.Length;
        Assert.InRange(common, 0.7, 0.97); // expected 0.8 + 0.2 * 13/32 = 0.88
    }

    [Fact]
    public void Model_long_digit_runs_follow_the_documented_mix()
    {
        const int n = 3000;
        int ascending = 0;
        int repeated = 0;
        for (int i = 0; i < n; i++)
        {
            string d = Assert.Single(PasswordModelHoneywordGenerator.Default.GenerateDecoys("583920", 1));
            Assert.Equal(6, d.Length);
            if (IsAscending(d))
                ascending++;
            else if (d.Distinct().Count() == 1)
                repeated++;
        }

        Assert.InRange(ascending / (double)n, 0.15, 0.25); // 1/5
        Assert.InRange(repeated / (double)n, 0.06, 0.14); // 4/5 * 1/8
    }

    [Fact]
    public void Model_two_digit_runs_can_be_sequences_and_repeats()
    {
        const int n = 4000;
        int ascending = 0;
        int repeated = 0;
        for (int i = 0; i < n; i++)
        {
            string decoy = Assert.Single(PasswordModelHoneywordGenerator.Default.GenerateDecoys("qwerty55", 1));
            Assert.Equal(8, decoy.Length);
            string d = decoy.Substring(6);
            Assert.All(d, c => Assert.InRange(c, '0', '9'));
            if (IsAscending(d))
                ascending++;
            if (d[0] == d[1])
                repeated++;
        }

        Assert.InRange(ascending / (double)n, 0.2, 0.34); // 1/5 + 4/5 * 7/8 * 1/10 = 0.27
        Assert.InRange(repeated / (double)n, 0.13, 0.21); // 4/5 * 1/8 + 4/5 * 7/8 * 1/10 = 0.17
    }

    private static bool IsAscending(string digits)
    {
        for (int i = 1; i < digits.Length; i++)
        {
            if (digits[i] - '0' != (digits[i - 1] - '0' + 1) % 10)
                return false;
        }
        return true;
    }

    [Theory]
    [InlineData("Zebra")]
    [InlineData("Apple")]
    public void Model_keeps_the_capital_of_Z_and_A(string password)
    {
        IReadOnlyList<string> decoys = PasswordModelHoneywordGenerator.Default.GenerateDecoys(password, 10);

        Assert.Equal(10, decoys.Count);
        Assert.All(decoys, d =>
        {
            Assert.Equal(password.Length, d.Length);
            Assert.InRange(d[0], 'A', 'Z');
            Assert.All(d.Substring(1), c => Assert.InRange(c, 'a', 'z'));
        });
    }

    [Fact]
    public void Model_replaces_runs_of_other_scripts()
    {
        IReadOnlyList<string> decoys = PasswordModelHoneywordGenerator.Default.GenerateDecoys("summerпароль", 10);

        Assert.Equal(10, decoys.Count);
        Assert.All(decoys, d =>
        {
            Assert.Equal(12, d.Length);
            Assert.False(d.EndsWith("пароль", StringComparison.Ordinal), d);
            Assert.All(d.Substring(6), c => Assert.InRange(c, 'а', 'я'));
        });
    }

    // =====================================================================================================
    // HoneyAccountRegistry
    // =====================================================================================================

    [Fact]
    public void Remove_accepts_an_account_of_exactly_MaxAccountLength()
    {
        var registry = new HoneyAccountRegistry();
        string longest = new string('a', HoneyAccountRegistry.MaxAccountLength);
        Assert.True(registry.Add(longest));
        Assert.True(registry.IsHoneyAccount(longest));
        Assert.True(registry.Remove(longest));
        Assert.Equal(0, registry.Count);
    }

    [Fact]
    public void Overlong_account_is_never_a_honey_account_even_if_it_normalizes_to_one()
    {
        string composed = string.Concat(Enumerable.Repeat("é", 600)); // 600 code units
        string decomposed = string.Concat(Enumerable.Repeat("é", 600)); // 1200 code units, same after NFKC
        var registry = new HoneyAccountRegistry(new[] { composed });

        Assert.True(decomposed.Length > HoneyAccountRegistry.MaxAccountLength);
        Assert.False(registry.IsHoneyAccount(decomposed));
        Assert.False(registry.CheckLogin(decomposed));
        Assert.False(registry.Remove(decomposed));
        Assert.True(registry.IsHoneyAccount(composed));
    }

    // =====================================================================================================
    // CredentialStuffingDetector
    // =====================================================================================================

    private static readonly DateTimeOffset T0 = new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Detector_options_accept_their_exact_limits()
    {
        Assert.Equal(TimeSpan.FromSeconds(1), new CredentialStuffingDetector(new CredentialStuffingOptions { Window = TimeSpan.FromSeconds(1) }).Window);
        Assert.Equal(TimeSpan.FromDays(1), new CredentialStuffingDetector(new CredentialStuffingOptions { Window = TimeSpan.FromDays(1) }).Window);
        Assert.Equal(10_000, new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 10_000 }).DistinctAccountThreshold);
        Assert.NotNull(new CredentialStuffingDetector(new CredentialStuffingOptions { MaxTrackedFingerprints = 1 }));
        Assert.NotNull(new CredentialStuffingDetector(new CredentialStuffingOptions { MaxTrackedFingerprints = 10_000_000 }));
        Assert.NotNull(new CredentialStuffingDetector(new CredentialStuffingOptions { MaxPasswordLength = 1 }));
        Assert.NotNull(new CredentialStuffingDetector(new CredentialStuffingOptions { MaxPasswordLength = 1024 * 1024 }));
        Assert.NotNull(new CredentialStuffingDetector(new CredentialStuffingOptions { MaxAccountLength = 1 }));
        Assert.NotNull(new CredentialStuffingDetector(new CredentialStuffingOptions { MaxAccountLength = 1024 * 1024 }));

        Assert.Equal("options", Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { Window = TimeSpan.FromDays(1) + TimeSpan.FromTicks(1) })).ParamName);
        Assert.Equal("options", Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 10_001 })).ParamName);
        Assert.Equal("options", Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { MaxTrackedFingerprints = 10_000_001 })).ParamName);
    }

    [Fact]
    public void Single_tracked_fingerprint_and_one_character_limits_work()
    {
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions
        {
            MaxTrackedFingerprints = 1,
            MaxPasswordLength = 1,
            MaxAccountLength = 1,
            DistinctAccountThreshold = 2,
            Clock = () => T0,
        });

        Assert.False(detector.RecordFailedLogin("a", "x"));
        Assert.True(detector.RecordFailedLogin("b", "x"));
        Assert.True(detector.IsFlagged("x"));
        Assert.False(detector.RecordFailedLogin("ab", "x")); // account too long: ignored
        Assert.False(detector.RecordFailedLogin("a", "xy")); // password too long: ignored
        Assert.Equal(1, detector.TrackedFingerprintCount);
    }

    [Fact]
    public void IsFlagged_accepts_a_password_of_exactly_MaxPasswordLength()
    {
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions
        {
            MaxPasswordLength = 8,
            DistinctAccountThreshold = 2,
            Clock = () => T0,
        });
        detector.RecordFailedLogin("a", "12345678");
        Assert.True(detector.RecordFailedLogin("b", "12345678"));

        Assert.True(detector.IsFlagged("12345678"));
    }

    [Fact]
    public void IsFlagged_retries_under_the_new_window_when_it_rotates_mid_call()
    {
        DateTimeOffset now = T0;
        int readsUntilJump = 0;
        CredentialStuffingDetector? detector = null;
        detector = new CredentialStuffingDetector(new CredentialStuffingOptions
        {
            DistinctAccountThreshold = 2,
            Window = TimeSpan.FromMinutes(10),
            Clock = () =>
            {
                if (--readsUntilJump == 0)
                {
                    // The window ends while IsFlagged is hashing, and the new window flags the password at once.
                    now = T0 + TimeSpan.FromMinutes(11);
                    detector!.RecordFailedLogin("a", "Winter2026!");
                    detector.RecordFailedLogin("b", "Winter2026!");
                }
                return now;
            },
        });
        Assert.False(detector.IsFlagged("Winter2026!")); // opens the first window

        readsUntilJump = 2; // the second clock read inside the next IsFlagged
        Assert.True(detector.IsFlagged("Winter2026!"));
        Assert.Equal(T0 + TimeSpan.FromMinutes(11), detector.WindowStart);
    }

    [Fact]
    public void Fingerprint_is_the_first_128_bits_of_the_window_HMAC_in_hex()
    {
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { Clock = () => T0 });
        detector.RecordFailedLogin("alice", "Winter2026!");

        byte[] key = WindowKey(detector, "PasswordKey");
        byte[] mac = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("Winter2026!"));
        string expected = Convert.ToHexStringLower(mac, 0, 16);

        Assert.Equal(expected, Assert.Single(detector.GetSnapshot()).FingerprintId);
    }

    [Fact]
    public void Reset_and_Dispose_zero_the_window_keys()
    {
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { Clock = () => T0 });
        detector.RecordFailedLogin("alice", "Winter2026!");
        byte[] passwordKey = WindowKey(detector, "PasswordKey");
        byte[] accountKey = WindowKey(detector, "AccountKey");
        Assert.Contains(passwordKey, b => b != 0);
        Assert.Contains(accountKey, b => b != 0);

        detector.Reset();
        Assert.All(passwordKey, b => Assert.Equal(0, b));
        Assert.All(accountKey, b => Assert.Equal(0, b));

        detector.RecordFailedLogin("alice", "Winter2026!");
        passwordKey = WindowKey(detector, "PasswordKey");
        accountKey = WindowKey(detector, "AccountKey");
        Assert.Contains(passwordKey, b => b != 0);

        detector.Dispose();
        Assert.All(passwordKey, b => Assert.Equal(0, b));
        Assert.All(accountKey, b => Assert.Equal(0, b));
        Assert.Null(GenerationField.GetValue(detector));
        detector.Dispose(); // idempotent
        Assert.Throws<ObjectDisposedException>(() => detector.GetSnapshot());
    }

    [Fact]
    public void FingerprintKey_equality_needs_both_halves()
    {
        Type type = typeof(CredentialStuffingDetector).GetNestedType("FingerprintKey", BindingFlags.NonPublic)!;
        object Key(ulong high, ulong low) => Activator.CreateInstance(type, high, low)!;

        Assert.True(Key(1, 2).Equals(Key(1, 2)));
        Assert.False(Key(1, 2).Equals(Key(1, 3)));
        Assert.False(Key(1, 2).Equals(Key(4, 2)));
        Assert.False(Key(1, 2).Equals("not a key"));
        Assert.Equal("0000000000000001" + "0000000000000002", Key(1, 2).ToString());
    }

    private static readonly FieldInfo GenerationField =
        typeof(CredentialStuffingDetector).GetField("_generation", BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static byte[] WindowKey(CredentialStuffingDetector detector, string name)
    {
        object generation = GenerationField.GetValue(detector)!;
        return (byte[])generation.GetType().GetProperty(name)!.GetValue(generation)!;
    }

    // =====================================================================================================
    // Guard messages: exact type, parameter name and message text
    // =====================================================================================================

    /// <summary>
    /// Asserts the exact exception type, its parameter name, and that its message is <paramref name="message"/>
    /// followed by the runtime's " (Parameter '...')" suffix (and, for out-of-range, the actual value).
    /// </summary>
    private static void AssertGuard<T>(Action action, string paramName, string message)
        where T : ArgumentException
    {
        T ex = Assert.Throws<T>(action);
        Assert.Equal(paramName, ex.ParamName);
        Assert.StartsWith(message + " (Parameter '" + paramName + "')", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Service_option_guards_report_their_exact_messages()
    {
        AssertGuard<ArgumentException>(() => TestSupport.Service(configure: o => o.Generator = null!), "options", "Generator is required.");
        AssertGuard<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxSweetwordCount = 1), "options", "MaxSweetwordCount must be between 2 and 1000.");
        AssertGuard<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxPasswordBytes = 63), "options", "MaxPasswordBytes must be between 64 and 1048576.");
        AssertGuard<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxConcurrency = -1), "options", "MaxConcurrency cannot be negative.");
        AssertGuard<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.ConcurrencyTimeout = TimeSpan.Zero), "options", "ConcurrencyTimeout must be positive or infinite.");
    }

    [Fact]
    public void Create_guards_report_their_exact_messages()
    {
        HoneywordService service = TestSupport.Service(new FixedGenerator(), o =>
        {
            o.MaxPasswordBytes = 64;
            o.MaxSweetwordCount = 5;
        });

        AssertGuard<ArgumentException>(() => service.Create("", 3), "password", "Password cannot be empty.");
        AssertGuard<ArgumentException>(() => service.Create("\uD800", 3), "password", "Password contains invalid UTF-16 or a code point that cannot be normalized.");
        AssertGuard<ArgumentOutOfRangeException>(() => service.Create("pw", 1), "sweetwordCount", "Sweetword count must be between 2 and 5.");
        // More than 4 * 64 code units: rejected before normalization.
        AssertGuard<ArgumentException>(() => service.Create(new string('a', (4 * 64) + 1), 3), "password", "Password exceeds 64 bytes.");
        // Short enough to normalize, but 65 bytes of UTF-8: rejected after normalization.
        AssertGuard<ArgumentException>(() => service.Create(new string('a', 65), 3), "password", "Password exceeds 64 bytes.");
        Assert.Equal(3, service.Create(new string('a', 64), 3).SweetwordCount);
    }

    [Fact]
    public void Registry_checker_and_generator_guards_report_their_exact_messages()
    {
        var registry = new HoneyAccountRegistry();
        AssertGuard<ArgumentException>(() => registry.Add(""), "account", "Account cannot be empty.");
        AssertGuard<ArgumentException>(() => registry.Add(new string('a', HoneyAccountRegistry.MaxAccountLength + 1)), "account", "Account cannot be longer than 1024 characters.");

        var checker = new InMemoryHoneychecker();
        AssertGuard<ArgumentOutOfRangeException>(() => checker.SetAsync("u", -1), "index", "Index cannot be negative.");

        AssertGuard<ArgumentException>(() => new PasswordModelHoneywordGenerator(new[] { "123", "", "naïve" }), "words", "The word list contains no usable words (1 to 32 ASCII letters).");
        AssertGuard<ArgumentException>(() => PasswordModelHoneywordGenerator.Default.GenerateDecoys("", 1), "realPassword", "Password cannot be empty.");
        AssertGuard<ArgumentOutOfRangeException>(() => new TweakingHoneywordGenerator(0), "tailLength", "Tail length must be between 1 and 16.");
        AssertGuard<ArgumentException>(() => TweakingHoneywordGenerator.Default.GenerateDecoys("", 1), "realPassword", "Password cannot be empty.");
    }

    [Fact]
    public void Detector_option_guards_report_their_exact_messages()
    {
        static Action Build(Action<CredentialStuffingOptions> configure) => () =>
        {
            var options = new CredentialStuffingOptions();
            configure(options);
            using var detector = new CredentialStuffingDetector(options);
        };

        AssertGuard<ArgumentOutOfRangeException>(Build(o => o.Window = TimeSpan.Zero), "options", "Window must be between 1 second and 1 day.");
        AssertGuard<ArgumentOutOfRangeException>(Build(o => o.DistinctAccountThreshold = 1), "options", "DistinctAccountThreshold must be between 2 and 10000.");
        AssertGuard<ArgumentOutOfRangeException>(Build(o => o.MaxTrackedFingerprints = 0), "options", "MaxTrackedFingerprints must be between 1 and 10000000.");
        AssertGuard<ArgumentOutOfRangeException>(Build(o => o.MaxPasswordLength = 0), "options", "MaxPasswordLength must be between 1 and 1048576.");
        AssertGuard<ArgumentOutOfRangeException>(Build(o => o.MaxPasswordLength = (1024 * 1024) + 1), "options", "MaxPasswordLength must be between 1 and 1048576.");
        AssertGuard<ArgumentOutOfRangeException>(Build(o => o.MaxAccountLength = 0), "options", "MaxAccountLength must be between 1 and 1048576.");
        AssertGuard<ArgumentOutOfRangeException>(Build(o => o.MaxAccountLength = (1024 * 1024) + 1), "options", "MaxAccountLength must be between 1 and 1048576.");
    }

    // =====================================================================================================
    // TweakingHoneywordGenerator: the attempt budget
    // =====================================================================================================

    /// <summary>
    /// A caller-supplied "seen" set that treats every string as already present rejects every candidate, so the
    /// defensive attempt budget is the only way out. For "7" and 30 decoys the basis widens to three digits
    /// (100 &lt; 2 * (1 + 30 + 20), 1000 &gt;= 2 * (1 + 30 + 30)), so no candidate is within one typo of the real
    /// password and every attempt reaches seen.Add: exactly 30 * 100 + 100 attempts, then a clear failure rather
    /// than an endless loop.
    /// </summary>
    [Fact]
    public void Tweaking_gives_up_after_exactly_its_attempt_budget()
    {
        var comparer = new EverythingEqualComparer();
        var seen = new HashSet<string>(comparer) { "7" };
        comparer.HashCalls = 0;
        var result = new List<string>();

        var ex = Assert.Throws<InvalidOperationException>(() => TweakingHoneywordGenerator.Default.AddDecoys("7", 30, seen, result, TweakingHoneywordGenerator.DefaultTailLength));

        Assert.Equal("Could not generate enough distinct decoys.", ex.Message);
        Assert.Equal((30 * 100) + 100, comparer.HashCalls);
        Assert.Empty(result);
        Assert.Single(seen);
    }

    /// <summary>Equality comparer under which every string equals every other; counts hash computations (one per HashSet.Add).</summary>
    private sealed class EverythingEqualComparer : IEqualityComparer<string>
    {
        public int HashCalls;

        public bool Equals(string? x, string? y) => true;

        public int GetHashCode(string obj)
        {
            HashCalls++;
            return 0;
        }
    }

    // =====================================================================================================
    // fakes
    // =====================================================================================================

    /// <summary>Counts how often continuations are posted to it while an operation runs.</summary>
    private sealed class SyncContextProbe : SynchronizationContext
    {
        private int _posts;

        /// <summary>
        /// Starts <paramref name="start"/> with the probe installed, checks it is still pending, runs
        /// <paramref name="release"/> on the thread pool and returns how many continuations were posted to the probe.
        /// </summary>
        public static async Task<int> PostsDuring(Func<Task> start, Action release)
        {
            var probe = new SyncContextProbe();
            SynchronizationContext? previous = Current;
            Task task;
            SetSynchronizationContext(probe);
            try
            {
                task = start();
            }
            finally
            {
                SetSynchronizationContext(previous);
            }

            Assert.False(task.IsCompleted, "the operation should be pending, not blocking or finished");
            await Task.Run(release);
            await task;
            return Volatile.Read(ref probe._posts);
        }

        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }

        public override void Send(SendOrPostCallback d, object? state) => d(state);
    }

    /// <summary>HMAC pepper that records its calls and inputs, and can hold back one async call.</summary>
    private sealed class RecordingPepper : IPasswordPepper
    {
        private readonly HmacPepper _inner = new("k1", HmacPepper.GenerateKey());
        private TaskCompletionSource _gate = new();
        private int _defer;
        private int _syncCalls;
        private int _asyncCalls;

        public string CurrentKeyId => "k1";

        public int SyncCalls => Volatile.Read(ref _syncCalls);

        public int AsyncCalls => Volatile.Read(ref _asyncCalls);

        public List<byte[]> Inputs { get; } = new();

        public void DeferNextAsyncCall()
        {
            _gate = new TaskCompletionSource();
            Volatile.Write(ref _defer, 1);
        }

        public void Release() => _gate.SetResult();

        public bool IsKnownKey(string keyId) => keyId == "k1";

        public byte[] Apply(string keyId, byte[] input)
        {
            Interlocked.Increment(ref _syncCalls);
            lock (Inputs)
                Inputs.Add(input);
            return _inner.Apply(keyId, input);
        }

        public async ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _asyncCalls);
            byte[] copy = (byte[])input.Clone();
            if (Interlocked.Exchange(ref _defer, 0) == 1)
                await _gate.Task.ConfigureAwait(false);
            return _inner.Apply(keyId, copy);
        }
    }

    /// <summary>In-memory honeychecker that can hold back its next call.</summary>
    private sealed class DeferredHoneychecker : IHoneychecker
    {
        private readonly InMemoryHoneychecker _inner = new();
        private TaskCompletionSource _gate = new();
        private int _defer;

        public void DeferNextCall()
        {
            _gate = new TaskCompletionSource();
            Volatile.Write(ref _defer, 1);
        }

        public void Release() => _gate.SetResult();

        public async Task SetAsync(string userId, int index, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref _defer, 0) == 1)
                await _gate.Task.ConfigureAwait(false);
            await _inner.SetAsync(userId, index, cancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> IsRealAsync(string userId, int index, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref _defer, 0) == 1)
                await _gate.Task.ConfigureAwait(false);
            return await _inner.IsRealAsync(userId, index, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Honeychecker that accepts anything, including a null user id, and counts calls.</summary>
    private sealed class PermissiveHoneychecker : IHoneychecker
    {
        public int Calls { get; private set; }

        public Task SetAsync(string userId, int index, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.CompletedTask;
        }

        public Task<bool> IsRealAsync(string userId, int index, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(false);
        }
    }
}
