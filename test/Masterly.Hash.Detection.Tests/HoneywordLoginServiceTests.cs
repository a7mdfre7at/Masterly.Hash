using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Detection.Tests;

public class HoneywordLoginServiceTests
{
    private static (HoneywordLoginService Login, InMemoryHoneychecker Checker, List<HoneywordBreachDetectedEventArgs> Breaches) Create()
    {
        var checker = new InMemoryHoneychecker();
        var clock = new FakeClock(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var login = new HoneywordLoginService(TestSupport.Service(new FixedGenerator()), checker, clock.Func);
        var breaches = new List<HoneywordBreachDetectedEventArgs>();
        login.BreachDetected += (_, e) => breaches.Add(e);
        return (login, checker, breaches);
    }

    [Fact]
    public async Task RealPassword_Succeeds()
    {
        var (login, checker, breaches) = Create();
        string stored = await login.RegisterAsync("alice", "s3cret!", 5);

        Assert.Equal(1, checker.Count);
        HoneywordLoginResult result = await login.LoginAsync("alice", "s3cret!", stored);
        Assert.Equal(HoneywordLoginOutcome.Success, result.Outcome);
        Assert.True(result.IsSuccess);
        Assert.Equal(HoneywordVerificationStatus.SweetwordMatch, result.Verification.Status);
        Assert.Empty(breaches);
    }

    [Fact]
    public async Task Decoy_IsBreachDetected_AndRaisesEvent()
    {
        var (login, _, breaches) = Create();
        string stored = await login.RegisterAsync("alice", "s3cret!", 5);

        HoneywordLoginResult result = await login.LoginAsync("alice", FixedGenerator.Decoy(2), stored);
        Assert.Equal(HoneywordLoginOutcome.BreachDetected, result.Outcome);
        Assert.False(result.IsSuccess);

        HoneywordBreachDetectedEventArgs e = Assert.Single(breaches);
        Assert.Equal("alice", e.UserId);
        Assert.Equal(result.Verification.Index, e.SweetwordIndex);
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), e.DetectedAt);
    }

    [Fact]
    public async Task WrongPassword_IsMismatch_WithoutConsultingHoneychecker()
    {
        var checker = new CountingHoneychecker();
        var login = new HoneywordLoginService(TestSupport.Service(), checker);
        string stored = await login.RegisterAsync("bob", "hunter22", 4);

        HoneywordLoginResult result = await login.LoginAsync("bob", "hunter23", stored);
        Assert.Equal(HoneywordLoginOutcome.Mismatch, result.Outcome);
        Assert.Equal(0, checker.Checks);
    }

    [Fact]
    public async Task UnknownUser_And_MalformedHash_AreMismatch()
    {
        var (login, _, breaches) = Create();
        Assert.Equal(HoneywordLoginOutcome.Mismatch, (await login.LoginAsync("ghost", "pw", null)).Outcome);
        HoneywordLoginResult bad = await login.LoginAsync("ghost", "pw", "$mhw$broken");
        Assert.Equal(HoneywordLoginOutcome.Mismatch, bad.Outcome);
        Assert.Equal(HoneywordVerificationStatus.MalformedHash, bad.Verification.Status);
        Assert.Empty(breaches);
    }

    [Fact]
    public async Task HoneycheckerWithoutEntry_FailsClosed()
    {
        var (login, checker, breaches) = Create();
        string stored = await login.RegisterAsync("carol", "pw-carol", 3);
        checker.Remove("carol");

        Assert.Equal(HoneywordLoginOutcome.BreachDetected, (await login.LoginAsync("carol", "pw-carol", stored)).Outcome);
        Assert.Single(breaches);
    }

    [Fact]
    public async Task OtherUsersHash_DoesNotLogIn()
    {
        var (login, _, _) = Create();
        await login.RegisterAsync("alice", "alice-pw", 5);
        string bobs = await login.RegisterAsync("bob", "bob-pw", 5);

        // Alice's password is not among the sweetwords of Bob's hash.
        Assert.Equal(HoneywordLoginOutcome.Mismatch, (await login.LoginAsync("alice", "alice-pw", bobs)).Outcome);
    }

    [Fact]
    public async Task HoneycheckerFailure_Propagates()
    {
        var login = new HoneywordLoginService(TestSupport.Service(), new ThrowingHoneychecker());
        HoneywordRecord record = TestSupport.Service().Create("pw", 2);
        await Assert.ThrowsAsync<InvalidOperationException>(() => login.RegisterAsync("u", "pw"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => login.LoginAsync("u", "pw", record.StoredHash));
    }

    [Fact]
    public async Task Arguments_AreValidated()
    {
        var (login, _, _) = Create();
        Assert.Throws<ArgumentNullException>(() => new HoneywordLoginService(null!, new InMemoryHoneychecker()));
        Assert.Throws<ArgumentNullException>(() => new HoneywordLoginService(TestSupport.Service(), null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => login.RegisterAsync(null!, "pw"));
        await Assert.ThrowsAsync<ArgumentNullException>(() => login.RegisterAsync("u", null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => login.LoginAsync(null!, "pw", null));
        await Assert.ThrowsAsync<ArgumentNullException>(() => login.LoginAsync("u", null!, null));
    }

    [Fact]
    public async Task InMemoryHoneychecker_Behaviour()
    {
        var checker = new InMemoryHoneychecker();
        Assert.False(await checker.IsRealAsync("u", 0));
        await checker.SetAsync("u", 3);
        Assert.True(await checker.IsRealAsync("u", 3));
        Assert.False(await checker.IsRealAsync("u", 2));
        Assert.False(await checker.IsRealAsync("U", 3)); // user ids are exact
        Assert.False(await checker.IsRealAsync("u", -1));
        await checker.SetAsync("u", 1);
        Assert.True(await checker.IsRealAsync("u", 1));
        Assert.True(checker.Remove("u"));
        Assert.False(checker.Remove("u"));
        Assert.Equal(0, checker.Count);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => checker.SetAsync("u", -1));
        await Assert.ThrowsAsync<ArgumentNullException>(() => checker.SetAsync(null!, 1));
        await Assert.ThrowsAsync<ArgumentNullException>(() => checker.IsRealAsync(null!, 1));
        Assert.Throws<ArgumentNullException>(() => checker.Remove(null!));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => checker.SetAsync("u", 1, cts.Token));
    }

    private sealed class CountingHoneychecker : IHoneychecker
    {
        private readonly InMemoryHoneychecker _inner = new InMemoryHoneychecker();

        public int Checks { get; private set; }

        public Task SetAsync(string userId, int index, CancellationToken cancellationToken = default) =>
            _inner.SetAsync(userId, index, cancellationToken);

        public Task<bool> IsRealAsync(string userId, int index, CancellationToken cancellationToken = default)
        {
            Checks++;
            return _inner.IsRealAsync(userId, index, cancellationToken);
        }
    }

    private sealed class ThrowingHoneychecker : IHoneychecker
    {
        public Task SetAsync(string userId, int index, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("unreachable");

        public Task<bool> IsRealAsync(string userId, int index, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("unreachable");
    }
}
