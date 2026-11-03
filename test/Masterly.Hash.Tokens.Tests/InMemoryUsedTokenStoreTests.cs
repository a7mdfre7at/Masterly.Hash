using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Tokens.Tests;

public class InMemoryUsedTokenStoreTests
{
    [Fact]
    public async Task RecordsEachNonceOnce()
    {
        var store = new InMemoryUsedTokenStore();
        DateTimeOffset until = DateTimeOffset.UtcNow.AddMinutes(5);

        Assert.True(await store.TryMarkUsedAsync("n1", until));
        Assert.False(await store.TryMarkUsedAsync("n1", until));
        Assert.True(await store.TryMarkUsedAsync("N1", until)); // ordinal
        Assert.True(store.Contains("n1"));
        Assert.False(store.Contains("n2"));
        Assert.False(store.Contains(null!));
        Assert.Equal(2, store.Count);
    }

    [Fact]
    public void PurgeRemovesOnlyEntriesPastRetentionPlusGrace()
    {
        var clock = new FakeClock(TestKeys.T0);
        var store = new InMemoryUsedTokenStore(clock.AsFunc());
        store.TryMarkUsed("old", TestKeys.T0.AddMinutes(1));
        store.TryMarkUsed("new", TestKeys.T0.AddHours(1));

        clock.Advance(TimeSpan.FromMinutes(1) + InMemoryUsedTokenStore.PurgeGrace);
        store.Purge();
        Assert.True(store.Contains("old")); // exactly at the cutoff is kept

        clock.Advance(TimeSpan.FromSeconds(1));
        store.Purge();
        Assert.False(store.Contains("old"));
        Assert.True(store.Contains("new"));
    }

    [Fact]
    public void PurgesAutomaticallyAsItIsUsed()
    {
        var clock = new FakeClock(TestKeys.T0);
        var store = new InMemoryUsedTokenStore(clock.AsFunc());
        for (int i = 0; i < 100; i++)
            store.TryMarkUsed("expired-" + i, TestKeys.T0);

        clock.Advance(TimeSpan.FromHours(1));
        for (int i = 0; i < 300; i++)
            store.TryMarkUsed("live-" + i, clock.Now.AddHours(1));

        Assert.Equal(0, Enumerable.Range(0, 100).Count(i => store.Contains("expired-" + i)));
        Assert.Equal(300, store.Count);
    }

    [Fact]
    public void ConcurrentMarkingAdmitsExactlyOneWinner()
    {
        var store = new InMemoryUsedTokenStore();
        int wins = 0;
        Parallel.For(0, 1000, _ =>
        {
            if (store.TryMarkUsed("shared", DateTimeOffset.UtcNow.AddMinutes(5)))
                Interlocked.Increment(ref wins);
        });
        Assert.Equal(1, wins);
    }

    [Fact]
    public async Task HonoursCancellationAndValidatesArguments()
    {
        var store = new InMemoryUsedTokenStore();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(async () => await store.TryMarkUsedAsync("n", DateTimeOffset.UtcNow, cts.Token));
        Assert.Equal(0, store.Count);
        Assert.Throws<ArgumentNullException>(() => store.TryMarkUsed(null!, DateTimeOffset.UtcNow));
    }
}
