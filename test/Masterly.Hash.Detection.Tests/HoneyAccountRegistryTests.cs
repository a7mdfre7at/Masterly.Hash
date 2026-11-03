using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Masterly.Hash.Detection.Tests;

public class HoneyAccountRegistryTests
{
    [Theory]
    [InlineData("admin2")]
    [InlineData("ADMIN2")]
    [InlineData("Admin2")]
    [InlineData("ａｄｍｉｎ２")] // full-width "admin2"
    public void IsHoneyAccount_IsCaseInsensitiveAndNormalized(string account)
    {
        var registry = new HoneyAccountRegistry(new[] { "admin2", "backup-svc" });
        Assert.True(registry.IsHoneyAccount(account));
    }

    [Fact]
    public void NonHoneyAccounts_AreNotFlagged()
    {
        var registry = new HoneyAccountRegistry(new[] { "admin2" });
        Assert.False(registry.IsHoneyAccount("admin"));
        Assert.False(registry.IsHoneyAccount("admin22"));
        Assert.False(registry.IsHoneyAccount(""));
        Assert.False(registry.CheckLogin("alice"));
    }

    [Fact]
    public void CheckLogin_RaisesEvent_IsHoneyAccount_DoesNot()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 5, 1, 12, 0, 0, TimeSpan.Zero));
        var registry = new HoneyAccountRegistry(new[] { "decoy" }, clock.Func);
        var events = new List<HoneyAccountAccessedEventArgs>();
        registry.HoneyAccountAccessed += (_, e) => events.Add(e);

        Assert.True(registry.IsHoneyAccount("decoy"));
        Assert.Empty(events);

        Assert.True(registry.CheckLogin("DECOY", "10.0.0.1"));
        HoneyAccountAccessedEventArgs e = Assert.Single(events);
        Assert.Equal("DECOY", e.Account);
        Assert.Equal("10.0.0.1", e.Context);
        Assert.Equal(clock.Now, e.Timestamp);

        Assert.False(registry.CheckLogin("real-user"));
        Assert.Single(events);
    }

    [Fact]
    public void AddAndRemove()
    {
        var registry = new HoneyAccountRegistry();
        Assert.Equal(0, registry.Count);
        Assert.True(registry.Add("trap"));
        Assert.False(registry.Add("TRAP"));
        Assert.Equal(1, registry.Count);
        Assert.True(registry.Remove("Trap"));
        Assert.False(registry.Remove("trap"));
        Assert.False(registry.IsHoneyAccount("trap"));
    }

    [Fact]
    public void Arguments_AreValidated()
    {
        var registry = new HoneyAccountRegistry();
        Assert.Throws<ArgumentNullException>(() => new HoneyAccountRegistry(null!));
        Assert.Throws<ArgumentNullException>(() => registry.Add(null!));
        Assert.Throws<ArgumentException>(() => registry.Add(""));
        Assert.Throws<ArgumentNullException>(() => registry.Remove(null!));
        Assert.Throws<ArgumentNullException>(() => registry.IsHoneyAccount(null!));
        Assert.Throws<ArgumentNullException>(() => registry.CheckLogin(null!));
    }

    [Fact]
    public void InvalidUtf16_DoesNotThrow()
    {
        var registry = new HoneyAccountRegistry(new[] { "a\uD800" });
        Assert.True(registry.IsHoneyAccount("A\uD800"));
    }

    [Fact]
    public void ConcurrentAddAndCheck_IsSafe()
    {
        var registry = new HoneyAccountRegistry();
        int hits = 0;
        registry.HoneyAccountAccessed += (_, _) => System.Threading.Interlocked.Increment(ref hits);
        Parallel.For(0, 1000, i =>
        {
            registry.Add("user" + i);
            registry.CheckLogin("USER" + i);
        });
        Assert.Equal(1000, registry.Count);
        Assert.Equal(1000, hits);
        Assert.All(Enumerable.Range(0, 1000), i => Assert.True(registry.IsHoneyAccount("user" + i)));
    }
}
