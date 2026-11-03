using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using IdentityCompatibilityMode = Microsoft.AspNetCore.Identity.PasswordHasherCompatibilityMode;
using IdentityHasherOptions = Microsoft.AspNetCore.Identity.PasswordHasherOptions;
using MasterlyOptions = Masterly.Hash.PasswordHasherOptions;

namespace Masterly.Hash.AspNetCore.Tests;

public sealed class TestUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string UserName { get; set; } = "alice";
    public string? NormalizedUserName { get; set; }
    public string? PasswordHash { get; set; }
}

internal static class TestHashers
{
    public static readonly HashProfile Fast = HashProfile.Argon2id("test", memoryKiB: 64, iterations: 1);
    public static readonly HashProfile Fast2 = HashProfile.Argon2id("test2", memoryKiB: 128, iterations: 1);

    public static void Weak(MasterlyOptions options)
    {
        options.DefaultProfile = Fast;
        options.AllowWeakProfiles = true;
    }

    /// <summary>Options configured like <c>AddMasterlyPasswordHasher</c> configures them, with a fast profile.</summary>
    public static MasterlyOptions IdentityOptions(Action<MasterlyOptions>? configure = null)
    {
        var options = new MasterlyOptions { ComputeRehashOnVerify = false };
        Weak(options);
        configure?.Invoke(options);
        options.AddAspNetIdentityFormats();
        return options;
    }

    /// <summary>A fast Masterly hasher configured like <c>AddMasterlyPasswordHasher</c> configures it.</summary>
    public static PasswordHasher CreateForIdentity(Action<MasterlyOptions>? configure = null) =>
        new PasswordHasher(IdentityOptions(configure));

    public static MasterlyIdentityPasswordHasher<TestUser> CreateAdapter(Action<MasterlyOptions>? configure = null)
    {
        MasterlyOptions options = IdentityOptions(configure);
        return new MasterlyIdentityPasswordHasher<TestUser>(new PasswordHasher(options), Options.Create(options));
    }

    /// <summary>Microsoft's own Identity hasher, in the given compatibility mode.</summary>
    public static PasswordHasher<TestUser> Microsoft(IdentityCompatibilityMode mode, int? iterations = null)
    {
        var options = new IdentityHasherOptions { CompatibilityMode = mode };
        if (iterations.HasValue)
            options.IterationCount = iterations.Value;
        return new PasswordHasher<TestUser>(Options.Create(options));
    }
}

/// <summary>A Masterly hasher that always throws <see cref="PasswordHasherBusyException"/>.</summary>
internal sealed class BusyHasher : IPasswordHasher
{
    public string Hash(string password) => throw new PasswordHasherBusyException();
    public string Hash(string password, HashProfile profile) => throw new PasswordHasherBusyException();
    public PasswordVerificationResult Verify(string password, string storedHash) => throw new PasswordHasherBusyException();
    public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) => throw new PasswordHasherBusyException();
    public ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default) => throw new PasswordHasherBusyException();
    public ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default) => throw new PasswordHasherBusyException();
    public ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) => throw new PasswordHasherBusyException();
    public bool NeedsRehash(string storedHash) => false;
    public HashInfo Inspect(string storedHash) => throw new NotSupportedException();
    public bool TryWrap(string legacyHash, out string wrappedHash) => throw new NotSupportedException();
}

/// <summary>Minimal in-memory Identity store with password support, counting updates.</summary>
internal sealed class InMemoryUserStore : IUserPasswordStore<TestUser>
{
    private readonly Dictionary<string, TestUser> _users = new(StringComparer.Ordinal);

    public int Updates { get; private set; }

    public void Add(TestUser user) => _users[user.Id] = user;

    public Task<string> GetUserIdAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(user.Id);
    public Task<string?> GetUserNameAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult<string?>(user.UserName);
    public Task SetUserNameAsync(TestUser user, string? userName, CancellationToken cancellationToken) { user.UserName = userName ?? ""; return Task.CompletedTask; }
    public Task<string?> GetNormalizedUserNameAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(user.NormalizedUserName);
    public Task SetNormalizedUserNameAsync(TestUser user, string? normalizedName, CancellationToken cancellationToken) { user.NormalizedUserName = normalizedName; return Task.CompletedTask; }
    public Task<IdentityResult> CreateAsync(TestUser user, CancellationToken cancellationToken) { Add(user); return Task.FromResult(IdentityResult.Success); }
    public Task<IdentityResult> UpdateAsync(TestUser user, CancellationToken cancellationToken) { Updates++; _users[user.Id] = user; return Task.FromResult(IdentityResult.Success); }
    public Task<IdentityResult> DeleteAsync(TestUser user, CancellationToken cancellationToken) { _users.Remove(user.Id); return Task.FromResult(IdentityResult.Success); }
    public Task<TestUser?> FindByIdAsync(string userId, CancellationToken cancellationToken) => Task.FromResult(_users.TryGetValue(userId, out TestUser? u) ? u : null);

    public Task<TestUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        foreach (TestUser user in _users.Values)
        {
            if (string.Equals(user.NormalizedUserName, normalizedUserName, StringComparison.Ordinal))
                return Task.FromResult<TestUser?>(user);
        }
        return Task.FromResult<TestUser?>(null);
    }

    public Task SetPasswordHashAsync(TestUser user, string? passwordHash, CancellationToken cancellationToken) { user.PasswordHash = passwordHash; return Task.CompletedTask; }
    public Task<string?> GetPasswordHashAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(user.PasswordHash);
    public Task<bool> HasPasswordAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(user.PasswordHash != null);
    public void Dispose() { }
}
