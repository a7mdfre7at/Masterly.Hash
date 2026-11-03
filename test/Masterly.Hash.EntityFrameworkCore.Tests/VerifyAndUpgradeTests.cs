using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace Masterly.Hash.EntityFrameworkCore.Tests;

public class VerifyAndUpgradeTests
{
    private const string Plain = "hunter2-but-longer";

    private static readonly byte[] V1Salt = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };

    private readonly PasswordHasher _hasher = TestHashers.Create();

    /// <summary>Inserts a user and then overwrites its hash with raw SQL, as legacy data already in the database.</summary>
    private static int SeedRaw(SqliteDb db, IPasswordHasher hasher, string? storedHash)
    {
        int id;
        using (TestDbContext context = db.Context(hasher))
        {
            var user = new User { UserName = "alice", PasswordHash = "placeholder-password" };
            context.Users.Add(user);
            context.SaveChanges();
            id = user.Id;
        }
        db.Execute("UPDATE Users SET PasswordHash = $h WHERE Id = $id", ("$h", storedHash), ("$id", id));
        return id;
    }

    [Fact]
    public async Task Upgrades_a_v1_hash()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, v1);

        await using TestDbContext context = db.Context(_hasher);
        User user = await context.Users.SingleAsync();
        Assert.Equal(v1, user.PasswordHash);

        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.LegacyFormat, result.RehashReason);
        Assert.StartsWith("$mh$p=test$", user.PasswordHash);
        Assert.Equal(user.PasswordHash, db.Scalar("SELECT PasswordHash FROM Users"));
        Assert.Equal(EntityState.Unchanged, context.Entry(user).State);

        PasswordVerificationResult again = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);
        Assert.Equal(VerificationStatus.Success, again.Status);
    }

    [Fact]
    public async Task Wrong_password_changes_nothing()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, v1);

        await using TestDbContext context = db.Context(_hasher);
        User user = await context.Users.SingleAsync();
        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, "wrong password");

        Assert.False(result.IsMatch);
        Assert.Equal(VerificationFailureReason.Mismatch, result.FailureReason);
        Assert.Equal(v1, user.PasswordHash);
        Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public async Task Upgrades_an_outdated_profile()
    {
        PasswordHasher old = TestHashers.Create(o => o.DefaultProfile = TestHashers.Fast2);
        PasswordHasher current = TestHashers.Create(o => o.AdditionalProfiles.Add(TestHashers.Fast2));
        string oldHash = old.Hash(Plain);
        using var db = new SqliteDb();
        SeedRaw(db, current, oldHash);

        await using TestDbContext context = db.Context(current);
        User user = await context.Users.SingleAsync();
        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.Equal(RehashReason.OutdatedProfile, result.RehashReason);
        Assert.StartsWith("$mh$p=test$", db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public async Task Current_hash_is_not_rewritten()
    {
        using var db = new SqliteDb();
        string hash = _hasher.Hash(Plain);
        SeedRaw(db, _hasher, hash);

        await using TestDbContext context = db.Context(_hasher);
        User user = await context.Users.SingleAsync();
        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.Equal(VerificationStatus.Success, result.Status);
        Assert.Equal(hash, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public async Task Detached_entity_is_upgraded_and_left_detached()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, v1);

        await using TestDbContext context = db.Context(_hasher);
        User user = await context.Users.AsNoTracking().SingleAsync();
        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.True(result.NeedsRehash);
        Assert.StartsWith("$mh$", user.PasswordHash);
        Assert.Equal(user.PasswordHash, db.Scalar("SELECT PasswordHash FROM Users"));
        Assert.Equal(EntityState.Detached, context.Entry(user).State);
        Assert.Equal("alice", db.Scalar("SELECT UserName FROM Users"));
    }

    [Fact]
    public async Task Null_stored_hash_fails_without_throwing()
    {
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, null);

        await using TestDbContext context = db.Context(_hasher);
        User user = await context.Users.SingleAsync();
        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.False(result.IsMatch);
        Assert.Equal(VerificationFailureReason.NoStoredHash, result.FailureReason);
    }

    [Theory]
    [InlineData("not a hash")]
    [InlineData("$mh$p=nope$AAAA$AAAA")]
    public async Task Garbage_stored_hash_fails_without_throwing(string stored)
    {
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, stored);

        await using TestDbContext context = db.Context(_hasher);
        User user = await context.Users.SingleAsync();
        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.False(result.IsMatch);
        Assert.Equal(stored, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public async Task Rehash_is_computed_when_hasher_does_not_precompute_it()
    {
        PasswordHasher lazy = TestHashers.Create(o => o.ComputeRehashOnVerify = false);
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedRaw(db, lazy, v1);

        await using TestDbContext context = db.Context(lazy);
        User user = await context.Users.SingleAsync();
        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.True(result.NeedsRehash);
        Assert.Null(result.Rehash);
        Assert.True(lazy.Verify(Plain, db.Scalar("SELECT PasswordHash FROM Users")!).Status == VerificationStatus.Success);
    }

    [Fact]
    public async Task Pending_password_change_is_not_overwritten()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, v1);

        await using TestDbContext context = db.Context(_hasher);
        User user = await context.Users.SingleAsync();
        context.Entry(user).Property(u => u.PasswordHash).CurrentValue = v1;
        context.Entry(user).Property(u => u.PasswordHash).IsModified = true;

        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);
        Assert.True(result.NeedsRehash);
        Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public async Task Concurrent_password_change_wins_over_the_upgrade()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        using (ConcurrencyDbContext seed = db.Create<ConcurrencyDbContext>(o => new ConcurrencyDbContext(o), _hasher))
        {
            seed.Accounts.Add(new Account { PasswordHash = "placeholder-password" });
            seed.SaveChanges();
        }
        db.Execute("UPDATE Accounts SET PasswordHash = $h", ("$h", v1));

        await using ConcurrencyDbContext login = db.Create<ConcurrencyDbContext>(o => new ConcurrencyDbContext(o), _hasher);
        Account account = await login.Accounts.SingleAsync();

        // Meanwhile a password reset stores a new hash.
        string reset = _hasher.Hash("the new password");
        db.Execute("UPDATE Accounts SET PasswordHash = $h", ("$h", reset));

        PasswordVerificationResult result = await login.VerifyAndUpgradeAsync(account, a => a.PasswordHash, Plain);

        Assert.True(result.IsMatch);
        Assert.Equal(reset, db.Scalar("SELECT PasswordHash FROM Accounts"));
        Assert.Equal(v1, account.PasswordHash);
        Assert.Equal(EntityState.Unchanged, login.Entry(account).State);
    }

    // Regression: without a concurrency token the upgrade was a blind UPDATE ... WHERE Id = @id, so a password reset
    // that committed during the verification was overwritten with the old password's hash.
    [Fact]
    public async Task Concurrent_reset_is_not_overwritten_even_without_a_concurrency_token()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, v1);

        await using TestDbContext login = db.Context(_hasher);
        Assert.False(login.Model.FindEntityType(typeof(User))!.FindProperty(nameof(User.PasswordHash))!.IsConcurrencyToken);
        User user = await login.Users.SingleAsync();

        string reset = _hasher.Hash("the new password");
        db.Execute("UPDATE Users SET PasswordHash = $h", ("$h", reset));

        PasswordVerificationResult result = await login.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.True(result.IsMatch);
        Assert.Equal(reset, db.Scalar("SELECT PasswordHash FROM Users"));
        Assert.Equal(EntityState.Unchanged, login.Entry(user).State);
    }

    [Fact]
    public async Task Detached_entity_with_a_tracked_twin_still_logs_in()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        int id = SeedRaw(db, _hasher, v1);

        await using TestDbContext context = db.Context(_hasher);
        User tracked = (await context.Users.FindAsync(id))!;
        User detached = await context.Users.AsNoTracking().SingleAsync();

        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(detached, u => u.PasswordHash, Plain);

        Assert.True(result.IsMatch);
        Assert.Equal(EntityState.Detached, context.Entry(detached).State);
        Assert.Equal(EntityState.Unchanged, context.Entry(tracked).State);
        Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Failed_upgrade_save_still_returns_the_successful_result(bool detached)
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, v1);
        db.Execute("CREATE TRIGGER no_updates BEFORE UPDATE ON Users BEGIN SELECT RAISE(ABORT, 'read-only'); END;");

        await using TestDbContext context = db.Context(_hasher);
        User user = detached ? await context.Users.AsNoTracking().SingleAsync() : await context.Users.SingleAsync();

        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.True(result.IsMatch);
        Assert.Equal(v1, user.PasswordHash);
        Assert.Equal(detached ? EntityState.Detached : EntityState.Unchanged, context.Entry(user).State);
        Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public async Task Failure_of_another_pending_change_is_rethrown_and_the_property_restored()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, v1);
        db.Execute("CREATE TRIGGER no_inserts BEFORE INSERT ON Users BEGIN SELECT RAISE(ABORT, 'no inserts'); END;");

        await using TestDbContext context = db.Context(_hasher);
        User user = await context.Users.SingleAsync();
        context.Users.Add(new User { UserName = "bob" });

        await Assert.ThrowsAsync<DbUpdateException>(() => context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain));
        Assert.Equal(v1, user.PasswordHash);
        Assert.False(context.Entry(user).Property(u => u.PasswordHash).IsModified);
    }

    [Fact]
    public async Task Explicit_hasher_overload_works_without_interceptor()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedRaw(db, _hasher, v1);

        await using TestDbContext context = db.Create<TestDbContext>(o => new TestDbContext(o), hasher: null);
        User user = await context.Users.SingleAsync();
        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(_hasher, user, u => u.PasswordHash, Plain);

        Assert.True(result.NeedsRehash);
        Assert.StartsWith("$mh$", db.Scalar("SELECT PasswordHash FROM Users"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain));
    }

    [Fact]
    public async Task Rejects_null_arguments()
    {
        using var db = new SqliteDb();
        await using TestDbContext context = db.Context(_hasher);
        var user = new User();
        await Assert.ThrowsAsync<ArgumentNullException>(() => ((DbContext)null!).VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain));
        await Assert.ThrowsAsync<ArgumentNullException>(() => context.VerifyAndUpgradeAsync<User>(null!, u => u.PasswordHash, Plain));
        await Assert.ThrowsAsync<ArgumentNullException>(() => context.VerifyAndUpgradeAsync(user, null!, Plain));
        await Assert.ThrowsAsync<ArgumentNullException>(() => context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => context.VerifyAndUpgradeAsync(null!, user, u => u.PasswordHash, Plain));
        Assert.Empty(context.Users.ToList());
    }
}
