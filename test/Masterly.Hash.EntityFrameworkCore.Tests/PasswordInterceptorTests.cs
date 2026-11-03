using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace Masterly.Hash.EntityFrameworkCore.Tests;

public class PasswordInterceptorTests
{
    private const string Plain = "correct horse battery staple";

    private readonly PasswordHasher _hasher = TestHashers.Create();

    [Fact]
    public void Insert_replaces_plaintext_with_hash_in_entity_and_database()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        var user = new User { UserName = "alice", PasswordHash = Plain };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.NotEqual(Plain, user.PasswordHash);
        Assert.StartsWith("$mh$p=test$", user.PasswordHash);
        Assert.Equal(user.PasswordHash, db.Scalar("SELECT PasswordHash FROM Users"));
        Assert.True(_hasher.Verify(Plain, user.PasswordHash!).IsMatch);
        Assert.Equal(EntityState.Unchanged, context.Entry(user).State);
    }

    [Fact]
    public async Task Insert_async_replaces_plaintext_with_hash()
    {
        using var db = new SqliteDb();
        await using TestDbContext context = db.Context(_hasher);
        var user = new User { UserName = "alice", PasswordHash = Plain };
        context.Users.Add(user);
        await context.SaveChangesAsync();

        Assert.True(_hasher.Verify(Plain, user.PasswordHash!).IsMatch);
        Assert.Equal(user.PasswordHash, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Update_hashes_new_password(bool async)
    {
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Context(_hasher))
        {
            seed.Users.Add(new User { UserName = "alice", PasswordHash = Plain });
            seed.SaveChanges();
        }

        using TestDbContext context = db.Context(_hasher);
        User user = context.Users.Single();
        string oldHash = user.PasswordHash!;
        user.PasswordHash = "a brand new password";
        if (async)
            await context.SaveChangesAsync();
        else
            context.SaveChanges();

        Assert.NotEqual(oldHash, user.PasswordHash);
        Assert.True(_hasher.Verify("a brand new password", user.PasswordHash!).IsMatch);
        Assert.False(_hasher.Verify(Plain, user.PasswordHash!).IsMatch);
        Assert.Equal(user.PasswordHash, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public void Update_through_Update_method_of_detached_entity_hashes_plaintext()
    {
        using var db = new SqliteDb();
        int id;
        using (TestDbContext seed = db.Context(_hasher))
        {
            var u = new User { UserName = "alice", PasswordHash = Plain };
            seed.Users.Add(u);
            seed.SaveChanges();
            id = u.Id;
        }

        using TestDbContext context = db.Context(_hasher);
        var detached = new User { Id = id, UserName = "alice", PasswordHash = "replacement password" };
        context.Users.Update(detached);
        context.SaveChanges();

        Assert.True(_hasher.Verify("replacement password", detached.PasswordHash!).IsMatch);
        Assert.Equal(detached.PasswordHash, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public void Already_hashed_value_is_stored_unchanged()
    {
        string hash = _hasher.Hash(Plain);
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        var user = new User { UserName = "alice", PasswordHash = hash };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.Equal(hash, user.PasswordHash);
        Assert.Equal(hash, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public void Recognized_hash_from_an_outdated_profile_is_stored_unchanged()
    {
        PasswordHasher old = TestHashers.Create(o => o.DefaultProfile = TestHashers.Fast2);
        PasswordHasher current = TestHashers.Create(o => o.AdditionalProfiles.Add(TestHashers.Fast2));
        string hash = old.Hash(Plain);
        Assert.True(current.Inspect(hash).NeedsRehash);

        using var db = new SqliteDb();
        using TestDbContext context = db.Context(current);
        var user = new User { UserName = "alice", PasswordHash = hash };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.Equal(hash, user.PasswordHash);
    }

    [Fact]
    public void Changing_another_property_does_not_touch_the_stored_password()
    {
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Context(_hasher))
        {
            seed.Users.Add(new User { UserName = "alice", PasswordHash = Plain });
            seed.SaveChanges();
        }
        string? before = db.Scalar("SELECT PasswordHash FROM Users");

        using TestDbContext context = db.Context(_hasher);
        User user = context.Users.Single();
        user.Nickname = "ally";
        context.SaveChanges();

        Assert.Equal(before, db.Scalar("SELECT PasswordHash FROM Users"));
        Assert.Equal("ally", db.Scalar("SELECT Nickname FROM Users"));
    }

    [Fact]
    public void Legacy_hash_already_in_database_survives_unrelated_updates()
    {
        string v1 = TestHashers.V1Sha512(Plain, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Context(_hasher))
        {
            seed.Users.Add(new User { UserName = "alice", PasswordHash = "placeholder" });
            seed.SaveChanges();
        }
        db.Execute("UPDATE Users SET PasswordHash = $h", ("$h", v1));

        using TestDbContext context = db.Context(_hasher);
        User user = context.Users.Single();
        user.Nickname = "ally";
        context.SaveChanges();

        Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    /// <summary>Seeds one user and overwrites its hash with raw SQL, as data already in the database.</summary>
    private int SeedStored(SqliteDb db, string storedHash)
    {
        using TestDbContext seed = db.Context(_hasher);
        var u = new User { UserName = "alice", PasswordHash = "placeholder" };
        seed.Users.Add(u);
        seed.SaveChanges();
        db.Execute("UPDATE Users SET PasswordHash = $h", ("$h", storedHash));
        return u.Id;
    }

    // Regression: Update() marks every property modified with originals equal to currents, so the stored v1 hash
    // was hashed as if it were a password. The real password stopped verifying and the v1 string became the password.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Legacy_hash_survives_Update_of_a_detached_entity(bool async)
    {
        string v1 = TestHashers.V1Sha512(Plain, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        using var db = new SqliteDb();
        SeedStored(db, v1);

        using TestDbContext context = db.Context(_hasher);
        User user = context.Users.AsNoTracking().Single();
        user.Nickname = "ally";
        context.Users.Update(user);
        if (async)
            await context.SaveChangesAsync();
        else
            context.SaveChanges();

        Assert.Equal(v1, user.PasswordHash);
        Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
        Assert.Equal("ally", db.Scalar("SELECT Nickname FROM Users"));
        Assert.True(_hasher.Verify(Plain, db.Scalar("SELECT PasswordHash FROM Users")!).IsMatch);
    }

    [Fact]
    public void Legacy_hash_survives_State_Modified_on_a_tracked_entity()
    {
        string v1 = TestHashers.V1Sha512(Plain, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        using var db = new SqliteDb();
        SeedStored(db, v1);

        using TestDbContext context = db.Context(_hasher);
        User user = context.Users.Single();
        context.Entry(user).State = EntityState.Modified;
        context.SaveChanges();

        Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public void Hash_of_an_unregistered_profile_survives_Update_of_a_detached_entity()
    {
        // A stored hash whose profile was removed from the hasher must not block unrelated disconnected updates.
        string retired = TestHashers.Create(o => o.DefaultProfile = TestHashers.Fast2).Hash(Plain);
        Assert.False(_hasher.Inspect(retired).IsRecognized);
        using var db = new SqliteDb();
        SeedStored(db, retired);

        using TestDbContext context = db.Context(_hasher);
        User user = context.Users.AsNoTracking().Single();
        user.Nickname = "ally";
        context.Users.Update(user);
        context.SaveChanges();

        Assert.Equal(retired, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public void Base64_looking_new_password_assigned_through_Update_is_still_hashed()
    {
        // The database check must not turn a new legacy-looking password into a stored plaintext.
        string base64Password = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray());
        Assert.True(_hasher.Inspect(base64Password).IsRecognized);
        using var db = new SqliteDb();
        int id = SeedStored(db, _hasher.Hash(Plain));

        using TestDbContext context = db.Context(_hasher);
        var detached = new User { Id = id, UserName = "alice", PasswordHash = base64Password };
        context.Users.Update(detached);
        context.SaveChanges();

        Assert.StartsWith("$mh$p=test$", detached.PasswordHash);
        Assert.True(_hasher.Verify(base64Password, db.Scalar("SELECT PasswordHash FROM Users")!).IsMatch);
    }

    [Fact]
    public void Unrecognized_hash_assigned_through_Update_still_fails()
    {
        using var db = new SqliteDb();
        string stored = _hasher.Hash(Plain);
        int id = SeedStored(db, stored);

        using TestDbContext context = db.Context(_hasher);
        context.Users.Update(new User { Id = id, UserName = "alice", PasswordHash = "$mh$garbage" });

        Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
        Assert.Equal(stored, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public void Legacy_hash_assigned_to_a_tracked_entity_is_hashed_when_it_differs_from_the_database()
    {
        string v1 = TestHashers.V1Sha512("another password", new byte[] { 4, 3, 2, 1 });
        using var db = new SqliteDb();
        SeedStored(db, _hasher.Hash(Plain));

        using TestDbContext context = db.Context(_hasher);
        User user = context.Users.Single();
        user.PasswordHash = v1;
        context.SaveChanges();

        Assert.StartsWith("$mh$p=test$", user.PasswordHash);
    }

    [Fact]
    public void Null_password_stays_null()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        var user = new User { UserName = "sso-only" };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.Null(user.PasswordHash);
        Assert.Null(db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public void Empty_password_fails_the_save_and_writes_nothing()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        context.Users.Add(new User { UserName = "alice", PasswordHash = "" });

        var ex = Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
        Assert.Contains("User.PasswordHash", ex.Message);
        Assert.IsAssignableFrom<ArgumentException>(ex.InnerException);
        Assert.Equal("0", db.Scalar("SELECT CAST(COUNT(*) AS TEXT) FROM Users"));
    }

    [Fact]
    public async Task Too_long_password_fails_without_leaking_it()
    {
        string secret = "SECRET-" + new string('x', 2000);
        using var db = new SqliteDb();
        await using TestDbContext context = db.Context(_hasher);
        context.Users.Add(new User { UserName = "alice", PasswordHash = secret });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => context.SaveChangesAsync());
        Assert.DoesNotContain("SECRET", ex.ToString());
    }

    [Fact]
    public void Base64_looking_plaintext_is_hashed_by_default()
    {
        // A 1.x hash is plain base64, so this password is "recognized" by the v1 legacy format.
        string base64Password = Convert.ToBase64String(Enumerable.Range(0, 72).Select(i => (byte)i).ToArray());
        Assert.True(_hasher.Inspect(base64Password).IsRecognized);

        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        var user = new User { UserName = "alice", PasswordHash = base64Password };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.StartsWith("$mh$", user.PasswordHash);
        Assert.True(_hasher.Verify(base64Password, user.PasswordHash!).IsMatch);
    }

    [Fact]
    public void Legacy_hash_is_kept_when_AcceptLegacyHashes_is_on()
    {
        string v1 = TestHashers.V1Sha512(Plain, new byte[] { 9, 8, 7, 6 });
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, configure: o => o.AcceptLegacyHashes = true);
        var user = new User { UserName = "alice", PasswordHash = v1 };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.Equal(v1, user.PasswordHash);
        Assert.True(_hasher.Verify(Plain, v1).NeedsRehash);
    }

    [Theory]
    [InlineData("$mh$p=unknown-profile$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$mh$garbage")]
    public void Unrecognized_masterly_hash_fails_instead_of_double_hashing(string value)
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        var user = new User { UserName = "alice", PasswordHash = value };
        context.Users.Add(user);

        var ex = Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
        Assert.DoesNotContain(value, ex.Message);
        Assert.Equal(value, user.PasswordHash);
    }

    [Fact]
    public void Hash_from_unknown_pepper_key_fails_instead_of_double_hashing()
    {
        PasswordHasher peppered = TestHashers.Create(o => o.Pepper = new Masterly.Hash.Pepper.HmacPepper("p1", new System.Collections.Generic.Dictionary<string, byte[]>
        {
            ["p1"] = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("pepper")),
        }));
        string hash = peppered.Hash(Plain);

        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        context.Users.Add(new User { UserName = "alice", PasswordHash = hash });

        Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
    }

    [Fact]
    public void Each_save_salts_independently()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        var a = new User { UserName = "a", PasswordHash = Plain };
        var b = new User { UserName = "b", PasswordHash = Plain };
        context.Users.AddRange(a, b);
        context.SaveChanges();

        Assert.NotEqual(a.PasswordHash, b.PasswordHash);
    }

    [Fact]
    public void Saving_twice_does_not_rehash()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        var user = new User { UserName = "alice", PasswordHash = Plain };
        context.Users.Add(user);
        context.SaveChanges();
        string first = user.PasswordHash!;

        context.Entry(user).Property(u => u.PasswordHash).IsModified = true;
        context.SaveChanges();

        Assert.Equal(first, user.PasswordHash);
    }

    [Fact]
    public void Without_interceptor_plaintext_would_be_stored()
    {
        // Documents why UseMasterlyHash is required: the annotation alone does nothing.
        using var db = new SqliteDb();
        using TestDbContext context = db.Create<TestDbContext>(o => new TestDbContext(o), hasher: null);
        context.Users.Add(new User { UserName = "alice", PasswordHash = Plain });
        context.SaveChanges();

        Assert.Equal(Plain, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public void Interceptor_rejects_null_arguments()
    {
        Assert.Throws<ArgumentNullException>(() => new MasterlyHashSaveChangesInterceptor(null!));
        var options = new MasterlyHashInterceptorOptions();
        options.Normalizers["x"] = null!;
        Assert.Throws<ArgumentException>(() => new MasterlyHashSaveChangesInterceptor(_hasher, null, options));
        Assert.Throws<ArgumentNullException>(() => new MasterlyHashSaveChangesInterceptor(_hasher).SavingChanges(null!, default));
    }
}
