using System;
using System.Linq;
using System.Threading.Tasks;
using Masterly.Hash.BlindIndex;
using Microsoft.EntityFrameworkCore;

namespace Masterly.Hash.EntityFrameworkCore.Tests;

public class BlindIndexTests
{
    private readonly PasswordHasher _hasher = TestHashers.Create();

    [Fact]
    public void Index_matches_known_answer_vector_end_to_end()
    {
        // Vector from test/Masterly.Hash.BlindIndex.Tests/KnownAnswerTests.cs, computed independently with CPython's
        // hmac module: key 0x00..0x1f, index "users.email", value "alice@example.com", 64 bits -> "k1:J11Swgv2Zu4".
        // The Email normalizer maps the mixed-case, padded input to that value first.
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, TestKeys.Kat());
        var user = new User { UserName = "alice", Email = "  Alice@Example.COM " };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.Equal("k1:J11Swgv2Zu4", user.EmailIndex);
        Assert.Equal("k1:J11Swgv2Zu4", db.Scalar("SELECT EmailIndex FROM Users"));
        Assert.Equal("  Alice@Example.COM ", user.Email);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Index_is_recomputed_when_source_changes(bool async)
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Context(_hasher, indexer))
        {
            seed.Users.Add(new User { UserName = "alice", Email = "alice@example.com", Phone = "+1 (555) 010-0000" });
            seed.SaveChanges();
        }

        using TestDbContext context = db.Context(_hasher, indexer);
        User user = context.Users.Single();
        string? phoneIndex = user.PhoneIndex;
        user.Email = "alice@new.example";
        if (async)
            await context.SaveChangesAsync();
        else
            context.SaveChanges();

        var options = new BlindIndexOptions { Normalizer = BlindIndexNormalizers.Email };
        Assert.Equal(indexer.Compute("alice@new.example", "users.email", options), user.EmailIndex);
        Assert.Equal(user.EmailIndex, db.Scalar("SELECT EmailIndex FROM Users"));
        Assert.Equal(phoneIndex, user.PhoneIndex);
    }

    [Fact]
    public void Index_uses_configured_normalizer_and_output_bits()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, indexer);
        var user = new User { UserName = "alice", Phone = "+1 (555) 010-0000" };
        context.Users.Add(user);
        context.SaveChanges();

        var options = new BlindIndexOptions { Normalizer = BlindIndexNormalizers.Phone, OutputBits = 32 };
        Assert.Equal(indexer.Compute("15550100000", "users.phone", options), user.PhoneIndex);
        Assert.True(indexer.Matches(user.PhoneIndex, "1-555-010-0000", "users.phone", options));
        Assert.True(BlindIndexer.TryGetKeyId(user.PhoneIndex, out string keyId));
        Assert.Equal("k1", keyId);
    }

    [Fact]
    public void Index_names_separate_domains()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, indexer);
        var user = new User { UserName = "x", Email = "a@b.io" };
        context.Users.Add(user);
        context.SaveChanges();

        // Same value, key, normalizer and length: only the index name differs.
        var emailOptions = new BlindIndexOptions { Normalizer = BlindIndexNormalizers.Email };
        Assert.Equal(indexer.Compute("a@b.io", "users.email", emailOptions), user.EmailIndex);
        Assert.NotEqual(indexer.Compute("a@b.io", "users.phone", emailOptions), user.EmailIndex);
    }

    [Fact]
    public void Null_or_blank_source_clears_the_index()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, indexer);
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        context.Users.Add(user);
        context.SaveChanges();
        Assert.NotNull(user.EmailIndex);

        user.Email = null;
        context.SaveChanges();
        Assert.Null(user.EmailIndex);
        Assert.Null(db.Scalar("SELECT EmailIndex FROM Users"));

        user.Email = "alice@example.com";
        context.SaveChanges();
        Assert.NotNull(user.EmailIndex);
        user.Email = "";
        context.SaveChanges();
        Assert.Null(user.EmailIndex);

        user.Phone = "() -";
        context.SaveChanges();
        Assert.Null(user.PhoneIndex); // empty after the phone normalizer strips non-digits
    }

    [Fact]
    public void Value_rejected_by_normalizer_fails_without_leaking_it()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, TestKeys.Ring("k1", "k1"));
        context.Users.Add(new User { UserName = "alice", Email = "SECRET-not-an-email" });

        var ex = Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
        Assert.DoesNotContain("SECRET", ex.ToString());
        Assert.IsAssignableFrom<ArgumentException>(ex.InnerException);
    }

    [Fact]
    public void Index_is_not_touched_when_source_is_unchanged()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Context(_hasher, indexer))
        {
            seed.Users.Add(new User { UserName = "alice", Email = "alice@example.com" });
            seed.SaveChanges();
        }

        // A new current key must not silently re-index rows that are saved for other reasons.
        using TestDbContext context = db.Context(_hasher, TestKeys.Ring("k2", "k1", "k2"));
        User user = context.Users.Single();
        string? before = user.EmailIndex;
        user.Nickname = "ally";
        context.SaveChanges();

        Assert.Equal(before, db.Scalar("SELECT EmailIndex FROM Users"));
    }

    // Regression: a direct write to the index property (mass assignment, a copied row) was saved as-is, so one row
    // could carry another row's index and be returned by a lookup for the other user's email.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Direct_write_to_the_index_is_replaced_by_the_derived_value(bool async)
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Context(_hasher, indexer))
        {
            seed.Users.AddRange(
                new User { UserName = "alice", Email = "alice@example.com" },
                new User { UserName = "mallory", Email = "mallory@example.com" });
            seed.SaveChanges();
        }

        using TestDbContext context = db.Context(_hasher, indexer);
        User alice = context.Users.Single(u => u.UserName == "alice");
        User mallory = context.Users.Single(u => u.UserName == "mallory");
        string? malloryIndex = mallory.EmailIndex;
        mallory.EmailIndex = alice.EmailIndex;
        if (async)
            await context.SaveChangesAsync();
        else
            context.SaveChanges();

        Assert.Equal(malloryIndex, mallory.EmailIndex);
        Assert.Equal(malloryIndex, db.Scalar("SELECT EmailIndex FROM Users WHERE UserName = 'mallory'"));
        using TestDbContext lookup = db.Context(_hasher, indexer);
        User found = Assert.Single(lookup.Users.WhereBlindIndex(u => u.EmailIndex, "alice@example.com").ToList());
        Assert.Equal("alice", found.UserName);
    }

    [Fact]
    public void Index_written_directly_on_insert_is_replaced_by_the_derived_value()
    {
        BlindIndexer indexer = TestKeys.Kat();
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, indexer);
        var user = new User { UserName = "x", Email = "Alice@Example.com", EmailIndex = "forged" };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.Equal("k1:J11Swgv2Zu4", user.EmailIndex); // same vector as Index_matches_known_answer_vector_end_to_end
    }

    [Fact]
    public void Marking_source_modified_reindexes_under_current_key()
    {
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Context(_hasher, TestKeys.Ring("k1", "k1")))
        {
            seed.Users.Add(new User { UserName = "alice", Email = "alice@example.com" });
            seed.SaveChanges();
        }

        BlindIndexer rotated = TestKeys.Ring("k2", "k1", "k2");
        using TestDbContext context = db.Context(_hasher, rotated);
        User user = context.Users.Single();
        Assert.True(rotated.NeedsReindex(user.EmailIndex));

        context.Entry(user).Property(u => u.Email).IsModified = true;
        context.SaveChanges();

        Assert.False(rotated.NeedsReindex(user.EmailIndex));
        Assert.StartsWith("k2:", db.Scalar("SELECT EmailIndex FROM Users"));
    }

    [Fact]
    public void Missing_indexer_fails_the_save()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, indexer: null);
        context.Users.Add(new User { UserName = "alice", Email = "alice@example.com" });

        var ex = Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
        Assert.Contains("IBlindIndexer", ex.Message);
    }

    [Fact]
    public void Missing_indexer_is_fine_when_every_indexed_value_is_null()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, indexer: null);
        var user = new User { UserName = "alice", PasswordHash = "pw-123456" };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.Null(user.EmailIndex);
        Assert.StartsWith("$mh$", user.PasswordHash);
    }

    [Fact]
    public void Invalid_utf16_source_fails_without_leaking_the_value()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, TestKeys.Ring("k1", "k1"));
        context.Users.Add(new User { UserName = "alice", Email = "SECRET\uD800@example.com" });

        var ex = Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
        Assert.DoesNotContain("SECRET", ex.ToString());
        Assert.Contains("users.email", ex.Message);
    }

    [Fact]
    public void Password_and_index_on_one_entity_are_both_processed()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, indexer);
        var user = new User { UserName = "alice", Email = "alice@example.com", PasswordHash = "pw-123456" };
        context.Users.Add(user);
        context.SaveChanges();

        Assert.True(_hasher.Verify("pw-123456", user.PasswordHash!).IsMatch);
        Assert.NotNull(user.EmailIndex);
    }
}
