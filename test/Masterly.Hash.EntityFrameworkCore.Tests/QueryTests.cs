using System;
using System.Linq;
using System.Threading.Tasks;
using Masterly.Hash.BlindIndex;
using Microsoft.EntityFrameworkCore;

namespace Masterly.Hash.EntityFrameworkCore.Tests;

public class QueryTests
{
    private static readonly BlindIndexOptions EmailOptions = new() { Normalizer = BlindIndexNormalizers.Email };

    private readonly PasswordHasher _hasher = TestHashers.Create();

    private static void Seed(SqliteDb db, IPasswordHasher hasher, BlindIndexer indexer, params string[] emails)
    {
        using TestDbContext context = db.Context(hasher, indexer);
        foreach (string email in emails)
            context.Users.Add(new User { UserName = email, Email = email });
        context.SaveChanges();
    }

    [Fact]
    public async Task Model_driven_query_finds_row_with_normalized_value()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        Seed(db, _hasher, indexer, "alice@example.com", "bob@example.com");

        await using TestDbContext context = db.Context(_hasher, indexer);
        User found = await context.Users.WhereBlindIndex(u => u.EmailIndex, " ALICE@example.com").SingleAsync();
        Assert.Equal("alice@example.com", found.UserName);
        Assert.Empty(context.Users.WhereBlindIndex(u => u.EmailIndex, "carol@example.com").ToList());
    }

    [Fact]
    public void Explicit_query_finds_row()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        Seed(db, _hasher, indexer, "alice@example.com", "bob@example.com");

        using TestDbContext context = db.Context(_hasher, indexer);
        User found = context.Users
            .Where(u => u.UserName != "nobody")
            .WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", "Bob@Example.com", EmailOptions)
            .Single();
        Assert.Equal("bob@example.com", found.UserName);

        // Wrong normalizer: the explicit overload trusts the caller, so the lookup misses.
        Assert.Empty(context.Users.WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", "Bob@Example.com").ToList());
    }

    [Fact]
    public void Rotation_query_finds_rows_indexed_with_an_older_key()
    {
        using var db = new SqliteDb();
        Seed(db, _hasher, TestKeys.Ring("k1", "k1"), "old@example.com");

        BlindIndexer rotated = TestKeys.Ring("k2", "k1", "k2");
        Seed(db, _hasher, rotated, "new@example.com");
        Assert.Equal(new[] { "k1", "k2" }, db.Column("SELECT EmailIndex FROM Users ORDER BY Id").Select(i => i![..2]).ToArray());

        using TestDbContext context = db.Context(_hasher, rotated);
        Assert.Equal("old@example.com", context.Users.WhereBlindIndex(u => u.EmailIndex, "old@example.com").Single().UserName);
        Assert.Equal("new@example.com", context.Users.WhereBlindIndex(u => u.EmailIndex, "new@example.com").Single().UserName);
        Assert.Equal("old@example.com", context.Users.WhereBlindIndex(u => u.EmailIndex, rotated, "users.email", "old@example.com", EmailOptions).Single().UserName);

        // Once the old key is retired, rows not yet re-indexed are no longer found.
        using TestDbContext retired = db.Context(_hasher, TestKeys.Ring("k2", "k2"));
        Assert.Empty(retired.Users.WhereBlindIndex(u => u.EmailIndex, "old@example.com").ToList());
    }

    [Fact]
    public void Query_uses_one_parameter_per_key_and_no_literals()
    {
        BlindIndexer rotated = TestKeys.Ring("k2", "k1", "k2");
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, rotated);

        string sql = context.Users.WhereBlindIndex(u => u.EmailIndex, "alice@example.com").ToQueryString();
        foreach (string candidate in rotated.ComputeAll("alice@example.com", "users.email", EmailOptions))
            Assert.Equal(1, Count(sql, candidate)); // once in the parameter declarations, never inline in the SQL
        Assert.Contains(" OR ", sql);
        Assert.DoesNotContain("json_each", sql);
        Assert.DoesNotContain("alice", sql);
    }

    [Fact]
    public void Candidates_helper_returns_current_key_first()
    {
        BlindIndexer rotated = TestKeys.Ring("k2", "k1", "k2");
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, rotated);

        var candidates = context.GetBlindIndexCandidates<User>(u => u.EmailIndex, "alice@example.com");
        Assert.Equal(rotated.ComputeAll("alice@example.com", "users.email", EmailOptions), candidates);
        Assert.StartsWith("k2:", candidates[0]);
        Assert.Empty(context.GetBlindIndexCandidates<User>(u => u.EmailIndex, ""));
    }

    [Fact]
    public void Empty_value_matches_nothing_even_rows_with_null_index()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Context(_hasher, indexer))
        {
            seed.Users.Add(new User { UserName = "no-email" });
            seed.SaveChanges();
        }

        using TestDbContext context = db.Context(_hasher, indexer);
        Assert.Empty(context.Users.WhereBlindIndex(u => u.EmailIndex, "").ToList());
        Assert.Empty(context.Users.WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", "", EmailOptions).ToList());
        Assert.Empty(context.Users.WhereBlindIndex(u => u.PhoneIndex, "( ) -").ToList());

        // A value the normalizer rejects is a caller error, as with IBlindIndexer itself.
        Assert.Throws<ArgumentException>(() => context.Users.WhereBlindIndex(u => u.EmailIndex, "  "));
    }

    [Fact]
    public void Shadow_property_selector_is_supported()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        Seed(db, _hasher, indexer, "alice@example.com");

        using TestDbContext context = db.Context(_hasher, indexer);
        Assert.Single(context.Users.WhereBlindIndex(u => EF.Property<string>(u, "EmailIndex"), "alice@example.com").ToList());
    }

    [Fact]
    public void Model_driven_query_rejects_misuse()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, indexer);

        Assert.Throws<InvalidOperationException>(() => context.Users.WhereBlindIndex(u => u.Nickname, "x"));
        Assert.Throws<ArgumentException>(() => context.Users.WhereBlindIndex(u => u.EmailIndex + "", "x"));
        Assert.Throws<ArgumentNullException>(() => context.Users.WhereBlindIndex(u => u.EmailIndex, null!));

        using TestDbContext noIndexer = db.Context(_hasher);
        Assert.Throws<InvalidOperationException>(() => noIndexer.Users.WhereBlindIndex(u => u.EmailIndex, "x"));

        using TestDbContext noInterceptor = db.Create<TestDbContext>(o => new TestDbContext(o), hasher: null);
        Assert.Throws<InvalidOperationException>(() => noInterceptor.Users.WhereBlindIndex(u => u.EmailIndex, "x"));
    }

    [Fact]
    public void Explicit_query_rejects_null_arguments()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        IQueryable<User> source = Array.Empty<User>().AsQueryable();
        Assert.Throws<ArgumentNullException>(() => source.WhereBlindIndex(null!, indexer, "users.email", "x"));
        Assert.Throws<ArgumentNullException>(() => source.WhereBlindIndex(u => u.EmailIndex, null!, "users.email", "x"));
        Assert.Throws<ArgumentNullException>(() => source.WhereBlindIndex(u => u.EmailIndex, indexer, null!, "x"));
        Assert.Throws<ArgumentNullException>(() => source.WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", null!));
        Assert.Throws<ArgumentException>(() => source.WhereBlindIndex(u => u.EmailIndex, indexer, "bad name!", "x"));
    }

    [Fact]
    public void Explicit_query_works_in_linq_to_objects()
    {
        BlindIndexer indexer = TestKeys.Ring("k2", "k1", "k2");
        var users = new[]
        {
            new User { UserName = "a", EmailIndex = indexer.ComputeWithKey("k1", "a@x.io", "users.email") },
            new User { UserName = "b", EmailIndex = indexer.Compute("b@x.io", "users.email") },
        }.AsQueryable();

        Assert.Equal("a", users.WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", "a@x.io").Single().UserName);
        Assert.Equal("b", users.WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", "b@x.io").Single().UserName);
    }

    private static int Count(string haystack, string needle)
    {
        int count = 0;
        for (int i = haystack.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = haystack.IndexOf(needle, i + 1, StringComparison.Ordinal))
            count++;
        return count;
    }
}
