using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.BlindIndex;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Masterly.Hash.EntityFrameworkCore.Tests;

internal static class TestHashers
{
    public static readonly HashProfile Fast = HashProfile.Argon2id("test", memoryKiB: 64, iterations: 1);
    public static readonly HashProfile Fast2 = HashProfile.Argon2id("test2", memoryKiB: 128, iterations: 1);

    public static PasswordHasher Create(Action<PasswordHasherOptions>? configure = null)
    {
        var options = new PasswordHasherOptions { DefaultProfile = Fast, AllowWeakProfiles = true };
        configure?.Invoke(options);
        return new PasswordHasher(options);
    }

    /// <summary>
    /// The Masterly.Hash 1.0.0 algorithm (git b71d95f..7cdefe2, SHA-512 default):
    /// <c>base64(SHA512(utf8(password) || salt) || salt)</c>.
    /// </summary>
    public static string V1Sha512(string password, byte[] salt)
    {
        byte[] data = Encoding.UTF8.GetBytes(password).Concat(salt).ToArray();
        return Convert.ToBase64String(SHA512.HashData(data).Concat(salt).ToArray());
    }
}

internal static class TestKeys
{
    /// <summary>The key 0x00..0x1f used by the Masterly.Hash.BlindIndex known-answer vectors.</summary>
    public static byte[] Sequential => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    public static byte[] Derived(string id) => SHA256.HashData(Encoding.UTF8.GetBytes("ef-blind-index-key-" + id));

    public static BlindIndexer Kat() => new("k1", Sequential);

    public static BlindIndexer Ring(string currentKeyId, params string[] keyIds) =>
        new(currentKeyId, keyIds.ToDictionary(id => id, Derived));
}

public sealed class User
{
    public int Id { get; set; }

    public string UserName { get; set; } = "";

    public string? PasswordHash { get; set; }

    public string? Email { get; set; }

    public string? EmailIndex { get; set; }

    public string? Phone { get; set; }

    public string? PhoneIndex { get; set; }

    public string? Nickname { get; set; }
}

public sealed class TestDbContext : DbContext
{
    public TestDbContext(DbContextOptions<TestDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(e =>
        {
            e.Property(u => u.PasswordHash).IsHashedPassword();
            e.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", BlindIndexNormalizers.Email);
            e.Property(u => u.Phone).HasBlindIndex(nameof(User.PhoneIndex), "users.phone", BlindIndexNormalizers.Phone, outputBits: 32);
            e.HasIndex(u => u.EmailIndex);
        });
    }
}

/// <summary>A context whose password column is a concurrency token, so the upgrade cannot overwrite a concurrent change.</summary>
public sealed class Account
{
    public int Id { get; set; }

    public string? PasswordHash { get; set; }
}

public sealed class ConcurrencyDbContext : DbContext
{
    public ConcurrencyDbContext(DbContextOptions<ConcurrencyDbContext> options) : base(options)
    {
    }

    public DbSet<Account> Accounts => Set<Account>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) =>
        modelBuilder.Entity<Account>().Property(a => a.PasswordHash).IsHashedPassword().IsConcurrencyToken();
}

/// <summary>An in-memory SQLite database that lives as long as the open connection.</summary>
internal sealed class SqliteDb : IDisposable
{
    public SqliteDb()
    {
        Connection = new SqliteConnection("DataSource=:memory:");
        Connection.Open();
    }

    public SqliteConnection Connection { get; }

    public TestDbContext Context(IPasswordHasher hasher, IBlindIndexer? indexer = null, Action<MasterlyHashInterceptorOptions>? configure = null) =>
        Create<TestDbContext>(o => new TestDbContext(o), hasher, indexer, configure);

    public TContext Create<TContext>(Func<DbContextOptions<TContext>, TContext> factory, IPasswordHasher? hasher, IBlindIndexer? indexer = null, Action<MasterlyHashInterceptorOptions>? configure = null)
        where TContext : DbContext
    {
        var builder = new DbContextOptionsBuilder<TContext>().UseSqlite(Connection);
        if (hasher != null)
            builder.UseMasterlyHash(hasher, indexer, configure);
        TContext context = factory(builder.Options);
        context.Database.EnsureCreated();
        return context;
    }

    /// <summary>Reads a column bypassing EF Core, to prove what actually reached the database.</summary>
    public string? Scalar(string sql)
    {
        using SqliteCommand command = Connection.CreateCommand();
        command.CommandText = sql;
        object? value = command.ExecuteScalar();
        return value is DBNull ? null : (string?)value;
    }

    public List<string?> Column(string sql)
    {
        using SqliteCommand command = Connection.CreateCommand();
        command.CommandText = sql;
        using SqliteDataReader reader = command.ExecuteReader();
        var values = new List<string?>();
        while (reader.Read())
            values.Add(reader.IsDBNull(0) ? null : reader.GetString(0));
        return values;
    }

    public void Execute(string sql, params (string Name, object? Value)[] parameters)
    {
        using SqliteCommand command = Connection.CreateCommand();
        command.CommandText = sql;
        foreach ((string name, object? value) in parameters)
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    public void Dispose() => Connection.Dispose();
}

public sealed class Member
{
    public int Id { get; set; }

    public Credentials Credentials { get; set; } = new();
}

public sealed class Credentials
{
    public string? PasswordHash { get; set; }

    public string? RecoveryEmail { get; set; }

    public string? RecoveryEmailIndex { get; set; }
}

/// <summary>Annotated properties on an owned type.</summary>
public sealed class OwnedDbContext : DbContext
{
    public OwnedDbContext(DbContextOptions<OwnedDbContext> options) : base(options)
    {
    }

    public DbSet<Member> Members => Set<Member>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) =>
        modelBuilder.Entity<Member>().OwnsOne(m => m.Credentials, c =>
        {
            c.Property(x => x.PasswordHash).IsHashedPassword();
            c.Property(x => x.RecoveryEmail).HasBlindIndex(nameof(Credentials.RecoveryEmailIndex), "members.recovery_email", BlindIndexNormalizers.Email);
        });
}
