---
title: Real-World Examples
sidebar_label: Examples
description: Complete recipes that combine the packages the way an application does, from sign-up and login to legacy migration, API keys, pepper rotation, audit logs and honeywords.
---

Each recipe below is a complete feature: the package list, the registration code and the endpoint or service that uses it. The types the recipes call your own (such as `IUserRepository` or `ICheckpointStore`) stand in for your data access and infrastructure. Everything that comes from Masterly.Hash is the real API.

The recipes build on each other in places. Recipe 1 defines `IUserRepository` and the request records, and later recipes reuse them.

| Recipe | Packages |
|---|---|
| [1. Sign-up and login with minimal APIs](#1-sign-up-and-login-with-minimal-apis) | `Masterly.Hash`, `Masterly.Hash.DependencyInjection`, `Masterly.Hash.AspNetCore` |
| [2. Migrating a WordPress user table](#2-migrating-a-wordpress-user-table) | `Masterly.Hash`, `Masterly.Hash.Legacy` |
| [3. ASP.NET Core Identity drop-in](#3-aspnet-core-identity-drop-in) | `Masterly.Hash.AspNetCore` |
| [4. EF Core entity with a hashed password and a blind-indexed email](#4-ef-core-entity-with-a-hashed-password-and-a-blind-indexed-email) | `Masterly.Hash.EntityFrameworkCore`, `Masterly.Hash.DependencyInjection` |
| [5. Issuing and verifying API keys](#5-issuing-and-verifying-api-keys) | `Masterly.Hash.Tokens` |
| [6. Rotating a pepper key](#6-rotating-a-pepper-key) | `Masterly.Hash.DependencyInjection` |
| [7. Password change with policy and breach check](#7-password-change-with-policy-and-breach-check) | `Masterly.Hash.Policy`, `Masterly.Hash.Pwned` |
| [8. Password reset with a single-use signed link](#8-password-reset-with-a-single-use-signed-link) | `Masterly.Hash.Tokens`, `Masterly.Hash.Policy` |
| [9. Tamper-evident audit log](#9-tamper-evident-audit-log) | `Masterly.Hash.Integrity` |
| [10. Honeywords and honey accounts](#10-honeywords-and-honey-accounts) | `Masterly.Hash.Detection` |

## 1. Sign-up and login with minimal APIs

This is the baseline every other recipe extends: one singleton hasher from configuration, a 503 when the hasher is saturated, a 400 for over-long passwords before any hashing, rate limiting on the auth endpoints, user-enumeration protection at login and upgrade on login.

```
dotnet add package Masterly.Hash.DependencyInjection
dotnet add package Masterly.Hash.AspNetCore
```

**1. Configure the hasher.** Every key under `MasterlyHash` is optional. Unknown or misspelled keys, unknown profile ids and out-of-range values stop the application at startup.

```json title="appsettings.json"
{
  "MasterlyHash": {
    "DefaultProfile": "2026a",
    "MaxConcurrency": 8,
    "ConcurrencyTimeout": "00:00:05"
  }
}
```

With profile `2026a` (Argon2id, 64 MiB per hash) and `MaxConcurrency` 8, at most 512 MiB is spent on hashing at any moment. A call that waits longer than `ConcurrencyTimeout` for a slot throws `PasswordHasherBusyException`. The defaults are the processor count and 30 seconds.

**2. Define the contracts.** Password fields are `SensitiveString`: `ToString()`, the debugger and JSON serialization all show `***`, while JSON deserialization reads the real value.

```csharp title="Contracts.cs"
using Masterly.Hash;

namespace Contoso.Accounts;

public sealed record RegisterRequest(string Email, SensitiveString Password);

public sealed record LoginRequest(string Email, SensitiveString Password);

public sealed record UserAccount(string Id, string Email, string UserName, string DisplayName, string? PasswordHash);

/// <summary>Your data access. Every method is a single parameterized query.</summary>
public interface IUserRepository
{
    Task<UserAccount?> FindByEmailAsync(string email, CancellationToken cancellationToken);

    Task<UserAccount?> FindByIdAsync(string id, CancellationToken cancellationToken);

    Task<bool> ExistsAsync(string email, CancellationToken cancellationToken);

    Task<UserAccount> CreateAsync(string email, string passwordHash, CancellationToken cancellationToken);

    /// <summary>
    /// UPDATE users SET password_hash = @newHash WHERE id = @id AND password_hash = @expectedHash.
    /// Returns false when the row no longer holds expectedHash, so a concurrent change is never overwritten.
    /// </summary>
    Task<bool> ReplacePasswordHashAsync(string id, string expectedHash, string newHash, CancellationToken cancellationToken);
}
```

**3. Wire up the application.**

```csharp title="Program.cs"
using System.Security.Claims;
using System.Threading.RateLimiting;
using Contoso.Accounts;
using Masterly.Hash;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));
builder.Services.AddProblemDetails();                  // required by UseExceptionHandler() on .NET 8
builder.Services.AddMasterlyHashExceptionHandler();    // PasswordHasherBusyException -> 503 + Retry-After
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth", httpContext => RateLimitPartition.GetFixedWindowLimiter(
        httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1) }));
});
builder.Services.AddScoped<IUserRepository, SqlUserRepository>();   // your implementation

WebApplication app = builder.Build();

app.UseExceptionHandler();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

RouteGroupBuilder auth = app.MapGroup("/api/v1")
    .RequireRateLimiting("auth")
    .WithPasswordLengthLimit();                         // 400 before the handler for passwords over MaxPasswordBytes

auth.MapPost("/users", async (RegisterRequest request, IUserRepository users, IPasswordHasher hasher, CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || request.Password is null || request.Password.IsEmpty)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["request"] = new[] { "An email address and a password are required." },
        });
    }

    if (await users.ExistsAsync(request.Email, cancellationToken))
    {
        return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "An account with this email address already exists.");
    }

    string passwordHash = await hasher.HashAsync(request.Password, cancellationToken);
    UserAccount user = await users.CreateAsync(request.Email, passwordHash, cancellationToken);
    return Results.Created($"/api/v1/users/{user.Id}", new { user.Id, user.Email });
});

auth.MapPost("/sessions", async (
    LoginRequest request,
    HttpContext httpContext,
    IUserRepository users,
    IPasswordHasher hasher,
    ILogger<Program> logger,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || request.Password is null)
    {
        return Results.Unauthorized();
    }

    UserAccount? user = await users.FindByEmailAsync(request.Email, cancellationToken);

    // For an unknown user (null stored hash) this still runs a full verification against a dummy hash.
    PasswordVerificationResult result = await hasher.VerifyOrDummyAsync(request.Password, user?.PasswordHash, cancellationToken);
    if (!result.IsMatch || user is null)
    {
        logger.LogInformation("Login failed: {FailureReason}", result.FailureReason);
        return Results.Unauthorized();
    }

    // Set only when the stored hash is outdated: 1.x, legacy, wrapped, older profile or older pepper key.
    if (result.Rehash is string freshHash && user.PasswordHash is string currentHash)
    {
        bool upgraded = await users.ReplacePasswordHashAsync(user.Id, currentHash, freshHash, cancellationToken);
        logger.LogInformation("Password hash upgrade for {UserId}: {RehashReason}, stored {Upgraded}", user.Id, result.RehashReason, upgraded);
    }

    ClaimsIdentity identity = new ClaimsIdentity(
        new[] { new Claim(ClaimTypes.NameIdentifier, user.Id) },
        CookieAuthenticationDefaults.AuthenticationScheme);
    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    return Results.NoContent();
});

app.Run();
```

What happens:

- `AddMasterlyHash` registers `PasswordHasher` and `IPasswordHasher` as one singleton. On hosts built with Microsoft.Extensions.Hosting 8.0 or later the options are validated at startup.
- `.WithPasswordLengthLimit()` checks every `SensitiveString` argument and every public `SensitiveString` property of an argument (one level deep) against `MaxPasswordBytes` (default 1024 UTF-8 bytes after NFKC). A value longer than 8 times the limit is rejected from its length alone.
- Every failed login returns the same 401. `FailureReason` (`Mismatch`, `NoStoredHash`, `UnknownFormat`, `UnknownPepperKey` and so on) goes to the log only; it is never meant for the end user.
- The upgrade is a compare-and-swap. If the user changed their password while this login was verifying, `ReplacePasswordHashAsync` returns false and the newer hash stays.

:::note

Answering 409 on sign-up tells a caller that the address is registered. If that matters for your application, accept the request, return the same response either way and send the existing user an email instead. See [User Enumeration](./user-enumeration.md).

:::

`HashAsync` throws `ArgumentException` for an empty password, a password over `MaxPasswordBytes`, or a password with an unpaired surrogate. The handler above rules out the first two. JSON can carry the third (`"\ud800"`), so either validate it or let it surface as a 500.

## 2. Migrating a WordPress user table

WordPress stores `$P$` phpass hashes (iterated MD5), `$wp$2y$` hashes (WordPress 6.8 and later) and, with some plugins, plain bcrypt. This recipe moves a WordPress user table into a .NET application in three steps: audit the table, onion-wrap every weak hash offline, then verify and upgrade at login.

```
dotnet add package Masterly.Hash.Legacy
dotnet add package MySqlConnector
```

**1. Build a hasher that knows the WordPress formats.** Use the same registration in the migration tool and in the application, so both classify hashes the same way.

```csharp title="WordPressHasher.cs"
using Masterly.Hash;
using Masterly.Hash.Legacy;

namespace Contoso.Migration;

public static class WordPressHasher
{
    public static PasswordHasherOptions Configure(PasswordHasherOptions options) =>
        options.AddLegacyFormats(PhpassFormat.Default, WordPressBcryptFormat.Default, BCryptFormat.Default);
}
```

`AddLegacyFormats` inserts the formats ahead of the built-in 1.x format, so `Inspect` and `TryWrap` pick the precise format. The default cost caps are a phpass log2 count of 18 (`PhpassFormat.DefaultMaxCostLog2`) and a bcrypt cost of 15 (`BCryptFormat.DefaultMaxCost`). A hash above its cap is not handled and reports as an unknown format.

**2. Audit, then wrap.** The tool below reads `wp_users` in keyset-paginated batches. `TryWrap` computes Argon2id over the legacy digest, so it needs no password, and it returns false for values that are already `$mh$` hashes, so the tool can be re-run safely.

```csharp title="Program.cs"
using System.Data.Common;
using Contoso.Migration;
using Masterly.Hash;
using Masterly.Hash.Legacy;
using MySqlConnector;

const int BatchSize = 500;

string connectionString = Environment.GetEnvironmentVariable("WORDPRESS_DB")
    ?? throw new InvalidOperationException("Set WORDPRESS_DB to the WordPress connection string.");
PasswordHasher hasher = new PasswordHasher(WordPressHasher.Configure(new PasswordHasherOptions()));

await using MySqlConnection connection = new MySqlConnection(connectionString);
await connection.OpenAsync();

// Step 1: report what the table holds. Nothing is verified and no password is needed.
HashAuditReport before = HashAudit.Audit(hasher, await ReadAllHashesAsync(connection));
Console.WriteLine(before.ToMarkdown());

// Step 2: wrap every weak hash.
int wrapped = 0;
ulong lastId = 0;
while (true)
{
    List<WordPressUser> batch = await ReadBatchAsync(connection, lastId, BatchSize);
    if (batch.Count == 0)
    {
        break;
    }

    lastId = batch[^1].Id;
    WordPressUser[] candidates = batch
        .Where(user => HashAudit.IsWeak(hasher.Inspect(user.PasswordHash).Format, user.PasswordHash))
        .ToArray();

    // TryWrap is synchronous and costs one Argon2id run (64 MiB) each; the hasher's concurrency gate bounds memory.
    string?[] replacements = new string?[candidates.Length];
    Parallel.For(0, candidates.Length, i =>
    {
        replacements[i] = hasher.TryWrap(candidates[i].PasswordHash, out string wrappedHash) ? wrappedHash : null;
    });

    for (int i = 0; i < candidates.Length; i++)
    {
        if (replacements[i] is string replacement)
        {
            wrapped += await ReplaceHashAsync(connection, candidates[i], replacement);
        }
    }
}

Console.WriteLine($"Wrapped {wrapped} hashes.");
Console.WriteLine(HashAudit.Audit(hasher, await ReadAllHashesAsync(connection)).ToMarkdown());

static async Task<List<string?>> ReadAllHashesAsync(DbConnection connection)
{
    List<string?> hashes = new List<string?>();
    await using DbCommand command = connection.CreateCommand();
    command.CommandText = "SELECT user_pass FROM wp_users";
    await using DbDataReader reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        hashes.Add(reader.IsDBNull(0) ? null : reader.GetString(0));
    }

    return hashes;
}

static async Task<List<WordPressUser>> ReadBatchAsync(DbConnection connection, ulong afterId, int batchSize)
{
    List<WordPressUser> batch = new List<WordPressUser>(batchSize);
    await using DbCommand command = connection.CreateCommand();
    command.CommandText = "SELECT ID, user_pass FROM wp_users WHERE ID > @afterId ORDER BY ID LIMIT @batchSize";
    AddParameter(command, "@afterId", afterId);
    AddParameter(command, "@batchSize", batchSize);
    await using DbDataReader reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        batch.Add(new WordPressUser(Convert.ToUInt64(reader.GetValue(0)), reader.GetString(1)));
    }

    return batch;
}

static async Task<int> ReplaceHashAsync(DbConnection connection, WordPressUser user, string wrappedHash)
{
    await using DbCommand command = connection.CreateCommand();
    // Only replace the value that was read: a row changed since then is left alone.
    command.CommandText = "UPDATE wp_users SET user_pass = @wrapped WHERE ID = @id AND user_pass = @original";
    AddParameter(command, "@wrapped", wrappedHash);
    AddParameter(command, "@id", user.Id);
    AddParameter(command, "@original", user.PasswordHash);
    return await command.ExecuteNonQueryAsync();
}

static void AddParameter(DbCommand command, string name, object value)
{
    DbParameter parameter = command.CreateParameter();
    parameter.ParameterName = name;
    parameter.Value = value;
    command.Parameters.Add(parameter);
}

internal sealed record WordPressUser(ulong Id, string PasswordHash);
```

The audit reads the whole column into memory for brevity. For a large table, stream it: `HashAudit.Audit` enumerates its input once and keeps only a 128-bit fingerprint per distinct hash (about 40 bytes each).

`HashAudit.IsWeak` counts phpass, unsalted digests, Masterly.Hash 1.x, ASP.NET Identity v2, bcrypt below cost 10 (`HashAudit.WeakBCryptCostBelow`) and PBKDF2 below 100,000 iterations (`HashAudit.WeakPbkdf2IterationsBelow`) as weak. Strong bcrypt hashes are left as they are and upgrade at login.

A wrapped hash looks like `$mh$p=2026a,w=phpass,wp=<base64>$<salt>$<tag>`. Under the default `2026a` profile a wrapped phpass hash is 107 characters and a wrapped bcrypt hash 130; a pepper adds `,k=` plus the key id, and the `2026f` profile's 64-byte tag adds 43. The longest case, a `$wp$2y$` hash wrapped under `2026f` with a 32-character pepper key id, is 218 characters, so every wrapped hash fits the `varchar(255)` `user_pass` column.

**3. Log users in from the .NET application.** Register the same formats on the application's hasher and use the login endpoint from recipe 1 unchanged.

```csharp title="Program.cs"
builder.Services
    .AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"))
    .Configure(options => WordPressHasher.Configure(options));
```

At each successful login `VerifyOrDummyAsync` returns `SuccessRehashNeeded` with `RehashReason.Wrapped` (or `LegacyFormat` for a hash that was not wrapped) and a fresh `Rehash`, which recipe 1 stores.

:::warning

Wrap only after the .NET application owns logins. WordPress cannot read `$mh$` hashes, so a wrapped user can no longer log in through WordPress itself. Keep the legacy formats registered until `HashAuditReport.Wrapped` and the per-format counts reach zero: a wrapped hash names its format (`w=phpass`) and does not verify if that format is not registered.

:::

The `masterly-hash wrap` command does the same job on a CSV export (`masterly-hash wrap users.csv users-wrapped.csv --column 3 --header`), streaming the file and writing the output atomically. The tool never holds a pepper, so use the library, as above, when the application has one. See [Command-Line Tool](./command-line-tool.md).

## 3. ASP.NET Core Identity drop-in

`AddMasterlyPasswordHasher` replaces Identity's `IPasswordHasher<TUser>`. Users keep logging in with the hashes Identity already wrote (v2 and v3 compatibility modes), and `UserManager` replaces each of them with Argon2id at that user's next successful login. Nothing else in Identity changes.

```
dotnet add package Masterly.Hash.AspNetCore
```

```csharp title="Program.cs"
using Contoso.Identity;
using Masterly.Hash;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

string connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("ConnectionStrings:Default is missing.");

builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlServer(connectionString));

builder.Services
    .AddIdentity<AppUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders()
    .AddMasterlyPasswordHasher(options =>
    {
        options.MaxConcurrency = 8;
    });

builder.Services.AddProblemDetails();
builder.Services.AddMasterlyHashExceptionHandler(options => options.RetryAfter = TimeSpan.FromSeconds(10));

WebApplication app = builder.Build();

app.UseExceptionHandler();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/v1/sessions", async (IdentityLoginRequest request, SignInManager<AppUser> signInManager) =>
{
    if (string.IsNullOrWhiteSpace(request.UserName) || request.Password is null)
    {
        return Results.Unauthorized();
    }

    SignInResult result = await signInManager.PasswordSignInAsync(
        request.UserName, request.Password.Reveal(), isPersistent: false, lockoutOnFailure: true);
    return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
})
.WithPasswordLengthLimit();

app.Run();
```

```csharp title="IdentityLoginRequest.cs"
using Masterly.Hash;

namespace Contoso.Identity;

public sealed record IdentityLoginRequest(string UserName, SensitiveString Password);
```

`AppUser` (an `IdentityUser`) and `AppDbContext` (an `IdentityDbContext<AppUser>`) are your existing Identity types. Login, registration and password changes keep going through `SignInManager` and `UserManager`.

`AddMasterlyPasswordHasher` does five things:

1. Calls `AddMasterlyHash`, so Identity shares the application's one `IPasswordHasher` singleton and its startup validation. Configuration bound with `AddMasterlyHash(IConfiguration)` is applied first.
2. Sets `ComputeRehashOnVerify` to `false`. `UserManager` re-hashes on `SuccessRehashNeeded` itself, so a second hash would be wasted. Your `configure` step runs after this.
3. Lowers `ConcurrencyTimeout` from the core default of 30 seconds to 2 seconds (`IdentityConcurrencyTimeout`) if you left it at the default. Identity's hasher interface is synchronous, so a queued login blocks a thread-pool thread; a short wait turns a flood into fast 503s instead of thread-pool starvation.
4. Registers `AspNetIdentityV3Format` and `AspNetIdentityV2Format` unless formats with those ids are already registered.
5. Adds `MasterlyPasswordLengthValidator<TUser>`, so `CreateAsync`, `AddPasswordAsync`, `ChangePasswordAsync` and `ResetPasswordAsync` return a failed `IdentityResult` with code `PasswordTooLong` (or `PasswordRequired`) instead of throwing from the hasher.

:::note

`Masterly.Hash` and `Microsoft.AspNetCore.Identity` both define `PasswordHasherOptions` and `PasswordVerificationResult`. A file that imports both namespaces cannot name either type without an alias, for example `using MasterlyOptions = Masterly.Hash.PasswordHasherOptions;`. The code above never names them, so it needs no alias.

:::

**Protect dormant accounts.** Identity v2 hashes are PBKDF2-HMAC-SHA1 with 1,000 iterations, and an account that never logs in keeps its hash. This job onion-wraps weak Identity hashes in place. The wrapped hashes still verify through the adapter and are replaced on the next login.

```csharp title="IdentityHashWrapper.cs"
using Masterly.Hash;
using Masterly.Hash.Legacy;
using Microsoft.EntityFrameworkCore;

namespace Contoso.Identity;

public sealed class IdentityHashWrapper
{
    private const int BatchSize = 500;
    private const string NativePrefix = "$mh$";

    private readonly AppDbContext _db;
    private readonly PasswordHasher _hasher;
    private readonly ILogger<IdentityHashWrapper> _logger;

    public IdentityHashWrapper(AppDbContext db, PasswordHasher hasher, ILogger<IdentityHashWrapper> logger)
    {
        _db = db;
        _hasher = hasher;
        _logger = logger;
    }

    public async Task<int> WrapWeakHashesAsync(CancellationToken cancellationToken)
    {
        int wrapped = 0;
        string lastId = string.Empty;
        while (true)
        {
            List<StoredHash> batch = await _db.Users
                .AsNoTracking()
                .Where(user => string.Compare(user.Id, lastId) > 0 && user.PasswordHash != null && !user.PasswordHash.StartsWith(NativePrefix))
                .OrderBy(user => user.Id)
                .Take(BatchSize)
                .Select(user => new StoredHash(user.Id, user.PasswordHash ?? string.Empty))
                .ToListAsync(cancellationToken);
            if (batch.Count == 0)
            {
                break;
            }

            lastId = batch[^1].UserId;
            foreach (StoredHash row in batch)
            {
                HashInfo info = _hasher.Inspect(row.Hash);
                if (!HashAudit.IsWeak(info.Format, row.Hash) || !_hasher.TryWrap(row.Hash, out string wrappedHash))
                {
                    continue;
                }

                // Compare-and-swap: a hash that changed since it was read is left alone.
                wrapped += await _db.Users
                    .Where(user => user.Id == row.UserId && user.PasswordHash == row.Hash)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(user => user.PasswordHash, wrappedHash), cancellationToken);
            }
        }

        _logger.LogInformation("Onion-wrapped {Count} weak Identity password hashes", wrapped);
        return wrapped;
    }

    private sealed record StoredHash(string UserId, string Hash);
}
```

`PasswordHasher` is the same singleton the adapter uses, so it already has the Identity formats registered. The default v3 format refuses stored hashes above 10,000,000 PBKDF2 iterations (`AspNetIdentityV3Format.DefaultMaxIterations`). If you never raised Identity's iteration count, register a tighter cap inside the `configure` step: `options.AddLegacyFormats(new AspNetIdentityV3Format(1_000_000))`. Register custom Identity formats there, not through the `MasterlyHashBuilder`, or startup validation reports a duplicate format id.

## 4. EF Core entity with a hashed password and a blind-indexed email

The EF Core interceptor hashes a password property on `SaveChanges` and keeps a blind index of the email column up to date, so the email can be stored encrypted and still be looked up by equality.

```
dotnet add package Masterly.Hash.EntityFrameworkCore
dotnet add package Masterly.Hash.DependencyInjection
```

**1. Model the entity.** `PasswordHash` holds the plaintext from assignment until `SaveChanges`, then the hash. `EmailIndex` is written by the interceptor.

```csharp title="AppDbContext.cs"
using Masterly.Hash.BlindIndex;
using Masterly.Hash.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Contoso.Data;

public sealed class User
{
    public Guid Id { get; set; }

    /// <summary>Assign the plaintext; after SaveChanges it holds "$mh$p=2026a$...".</summary>
    public string? PasswordHash { get; set; }

    /// <summary>Encrypt this column with your own value converter or database encryption.</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>Maintained by the interceptor. Never write it yourself.</summary>
    public string? EmailIndex { get; set; }
}

public sealed class AppDbContext : DbContext
{
    public const string EmailIndexName = "users.email";

    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.Property(user => user.PasswordHash).IsHashedPassword();
            entity.Property(user => user.Email).HasBlindIndex(nameof(User.EmailIndex), EmailIndexName, BlindIndexNormalizers.Email);
            entity.HasIndex(user => user.EmailIndex);
        });
    }
}
```

**2. Register one hasher, one indexer and one interceptor.** The interceptor is thread-safe and caches a plan per entity type, so register a single instance and add it to every context.

```json title="appsettings.json"
{
  "BlindIndex": {
    "CurrentKeyId": "bi1",
    "Keys": { "bi1": "<base64 of 32 random bytes, from your secret store>" }
  }
}
```

```csharp title="Program.cs"
using System.Net.Mail;
using Contoso.Accounts;
using Contoso.Data;
using Masterly.Hash;
using Masterly.Hash.BlindIndex;
using Masterly.Hash.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

KeyRingSettings blindIndexKeys = builder.Configuration.GetSection("BlindIndex").Get<KeyRingSettings>()
    ?? throw new InvalidOperationException("The BlindIndex section is missing.");
string connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("ConnectionStrings:Default is missing.");

builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));
builder.Services.AddSingleton<IBlindIndexer>(BlindIndexer.FromBase64(blindIndexKeys.CurrentKeyId, blindIndexKeys.Keys));
builder.Services.AddSingleton(provider => new MasterlyHashSaveChangesInterceptor(
    provider.GetRequiredService<IPasswordHasher>(),
    provider.GetRequiredService<IBlindIndexer>()));
builder.Services.AddDbContext<AppDbContext>((provider, options) => options
    .UseSqlServer(connectionString)
    .AddInterceptors(provider.GetRequiredService<MasterlyHashSaveChangesInterceptor>()));
```

```csharp title="KeyRingSettings.cs"
namespace Contoso.Data;

public sealed class KeyRingSettings
{
    public string CurrentKeyId { get; set; } = string.Empty;

    public Dictionary<string, string> Keys { get; set; } = new Dictionary<string, string>(StringComparer.Ordinal);
}
```

For a single context without dependency injection, `options.UseMasterlyHash(hasher, indexer)` creates and adds the interceptor in one call.

**3. Sign up and log in.**

```csharp title="Program.cs (continued)"
const int MaxIndexCandidates = 10;

WebApplication app = builder.Build();

app.MapPost("/api/v1/users", async (RegisterRequest request, AppDbContext db, CancellationToken cancellationToken) =>
{
    if (!MailAddress.TryCreate(request.Email, out _) || request.Password is null || request.Password.IsEmpty)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["request"] = new[] { "A valid email address and a password are required." },
        });
    }

    if (await db.Users.WhereBlindIndex(user => user.EmailIndex, request.Email).AnyAsync(cancellationToken))
    {
        return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "An account with this email address already exists.");
    }

    User user = new User { Id = Guid.NewGuid(), Email = request.Email, PasswordHash = request.Password.Reveal() };
    db.Users.Add(user);
    await db.SaveChangesAsync(cancellationToken);   // hashes PasswordHash with HashAsync and writes EmailIndex

    return Results.Created($"/api/v1/users/{user.Id}", new { user.Id });
})
.WithPasswordLengthLimit();

app.MapPost("/api/v1/sessions", async (LoginRequest request, AppDbContext db, IPasswordHasher hasher, CancellationToken cancellationToken) =>
{
    if (!MailAddress.TryCreate(request.Email, out _) || request.Password is null)
    {
        return Results.Unauthorized();
    }

    // The index is a truncated HMAC: rule out rare false positives by comparing the decrypted value.
    string normalizedEmail = BlindIndexNormalizers.Email.Normalize(request.Email);
    List<User> candidates = await db.Users
        .WhereBlindIndex(user => user.EmailIndex, request.Email)
        .Take(MaxIndexCandidates)
        .ToListAsync(cancellationToken);
    User? user = candidates.FirstOrDefault(candidate => BlindIndexNormalizers.Email.Normalize(candidate.Email) == normalizedEmail);

    string password = request.Password.Reveal();
    PasswordVerificationResult result = user is null
        ? await hasher.VerifyOrDummyAsync(password, null, cancellationToken)
        : await db.VerifyAndUpgradeAsync(user, candidate => candidate.PasswordHash, password, cancellationToken);

    return result.IsMatch ? Results.NoContent() : Results.Unauthorized();   // issue your cookie or token here
})
.WithPasswordLengthLimit();

app.Run();
```

`RegisterRequest` and `LoginRequest` are the records from recipe 1. What happens:

- `WhereBlindIndex` on a `DbSet` reads the index name, normalizer and length from the model and matches the index under every key in the ring, so rows written under an older key are still found during rotation.
- `BlindIndexNormalizers.Email` applies NFKC, trims and lower-cases, so `Ann@Example.COM` and `ann@example.com` share an index. It throws `ArgumentException` for a value without `@` or with an empty local part or domain, which is why the endpoints validate the address first.
- `VerifyAndUpgradeAsync` verifies, and when the hash is outdated writes `Rehash` and calls `SaveChangesAsync`. It re-reads the row first and skips the upgrade if a password reset committed meanwhile. Make `PasswordHash` (or a row version) a concurrency token to close the remaining window between that read and the `UPDATE`.

:::warning

`ExecuteUpdate`, raw SQL and bulk-insert libraries skip the interceptor and write plaintext as-is. Hash explicitly with `hasher.HashAsync(...)` on those paths. Also keep the blind-index keys out of the database and separate from any pepper key: blind indexes reveal which rows share a value.

:::

**Rotating the blind-index key.** Add the new key to `Keys`, make it `CurrentKeyId` and keep the old one. Lookups keep working. Re-index rows in batches by marking the source property modified; the interceptor writes a fresh index. Stored indexes have the form `<keyId>:<base64>`, so the old rows are easy to find:

```csharp title="ReindexEmails.cs"
List<User> stale = await db.Users
    .Where(user => user.EmailIndex != null && user.EmailIndex.StartsWith("bi1:"))
    .Take(500)
    .ToListAsync(cancellationToken);
foreach (User user in stale)
{
    db.Entry(user).Property(entity => entity.Email).IsModified = true;
}

await db.SaveChangesAsync(cancellationToken);
```

Remove the old key only when no row uses it any more.

## 5. Issuing and verifying API keys

API keys are high-entropy, so they need a fast keyed hash, not Argon2id. `ApiKeyHasher` stores an HMAC-SHA256 lookup hash that can sit in a unique index, and the key format carries a CRC-32 checksum that rejects typos without a database round trip.

```
dotnet add package Masterly.Hash.Tokens
```

**1. Store only the lookup hash.**

```csharp title="ApiKeyRecord.cs"
namespace Contoso.ApiKeys;

public sealed class ApiKeyRecord
{
    public Guid Id { get; set; }

    public string OwnerId { get; set; } = string.Empty;

    /// <summary>"&lt;keyId&gt;:&lt;base64 HMAC&gt;". Give it a unique index.</summary>
    public string LookupHash { get; set; } = string.Empty;

    /// <summary>"acme_live_...wXyZ", safe to show in a key list.</summary>
    public string Hint { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }
}
```

In `OnModelCreating`: `modelBuilder.Entity<ApiKeyRecord>().HasIndex(key => key.LookupHash).IsUnique();`

**2. Register the hasher and the generator.** The ring keys live outside the database. Each must be at least 32 bytes (`HmacKeyRing.MinKeyLength`); `masterly-hash apikey generate --prefix acme_live` prints a new key together with a fresh lookup key.

```csharp title="Program.cs"
using System.Security.Claims;
using Contoso.ApiKeys;
using Contoso.Data;
using Masterly.Hash.Tokens;
using Microsoft.EntityFrameworkCore;

KeyRingSettings apiKeyRing = builder.Configuration.GetSection("ApiKeys").Get<KeyRingSettings>()
    ?? throw new InvalidOperationException("The ApiKeys section is missing.");

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(new ApiKeyHasher(HmacKeyRing.FromBase64(apiKeyRing.CurrentKeyId, apiKeyRing.Keys)));
builder.Services.AddSingleton(provider => new ApiKeyGenerator(provider.GetRequiredService<ApiKeyHasher>(), "acme_live"));
builder.Services.AddScoped<ApiKeyAuthenticator>();
```

`KeyRingSettings` is the class from recipe 4, and `AppDbContext` gets a `DbSet<ApiKeyRecord> ApiKeys`. A prefix is 1 to 32 ASCII letters, digits and single underscores, starting with a letter and not ending with an underscore.

**3. Authenticate requests.**

```csharp title="ApiKeyAuthenticator.cs"
using Contoso.Data;
using Masterly.Hash.Tokens;
using Microsoft.EntityFrameworkCore;

namespace Contoso.ApiKeys;

public sealed class ApiKeyAuthenticator
{
    private readonly AppDbContext _db;
    private readonly ApiKeyHasher _hasher;

    public ApiKeyAuthenticator(AppDbContext db, ApiKeyHasher hasher)
    {
        _db = db;
        _hasher = hasher;
    }

    public async Task<ApiKeyRecord?> AuthenticateAsync(string? presentedKey, CancellationToken cancellationToken)
    {
        // Offline: rejects garbage, typos and over-long input without touching the database.
        if (presentedKey is null || !ApiKey.HasValidChecksum(presentedKey))
        {
            return null;
        }

        // One lookup hash per ring key (current first), so keys hashed before a rotation are still found.
        IReadOnlyList<string> lookupHashes = _hasher.ComputeAllLookupHashes(presentedKey);
        ApiKeyRecord? record = await _db.ApiKeys
            .SingleOrDefaultAsync(key => lookupHashes.Contains(key.LookupHash) && key.RevokedAt == null, cancellationToken);
        if (record is null || !_hasher.Verify(presentedKey, record.LookupHash))
        {
            return null;
        }

        if (_hasher.NeedsRehash(record.LookupHash))
        {
            record.LookupHash = _hasher.ComputeLookupHash(presentedKey);   // migrate to the current ring key
            await _db.SaveChangesAsync(cancellationToken);
        }

        return record;
    }
}
```

```csharp title="ApiKeyEndpointFilter.cs"
namespace Contoso.ApiKeys;

public sealed class ApiKeyEndpointFilter : IEndpointFilter
{
    public const string HeaderName = "X-Api-Key";
    public const string ItemKey = "ApiKeyRecord";

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        HttpContext httpContext = context.HttpContext;
        ApiKeyAuthenticator authenticator = httpContext.RequestServices.GetRequiredService<ApiKeyAuthenticator>();
        string? presentedKey = httpContext.Request.Headers[HeaderName];

        ApiKeyRecord? record = await authenticator.AuthenticateAsync(presentedKey, httpContext.RequestAborted);
        if (record is null)
        {
            return Results.Unauthorized();
        }

        httpContext.Items[ItemKey] = record;
        return await next(context);
    }
}
```

**4. Issue, use and revoke keys.**

```csharp title="Program.cs (continued)"
app.MapPost("/api/v1/api-keys", async (ClaimsPrincipal principal, ApiKeyGenerator generator, AppDbContext db, TimeProvider clock, CancellationToken cancellationToken) =>
{
    string? ownerId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
    if (ownerId is null)
    {
        return Results.Unauthorized();
    }

    GeneratedApiKey created = generator.Generate();
    ApiKeyRecord record = new ApiKeyRecord
    {
        Id = Guid.NewGuid(),
        OwnerId = ownerId,
        LookupHash = created.LookupHash,
        Hint = created.Hint,
        CreatedAt = clock.GetUtcNow(),
    };
    db.ApiKeys.Add(record);
    await db.SaveChangesAsync(cancellationToken);

    // The only time the plaintext is ever returned.
    return Results.Created($"/api/v1/api-keys/{record.Id}", new { record.Id, apiKey = created.PlainText, record.Hint });
})
.RequireAuthorization();

app.MapDelete("/api/v1/api-keys/{id:guid}", async (Guid id, ClaimsPrincipal principal, AppDbContext db, TimeProvider clock, CancellationToken cancellationToken) =>
{
    string? ownerId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
    ApiKeyRecord? record = await db.ApiKeys.SingleOrDefaultAsync(key => key.Id == id && key.OwnerId == ownerId, cancellationToken);
    if (record is null)
    {
        return Results.NotFound();
    }

    record.RevokedAt = clock.GetUtcNow();
    await db.SaveChangesAsync(cancellationToken);
    return Results.NoContent();
})
.RequireAuthorization();

app.MapGet("/api/v1/reports", (HttpContext httpContext) =>
{
    ApiKeyRecord caller = (ApiKeyRecord)httpContext.Items[ApiKeyEndpointFilter.ItemKey]!;   // set by the filter
    return Results.Ok(new { caller.OwnerId });
})
.AddEndpointFilter<ApiKeyEndpointFilter>();
```

Notes:

- A key is `<prefix>_<base62 random><6-character base62 CRC-32>` with 32 random bytes by default (`ApiKey.DefaultEntropyBytes`, 16 to 64 allowed). The checksum is public and is not a security control: a valid checksum does not prove the key was ever issued, so the lookup is always required.
- `ApiKeyHasher.Verify` never throws. It returns false for null, empty, over-long (more than 1024 characters, `ApiKeyHasher.MaxApiKeyLength`) or malformed input and for a lookup hash made with a key that is no longer in the ring.
- To rotate the ring, add the new key and make it current. Keys hashed under the old one are found through `ComputeAllLookupHashes` and migrated by the `NeedsRehash` branch on their next use. `ApiKeyHasher.TryGetKeyId` reads the key id of a stored lookup hash, so you can count what is left before removing the old key.

## 6. Rotating a pepper key

A pepper is a server-side secret mixed into every password before hashing. Each stored hash names the key it was made with (`$mh$p=2026a,k=k1$...`), which is what makes rotation possible: hashes under an older key keep verifying and are rehashed at the next login.

**1. Generate the new key** with `masterly-hash pepper generate`, or in code with `Convert.ToBase64String(HmacPepper.GenerateKey())`. Both produce 32 random bytes (`HmacPepper.MinKeyLength`), the minimum the configuration accepts. Store it in your secret store, never in the database or in source control.

**2. Deploy the new key everywhere before using it.** In a rolling deployment, an instance that does not know `k2` fails every `k2` hash with `UnknownPepperKey`. So the first release adds the key and keeps `k1` current:

```json title="appsettings.json (release 1)"
{
  "MasterlyHash": {
    "Pepper": {
      "CurrentKeyId": "k1",
      "Keys": {
        "k1": "<from the secret store>",
        "k2": "<from the secret store>"
      }
    }
  }
}
```

In practice the key values come from environment variables or a secret provider rather than the file, for example `MasterlyHash__Pepper__Keys__k2`. Configuration keys are case-insensitive, so two key ids that differ only by case cannot both be configured.

**3. Switch the current key** in the second release, once every instance runs release 1:

```json title="appsettings.json (release 2)"
{
  "MasterlyHash": {
    "Pepper": {
      "CurrentKeyId": "k2",
      "Keys": {
        "k1": "<from the secret store>",
        "k2": "<from the secret store>"
      }
    }
  }
}
```

New hashes now use `k2`. A login with a `k1` hash succeeds with `SuccessRehashNeeded` and `RehashReason.OutdatedPepperKey`, and the login endpoint from recipe 1 stores the fresh `k2` hash. A hash made before any pepper was configured is flagged with the same reason, which is also how adding a pepper to an existing application works.

**4. Track progress.** `Inspect` reads the key id of a stored hash without verifying it:

```csharp title="PepperKeyUsage.cs"
using Masterly.Hash;

namespace Contoso.Maintenance;

public static class PepperKeyUsage
{
    public const string NoPepper = "(none)";

    /// <summary>Counts native hashes by pepper key id. Stream storedHashes from the password column.</summary>
    public static IReadOnlyDictionary<string, long> Count(IPasswordHasher hasher, IEnumerable<string?> storedHashes)
    {
        Dictionary<string, long> counts = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (string? storedHash in storedHashes)
        {
            if (string.IsNullOrEmpty(storedHash))
            {
                continue;
            }

            // Skip legacy hashes and malformed $mh$ values (no profile id). A key missing from the ring still counts.
            HashInfo info = hasher.Inspect(storedHash);
            if (!info.IsNative || info.ProfileId is null)
            {
                continue;
            }

            string keyId = info.PepperKeyId ?? NoPepper;
            counts[keyId] = counts.GetValueOrDefault(keyId) + 1;
        }

        return counts;
    }
}
```

**5. Retire the old key.** The pepper is applied before Argon2id, so a `k1` hash cannot be moved to `k2` without the user's password. When the `k1` count stops falling, the remaining accounts are dormant. Either keep `k1` until they return, or clear their hashes and send them a reset link (recipe 8). Then remove `k1` from `Keys`. From that point a `k1` hash fails with `UnknownPepperKey`.

:::danger

Never remove a key while hashes still use it unless those users have been moved to a reset flow. A removed key locks every one of them out, and no amount of configuration brings the hashes back if the key itself is lost.

:::

The same rotation works with the remote peppers: [HashiCorp Vault](./hashicorp-vault.md), [AWS KMS](./aws-kms.md) and [Azure Key Vault](./azure-key-vault.md). For the details of `HmacPepper`, see [Peppers](./peppers.md).

## 7. Password change with policy and breach check

A password change verifies the current password, checks the new one against the NIST SP 800-63B rules and the Have I Been Pwned corpus, then stores the new hash with a compare-and-swap.

```
dotnet add package Masterly.Hash.Policy
dotnet add package Masterly.Hash.Pwned
```

**1. Register the policy with a breach checker.**

```csharp title="Program.cs"
using Masterly.Hash.Policy;
using Masterly.Hash.Pwned;

builder.Services.AddPwnedPasswords(options =>
{
    options.UserAgent = "Contoso-Accounts/1.0";   // the API requires a User-Agent that names your application
    options.EnableCache = true;                    // bounded LRU range cache: 1 hour, 256 entries by default
});

builder.Services.AddSingleton<IPasswordPolicy>(provider => new PasswordPolicy(
    new PasswordPolicyOptions { ContextWords = { "Contoso" } },
    provider.GetRequiredService<IBreachedPasswordChecker>()));
```

`AddPwnedPasswords` registers a singleton `IBreachedPasswordChecker` that takes a fresh `HttpClient` from `IHttpClientFactory` for every lookup, so it is safe inside the singleton policy. It returns the `IHttpClientBuilder`, so resilience handlers can be added. Only the first 5 hex characters of the password's SHA-1 leave the process.

**2. Handle the change.**

```csharp title="ChangePasswordRequest.cs"
using Masterly.Hash;

namespace Contoso.Accounts;

public sealed record ChangePasswordRequest(SensitiveString CurrentPassword, SensitiveString NewPassword);
```

```csharp title="Program.cs (continued)"
app.MapPost("/api/v1/account/password", async (
    ChangePasswordRequest request,
    ClaimsPrincipal principal,
    IUserRepository users,
    IPasswordHasher hasher,
    IPasswordPolicy policy,
    ILogger<Program> logger,
    CancellationToken cancellationToken) =>
{
    string? userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
    UserAccount? user = userId is null ? null : await users.FindByIdAsync(userId, cancellationToken);
    if (user?.PasswordHash is not string currentHash || request.CurrentPassword is null || request.NewPassword is null)
    {
        return Results.Unauthorized();
    }

    PasswordVerificationResult current = await hasher.VerifyAsync(request.CurrentPassword, currentHash, cancellationToken);
    if (!current.IsMatch)
    {
        return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "The current password is incorrect.");
    }

    PasswordContext context = new PasswordContext
    {
        UserName = user.UserName,
        Email = user.Email,
        DisplayName = user.DisplayName,
        ApplicationName = "Contoso",
    };
    PasswordPolicyResult verdict = await policy.EvaluateAsync(request.NewPassword, context, cancellationToken);
    if (!verdict.IsAcceptable)
    {
        string[] messages = verdict.Violations.Select(violation => violation.Message).Concat(verdict.Suggestions).ToArray();
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["newPassword"] = messages });
    }

    if (verdict.BreachCheckUnavailable)
    {
        // Fail-open: the password passed every local rule. Return 503 here instead to make the check mandatory.
        logger.LogWarning("Breach check unavailable for {UserId}; password accepted on local rules only", user.Id);
    }

    string newHash = await hasher.HashAsync(request.NewPassword, cancellationToken);
    if (!await users.ReplacePasswordHashAsync(user.Id, currentHash, newHash, cancellationToken))
    {
        return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "The password was changed by another request.");
    }

    logger.LogInformation("Password changed for {UserId}", user.Id);
    return Results.NoContent();   // also invalidate the user's other sessions here
})
.RequireAuthorization()
.RequireRateLimiting("auth")
.WithPasswordLengthLimit();
```

The defaults the policy applies:

| Rule | Default | Violation code |
|---|---|---|
| Minimum length in code points after NFKC | 15 (`MinLength`; 8 is the lowest allowed, for passwords that are one factor of MFA) | `TooShort` |
| Maximum length | 128 (`MaxLength`, 64 to 4096) | `TooLong` |
| The 10,000 most common passwords plus `BlockedPasswords` | on (`BlockCommonPasswords`) | `CommonPassword` |
| User name, email, display name, application name and `ContextWords` of 4 or more code points | on (`CheckContextWords`, `MinContextWordLength` 4) | `ContainsContextWord` |
| Only repeats, sequences or keyboard runs | on (`RejectRepetitiveOrSequential`) | `RepetitiveOrSequential` |
| Strength score below `MinimumScore` | 3 | `TooWeak` |
| Seen in breaches at least `MinimumBreachOccurrences` times | 1 | `Breached` |

There are no composition rules and no expiry, as NIST SP 800-63B requires. `Violations`, `Suggestions` and `ToString()` never contain the password and are safe to return and log. Do not log or store `verdict.StrengthEstimate`: its details are derived from the password.

:::tip

Apply the same policy at sign-up. In recipe 1, call `policy.EvaluateAsync(request.Password, new PasswordContext { Email = request.Email }, cancellationToken)` before `HashAsync` and return the violations as a 400.

:::

## 8. Password reset with a single-use signed link

A reset link carries a signed, expiring, purpose-bound token. Recording its nonce in a shared store makes it single-use. The new password goes through the policy from recipe 7.

```
dotnet add package Masterly.Hash.Tokens
```

**1. Give tokens their own key ring and a shared used-token store.** `InMemoryUsedTokenStore` works only within one process. For several servers, implement `IUsedTokenStore` on storage with an atomic insert, such as a table with a unique key on the nonce.

```csharp title="UsedTokenStore.cs"
using Contoso.Data;
using Masterly.Hash.Tokens;
using Microsoft.EntityFrameworkCore;

namespace Contoso.Accounts;

public sealed class UsedToken
{
    /// <summary>Primary key (HasKey(token => token.Nonce)): the database enforces single use.</summary>
    public string Nonce { get; set; } = string.Empty;

    /// <summary>Delete rows after this time, never earlier.</summary>
    public DateTimeOffset RetainUntil { get; set; }
}

public sealed class EfUsedTokenStore : IUsedTokenStore
{
    private readonly IDbContextFactory<AppDbContext> _contexts;

    public EfUsedTokenStore(IDbContextFactory<AppDbContext> contexts)
    {
        _contexts = contexts;
    }

    public async ValueTask<bool> TryMarkUsedAsync(string nonce, DateTimeOffset retainUntil, CancellationToken cancellationToken = default)
    {
        await using AppDbContext db = await _contexts.CreateDbContextAsync(cancellationToken);
        db.UsedTokens.Add(new UsedToken { Nonce = nonce, RetainUntil = retainUntil });
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException)
        {
            await using AppDbContext check = await _contexts.CreateDbContextAsync(cancellationToken);
            if (await check.UsedTokens.AnyAsync(token => token.Nonce == nonce, cancellationToken))
            {
                return false;   // already redeemed
            }

            throw;
        }
    }
}
```

```csharp title="Program.cs"
using Contoso.Data;
using Masterly.Hash.Tokens;

KeyRingSettings tokenRing = builder.Configuration.GetSection("ResetTokens").Get<KeyRingSettings>()
    ?? throw new InvalidOperationException("The ResetTokens section is missing.");

builder.Services.AddSingleton(new SignedTokenService(HmacKeyRing.FromBase64(tokenRing.CurrentKeyId, tokenRing.Keys)));
builder.Services.AddSingleton<IUsedTokenStore, EfUsedTokenStore>();
```

`EfUsedTokenStore` needs an `IDbContextFactory<AppDbContext>`, so register the context with `AddDbContextFactory` rather than `AddDbContext`, and add a `DbSet<UsedToken> UsedTokens` with `modelBuilder.Entity<UsedToken>().HasKey(token => token.Nonce);`.

**2. Request and confirm.**

```csharp title="ResetContracts.cs"
using Masterly.Hash;

namespace Contoso.Accounts;

public sealed record ResetRequest(string Email);

public sealed record ResetConfirmation(string Token, SensitiveString NewPassword);
```

```csharp title="Program.cs (continued)"
const string ResetPurpose = "password-reset";

app.MapPost("/api/v1/password-resets", async (ResetRequest request, IUserRepository users, SignedTokenService tokens, IResetEmailSender email, CancellationToken cancellationToken) =>
{
    UserAccount? user = string.IsNullOrWhiteSpace(request.Email) ? null : await users.FindByEmailAsync(request.Email, cancellationToken);
    if (user is not null)
    {
        string token = tokens.Create(ResetPurpose, user.Id, TimeSpan.FromMinutes(30));
        await email.SendResetLinkAsync(user.Email, $"https://contoso.example/reset?token={Uri.EscapeDataString(token)}", cancellationToken);
    }

    return Results.Accepted();   // the same answer whether or not the account exists
})
.RequireRateLimiting("auth");

app.MapPost("/api/v1/password-resets/confirm", async (
    ResetConfirmation request,
    SignedTokenService tokens,
    IUsedTokenStore usedTokens,
    IUserRepository users,
    IPasswordHasher hasher,
    IPasswordPolicy policy,
    CancellationToken cancellationToken) =>
{
    // Validate first without consuming, so a rejected password does not burn the link.
    if (request.NewPassword is null || !tokens.TryValidate(request.Token, ResetPurpose, out SignedTokenPayload? payload))
    {
        return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "The reset link is invalid or has expired.");
    }

    UserAccount? user = await users.FindByIdAsync(payload.Subject, cancellationToken);
    if (user?.PasswordHash is not string currentHash)
    {
        return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "The reset link is invalid or has expired.");
    }

    PasswordContext context = new PasswordContext { UserName = user.UserName, Email = user.Email, DisplayName = user.DisplayName };
    PasswordPolicyResult verdict = await policy.EvaluateAsync(request.NewPassword, context, cancellationToken);
    if (!verdict.IsAcceptable)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["newPassword"] = verdict.Violations.Select(violation => violation.Message).ToArray(),
        });
    }

    SignedTokenResult consumed = await tokens.ConsumeAsync(request.Token, ResetPurpose, usedTokens, cancellationToken);
    if (!consumed.IsValid)
    {
        return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "The reset link is invalid or has expired.");
    }

    string newHash = await hasher.HashAsync(request.NewPassword, cancellationToken);
    if (!await users.ReplacePasswordHashAsync(user.Id, currentHash, newHash, cancellationToken))
    {
        return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "The password was changed by another request.");
    }

    return Results.NoContent();   // also invalidate the user's sessions here
})
.RequireRateLimiting("auth")
.WithPasswordLengthLimit();
```

`IResetEmailSender` is your own. Notes:

- `Validate` and `TryValidate` never throw for a bad token. `Validate` reports `Valid`, `Expired`, `InvalidSignature`, `WrongPurpose`, `Malformed`, `UnknownKey` or `NotYetValid`; `ConsumeAsync` adds `AlreadyUsed`. Log the status, never the token.
- The defaults are a 30-second `ClockSkew`, a 1024-character `MaxTokenLength`, a 512-byte `MaxSubjectBytes` and a 30-day `MaxLifetime` (`SignedTokenOptions`).
- Tokens are signed, not encrypted: the subject (here the user id) is readable by whoever holds the link. Never put secrets in it.
- `ConsumeAsync` asks the store to keep a nonce until expiry plus twice the clock skew plus one minute. A clean-up job may delete `UsedToken` rows after `RetainUntil`, never before.
- Use a different ring from the API-key ring in recipe 5. Each ring key already yields separate subkeys for lookup hashes and signatures, but separate rings limit what one leaked key affects.

## 9. Tamper-evident audit log

A hash chain makes an audit table tamper-evident: every entry's hash covers its sequence number, its payload and the previous entry's hash, so editing, deleting, inserting or reordering any row breaks the chain from that point on. With an HMAC key kept outside the database, someone who can write the table still cannot forge a valid chain.

```
dotnet add package Masterly.Hash.Integrity
```

**1. Store the entries.**

```csharp title="AuditEntryRow.cs"
using Masterly.Hash.Integrity;

namespace Contoso.Audit;

public sealed class AuditEntryRow
{
    /// <summary>Primary key, not database-generated: a concurrent append for the same sequence fails.</summary>
    public long Sequence { get; set; }

    public byte[] PreviousHash { get; set; } = Array.Empty<byte>();

    /// <summary>UTF-8 JSON of an AuditEvent. Everything that must be tamper-evident, including the time, goes here.</summary>
    public byte[] Payload { get; set; } = Array.Empty<byte>();

    public byte[] Hash { get; set; } = Array.Empty<byte>();
}

public sealed record AuditEvent(DateTimeOffset OccurredAt, string ActorId, string Action, string TargetId);

/// <summary>Your storage for the chain head, in a system the database's writers cannot modify.</summary>
public interface ICheckpointStore
{
    Task<CheckpointRecord?> LoadAsync(CancellationToken cancellationToken);

    Task SaveAsync(CheckpointRecord checkpoint, CancellationToken cancellationToken);
}

public sealed record CheckpointRecord(long Sequence, byte[] Hash);

public sealed record AuditChainKey(ContentHashAlgorithm Algorithm);
```

In `OnModelCreating`: `modelBuilder.Entity<AuditEntryRow>().HasKey(row => row.Sequence);` and `.Property(row => row.Sequence).ValueGeneratedNever();`.

**2. Register the keyed algorithm.** `ContentHashAlgorithm.HmacSha256` requires a key of at least 32 bytes (`ContentHashAlgorithm.MinHmacKeyLength`). The key id (`audit-1`) is part of every entry hash.

```csharp title="Program.cs"
using Contoso.Audit;
using Masterly.Hash.Integrity;
using Microsoft.EntityFrameworkCore;

string connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("ConnectionStrings:Default is missing.");
byte[] auditKey = Convert.FromBase64String(builder.Configuration["Audit:Key"]
    ?? throw new InvalidOperationException("Audit:Key is missing."));

builder.Services.AddSingleton(new AuditChainKey(ContentHashAlgorithm.HmacSha256("audit-1", auditKey)));
builder.Services.AddDbContextFactory<AuditDbContext>(options => options.UseSqlServer(connectionString));
builder.Services.AddSingleton<AuditLog>();
```

**3. Append and verify.**

```csharp title="AuditLog.cs"
using System.Text.Json;
using Masterly.Hash.Integrity;
using Microsoft.EntityFrameworkCore;

namespace Contoso.Audit;

public sealed class AuditLog
{
    private const int MaxAppendAttempts = 5;

    private readonly IDbContextFactory<AuditDbContext> _contexts;
    private readonly ICheckpointStore _checkpoints;
    private readonly ContentHashAlgorithm _algorithm;
    private readonly ILogger<AuditLog> _logger;

    public AuditLog(IDbContextFactory<AuditDbContext> contexts, ICheckpointStore checkpoints, AuditChainKey key, ILogger<AuditLog> logger)
    {
        _contexts = contexts;
        _checkpoints = checkpoints;
        _algorithm = key.Algorithm;
        _logger = logger;
    }

    public async Task<long> AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(auditEvent);
        for (int attempt = 1; ; attempt++)
        {
            await using AuditDbContext db = await _contexts.CreateDbContextAsync(cancellationToken);
            AuditEntryRow? last = await db.AuditEntries
                .AsNoTracking()
                .OrderByDescending(row => row.Sequence)
                .FirstOrDefaultAsync(cancellationToken);

            HashChainEntry next = HashChain.CreateNext(last is null ? null : ToEntry(last), payload, _algorithm);
            db.AuditEntries.Add(new AuditEntryRow
            {
                Sequence = next.Sequence,
                PreviousHash = next.PreviousHash.ToArray(),
                Payload = next.Payload.ToArray(),
                Hash = next.Hash.ToArray(),
            });

            try
            {
                await db.SaveChangesAsync(cancellationToken);
                return next.Sequence;
            }
            catch (DbUpdateException exception) when (attempt < MaxAppendAttempts)
            {
                _logger.LogWarning(exception, "Audit append lost the race for sequence {Sequence}; retrying", next.Sequence);
            }
        }
    }

    public async Task<HashChainVerificationResult> VerifyAsync(CancellationToken cancellationToken)
    {
        CheckpointRecord? trusted = await _checkpoints.LoadAsync(cancellationToken);
        HashChainCheckpoint? expectedHead = trusted is null ? null : new HashChainCheckpoint(trusted.Sequence, trusted.Hash);

        await using AuditDbContext db = await _contexts.CreateDbContextAsync(cancellationToken);
        List<AuditEntryRow> rows = await db.AuditEntries.AsNoTracking().OrderBy(row => row.Sequence).ToListAsync(cancellationToken);
        List<HashChainEntry> entries = rows.Select(ToEntry).ToList();

        HashChainVerificationResult result = HashChain.Verify(entries, _algorithm, anchor: null, expectedHead: expectedHead);
        if (!result.IsValid)
        {
            _logger.LogCritical("Audit chain broken: {Failure} at sequence {Sequence}", result.Failure, result.BrokenSequence);
            return result;
        }

        if (result.Head is HashChainCheckpoint head)
        {
            await _checkpoints.SaveAsync(new CheckpointRecord(head.Sequence, head.Hash.ToArray()), cancellationToken);
        }

        return result;
    }

    private static HashChainEntry ToEntry(AuditEntryRow row) =>
        new HashChainEntry(row.Sequence, row.PreviousHash, row.Payload, row.Hash);
}
```

`AuditDbContext` is an ordinary context with a `DbSet<AuditEntryRow> AuditEntries`. Run `VerifyAsync` on a schedule. What it catches:

| `HashChainFailure` | Meaning |
|---|---|
| `Gap` | Sequence numbers are missing: rows were deleted. |
| `Reorder`, `Duplicate` | Rows are out of order, or a sequence number appears twice. |
| `PreviousHashMismatch` | A row was replaced or inserted. |
| `HashMismatch` | A row's payload or sequence was edited. |
| `Truncated` | The chain ends before the trusted checkpoint: the newest rows were deleted. |
| `HeadMismatch` | The row at the checkpoint differs: history up to it was rewritten. |
| `InvalidEntry` | The input contained a null entry. |

`Verify` never throws for bad entries. `Reason` explains the failure without payloads or hashes.

:::warning

Rows appended after the newest checkpoint are protected only by the links and the HMAC key. Refresh the checkpoint often and keep it where the database's writers cannot reach it: another system, a write-once bucket, a signed receipt. Without a key and a checkpoint, anyone who can write the table can recompute the whole chain.

:::

`VerifyAsync` loads the whole table. For a large log, verify only the new rows with `HashChain.Verify(newRows, algorithm, anchor: lastCheckpoint, expectedHead: null)`, where the first row must have sequence `anchor.Sequence + 1` and link to its hash, and run the full pass less often. Appends serialize on the sequence key; for high write rates, funnel them through one writer instead of retrying. For a single process, `HashChainLog` keeps the chain in memory with `Append`, `Head` and `Verify`.

## 10. Honeywords and honey accounts

Honeywords make a cracked password database detectable. Each user's stored hash covers k sweetwords: the real password and k-1 decoys. Only a separate honeychecker knows which index is real, so a login with a decoy means someone cracked the hashes. Honey accounts are decoy user names that no real user owns; any login attempt against one raises an alert.

```
dotnet add package Masterly.Hash.Detection
```

**1. Talk to the honeychecker over the network.** It must run as a separate, hardened service with its own storage, credentials and alerting, and should expose only "set" and "is this index real?". `InMemoryHoneychecker` is for tests and demos only.

```csharp title="HttpHoneychecker.cs"
using System.Net.Http.Json;
using Masterly.Hash.Detection;

namespace Contoso.Security;

public sealed class HttpHoneychecker : IHoneychecker
{
    private readonly HttpClient _http;

    public HttpHoneychecker(HttpClient http)
    {
        _http = http;
    }

    public async Task SetAsync(string userId, int index, CancellationToken cancellationToken = default)
    {
        using HttpResponseMessage response = await _http.PutAsJsonAsync(
            $"v1/users/{Uri.EscapeDataString(userId)}/index", new HoneycheckerIndex(index), cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async Task<bool> IsRealAsync(string userId, int index, CancellationToken cancellationToken = default)
    {
        using HttpResponseMessage response = await _http.PostAsJsonAsync(
            $"v1/users/{Uri.EscapeDataString(userId)}/check", new HoneycheckerIndex(index), cancellationToken);
        response.EnsureSuccessStatusCode();   // unreachable checker: the exception propagates and the login fails closed
        HoneycheckerVerdict? verdict = await response.Content.ReadFromJsonAsync<HoneycheckerVerdict>(cancellationToken);
        return verdict is { IsReal: true };
    }

    private sealed record HoneycheckerIndex(int Index);

    private sealed record HoneycheckerVerdict(bool IsReal);
}
```

**2. Register the services.** `HoneywordService` takes the concrete `PasswordHasher` and uses its profiles. The hasher does not expose its pepper, so pass the same `IPasswordPepper` explicitly if you use one.

```csharp title="Program.cs"
using Contoso.Security;
using Masterly.Hash;
using Masterly.Hash.Detection;
using Microsoft.Extensions.Options;

string honeycheckerUrl = builder.Configuration["Honeychecker:BaseUrl"]
    ?? throw new InvalidOperationException("Honeychecker:BaseUrl is missing.");

builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));
builder.Services.AddHttpClient<IHoneychecker, HttpHoneychecker>(client => client.BaseAddress = new Uri(honeycheckerUrl));
builder.Services.AddSingleton(provider => new HoneywordService(
    provider.GetRequiredService<PasswordHasher>(),
    new HoneywordServiceOptions
    {
        Generator = PasswordModelHoneywordGenerator.Default,
        Pepper = provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.Pepper,
    }));
builder.Services.AddScoped(provider =>
{
    HoneywordLoginService login = new HoneywordLoginService(
        provider.GetRequiredService<HoneywordService>(),
        provider.GetRequiredService<IHoneychecker>());
    ISecurityAlerts alerts = provider.GetRequiredService<ISecurityAlerts>();
    login.BreachDetected += (_, e) => alerts.Raise($"Honeyword used for user {e.UserId} at {e.DetectedAt:O}");
    return login;
});
builder.Services.AddSingleton(provider =>
{
    HoneyAccountRegistry registry = new HoneyAccountRegistry(new[] { "admin2@contoso.example", "backup-svc@contoso.example" });
    ISecurityAlerts alerts = provider.GetRequiredService<ISecurityAlerts>();
    registry.HoneyAccountAccessed += (_, e) => alerts.Raise($"Honey account {e.Account} tried from {e.Context}");
    return registry;
});
```

`ISecurityAlerts` is your paging or SIEM integration. `HoneywordLoginService` is scoped because the typed `HttpClient` behind `IHoneychecker` is transient.

**3. Register users and log them in.** Honeyword hashes use their own format (`$mhw$p=2026a$<salt>$<tag1>,...,<tagk>`), which `PasswordHasher` does not verify. During a rollout the table holds both kinds, so the login checks which one it has. Users move to honeywords when they set a password.

```csharp title="Program.cs (continued)"
app.MapPost("/api/v1/users", async (RegisterRequest request, IUserRepository users, HoneywordLoginService honeywords, CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || request.Password is null || request.Password.IsEmpty)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["request"] = new[] { "An email address and a password are required." } });
    }

    // The account cannot log in until the honeyword hash replaces the empty one below.
    UserAccount user = await users.CreateAsync(request.Email, passwordHash: string.Empty, cancellationToken);
    // k = 20 sweetwords by default. Persist the hash only after the honeychecker has stored the index.
    string honeywordHash = await honeywords.RegisterAsync(user.Id, request.Password.Reveal(), cancellationToken: cancellationToken);
    await users.ReplacePasswordHashAsync(user.Id, string.Empty, honeywordHash, cancellationToken);
    return Results.Created($"/api/v1/users/{user.Id}", new { user.Id });
})
.WithPasswordLengthLimit();

app.MapPost("/api/v1/sessions", async (
    LoginRequest request,
    HttpContext httpContext,
    IUserRepository users,
    IPasswordHasher hasher,
    HoneywordLoginService honeywords,
    HoneyAccountRegistry honeyAccounts,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || request.Password is null)
    {
        return Results.Unauthorized();
    }

    string password = request.Password.Reveal();
    if (honeyAccounts.CheckLogin(request.Email, context: httpContext.Connection.RemoteIpAddress?.ToString()))
    {
        await hasher.VerifyOrDummyAsync(password, null, cancellationToken);   // same cost as a real wrong password
        return Results.Unauthorized();
    }

    UserAccount? user = await users.FindByEmailAsync(request.Email, cancellationToken);
    string? storedHash = user?.PasswordHash;

    if (storedHash is not null && !HoneywordService.IsHoneywordHash(storedHash))
    {
        // Not migrated yet: an ordinary $mh$ or legacy hash.
        PasswordVerificationResult result = await hasher.VerifyAsync(password, storedHash, cancellationToken);
        return result.IsMatch ? Results.NoContent() : Results.Unauthorized();
    }

    HoneywordLoginResult login = await honeywords.LoginAsync(user?.Id ?? request.Email, password, storedHash, cancellationToken);
    // BreachDetected gets exactly the same answer as Mismatch: the attacker must not learn that the decoy was noticed.
    return login.IsSuccess ? Results.NoContent() : Results.Unauthorized();
})
.RequireRateLimiting("auth")
.WithPasswordLengthLimit();
```

What happens:

- `RegisterAsync` creates the record, stores the real index in the honeychecker, then returns the hash. If persisting the hash fails afterwards, call `RegisterAsync` again rather than keeping the old hash; otherwise the user's next correct login is reported as a breach.
- `LoginAsync` runs exactly one key derivation, compares against every tag in constant time, and asks the honeychecker only when a sweetword matched. For an unknown user (null stored hash) it still runs one derivation against a dummy.
- On `Success` the result withholds the index (-1). Log `login.Outcome` or `login.Verification.Status`, never the index next to a user id.
- The built-in generators never place a decoy within one typo (one substitution, insertion, deletion or swap of neighbouring characters) of the real password, so a single typo cannot raise the alarm. Two or more typos still can: treat one hit as a strong signal and hits across many accounts as a confirmed breach.
- `HoneyAccountRegistry` matching ignores case and applies NFKC, so `Admin`, `ADMIN` and full-width `ａｄｍｉｎ` are the same account. Names longer than 1024 characters (`HoneyAccountRegistry.MaxAccountLength`) are never honey accounts.

:::warning

Creating a record costs k key derivations, one per sweetword (20 by default, `HoneywordService.DefaultSweetwordCount`). At the roughly 171 ms per `2026a` hash measured in the project benchmarks, that is several seconds of CPU per sign-up or password change, so keep k modest and expect that latency. A login still costs one derivation. Never regenerate the decoys for an unchanged password: an attacker with two copies of the table could intersect the two sweetword sets.

:::

For credential-stuffing and password-spraying detection on the same login endpoint, add `CredentialStuffingDetector.RecordFailedLogin(account, password)` on every failure. See [Attack Detection](./attack-detection.md).

## See also

- [Hashing and Verifying](./hashing-and-verifying.md)
- [Upgrade on Login](./upgrade-on-login.md)
- [Limits and Concurrency](./limits-and-concurrency.md)
- [Legacy Formats](./legacy-formats.md) and [Onion Wrapping](./onion-wrapping.md)
- [ASP.NET Core Identity](./aspnetcore-identity.md) and [Entity Framework Core](./entity-framework-core.md)
- [API Keys and Tokens](./api-keys-and-tokens.md) and [Blind Indexes](./blind-indexes.md)
- [Password Policy](./password-policy.md) and [Breach Checking](./breach-checking.md)
- [Merkle Trees and Hash Chains](./merkle-trees-and-hash-chains.md)
- [Testing](./testing.md): a fast hasher for the tests of code like the recipes above
