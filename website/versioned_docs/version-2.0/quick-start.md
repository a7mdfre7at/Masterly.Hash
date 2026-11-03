---
title: "Quick Start"
sidebar_label: "Quick Start"
description: "Hash a password, verify it, upgrade outdated hashes on login and wire the hasher into an ASP.NET Core app."
---

This page hashes a password, verifies it, stores the upgraded hash that a login can hand back, and then moves the same code into an ASP.NET Core minimal API. It takes about five minutes.

**1. Install the package.**

```bash
dotnet add package Masterly.Hash
```

**2. Hash a password when the user signs up.** `Password.Hash` uses Argon2id with the default profile, `2026a` (64 MiB, 3 passes), and a fresh random 16-byte salt. Store the returned string as it is, in a single text column.

```csharp title="SignUp.cs"
using Masterly.Hash;

string stored = Password.Hash("correct horse battery staple");

Console.WriteLine(stored);
```

```text title="Console output (the salt and tag differ on every run)"
$mh$p=2026a$nlsVeVz92iTfQWZ9nBrDRg$xVNTAHiw3CqIC1XJm+HSZli7L1AqyZ/6bFjlI7KCQ7w
```

The string records the profile id (`2026a`), the salt and the tag. It never records cost parameters: those come from the compiled-in profile, so a tampered row cannot make verification cheaper or more expensive. Because the salt is random, hashing the same password twice gives two different strings. Never compare hash strings; always call `Verify`.

**3. Verify the password when the user logs in.** `Password.Verify` returns a `PasswordVerificationResult`. `IsMatch` tells you whether the password is correct. It never throws for a bad stored hash; a malformed or unknown string simply fails.

```csharp title="LogIn.cs"
using Masterly.Hash;

// Inside your login method. user, users, enteredPassword and LoginOutcome are your own types and values;
// user.PasswordHash holds the string from step 2.
PasswordVerificationResult result = Password.Verify(enteredPassword, user.PasswordHash);

if (!result.IsMatch)
{
    // Wrong password, or the stored hash is unusable. result.FailureReason says which:
    // log it, but show the user one generic message.
    return LoginOutcome.Failed;
}

if (result.Rehash is string fresh)
{
    // The stored hash is outdated (older profile, older pepper key, a 1.x or legacy hash).
    // fresh is a new hash of the same password with the current settings.
    user.PasswordHash = fresh;
    await users.SaveAsync(user, cancellationToken);
}

return LoginOutcome.Succeeded;
```

That is upgrade-on-login. When a later release ships a stronger profile, or you rotate the pepper key, every user is moved to the new settings the next time they log in, with no migration script. See [Upgrade on Login](./upgrade-on-login.md).

**4. Do the same work for users who do not exist.** If your login looks the user up first and skips verification when there is no such user, the response time shows which email addresses have accounts. Pass the stored hash, or `null` when there is no user, to `VerifyOrDummy`. It verifies against a throwaway hash in the same format, so both paths cost one Argon2id run.

```csharp title="LogIn.cs"
// account is null when no user has this email address.
PasswordVerificationResult result = Password.VerifyOrDummy(enteredPassword, account?.PasswordHash);
```

For an unknown user the result is a failure with `FailureReason` set to `VerificationFailureReason.NoStoredHash`. See [User Enumeration](./user-enumeration.md).

**5. Move it into ASP.NET Core.** In an application, register one hasher in the container and inject `IPasswordHasher`, instead of calling the static `Password` class. That makes the hasher configurable and replaceable in tests. Add the two integration packages:

```bash
dotnet add package Masterly.Hash.DependencyInjection
dotnet add package Masterly.Hash.AspNetCore
```

```csharp title="Program.cs"
using Masterly.Hash;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddMasterlyHash();                  // one PasswordHasher singleton, also IPasswordHasher
builder.Services.AddMasterlyHashExceptionHandler();  // PasswordHasherBusyException -> 503 + Retry-After
builder.Services.AddProblemDetails();
builder.Services.AddSingleton<IAccountRepository, AccountRepository>();  // your own data access

WebApplication app = builder.Build();

app.UseExceptionHandler();

app.MapPost("/api/v1/accounts", async (
    Credentials request,
    IPasswordHasher hasher,
    IAccountRepository accounts,
    CancellationToken cancellationToken) =>
{
    string passwordHash = await hasher.HashAsync(request.Password, cancellationToken);
    await accounts.AddAsync(request.Email, passwordHash, cancellationToken);
    return Results.NoContent();
}).WithPasswordLengthLimit();

app.MapPost("/api/v1/sessions", async (
    Credentials request,
    IPasswordHasher hasher,
    IAccountRepository accounts,
    CancellationToken cancellationToken) =>
{
    Account? account = await accounts.FindByEmailAsync(request.Email, cancellationToken);

    PasswordVerificationResult result =
        await hasher.VerifyOrDummyAsync(request.Password, account?.PasswordHash, cancellationToken);

    if (!result.IsMatch)
    {
        return Results.Unauthorized();
    }

    if (result.Rehash is string fresh && account is not null)
    {
        await accounts.UpdatePasswordHashAsync(account.Email, fresh, cancellationToken);
    }

    return Results.NoContent();
}).WithPasswordLengthLimit();

app.Run();

// SensitiveString shows "***" in ToString(), the debugger and JSON output,
// so the password cannot end up in a log by accident.
public sealed record Credentials(string Email, SensitiveString Password);
```

```csharp title="IAccountRepository.cs"
public sealed record Account(string Email, string PasswordHash);

public interface IAccountRepository
{
    Task<Account?> FindByEmailAsync(string email, CancellationToken cancellationToken);

    Task AddAsync(string email, string passwordHash, CancellationToken cancellationToken);

    Task UpdatePasswordHashAsync(string email, string passwordHash, CancellationToken cancellationToken);
}
```

What each piece does:

- `AddMasterlyHash()` registers one thread-safe `PasswordHasher` with the default options and validates the options at startup. See [Dependency Injection](./dependency-injection.md).
- The `SensitiveString` overloads of `HashAsync` and `VerifyOrDummyAsync` are extension methods on `IPasswordHasher`, in the `Masterly.Hash` namespace. The JSON body binds the real password into `SensitiveString`, but serializing the record writes `"***"`.
- The hasher runs at most one Argon2id computation per processor at a time, so a login flood cannot exhaust memory. A call that waits longer than 30 seconds for a slot throws `PasswordHasherBusyException`. `AddMasterlyHashExceptionHandler()` turns it into `503 Service Unavailable` with a `Retry-After` header. See [Limits and Concurrency](./limits-and-concurrency.md).
- `WithPasswordLengthLimit()` rejects a password longer than the hasher accepts (1024 UTF-8 bytes by default) before any hashing work, instead of letting `HashAsync` throw. See [ASP.NET Core Identity](./aspnetcore-identity.md).

:::tip

Using ASP.NET Core Identity? You do not need any of the endpoint code. Call `services.AddIdentity<AppUser, IdentityRole>().AddMasterlyPasswordHasher()` and Identity uses Argon2id from then on, while existing Identity hashes keep verifying and are upgraded on the next login. See [ASP.NET Core Identity](./aspnetcore-identity.md).

:::

## Next steps

- To understand what the hasher does with a password, read [How It Works](./how-it-works.md).
- For every overload, result field, failure reason and exception, see [Hashing and Verifying](./hashing-and-verifying.md).
- To pick a profile for serverless hosts or NIST-only environments, see [Profiles](./profiles.md).
- To add a server-side secret to every hash, see [Peppers](./peppers.md).
- To migrate an existing user table, see [Legacy Formats](./legacy-formats.md) or [Upgrading from 1.x](./upgrading-from-1x.md).
