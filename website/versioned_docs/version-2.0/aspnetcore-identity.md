---
title: ASP.NET Core Identity
sidebar_label: ASP.NET Core Identity
description: Replace Identity's password hasher with Masterly.Hash, keep existing users logging in, answer overload with 503 and reject over-long passwords early.
---

`Masterly.Hash.AspNetCore` connects Masterly.Hash to ASP.NET Core. It gives you three things:

- An ASP.NET Core Identity adapter, `MasterlyIdentityPasswordHasher<TUser>`, that replaces Identity's `PasswordHasher<TUser>`. It still verifies the hashes Identity already wrote, and `UserManager` upgrades each one to Argon2id on that user's next successful login.
- An exception handler that turns `PasswordHasherBusyException` into `503 Service Unavailable` with `Retry-After`.
- A minimal API endpoint filter that rejects over-long passwords with `400` before the handler, and the hasher, run.

```bash
dotnet add package Masterly.Hash.AspNetCore
```

The package targets `net8.0`. It references `Masterly.Hash`, `Masterly.Hash.Legacy` and `Masterly.Hash.DependencyInjection`, so you do not need to add those yourself.

The registration methods live in framework namespaces, so they need no extra `using`: `AddMasterlyPasswordHasher` and `AddMasterlyHashExceptionHandler` are in `Microsoft.Extensions.DependencyInjection`, and `WithPasswordLengthLimit` is in `Microsoft.AspNetCore.Builder`. The types (`MasterlyIdentityPasswordHasher<TUser>`, `MasterlyPasswordLengthValidator<TUser>`, `PasswordHasherBusyExceptionHandler`, `MasterlyHashExceptionHandlerOptions`, `PasswordLengthEndpointFilter` and the `AddAspNetIdentityFormats` extension) are in `Masterly.Hash.AspNetCore`.

:::note

`Microsoft.AspNetCore.Identity` also defines `PasswordHasherOptions` and `PasswordVerificationResult`. In a file that imports both `Masterly.Hash` and `Microsoft.AspNetCore.Identity`, those names are ambiguous (`CS0104`). Qualify them or add an alias such as `using MasterlyHasherOptions = Masterly.Hash.PasswordHasherOptions;`.

:::

## Replace the Identity password hasher

**1. Call `AddMasterlyPasswordHasher` on the Identity builder.** It works on the builder returned by `AddIdentity`, `AddIdentityCore` or `AddDefaultIdentity`.

```csharp title="Program.cs"
using Masterly.Hash;
using Microsoft.AspNetCore.Identity;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddIdentityCore<AppUser>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddMasterlyPasswordHasher();
```

**2. Keep using `UserManager` and `SignInManager` as before.** New passwords are hashed with Argon2id. Existing Identity hashes verify, report `SuccessRehashNeeded`, and `UserManager` stores the new hash.

**3. Optionally adjust the options.** The callback receives the Masterly.Hash `PasswordHasherOptions`:

```csharp title="Program.cs"
using Masterly.Hash;

builder.Services
    .AddIdentityCore<AppUser>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddMasterlyPasswordHasher(options => options.DefaultProfile = HashProfile.Fips2026a);
```

### What `AddMasterlyPasswordHasher` does

It calls `AddMasterlyHash` from [Dependency Injection](./dependency-injection.md), so the hasher is the same validated singleton every other `IPasswordHasher` consumer gets, then adds one configure step that runs in this order:

1. Sets `ComputeRehashOnVerify` to `false`. `UserManager` re-hashes on its own when it gets `SuccessRehashNeeded`, so a second hash computed during verification would be wasted work.
2. Lowers `ConcurrencyTimeout` to 2 seconds (`MasterlyIdentityBuilderExtensions.IdentityConcurrencyTimeout`) if it is still the core default of 30 seconds. Identity's hasher interface is synchronous, so a login waiting for a slot blocks a thread-pool thread. A short wait turns a login flood into fast 503s instead of thread-pool starvation.
3. Runs your `configure` callback, which may override anything above.
4. Adds the ASP.NET Core Identity v3 and v2 formats (`AspNetIdentityV3Format.Default` and `AspNetIdentityV2Format.Instance`), unless formats with the ids `aspnet-identity-v3` or `aspnet-identity-v2` are already registered. They are inserted ahead of the built-in 1.x format.

It also:

- removes every existing `IPasswordHasher<TUser>` registration and adds `MasterlyIdentityPasswordHasher<TUser>` as a scoped service;
- adds `MasterlyPasswordLengthValidator<TUser>` as an `IPasswordValidator<TUser>` (once, alongside Identity's own validator).

The step is registered for the shared hasher, so these settings apply to every consumer of `IPasswordHasher` in the application, not only to Identity.

:::note

If you also call `AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"))`, the configuration is applied first and this step after it. So `ComputeRehashOnVerify` from configuration is always overridden to `false`, and a configured `ConcurrencyTimeout` of exactly `00:00:30` is lowered to 2 seconds. Set either value inside the `configure` callback to keep it.

:::

### Result mapping

`VerifyHashedPassword` maps the Masterly.Hash result one to one:

| Masterly.Hash `VerificationStatus` | Identity `PasswordVerificationResult` |
|------------------------------------|---------------------------------------|
| `Success` | `Success` |
| `SuccessRehashNeeded` (legacy format, wrapped hash, outdated profile or pepper key) | `SuccessRehashNeeded` |
| `Failed` (any `VerificationFailureReason`) | `Failed` |

The adapter never throws for a bad stored hash. A `null`, empty, malformed, unrecognized or over-cost stored hash returns `Failed`.

| Method | Throws |
|--------|--------|
| `HashPassword(user, password)` | `ArgumentNullException` for a `null` password. `ArgumentException` for an empty password or one over `MaxPasswordBytes`. `PasswordHasherBusyException` at the concurrency limit. |
| `VerifyHashedPassword(user, hashedPassword, providedPassword)` | `ArgumentNullException` for a `null` provided password. `PasswordHasherBusyException` at the concurrency limit. |

The `user` argument is not used: Masterly hashes carry their own salt.

### Password length checks

Passwords are length-checked before any normalization work. A password longer than 8 times `MaxPasswordBytes` in UTF-16 code units is refused from its length alone, because NFKC normalization can expand some characters up to 18 times (U+FDFA, for example). `VerifyHashedPassword` returns `Failed` for such a value, and `HashPassword` throws `ArgumentException`.

`MasterlyPasswordLengthValidator<TUser>` makes `UserManager.CreateAsync`, `AddPasswordAsync`, `ChangePasswordAsync` and `ResetPasswordAsync` return a failed `IdentityResult` instead of letting the hasher throw. Identity's own validator has no maximum length.

| Case | `IdentityError.Code` | Description |
|------|----------------------|-------------|
| Empty password | `PasswordRequired` | "A password is required." |
| Over `MaxPasswordBytes` (UTF-8 after NFKC) | `PasswordTooLong` | "Passwords must be at most 1024 bytes long." (with the configured limit) |

The codes are available as `MasterlyPasswordLengthValidator<TUser>.PasswordRequiredCode` and `PasswordTooLongCode`.

A legacy hash that verifies but whose password is over `MaxPasswordBytes` after NFKC (legacy formats measure raw UTF-8, new hashes measure UTF-8 after NFKC) is reported as `Success`, not `SuccessRehashNeeded`. The still-valid legacy hash is kept instead of making `UserManager` re-hash and throw.

### Custom Identity formats

`AspNetIdentityV3Format.Default` refuses stored hashes whose PBKDF2 work exceeds `AspNetIdentityV3Format.DefaultMaxIterations` (10,000,000). That caps the work a tampered row can force, but 10 million iterations is still seconds of CPU per attempt while holding a hasher slot. If you never raised Identity's `IterationCount` far above its default of 100,000, register a tighter cap inside `configure`:

```csharp title="Program.cs"
using Masterly.Hash;
using Masterly.Hash.Legacy;

builder.Services
    .AddIdentityCore<AppUser>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddMasterlyPasswordHasher(options => options.AddLegacyFormats(new AspNetIdentityV3Format(1_000_000)));
```

Because a format with the id `aspnet-identity-v3` is now registered, step 4 skips the default instance.

:::warning

Register custom Identity format instances inside the `configure` callback, not through `MasterlyHashBuilder.AddLegacyFormat`. A builder step registered after `AddMasterlyPasswordHasher` runs after the default formats were added, and startup validation then reports a duplicate format id.

:::

### Without dependency injection

```csharp title="IdentitySetup.cs"
using Masterly.Hash;
using Masterly.Hash.AspNetCore;

PasswordHasherOptions options = new PasswordHasherOptions { ComputeRehashOnVerify = false }.AddAspNetIdentityFormats();
MasterlyIdentityPasswordHasher<AppUser> identityHasher =
    new MasterlyIdentityPasswordHasher<AppUser>(new PasswordHasher(options), options.MaxPasswordBytes);
```

`AddAspNetIdentityFormats` is an extension on `PasswordHasherOptions`. It adds both Identity formats, leaves a format whose id is already registered in place, and returns the same options. Pass the `MaxPasswordBytes` the hasher was built with; the constructor throws `ArgumentOutOfRangeException` for a limit below 1.

## Answer overload with 503

When the hasher is at its concurrency limit for longer than `ConcurrencyTimeout`, it throws `PasswordHasherBusyException` (see [Limits and concurrency](./limits-and-concurrency.md)). `PasswordHasherBusyExceptionHandler` maps it to `503 Service Unavailable` so clients back off instead of piling on.

```csharp title="Program.cs"
builder.Services.AddProblemDetails();                  // UseExceptionHandler() needs it on .NET 8
builder.Services.AddMasterlyHashExceptionHandler();

WebApplication app = builder.Build();
app.UseExceptionHandler();
```

The response has:

- status `503`;
- `Retry-After` in whole seconds (default `5`);
- `Cache-Control: no-store`;
- a problem details body with title `Service Unavailable`, detail `The server is busy. Try again later.` and type `https://tools.ietf.org/html/rfc9110#section-15.6.4`. It is written through `IProblemDetailsService` when one is registered, otherwise as `application/problem+json`.

Neither the body nor the headers contain the password or exception details.

| Option | Default | Range |
|--------|---------|-------|
| `MasterlyHashExceptionHandlerOptions.RetryAfter` | 5 seconds | 1 second to 1 day. Rounded up to whole seconds. Outside the range the setter throws `ArgumentOutOfRangeException`. |

```csharp title="Program.cs"
builder.Services.AddMasterlyHashExceptionHandler(options => options.RetryAfter = TimeSpan.FromSeconds(10));
```

How the handler behaves:

- It handles a `PasswordHasherBusyException` thrown directly or wrapped as an inner exception, including inside an `AggregateException`, up to 8 levels deep. Other exceptions go to the next handler.
- If the response has already started, it logs a warning and leaves the exception to the next handler.
- It logs a warning for every 503: `The password hasher is at its concurrency limit; responding 503 with Retry-After {RetryAfter}s.`
- Calling `AddMasterlyHashExceptionHandler` twice registers the handler once and only adds configure steps.

:::note

Exception handlers run in registration order. Call `AddMasterlyHashExceptionHandler` before you register any catch-all `IExceptionHandler`.

:::

## Limit password length on minimal APIs

`.WithPasswordLengthLimit()` adds `PasswordLengthEndpointFilter`, which rejects a request with `400 Bad Request` before the handler runs when a password exceeds `MaxPasswordBytes`. Declare password fields as `SensitiveString` so the filter can find them and so they are redacted from logs and serialized output.

```csharp title="Program.cs"
using Masterly.Hash;

app.MapPost("/login", async (LoginRequest request, IPasswordHasher hasher, IUserStore users, CancellationToken cancellationToken) =>
    {
        string? storedHash = await users.FindPasswordHashAsync(request.UserName, cancellationToken);
        PasswordVerificationResult result =
            await hasher.VerifyOrDummyAsync(request.Password.Reveal(), storedHash, cancellationToken);
        return result.IsMatch ? Results.Ok() : Results.Unauthorized();
    })
    .WithPasswordLengthLimit();

public sealed record LoginRequest(string UserName, SensitiveString Password);
```

`IUserStore` is your own repository.

The filter checks:

- every argument of type `SensitiveString`;
- every public, non-indexed `SensitiveString` property of an argument, one level deep (`LoginRequest.Password`).

Plain `string` arguments are not checked. Only the getters of `SensitiveString` properties are invoked.

The length is measured the way the hasher measures it: UTF-8 bytes after NFKC normalization. A value longer than 8 times the limit is rejected from its length alone, so the check itself cannot be used to exhaust memory. The `400` response is a problem details body with title `Password too long` and detail `The password exceeds the maximum length of 1024 bytes.` (with the configured limit). It never echoes the value.

The filter works on single endpoints and on route groups (`app.MapGroup("/account").WithPasswordLengthLimit()`). It reads the limit from `IOptions<PasswordHasherOptions>`, so it requires `AddMasterlyHash` or `AddMasterlyPasswordHasher`. To use a fixed limit, create it with `new PasswordLengthEndpointFilter(maxPasswordBytes)`. Its public `IsTooLong(SensitiveString)` method applies the same check in your own code.

## Security notes

- **Identity v2 hashes are weak.** They are PBKDF2-HMAC-SHA1 with 1000 iterations. They are upgraded on login, but accounts that never log in keep them. Wrap them offline with `IPasswordHasher.TryWrap`; see [Onion wrapping](./onion-wrapping.md).
- **`MaxPasswordBytes` applies to existing users.** With the default of 1024, a legacy password longer than 1024 UTF-8 bytes no longer verifies. Raise the limit during migration if your users have such passwords.
- **Identity calls the synchronous API.** `IPasswordHasher<TUser>` has no async methods, so the adapter calls `Hash` and `Verify`. The HashiCorp Vault and AWS KMS peppers then block a thread for a network round trip on every hash and verify. The Azure Key Vault pepper computes the HMAC locally with a cached key and does not have this cost. Behind Identity, prefer a pepper that keeps the key in memory, and keep `ConcurrencyTimeout` short.
- **Map `PasswordHasherBusyException` to 503.** Without the handler it surfaces as a `500`.
- **Use `SensitiveString` for password fields** in request models. The `MH0004` analyzer flags passwords written to logs; see [Analyzers](./analyzers.md).

## See also

- [Dependency Injection](./dependency-injection.md)
- [Legacy formats](./legacy-formats.md)
- [Upgrade on login](./upgrade-on-login.md)
- [Limits and concurrency](./limits-and-concurrency.md)
- [Entity Framework Core](./entity-framework-core.md)
