# Masterly.Hash.AspNetCore

ASP.NET Core integration for [Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash):

- **ASP.NET Core Identity adapter**: `MasterlyIdentityPasswordHasher<TUser>` replaces Identity's `PasswordHasher<TUser>`.
  It still verifies the hashes Identity already wrote (v2 and v3 compatibility modes), so no user is locked out, and
  `UserManager` upgrades each of them to Argon2id on that user's next successful login.
- **503 on overload**: `PasswordHasherBusyExceptionHandler` maps `PasswordHasherBusyException` to `503 Service Unavailable`
  with `Retry-After`.
- **Minimal API DoS guard**: `.WithPasswordLengthLimit()` rejects over-long `SensitiveString` passwords with `400`
  before the handler (and the hasher) runs.

Targets .NET 8 or later.

## Install

```
dotnet add package Masterly.Hash.AspNetCore
```

## Identity

```csharp
builder.Services
    .AddIdentityCore<AppUser>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddMasterlyPasswordHasher();               // optional: o => o.DefaultProfile = HashProfile.Fips2026a
```

`AddMasterlyPasswordHasher`:

1. calls `AddMasterlyHash` (from `Masterly.Hash.DependencyInjection`), so the hasher is the same singleton as
   `IPasswordHasher` everywhere else, and options are validated at startup;
2. sets `ComputeRehashOnVerify = false` (UserManager re-hashes on `SuccessRehashNeeded` itself, so a second hash
   would be wasted work); your `configure` step runs after this and may change it;
3. lowers `ConcurrencyTimeout` from the core default of 30 s to 2 s (unless you set another value): Identity's hasher is
   synchronous, so a queued login blocks a thread-pool thread, and failing fast with 503 beats thread-pool starvation;
4. registers `AspNetIdentityV3Format` and `AspNetIdentityV2Format` from `Masterly.Hash.Legacy` unless you registered
   formats with those ids yourself (e.g. a v3 format with a different iteration cap);
5. replaces the `IPasswordHasher<TUser>` registration and adds `MasterlyPasswordLengthValidator<TUser>`, so
   `CreateAsync`, `ChangePasswordAsync`, `ResetPasswordAsync` and `AddPasswordAsync` return a failed `IdentityResult`
   (code `PasswordTooLong`) for a password over `MaxPasswordBytes` instead of throwing.

Results map one to one: `Success`, `SuccessRehashNeeded` (legacy format, outdated profile or pepper key) and `Failed`
(wrong password, empty password, or an unknown, malformed or over-cost stored hash; the adapter never throws for a bad
stored hash).

Without dependency injection:

```csharp
var options = new PasswordHasherOptions { ComputeRehashOnVerify = false }.AddAspNetIdentityFormats();
var identityHasher = new MasterlyIdentityPasswordHasher<AppUser>(new PasswordHasher(options), options.MaxPasswordBytes);
```

## 503 with Retry-After

```csharp
builder.Services.AddProblemDetails();                 // required by UseExceptionHandler() on .NET 8
builder.Services.AddMasterlyHashExceptionHandler();   // o => o.RetryAfter = TimeSpan.FromSeconds(10)
...
app.UseExceptionHandler();
```

The response is `503`, `Retry-After: <seconds>` (default 5), `Cache-Control: no-store` and a problem details body
(written through `IProblemDetailsService` when one is registered). Other exceptions go to the next handler. Register it
before any catch-all `IExceptionHandler`.

## Password length limit (minimal APIs)

```csharp
public sealed record LoginRequest(string UserName, SensitiveString Password);

app.MapPost("/login", async (LoginRequest request, IPasswordHasher hasher) => { ... })
   .WithPasswordLengthLimit();                        // also works on MapGroup(...)
```

The filter checks every `SensitiveString` argument and every public `SensitiveString` property of an argument (one
level deep) against `PasswordHasherOptions.MaxPasswordBytes`, measured the way the hasher measures it (UTF-8 after NFKC).

## Security notes

- Identity v2 hashes are PBKDF2-HMAC-SHA1 with 1000 iterations. They are upgraded on login, but accounts that never log
  in keep them: consider onion-wrapping them offline with `IPasswordHasher.TryWrap` (see `Masterly.Hash.Legacy`).
- The v3 format refuses stored hashes whose PBKDF2 work exceeds 10,000,000 iterations. That caps, but does not remove,
  the work a tampered row can force: seconds of CPU per attempt, holding a hasher slot. If you never raised Identity's
  `IterationCount` far above its default (100,000), register a tighter cap inside `configure`, e.g.
  `o.AddLegacyFormats(new AspNetIdentityV3Format(1_000_000))`.
- Passwords are length-checked before NFKC normalization (which can expand some characters 18x): input longer than 8x
  `MaxPasswordBytes` is refused from its length alone, both by the Identity adapter and by `.WithPasswordLengthLimit()`.
- `MaxPasswordBytes` (default 1024) also applies to existing Identity users: a longer legacy password no longer verifies,
  so raise the limit during migration if your users have such passwords. A legacy password that verifies but is over the
  limit after NFKC keeps its legacy hash (the adapter reports `Success`, not `SuccessRehashNeeded`).
- `MaxConcurrency` bounds memory under a login flood; map the resulting `PasswordHasherBusyException` to 503 so clients
  back off. Neither the 503 nor the 400 response contains the password or exception details.
- Use `SensitiveString` for password fields so they are redacted from logs and serialized output.
