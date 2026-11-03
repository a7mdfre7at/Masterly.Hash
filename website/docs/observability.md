---
title: Observability
sidebar_label: Observability
description: The Masterly.Hash meter, its instruments and tags, how to export them with OpenTelemetry, and what to log around password checks.
---

Every `PasswordHasher` publishes metrics through `System.Diagnostics.Metrics`. This page lists the instruments and their tags, shows how to export them with OpenTelemetry or watch them with `dotnet-counters`, and explains what to log, and what never to log, around password checks.

## The meter

| Property | Value |
|----------|-------|
| Meter name | `Masterly.Hash`, available as `PasswordHasher.MeterName` and `MasterlyHashBuilder.MeterName` (namespace `Masterly.Hash.DependencyInjection`) |
| Meter version | The version of the `Masterly.Hash` assembly |
| Scope | One static meter per process. Every `PasswordHasher` instance, including `PasswordHasher.Default` and hashers you create yourself, records to it. |

No tag ever contains secret material: no password, no hash, no salt, no pepper key, no key id.

## Instruments

| Instrument | Type | Unit | Tags | Recorded |
|------------|------|------|------|----------|
| `masterly.hash.hashes` | `Counter<long>` | `{hash}` | `profile` | Once per new hash. |
| `masterly.hash.verifications` | `Counter<long>` | `{verification}` | `format`, `outcome`, `reason` | Once per completed verification. |
| `masterly.hash.duration` | `Histogram<double>` | `ms` | `operation` plus `profile` (hash) or `format` (verify) | Once per new hash and once per completed verification. |
| `masterly.hash.busy_rejections` | `Counter<long>` | `{rejection}` | none | Each time a call gives up waiting for a slot and throws `PasswordHasherBusyException`. |

### Tags

| Tag | Values |
|-----|--------|
| `operation` | `hash` or `verify`. Only on `masterly.hash.duration`. |
| `profile` | The id of the profile the hash was made with: `2026a`, `2026c`, `2026f`, or a custom profile id. |
| `format` | `mh` for a native `$mh$` hash (including onion-wrapped ones), the id of the legacy format that handled the stored hash (`v1`, `bcrypt`, `aspnet-identity-v3`, `django-pbkdf2`, ...), or `unknown` when no registered format recognized it. |
| `outcome` | The `VerificationStatus` name: `Success`, `SuccessRehashNeeded` or `Failed`. |
| `reason` | For `Failed`, the `VerificationFailureReason` name (`Mismatch`, `UnknownFormat`, `MalformedHash`, `UnknownProfile`, `UnknownPepperKey`, `PasswordTooLong`). Otherwise the `RehashReason` name: `None` for a current hash, or `LegacyFormat`, `Wrapped`, `OutdatedProfile`, `OutdatedPepperKey`. |

Tag cardinality is small and bounded: profiles and formats come from your registration, and the other tags are enum names.

### What each measurement covers

- **New hashes** include more than `Hash` and `HashAsync` calls. The replacement hash computed during a successful verify of an outdated hash (when `ComputeRehashOnVerify` is on) and every hash created by `TryWrap` are counted too, with the default profile's id.
- **Hash duration** covers salt generation, the wait for a concurrency slot and the key derivation. It does not include the pepper call, which runs before it.
- **Verify duration** covers the pepper call, the wait for a slot, the key derivation and, for an outdated hash with `ComputeRehashOnVerify` on, the replacement hash.
- **For a legacy hash** that fails (`Mismatch`, `PasswordTooLong`), `format` is the first registered format that claimed the string. For a match, it is the format that verified it.

Some calls record nothing:

- `Verify` with a `null` or empty stored hash (`NoStoredHash`), an empty password (`EmptyPassword`) or a password with invalid UTF-16 (`InvalidPassword`). These return before any work is done.
- `VerifyOrDummy` and `VerifyOrDummyAsync` with a `null` stored hash. The dummy verification for an unknown user does the same work as a real one, but it is not counted, so `masterly.hash.verifications` counts only users that exist.
- Calls that end with an exception: `PasswordHasherBusyException` (counted only in `masterly.hash.busy_rejections`), cancellation, or a pepper failure.

## Export with OpenTelemetry

Add the meter by name. With `Masterly.Hash.DependencyInjection` you can use the constant on the builder; without it, use `PasswordHasher.MeterName`.

```csharp title="Program.cs"
using Masterly.Hash;
using OpenTelemetry.Metrics;

builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));

builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics
        .AddMeter(PasswordHasher.MeterName)   // "Masterly.Hash"
        .AddOtlpExporter());
```

`AddOpenTelemetry` comes from the `OpenTelemetry.Extensions.Hosting` package and `AddOtlpExporter` from `OpenTelemetry.Exporter.OpenTelemetryProtocol`. Any other OpenTelemetry exporter works the same way.

Argon2id hashes typically take tens to hundreds of milliseconds. If the default histogram buckets are too coarse for your profile, set your own boundaries with a view:

```csharp title="Program.cs"
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics
        .AddMeter(PasswordHasher.MeterName)
        .AddView("masterly.hash.duration", new ExplicitBucketHistogramConfiguration
        {
            Boundaries = new double[] { 10, 25, 50, 100, 250, 500, 1000, 2500, 5000 },
        })
        .AddOtlpExporter());
```

## Watch live with dotnet-counters

```bash
dotnet-counters monitor --process-id <pid> --counters Masterly.Hash
```

This shows the counters and the duration percentiles of a running process without any code change.

## What to watch

| Signal | Query | What it tells you |
|--------|-------|-------------------|
| Migration progress | `masterly.hash.verifications` by `format` | The share of logins still on legacy formats. It should fall toward zero as users log in. See [Upgrade on login](./upgrade-on-login.md). |
| Upgrades | `outcome = SuccessRehashNeeded` by `reason` | Logins that triggered a rehash: after a profile change (`OutdatedProfile`), a pepper rotation (`OutdatedPepperKey`) or for legacy and wrapped hashes. |
| Failed logins | `outcome = Failed`, `reason = Mismatch` | Wrong passwords. A sudden rise can mean credential stuffing; see [Attack detection](./attack-detection.md). |
| Configuration errors | `reason = UnknownPepperKey` or `UnknownProfile` | A pepper key was removed before its hashes were rehashed, or a profile was dropped from the registration. See [Peppers](./peppers.md) and [Profiles](./profiles.md). |
| Damaged rows | `reason = MalformedHash` or `format = unknown` | Stored hashes that cannot be parsed or are in no registered format. Audit the table; see [Auditing hash tables](./auditing-hash-tables.md). |
| Over-long input | `reason = PasswordTooLong` | Passwords above `MaxPasswordBytes`. |
| Saturation | `masterly.hash.busy_rejections` above zero | Logins arrive faster than `MaxConcurrency` slots free up. Clients got `PasswordHasherBusyException` (503 with the ASP.NET Core handler). See [Limits and concurrency](./limits-and-concurrency.md). |
| Latency | `masterly.hash.duration` p95 and p99 by `operation` | Time per hash, including queueing for a slot. When p99 approaches `ConcurrencyTimeout`, rejections follow. |

:::tip

Duration includes the wait for a concurrency slot, so rising latency with a steady `profile` usually means queueing, not a slower machine. Compare it with `busy_rejections` and the [Performance](./performance.md) numbers for your profile.

:::

## Measure in tests

The meter is process-wide, so a `MeterListener` sees measurements from every hasher in the process. Filter by instrument and run such tests without parallel hashing work, or assert only on lower bounds.

```csharp title="BusyRejectionTests.cs"
using System.Diagnostics.Metrics;
using System.Threading;
using Masterly.Hash;

long rejections = 0;

using MeterListener listener = new MeterListener();
listener.InstrumentPublished = (instrument, meterListener) =>
{
    if (instrument.Meter.Name == PasswordHasher.MeterName)
    {
        meterListener.EnableMeasurementEvents(instrument);
    }
};
listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
{
    if (instrument.Name == "masterly.hash.busy_rejections")
    {
        Interlocked.Add(ref rejections, measurement);
    }
});
listener.Start();
```

For fast hashers in tests, see [Testing](./testing.md).

## Logging

The core library does not log. It reports outcomes through `PasswordVerificationResult` and the metrics above, and throws exceptions whose messages never contain the password, the stored hash or key material.

| Source | Logger category | Level | Message |
|--------|-----------------|-------|---------|
| `PasswordHasherBusyExceptionHandler` | `Masterly.Hash.AspNetCore.PasswordHasherBusyExceptionHandler` | Warning | `The password hasher is at its concurrency limit; responding 503 with Retry-After {RetryAfter}s.` |
| `PasswordHasherBusyExceptionHandler` | same | Warning | "The password hasher is at its concurrency limit, but the response has already started; cannot send 503." |
| Options validation (`Masterly.Hash.DependencyInjection`) | startup exception | | Names settings and key ids only, never key text or key bytes. |

See [ASP.NET Core Identity](./aspnetcore-identity.md#answer-overload-with-503) for the handler.

### Logging your own login events

Log the outcome, not the input. `VerificationFailureReason` and `RehashReason` are meant for logs and metrics, never for the end user: tell the user only that the login failed.

```csharp title="LoginService.cs"
PasswordVerificationResult result = await _hasher.VerifyOrDummyAsync(password, storedHash, cancellationToken);

_logger.LogInformation(
    "Login for {UserId}: {Status} ({FailureReason}, {RehashReason})",
    userId, result.Status, result.FailureReason, result.RehashReason);
```

- Never log the password, the stored hash or `PasswordVerificationResult.Rehash`. The `MH0004` analyzer flags passwords passed to logging calls; see [Analyzers](./analyzers.md).
- Declare password fields as `SensitiveString`. Its `ToString()`, debugger display and JSON serialization all show `***`, so a request model logged by mistake does not leak the password.
- `PasswordVerificationResult.ToString()` returns `Success`, `SuccessRehashNeeded (<reason>)` or `Failed (<reason>)` and is safe to log.
- Do not log the user name for failed logins of unknown accounts if user enumeration matters to you; see [User enumeration](./user-enumeration.md).

## Tracing

Masterly.Hash has no `ActivitySource`. A password check runs inside the request span your web framework already creates; the duration histogram gives the hashing share of it. To see hashing as its own span, wrap the call in an `Activity` from your own `ActivitySource`, and do not add the password or hash as span attributes.

## See also

- [Limits and concurrency](./limits-and-concurrency.md)
- [Upgrade on login](./upgrade-on-login.md)
- [Attack detection](./attack-detection.md)
- [Dependency Injection](./dependency-injection.md)
- [Performance](./performance.md)
