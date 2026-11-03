---
title: "Performance"
sidebar_label: "Performance"
description: "What each profile costs in time and memory, how to choose a profile and a concurrency limit for your hardware, and how to run the benchmarks."
---

A password hash is slow on purpose: the cost you pay per login is the cost an attacker pays per guess. This page shows what the built-in profiles cost, how to choose a profile and a concurrency limit for your hosts, what to monitor, and how to run the benchmark suite yourself.

## What a hash costs

The published numbers come from the benchmark suite's quick mode on an AMD Ryzen 9 7950X with .NET 10, on one thread, as the median of 15 runs:

| Profile | Algorithm | Parameters | Hash | Verify | Allocated per call |
|---------|-----------|------------|-----:|-------:|-------------------:|
| `2026a` (`HashProfile.Server2026a`, default) | Argon2id | m=64 MiB, t=3, p=1 | 170.6 ms | 176.9 ms | 64.3 MiB |
| `2026c` (`HashProfile.Constrained2026a`) | Argon2id | m=19 MiB, t=2, p=1 | 35.1 ms | 33.1 ms | 19.2 MiB |
| `2026f` (`HashProfile.Fips2026a`) | PBKDF2-HMAC-SHA512 | 210,000 iterations | 80.2 ms | 81.5 ms | under 0.1 MiB |

Other operations, from the same run:

| Operation | Cost |
|-----------|------|
| Verify a Masterly.Hash 1.x hash (salted SHA-512) | 5.4 µs |
| Verify a 1.x hash including its rehash to `2026a` (the first login after upgrading) | 184 ms |
| `HmacPepper.Apply` (one HMAC-SHA256) | 0.7 µs |

Your hardware will differ: cloud vCPUs are often much slower per thread than a desktop CPU. Measure on the machines that will serve logins; see [Choosing a profile](#choosing-a-profile).

**What these numbers tell you.**

- **Verify costs the same as hash.** Verification recomputes the hash with the stored salt, so a login costs one hash. A wrong password costs the same as a right one (the `VerifyWrongPassword` benchmark measures this), so timing does not reveal whether a guess was close.
- **Argon2id memory is real allocation.** Each `2026a` call allocates about 64 MiB of managed memory and each `2026c` call about 19 MiB. That memory, not CPU, is usually what limits how many logins a host can run at once.
- **PBKDF2 is CPU only.** `2026f` allocates almost nothing, but it is not memory-hard, so GPUs attack it far more cheaply than Argon2id. Use it only where you must use NIST-approved primitives.
- **Parsing is cheap.** `Inspect` and `NeedsRehash` never run the key-derivation function, so you can call them on every row of a table. See [Auditing hash tables](./auditing-hash-tables.md).
- **A pepper is almost free locally.** `HmacPepper` adds well under a microsecond. A remote pepper ([HashiCorp Vault](./hashicorp-vault.md), [AWS KMS](./aws-kms.md), [Azure Key Vault](./azure-key-vault.md)) adds a network round trip to every hash and verify instead; use the async methods with those.

## Choosing a profile

**1. Measure on production hardware.** Run the [`bench` command](./command-line-tool.md#bench) on a machine like the ones that serve logins, with the latency you can accept for one hash:

```bash
masterly-hash bench --target-ms 250
```

It times each built-in profile (one warm-up run, then the median of five) and recommends `Server2026a` when `2026a` takes no longer than the target, and `Constrained2026a` otherwise.

**2. Pick the profile.**

| Situation | Profile |
|-----------|---------|
| Web backends where `2026a` fits your latency target | `2026a` (the default) |
| Serverless functions, small containers, or hosts where `2026a` is too slow or uses too much memory | `2026c` |
| Only NIST-approved primitives are allowed (for example a FIPS 140 policy) | `2026f` |

```csharp title="Program.cs"
using Masterly.Hash;

builder.Services.AddMasterlyHash(options => options.DefaultProfile = HashProfile.Constrained2026a);
```

Changing the default never breaks existing logins: every hasher registers all three built-in profiles, and hashes made with the old default are replaced on the next successful login. See [Profiles](./profiles.md) and [Upgrade on login](./upgrade-on-login.md).

**3. Do not go below `2026c`.** `2026c` is the OWASP minimum for Argon2id (19 MiB, two passes). If even `2026c` is over your target, add capacity or lower the concurrency limit instead. Custom profiles below the OWASP minimums are refused unless you set `PasswordHasherOptions.AllowWeakProfiles`, which exists only for tests.

:::warning

Do not lower the cost to make a load test pass. A cheaper profile makes every stored hash cheaper to crack, for as long as those hashes exist. Scale the login tier instead.

:::

## Sizing concurrency and memory

The hasher limits how many hashes run at once with `PasswordHasherOptions.MaxConcurrency`, so a login flood cannot exhaust memory:

| Option | Default | Effect |
|--------|---------|--------|
| `MaxConcurrency` | `Environment.ProcessorCount` | Maximum hashes and verifications computed at the same time. `0` disables the limit. |
| `ConcurrencyTimeout` | 30 seconds | How long a call waits for a free slot before it throws `PasswordHasherBusyException`. |

With ASP.NET Core Identity, `AddMasterlyPasswordHasher` lowers the timeout to 2 seconds if you left it at the default, because Identity's hasher interface is synchronous and a waiting login blocks a thread-pool thread.

**Peak memory** for password hashing is about `MaxConcurrency` × the profile's memory:

| `MaxConcurrency` | `2026a` (64 MiB) | `2026c` (19 MiB) |
|-----------------:|-----------------:|-----------------:|
| 2 | 128 MiB | 38 MiB |
| 4 | 256 MiB | 76 MiB |
| 8 | 512 MiB | 152 MiB |
| 16 | 1 GiB | 304 MiB |

Add headroom on top: the garbage collector does not hand freed Argon2 buffers back to the operating system at once, so the process working set can stay above this for a while.

**Throughput** is bounded by `MaxConcurrency` ÷ the time per hash. On a host where `2026a` takes 171 ms, a limit of 8 allows at most about 8 ÷ 0.171 ≈ 47 logins per second; beyond that, calls queue and then fail with `PasswordHasherBusyException`. Size `MaxConcurrency` so that peak memory fits the container's memory limit, and add instances when you need more logins per second.

```csharp title="Program.cs"
using System;
using Masterly.Hash;

builder.Services.AddMasterlyHash(options =>
{
    options.DefaultProfile = HashProfile.Constrained2026a;   // 19 MiB per hash
    options.MaxConcurrency = 8;                              // at most about 152 MiB in flight
    options.ConcurrencyTimeout = TimeSpan.FromSeconds(5);
});

// Answer PasswordHasherBusyException with 503 and Retry-After (Masterly.Hash.AspNetCore).
builder.Services.AddProblemDetails();
builder.Services.AddMasterlyHashExceptionHandler();
```

Map the busy exception to `503 Service Unavailable` so clients back off instead of retrying at once. `AddMasterlyHashExceptionHandler` does that with a `Retry-After` header of 5 seconds by default; it needs `app.UseExceptionHandler()` in the pipeline. See [Limits and concurrency](./limits-and-concurrency.md) for the details.

**Prefer the async methods** (`HashAsync`, `VerifyAsync`, `VerifyOrDummyAsync`) in request handlers. They wait for a slot asynchronously, so a queue of logins does not hold thread-pool threads, and they are the only path that uses a remote pepper's asynchronous API.

## Costs you might not expect

- **The first login after an upgrade costs two operations.** Verifying a legacy or outdated hash and producing its replacement means a legacy verify plus a new hash: for a 1.x hash, 5.4 µs plus about 180 ms for `2026a`. If many users return at once after a migration, expect a burst of full-cost hashes. `ComputeRehashOnVerify = false` skips computing the replacement during verification (then `Rehash` is `null` and your code must hash the password itself), which moves the cost but does not remove it.
- **Unknown users cost a full verification.** `VerifyOrDummy` with a `null` stored hash verifies against a dummy hash, so a login for an account that does not exist takes as long as one that does. That is the point (see [User enumeration](./user-enumeration.md)); budget for it when sizing against credential-stuffing traffic. The `VerifyOrDummyBenchmarks` ratio should be close to 1.00.
- **Onion wrapping a table is offline work.** Wrapping costs one full hash per row. At 171 ms per `2026a` hash, a million rows is about 47 hours of single-core time, or about six hours with 8 hashes in parallel. Plan it as a batch job; see [Onion wrapping](./onion-wrapping.md).
- **Tests do not need the real cost.** Use `FastPasswordHasher` from `Masterly.Hash.Testing`, which runs the production code path with a 64 KiB profile. See [Testing](./testing.md).

## Monitoring in production

The hasher publishes metrics on the `System.Diagnostics.Metrics` meter `Masterly.Hash` (the constant `PasswordHasher.MeterName`). No tag ever contains secret material.

| Instrument | Type | Unit | Tags | What to watch |
|------------|------|------|------|---------------|
| `masterly.hash.duration` | Histogram | ms | `operation` (`hash` or `verify`), plus `profile` for hashes or `format` for verifications | p95 and p99 latency per operation. The time includes waiting for a concurrency slot. |
| `masterly.hash.hashes` | Counter | `{hash}` | `profile` | New hashes, including replacements computed during verification and wrapped hashes. |
| `masterly.hash.verifications` | Counter | `{verification}` | `format`, `outcome`, `reason` | Login volume, failure reasons and how many legacy hashes remain. |
| `masterly.hash.busy_rejections` | Counter | `{rejection}` | | Calls rejected at the concurrency limit. Any steady value means the login tier is undersized. |

A rising `duration` with a flat request rate usually means noisy neighbours or CPU throttling. A non-zero `busy_rejections` means you need more instances or a higher `MaxConcurrency` (if memory allows). See [Observability](./observability.md) for wiring the meter into OpenTelemetry.

## Running the benchmarks

The suite lives in [`perf/Masterly.Hash.Benchmarks`](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/perf/Masterly.Hash.Benchmarks/README.md). It is a console app for local runs, built with [BenchmarkDotNet](https://benchmarkdotnet.org/) 0.15.8. It targets `net10.0`, so you need the .NET 10 SDK. It is never packed or shipped.

Always build in Release, and run from the repository root:

```bash
# Quick mode: a Stopwatch-based run that prints Markdown tables (the CHANGELOG numbers come from here)
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --quick
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --quick --runs 31 --warmup 3

# The full BenchmarkDotNet suite, with an interactive picker
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks

# One class, or everything
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --filter '*ProfileBenchmarks*'
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --filter '*'

# Smoke test: one cold iteration per benchmark, in-process
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --filter '*' --job Dry --inProcess
```

Any arguments without `--quick` go to BenchmarkDotNet's `BenchmarkSwitcher`, so all its options work (`--list flat`, `--job short`, `--exporters json`, `--artifacts <dir>`). Results are written to `BenchmarkDotNet.Artifacts/`. The process exits with 1 if a benchmark has critical validation errors.

### Quick mode

Quick mode takes about 20 seconds with the defaults and is what you run to compare two machines or two builds.

| Option | Default | Range |
|--------|---------|-------|
| `--runs N` | 15 | 1 to 10,000 |
| `--warmup N` | 2 | 0 to 10,000 |

Any other argument prints a usage line and exits with code 2. The output starts with the machine (CPU model, logical cores, architecture, OS, .NET version, GC mode and build configuration; a Debug build is flagged as not representative), then three tables:

1. **Hash cost per profile:** `| Profile | Algorithm | Params | Median ms | Allocated MiB |`. The median time and managed allocation of one `Hash` call. This is the table that goes into `CHANGELOG.md`.
2. **Verify cost per profile:** the median of verifying the correct password, and the peak working set delta. The peak is measured over all calls for a profile, so it includes Argon2 buffers the GC has not collected yet; the memory one call needs is the Allocated column.
3. **Other operations:** 1.x verify with and without the rehash to `2026a`, `HmacPepper.Apply`, `2026c` verify with and without a pepper, `VerifyOrDummy` for a known and an unknown user, and `Inspect` on a Masterly, a 1.x and a malformed hash. Microsecond-scale operations are timed in batches of 2,000 calls.

Quick mode uses one thread, no concurrency limit and a 16-character ASCII password, so the numbers show the cost of one call, not throughput under load. Profiles are measured cheapest-memory first, so one profile's peak memory does not hide another's.

### The BenchmarkDotNet classes

Every class uses `[MemoryDiagnoser]`, so Argon2id memory shows up in the Allocated column.

| Class | Benchmarks | Baseline |
|-------|------------|----------|
| `ProfileBenchmarks` | `Hash`, `Verify` and `VerifyWrongPassword`, for each of `2026a`, `2026c` and `2026f` | |
| `LegacyBenchmarks` | `V1FormatVerify` (the raw 1.x format check, which tries SHA-512, SHA-384 and SHA-256), `V1Verify` (through the hasher, no rehash) and `V1VerifyAndRehash` (with the upgrade to `2026a`) | `V1FormatVerify` |
| `PepperBenchmarks` | `PepperApply` (one HMAC-SHA256), `VerifyPlain` and `VerifyPeppered`, on `2026c` | `VerifyPlain` |
| `VerifyOrDummyBenchmarks` | `KnownUser` and `UnknownUser` (`VerifyOrDummy` with `null`); the ratio should be close to 1.00 | `KnownUser` |
| `InspectBenchmarks` | `Inspect` on a current peppered hash, an unpeppered hash, another profile, a 1.x hash and a malformed hash, and `NeedsRehash` | `InspectCurrent` |

Every class except `InspectBenchmarks` (which never verifies) checks during setup that its stored hash actually verifies, so a broken setup fails instead of timing an early-out failure path. The benchmarks use a fixed test password and randomly generated pepper keys, and never touch the network.

### Getting stable numbers

- Build in Release. Quick mode labels a Debug build as not representative.
- Close other heavy applications, plug in laptops and use a fixed power plan. BenchmarkDotNet switches Windows to the High Performance plan while it runs.
- Run on the hardware you deploy to. Desktop CPUs with high boost clocks are much faster per thread than most cloud vCPUs.
- For publishable numbers, use the BenchmarkDotNet suite rather than quick mode.

## See also

- [Profiles](./profiles.md)
- [Limits and concurrency](./limits-and-concurrency.md)
- [Observability](./observability.md)
- [Command-line tool: bench](./command-line-tool.md#bench)
- [Benchmarks README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/perf/Masterly.Hash.Benchmarks/README.md)
