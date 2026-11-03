# Masterly.Hash.Benchmarks

Performance measurements for Masterly.Hash. This is a console app for local runs only; it is not packed or shipped.

## What it measures

| Class | Benchmarks |
|---|---|
| `ProfileBenchmarks` | `Hash`, `Verify` and `VerifyWrongPassword` for each built-in profile (`2026a`, `2026c`, `2026f`) |
| `LegacyBenchmarks` | Masterly.Hash 1.x (salted SHA-512) verify: the raw format check, through the hasher, and with the upgrade to `2026a` |
| `PepperBenchmarks` | `HmacPepper.Apply` alone, and `Verify` with and without an `HmacPepper` on the same profile |
| `VerifyOrDummyBenchmarks` | `VerifyOrDummy` for a known user and for `null` (unknown user); the ratio should be close to 1.00 |
| `InspectBenchmarks` | `Inspect` / `NeedsRehash` throughput for current, unpeppered, other-profile, v1 and malformed hashes |

Every class uses `[MemoryDiagnoser]`. Argon2id memory shows up as managed allocations (about 64 MiB per call for `2026a`).

## Running

Always use Release. Run from the repository root:

```bash
# Quick mode: a Stopwatch run that takes about 20 seconds and prints a markdown table for CHANGELOG.md
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --quick
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --quick --runs 31 --warmup 3

# Full BenchmarkDotNet suite (interactive picker)
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks

# One class, or everything
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --filter '*ProfileBenchmarks*'
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --filter '*'

# Smoke test: one cold iteration per benchmark, in-process (no child project build)
dotnet run -c Release --project perf/Masterly.Hash.Benchmarks -- --filter '*' --job Dry --inProcess
```

Anything other than `--quick` goes to BenchmarkDotNet's `BenchmarkSwitcher`, so all of its options work
(`--list flat`, `--job short`, `--exporters json`, `--artifacts <dir>`, ...). Results are written to
`BenchmarkDotNet.Artifacts/`.

## Quick mode output

Quick mode prints the machine (CPU model, OS, .NET version, GC mode, build configuration) and then:

- `| Profile | Algorithm | Params | Median ms | Allocated MiB |`: median time and managed allocation of one `Hash` call
  per built-in profile. This is the table that goes into `CHANGELOG.md`.
- Verify median and the peak working set delta per profile. The peak is measured over all calls for a profile, so it
  also counts Argon2 buffers the GC has not collected yet. The memory one call needs is the Allocated column.
- Microsecond-scale operations (v1 verify, pepper, `VerifyOrDummy`, `Inspect`), timed in batches.

Quick mode runs on a single thread with no concurrency limit, so the numbers show the cost of one call.
For publishable numbers, use the BenchmarkDotNet suite.

## Notes

- To get stable numbers, close other heavy applications, plug in laptops, and use a fixed power plan.
  BenchmarkDotNet switches Windows to the High Performance plan while it runs.
- Login latency is a choice you make. If `2026a` is too slow or uses too much memory on your hosts, use `2026c`
  (`HashProfile.Constrained2026a`). Do not use weaker custom profiles.
- The benchmarks use a fixed test password and random pepper keys. They never touch the network.
