using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime;
using System.Threading;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Benchmarks
{
    /// <summary>
    /// <c>--quick</c>: a Stopwatch-based measurement that finishes in seconds and prints a markdown table for the
    /// CHANGELOG. Use the BenchmarkDotNet suite for publishable numbers.
    /// </summary>
    internal static class QuickRunner
    {
        public const string Flag = "--quick";
        private const int DefaultRuns = 15;
        private const int DefaultWarmup = 2;
        private const int MaxRuns = 10_000;
        private const int MicroBatch = 2_000;
        private const double MiB = 1024.0 * 1024.0;

        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        /// <summary>True if the arguments ask for quick mode.</summary>
        public static bool IsRequested(string[] args) => Array.IndexOf(args, Flag) >= 0;

        /// <summary>Runs the quick measurement. Returns the process exit code.</summary>
        public static int Run(string[] args, TextWriter output)
        {
            if (args == null) throw new ArgumentNullException(nameof(args));
            if (output == null) throw new ArgumentNullException(nameof(output));

            if (!TryParse(args, out int runs, out int warmup, out string? error))
            {
                output.WriteLine(error);
                output.WriteLine("Usage: --quick [--runs N] [--warmup N]");
                return 2;
            }

            output.WriteLine("# Masterly.Hash quick benchmark");
            output.WriteLine();
            foreach (string line in MachineInfo.Describe())
                output.WriteLine("- " + line);
            output.WriteLine($"- Method: median of {runs} runs per profile after {warmup} warm-up runs; single thread; password of 16 ASCII chars");
            output.WriteLine();

            // Measure cheapest-memory first so each profile's peak is not hidden by an earlier, larger one.
            var results = new Dictionary<string, ProfileResult>(StringComparer.Ordinal);
            foreach (HashProfile profile in BenchmarkData.BuiltInProfiles)
                results[profile.Id] = MeasureProfile(profile, runs, warmup);

            output.WriteLine("| Profile | Algorithm | Params | Median ms | Allocated MiB |");
            output.WriteLine("|---|---|---|---:|---:|");
            foreach (HashProfile profile in new[] { HashProfile.Server2026a, HashProfile.Constrained2026a, HashProfile.Fips2026a })
            {
                ProfileResult r = results[profile.Id];
                output.WriteLine($"| {profile.Id} | {AlgorithmName(profile)} | {Params(profile)} | {Ms(r.HashMedianMs)} | {r.AllocatedMiB.ToString("F2", Inv)} |");
            }

            output.WriteLine();
            output.WriteLine("Median ms and Allocated MiB are per Hash call. Verify of a matching password:");
            output.WriteLine();
            output.WriteLine("| Profile | Verify median ms | Peak working set delta MiB |");
            output.WriteLine("|---|---:|---:|");
            foreach (HashProfile profile in new[] { HashProfile.Server2026a, HashProfile.Constrained2026a, HashProfile.Fips2026a })
            {
                ProfileResult r = results[profile.Id];
                output.WriteLine($"| {profile.Id} | {Ms(r.VerifyMedianMs)} | {r.PeakWorkingSetDeltaMiB.ToString("F1", Inv)} |");
            }
            output.WriteLine();
            output.WriteLine("Peak working set delta is measured over all calls of a profile, so it includes Argon2 buffers the GC");
            output.WriteLine("has not collected yet; the memory one call needs is Allocated MiB.");

            output.WriteLine();
            output.WriteLine("| Operation | Median | Allocated |");
            output.WriteLine("|---|---:|---:|");
            foreach (OtherResult r in MeasureOthers(runs, warmup))
                output.WriteLine($"| {r.Name} | {r.Median} | {r.Allocated} |");

            return 0;
        }

        private static bool TryParse(string[] args, out int runs, out int warmup, out string? error)
        {
            runs = DefaultRuns;
            warmup = DefaultWarmup;
            error = null;
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == Flag)
                    continue;
                if (arg == "--runs" || arg == "--warmup")
                {
                    if (i + 1 >= args.Length ||
                        !int.TryParse(args[i + 1], NumberStyles.None, Inv, out int value) ||
                        value > MaxRuns || (arg == "--runs" && value < 1))
                    {
                        error = $"{arg} needs an integer between {(arg == "--runs" ? 1 : 0)} and {MaxRuns}.";
                        return false;
                    }
                    if (arg == "--runs") runs = value; else warmup = value;
                    i++;
                    continue;
                }
                error = $"Unknown argument '{arg}'.";
                return false;
            }
            return true;
        }

        private static ProfileResult MeasureProfile(HashProfile profile, int runs, int warmup)
        {
            PasswordHasher hasher = BenchmarkData.Hasher(profile);
            var hashMs = new double[runs];
            var hashBytes = new double[runs];
            string stored;

            // The baseline is taken after the GC has decommitted everything it can, and sampling covers the
            // first call, so memory the GC keeps committed between calls still counts towards the peak.
            long baseline = SettleAndReadWorkingSet();
            long peak;
            using (var sampler = new WorkingSetSampler())
            {
                stored = hasher.Hash(BenchmarkData.Password);
                for (int i = 0; i < warmup; i++)
                {
                    hasher.Hash(BenchmarkData.Password);
                    hasher.Verify(BenchmarkData.Password, stored);
                }

                for (int i = 0; i < runs; i++)
                {
                    long before = GC.GetTotalAllocatedBytes(precise: true);
                    long start = Stopwatch.GetTimestamp();
                    hasher.Hash(BenchmarkData.Password);
                    hashMs[i] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                    hashBytes[i] = GC.GetTotalAllocatedBytes(precise: true) - before;
                }
                peak = sampler.Stop();
            }

            var verifyMs = new double[runs];
            for (int i = 0; i < runs; i++)
            {
                long start = Stopwatch.GetTimestamp();
                PasswordVerificationResult result = hasher.Verify(BenchmarkData.Password, stored);
                verifyMs[i] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                BenchmarkData.EnsureMatch(result, profile.Id);
            }

            return new ProfileResult(
                Median(hashMs), Median(verifyMs), Median(hashBytes) / MiB, Math.Max(0, peak - baseline) / MiB);
        }

        private static IEnumerable<OtherResult> MeasureOthers(int runs, int warmup)
        {
            // v1 legacy verify, without the Argon2id rehash so only the legacy check is timed.
            string v1 = BenchmarkData.V1Hash(BenchmarkData.Password);
            PasswordHasher noRehash = BenchmarkData.Hasher(HashProfile.Server2026a, computeRehash: false);
            BenchmarkData.EnsureMatch(noRehash.Verify(BenchmarkData.Password, v1), "v1 hash");
            yield return Micro("v1 legacy Verify (no rehash)", runs, warmup, () => noRehash.Verify(BenchmarkData.Password, v1));

            // v1 legacy verify including the upgrade to 2026a (the first login after upgrading).
            PasswordHasher withRehash = BenchmarkData.Hasher(HashProfile.Server2026a);
            yield return Macro("v1 legacy Verify + rehash to 2026a", runs, warmup, () => withRehash.Verify(BenchmarkData.Password, v1));

            // Pepper: the HMAC alone, then Verify with and without it on 2026c.
            HmacPepper pepper = BenchmarkData.NewPepper();
            byte[] encoded = HashPrimitives.EncodePassword(BenchmarkData.Password);
            try
            {
                yield return Micro("HmacPepper.Apply (HMAC-SHA256)", runs, warmup, () => pepper.Apply(pepper.CurrentKeyId, encoded));
            }
            finally
            {
                HashPrimitives.Zero(encoded);
            }

            PasswordHasher plain = BenchmarkData.Hasher(HashProfile.Constrained2026a);
            PasswordHasher peppered = BenchmarkData.Hasher(HashProfile.Constrained2026a, pepper);
            string plainHash = plain.Hash(BenchmarkData.Password);
            string pepperedHash = peppered.Hash(BenchmarkData.Password);
            BenchmarkData.EnsureMatch(peppered.Verify(BenchmarkData.Password, pepperedHash), "peppered hash");
            yield return Macro("2026c Verify, no pepper", runs, warmup, () => plain.Verify(BenchmarkData.Password, plainHash));
            yield return Macro("2026c Verify, HmacPepper", runs, warmup, () => peppered.Verify(BenchmarkData.Password, pepperedHash));

            // User-enumeration protection: an unknown user should cost about the same as a known one.
            PasswordHasher server = BenchmarkData.Hasher(HashProfile.Server2026a);
            string serverHash = server.Hash(BenchmarkData.Password);
            server.VerifyOrDummy(BenchmarkData.Password, null);
            yield return Macro("2026a VerifyOrDummy, known user", runs, warmup, () => server.VerifyOrDummy(BenchmarkData.Password, serverHash));
            yield return Macro("2026a VerifyOrDummy, null (unknown user)", runs, warmup, () => server.VerifyOrDummy(BenchmarkData.Password, null));

            // Parsing only; no KDF.
            yield return Micro("Inspect ($mh$ hash)", runs, warmup, () => server.Inspect(serverHash));
            yield return Micro("Inspect (v1 hash)", runs, warmup, () => server.Inspect(v1));
            yield return Micro("Inspect (malformed $mh$)", runs, warmup, () => server.Inspect("$mh$p=2026a$*$*"));
        }

        /// <summary>Times one call per sample, for millisecond-scale operations.</summary>
        private static OtherResult Macro(string name, int runs, int warmup, Func<object> action)
        {
            for (int i = 0; i < warmup; i++)
                action();
            var ms = new double[runs];
            var bytes = new double[runs];
            for (int i = 0; i < runs; i++)
            {
                long before = GC.GetTotalAllocatedBytes(precise: true);
                long start = Stopwatch.GetTimestamp();
                action();
                ms[i] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                bytes[i] = GC.GetTotalAllocatedBytes(precise: true) - before;
            }
            return new OtherResult(name, Ms(Median(ms)) + " ms", (Median(bytes) / MiB).ToString("F2", Inv) + " MiB");
        }

        /// <summary>Times a batch of calls per sample, for microsecond-scale operations.</summary>
        private static OtherResult Micro(string name, int runs, int warmup, Func<object> action)
        {
            for (int i = 0; i < Math.Max(1, warmup) * MicroBatch; i++)
                action();
            var us = new double[runs];
            var bytes = new double[runs];
            for (int i = 0; i < runs; i++)
            {
                long before = GC.GetTotalAllocatedBytes(precise: true);
                long start = Stopwatch.GetTimestamp();
                for (int j = 0; j < MicroBatch; j++)
                    action();
                us[i] = Stopwatch.GetElapsedTime(start).TotalMilliseconds * 1000.0 / MicroBatch;
                bytes[i] = (double)(GC.GetTotalAllocatedBytes(precise: true) - before) / MicroBatch;
            }
            return new OtherResult(name, Median(us).ToString("F2", Inv) + " us", Median(bytes).ToString("F0", Inv) + " B");
        }

        private static long SettleAndReadWorkingSet()
        {
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            // Aggressive also decommits free memory, so the working set drops back to what is live.
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            return Environment.WorkingSet;
        }

        private static double Median(double[] values)
        {
            var sorted = (double[])values.Clone();
            Array.Sort(sorted);
            int mid = sorted.Length / 2;
            return sorted.Length % 2 == 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2.0;
        }

        private static string Ms(double value) => value.ToString(value >= 10 ? "F1" : "F2", Inv);

        private static string AlgorithmName(HashProfile profile) =>
            profile.Algorithm == HashAlgorithmKind.Argon2id ? "Argon2id" : "PBKDF2-HMAC-SHA512";

        private static string Params(HashProfile profile) =>
            profile.Algorithm == HashAlgorithmKind.Argon2id
                ? string.Format(Inv, "m={0} MiB, t={1}, p={2}", profile.MemoryKiB / 1024.0, profile.Iterations, profile.Parallelism)
                : string.Format(Inv, "{0:N0} iterations", profile.Iterations);

        private readonly struct ProfileResult
        {
            public ProfileResult(double hashMedianMs, double verifyMedianMs, double allocatedMiB, double peakWorkingSetDeltaMiB)
            {
                HashMedianMs = hashMedianMs;
                VerifyMedianMs = verifyMedianMs;
                AllocatedMiB = allocatedMiB;
                PeakWorkingSetDeltaMiB = peakWorkingSetDeltaMiB;
            }

            public double HashMedianMs { get; }
            public double VerifyMedianMs { get; }
            public double AllocatedMiB { get; }
            public double PeakWorkingSetDeltaMiB { get; }
        }

        private readonly struct OtherResult
        {
            public OtherResult(string name, string median, string allocated)
            {
                Name = name;
                Median = median;
                Allocated = allocated;
            }

            public string Name { get; }
            public string Median { get; }
            public string Allocated { get; }
        }

        /// <summary>Polls the process working set on a background thread and keeps the maximum.</summary>
        private sealed class WorkingSetSampler : IDisposable
        {
            private readonly Thread _thread;
            private long _max;
            private volatile bool _stop;

            public WorkingSetSampler()
            {
                _max = Environment.WorkingSet;
                _thread = new Thread(Loop) { IsBackground = true, Name = "working-set-sampler" };
                _thread.Start();
            }

            /// <summary>Stops sampling and returns the largest working set seen.</summary>
            public long Stop()
            {
                _stop = true;
                _thread.Join();
                Sample();
                return Interlocked.Read(ref _max);
            }

            public void Dispose()
            {
                if (!_stop)
                    Stop();
            }

            private void Loop()
            {
                while (!_stop)
                {
                    Sample();
                    Thread.Sleep(1);
                }
            }

            private void Sample()
            {
                long current = Environment.WorkingSet;
                long seen;
                while (current > (seen = Interlocked.Read(ref _max)))
                {
                    if (Interlocked.CompareExchange(ref _max, current, seen) == seen)
                        break;
                }
            }
        }
    }
}
