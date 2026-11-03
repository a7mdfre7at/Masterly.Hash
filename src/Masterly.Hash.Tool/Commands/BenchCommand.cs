using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary><c>bench [--target-ms 250]</c>: times each built-in profile and recommends one.</summary>
    internal static class BenchCommand
    {
        public const int Samples = 5;
        public const int DefaultTargetMs = 250;
        public const int MaxTargetMs = 60_000;

        public static readonly IReadOnlyList<HashProfile> Profiles = new[]
        {
            HashProfile.Server2026a, HashProfile.Constrained2026a, HashProfile.Fips2026a,
        };

        public static Command Create(ToolEnvironment environment)
        {
            var target = new Option<int>("--target-ms")
            {
                Description = "Longest acceptable time for one hash on this machine, in milliseconds.",
                DefaultValueFactory = _ => DefaultTargetMs,
                HelpName = "ms",
            };
            var command = new Command("bench", "Time each built-in profile on this machine (median of 5 runs) and recommend Server2026a or Constrained2026a.")
            {
                target,
            };
            command.SetAction(parse => Execute(environment, parse.GetValue(target)));
            return command;
        }

        public static int Execute(ToolEnvironment environment, int targetMs)
        {
            if (targetMs < 1 || targetMs > MaxTargetMs)
                throw new ToolException("--target-ms must be between 1 and 60000.");

            TextWriter output = environment.Console.Out;
            TextWriter progress = environment.Console.Error;
            var medians = new double[Profiles.Count];
            for (int i = 0; i < Profiles.Count; i++)
            {
                progress.WriteLine("bench: " + Profiles[i].Id + "...");
                medians[i] = Median(environment, Profiles[i]);
            }

            double server = medians[0];
            double constrained = medians[1];
            bool serverFits = server <= targetMs;
            string recommended = serverFits ? "Server2026a" : "Constrained2026a";

            output.WriteLine(string.Format(CultureInfo.InvariantCulture,
                "Median of {0} runs per profile; target {1} ms per hash.", Samples, targetMs));
            output.WriteLine();
            output.WriteLine("| Profile | Parameters | Median (ms) |");
            output.WriteLine("|---|---|---:|");
            for (int i = 0; i < Profiles.Count; i++)
                output.WriteLine("| " + Profiles[i].Id + " | " + Parameters(Profiles[i]) + " | " + CommandHelpers.Milliseconds(medians[i]) + " |");
            output.WriteLine();

            if (serverFits)
            {
                output.WriteLine("Recommendation: Server2026a (2026a takes " + CommandHelpers.Milliseconds(server) +
                    " ms, within the " + CommandHelpers.Number(targetMs) + " ms target).");
            }
            else
            {
                output.WriteLine("Recommendation: Constrained2026a (2026a takes " + CommandHelpers.Milliseconds(server) +
                    " ms, over the " + CommandHelpers.Number(targetMs) + " ms target; 2026c takes " + CommandHelpers.Milliseconds(constrained) + " ms).");
                if (constrained > targetMs)
                {
                    output.WriteLine("Even 2026c exceeds the target. It is the OWASP minimum, so do not go lower: " +
                        "add capacity or lower PasswordHasherOptions.MaxConcurrency instead.");
                }
            }
            output.WriteLine();

            output.WriteLine("| OS | Arch | Cores | Runtime | 2026a (ms) | 2026c (ms) | 2026f (ms) | Recommended |");
            output.WriteLine("|---|---|---:|---|---:|---:|---:|---|");
            output.WriteLine("| " + Cell(RuntimeInformation.OSDescription) +
                " | " + RuntimeInformation.ProcessArchitecture +
                " | " + CommandHelpers.Number(Environment.ProcessorCount) +
                " | " + Cell(RuntimeInformation.FrameworkDescription) +
                " | " + CommandHelpers.Milliseconds(medians[0]) +
                " | " + CommandHelpers.Milliseconds(medians[1]) +
                " | " + CommandHelpers.Milliseconds(medians[2]) +
                " | " + recommended + " |");
            return ExitCodes.Success;
        }

        /// <summary>One warm-up run (JIT, first allocation), then the median of <see cref="Samples"/> runs.</summary>
        internal static double Median(ToolEnvironment environment, HashProfile profile)
        {
            environment.MeasureMilliseconds(profile);
            var times = new double[Samples];
            for (int i = 0; i < Samples; i++)
                times[i] = environment.MeasureMilliseconds(profile);
            Array.Sort(times);
            return times[Samples / 2];
        }

        private static string Parameters(HashProfile profile) =>
            profile.Algorithm == HashAlgorithmKind.Argon2id
                ? string.Format(CultureInfo.InvariantCulture, "Argon2id m={0} KiB, t={1}, p={2}", profile.MemoryKiB, profile.Iterations, profile.Parallelism)
                : string.Format(CultureInfo.InvariantCulture, "PBKDF2-SHA512 i={0}", profile.Iterations);

        private static string Cell(string value) => value.Replace("|", "\\|").Trim();
    }
}
