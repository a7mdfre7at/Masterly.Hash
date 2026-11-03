using System;
using System.Collections.Generic;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;

namespace Masterly.Hash.Benchmarks
{
    /// <summary>
    /// Entry point. <c>--quick</c> runs the Stopwatch-based measurement; anything else goes to BenchmarkDotNet's
    /// <see cref="BenchmarkSwitcher"/> (e.g. <c>--filter *Profile*</c>, <c>--list flat</c>, <c>--job short</c>).
    /// </summary>
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (QuickRunner.IsRequested(args))
                return QuickRunner.Run(args, Console.Out);

            IEnumerable<Summary> summaries = BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
            foreach (Summary summary in summaries)
            {
                if (summary.HasCriticalValidationErrors)
                    return 1;
            }
            return 0;
        }
    }
}
