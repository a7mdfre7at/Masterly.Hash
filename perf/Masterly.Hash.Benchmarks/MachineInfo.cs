using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Masterly.Hash.Benchmarks
{
    /// <summary>Describes the machine a measurement ran on, for the CHANGELOG.</summary>
    internal static class MachineInfo
    {
        /// <summary>One line per fact: CPU, OS, runtime, GC mode.</summary>
        public static IReadOnlyList<string> Describe()
        {
            return new[]
            {
                $"CPU: {CpuModel()} ({Environment.ProcessorCount} logical cores, {RuntimeInformation.ProcessArchitecture})",
                $"OS: {RuntimeInformation.OSDescription}",
                $".NET: {RuntimeInformation.FrameworkDescription} ({RuntimeInformation.RuntimeIdentifier})",
                $"GC: {(GCSettings.IsServerGC ? "Server" : "Workstation")}, {GCSettings.LatencyMode}",
                $"Build: {BuildConfiguration}",
            };
        }

        /// <summary>The configuration this assembly was compiled in.</summary>
        public static string BuildConfiguration =>
#if DEBUG
            "Debug (numbers are NOT representative; use -c Release)";
#else
            "Release";
#endif

        /// <summary>CPU model name, or a placeholder when the platform does not expose it cheaply.</summary>
        public static string CpuModel()
        {
            try
            {
                string? model = null;
                if (OperatingSystem.IsWindows())
                    model = WindowsCpuModel();
                else if (OperatingSystem.IsLinux())
                    model = LinuxCpuModel();
                else if (OperatingSystem.IsMacOS())
                    model = MacCpuModel();

                if (!string.IsNullOrWhiteSpace(model))
                    return model.Trim();
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException ||
                                       ex is System.Security.SecurityException || ex is InvalidOperationException ||
                                       ex is System.ComponentModel.Win32Exception)
            {
                // Fall through to the placeholder; the CPU model is informational only.
            }

            return "unknown CPU model";
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static string? WindowsCpuModel()
        {
            using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0"))
                return key?.GetValue("ProcessorNameString") as string;
        }

        private static string? LinuxCpuModel()
        {
            const string CpuInfo = "/proc/cpuinfo";
            if (!File.Exists(CpuInfo))
                return null;
            foreach (string line in File.ReadLines(CpuInfo))
            {
                if (line.StartsWith("model name", StringComparison.Ordinal) || line.StartsWith("Model", StringComparison.Ordinal))
                {
                    int colon = line.IndexOf(':');
                    if (colon >= 0)
                        return line.Substring(colon + 1);
                }
            }
            return null;
        }

        private static string? MacCpuModel()
        {
            var start = new ProcessStartInfo("sysctl", "-n machdep.cpu.brand_string")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using (Process? process = Process.Start(start))
            {
                if (process == null)
                    return null;
                string output = process.StandardOutput.ReadToEnd();
                return process.WaitForExit(2000) ? output : null;
            }
        }
    }
}
