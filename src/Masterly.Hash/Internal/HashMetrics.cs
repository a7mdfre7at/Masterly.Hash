using System.Collections.Generic;
using System.Diagnostics.Metrics;

namespace Masterly.Hash.Internal
{
    /// <summary>
    /// <c>System.Diagnostics.Metrics</c> instruments, picked up by OpenTelemetry with
    /// <c>.AddMeter("Masterly.Hash")</c>. No tag ever contains secret material.
    /// </summary>
    internal static class HashMetrics
    {
        public const string MeterName = "Masterly.Hash";

        private static readonly Meter Meter = new Meter(MeterName, typeof(HashMetrics).Assembly.GetName().Version?.ToString());

        private static readonly Histogram<double> Duration = Meter.CreateHistogram<double>(
            "masterly.hash.duration", "ms", "Time spent computing a password hash or verification.");

        private static readonly Counter<long> Verifications = Meter.CreateCounter<long>(
            "masterly.hash.verifications", "{verification}", "Password verifications by format and outcome.");

        private static readonly Counter<long> Hashes = Meter.CreateCounter<long>(
            "masterly.hash.hashes", "{hash}", "New password hashes by profile.");

        private static readonly Counter<long> Rejections = Meter.CreateCounter<long>(
            "masterly.hash.busy_rejections", "{rejection}", "Calls rejected at the concurrency limit.");

        public static void RecordHash(string profileId, double elapsedMs)
        {
            var profile = new KeyValuePair<string, object?>("profile", profileId);
            Hashes.Add(1, profile);
            Duration.Record(elapsedMs, new KeyValuePair<string, object?>("operation", "hash"), profile);
        }

        public static void RecordVerify(string format, PasswordVerificationResult result, double elapsedMs)
        {
            var formatTag = new KeyValuePair<string, object?>("format", format);
            Verifications.Add(1,
                formatTag,
                new KeyValuePair<string, object?>("outcome", result.Status.ToString()),
                new KeyValuePair<string, object?>("reason", result.Status == VerificationStatus.Failed ? result.FailureReason.ToString() : result.RehashReason.ToString()));
            Duration.Record(elapsedMs, new KeyValuePair<string, object?>("operation", "verify"), formatTag);
        }

        public static void RecordBusy() => Rejections.Add(1);
    }
}
