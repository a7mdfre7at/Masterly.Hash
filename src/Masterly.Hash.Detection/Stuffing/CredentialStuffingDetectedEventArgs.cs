using System;

namespace Masterly.Hash.Detection
{
    /// <summary>
    /// Event data for <see cref="CredentialStuffingDetector.StuffingDetected"/>. Contains no password and no account
    /// name: only a fingerprint that is meaningless outside its window.
    /// </summary>
    public sealed class CredentialStuffingDetectedEventArgs : EventArgs
    {
        internal CredentialStuffingDetectedEventArgs(string fingerprintId, int distinctAccountCount, DateTimeOffset windowStart, DateTimeOffset windowEnd, DateTimeOffset detectedAt)
        {
            FingerprintId = fingerprintId;
            DistinctAccountCount = distinctAccountCount;
            WindowStart = windowStart;
            WindowEnd = windowEnd;
            DetectedAt = detectedAt;
        }

        /// <summary>
        /// Hex id of the password fingerprint (truncated HMAC-SHA256 under a per-window random key). Use it to
        /// correlate alerts and <see cref="CredentialStuffingDetector.GetSnapshot"/> within the same window; it cannot
        /// be linked to the password or to fingerprints of other windows.
        /// </summary>
        public string FingerprintId { get; }

        /// <summary>Number of distinct accounts the password failed against when the threshold was reached.</summary>
        public int DistinctAccountCount { get; }

        /// <summary>Start of the window.</summary>
        public DateTimeOffset WindowStart { get; }

        /// <summary>End of the window (exclusive).</summary>
        public DateTimeOffset WindowEnd { get; }

        /// <summary>When the threshold was reached.</summary>
        public DateTimeOffset DetectedAt { get; }
    }

    /// <summary>A tracked fingerprint, as returned by <see cref="CredentialStuffingDetector.GetSnapshot"/>.</summary>
    public sealed class FingerprintStatistics
    {
        internal FingerprintStatistics(string fingerprintId, int distinctAccountCount, bool isFlagged)
        {
            FingerprintId = fingerprintId;
            DistinctAccountCount = distinctAccountCount;
            IsFlagged = isFlagged;
        }

        /// <summary>Hex fingerprint id, valid only within the current window.</summary>
        public string FingerprintId { get; }

        /// <summary>Distinct accounts seen so far (stops growing once flagged).</summary>
        public int DistinctAccountCount { get; }

        /// <summary>True if the threshold was reached in this window.</summary>
        public bool IsFlagged { get; }
    }
}
