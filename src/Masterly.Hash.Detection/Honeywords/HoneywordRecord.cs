using System;

namespace Masterly.Hash.Detection
{
    /// <summary>
    /// The result of <see cref="HoneywordService.Create(string, int)"/>. The two halves go to two different systems:
    /// <see cref="StoredHash"/> to the user database, <see cref="RealIndex"/> to the honeychecker. Never store them together.
    /// </summary>
    public sealed class HoneywordRecord
    {
        internal HoneywordRecord(string storedHash, int realIndex, int sweetwordCount)
        {
            StoredHash = storedHash ?? throw new ArgumentNullException(nameof(storedHash));
            RealIndex = realIndex;
            SweetwordCount = sweetwordCount;
        }

        /// <summary>The <c>$mhw$</c> string to store with the user. It does not reveal which sweetword is real.</summary>
        public string StoredHash { get; }

        /// <summary>Zero-based position of the real password among the sweetwords. Send it only to the honeychecker.</summary>
        public int RealIndex { get; }

        /// <summary>Number of sweetwords (real password plus decoys).</summary>
        public int SweetwordCount { get; }

        /// <summary>Shows only the sweetword count, so the real index cannot end up in a log next to the hash.</summary>
        public override string ToString() => $"HoneywordRecord (k={SweetwordCount})";
    }
}
