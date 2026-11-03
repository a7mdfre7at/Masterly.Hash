using System;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Pwned.Internal
{
    /// <summary>
    /// A parsed, immutable <c>/range/{prefix}</c> answer: the non-padding entries as packed suffixes and counts.
    /// Stored flat (about 26 bytes per entry) so cached ranges stay small.
    /// </summary>
    internal sealed class RangeResponse
    {
        /// <summary>Longest accepted count, in digits; 18 digits always fit in a <see cref="long"/>.</summary>
        private const int MaxCountDigits = 18;

        private readonly byte[] _suffixes;
        private readonly long[] _counts;

        private RangeResponse(byte[] suffixes, long[] counts)
        {
            _suffixes = suffixes;
            _counts = counts;
        }

        /// <summary>Number of non-padding entries.</summary>
        public int Count => _counts.Length;

        /// <summary>
        /// Parses <c>SUFFIX:COUNT</c> lines separated by CRLF or LF. Suffixes are 35 hex digits in either case;
        /// counts are decimal. Entries with count 0 (added by <c>Add-Padding</c>) are dropped. Blank lines and
        /// surrounding spaces are tolerated; any other malformed line rejects the whole response, so a corrupted
        /// answer cannot silently turn a breached password into a clean one.
        /// </summary>
        public static bool TryParse(byte[] body, int length, out RangeResponse? response)
        {
            response = null;
            if (body == null || length < 0 || length > body.Length)
                return false;

            // Upper bound on entries: the shortest valid line is 35 + 1 + 1 bytes plus a separator.
            int capacity = length / (PwnedHash.SuffixLength + 2) + 1;
            var suffixes = new byte[capacity * PwnedHash.SuffixBytes];
            var counts = new long[capacity];
            int entries = 0;

            int pos = 0;
            while (pos < length)
            {
                int lineEnd = Array.IndexOf(body, (byte)'\n', pos, length - pos);
                if (lineEnd < 0)
                    lineEnd = length;
                int start = pos;
                int end = lineEnd;
                pos = lineEnd + 1;

                while (start < end && IsSpace(body[start])) start++;
                while (end > start && (IsSpace(body[end - 1]) || body[end - 1] == (byte)'\r')) end--;
                if (start == end)
                    continue;

                int colon = Array.IndexOf(body, (byte)':', start, end - start);
                if (colon < 0)
                    return false;
                if (entries == capacity)
                    return false;
                if (!PwnedHash.TryParseSuffix(body, start, colon - start, suffixes, entries * PwnedHash.SuffixBytes))
                    return false;
                if (!TryParseCount(body, colon + 1, end - colon - 1, out long count))
                    return false;
                if (count == 0)
                    continue; // padding entry; the slot is reused by the next line

                counts[entries] = count;
                entries++;
            }

            if (entries < capacity)
            {
                var trimmedSuffixes = new byte[entries * PwnedHash.SuffixBytes];
                Buffer.BlockCopy(suffixes, 0, trimmedSuffixes, 0, trimmedSuffixes.Length);
                var trimmedCounts = new long[entries];
                Array.Copy(counts, trimmedCounts, entries);
                suffixes = trimmedSuffixes;
                counts = trimmedCounts;
            }

            response = new RangeResponse(suffixes, counts);
            return true;
        }

        /// <summary>
        /// Returns the count for a packed suffix, or 0 if absent. Every entry is compared with
        /// <see cref="HashPrimitives.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> and the scan never stops early, so timing does not reveal
        /// where in the range the password's hash sits. Duplicates resolve to the largest count.
        /// </summary>
        public long Lookup(byte[] packedSuffix)
        {
            long found = 0;
            for (int i = 0; i < _counts.Length; i++)
            {
                var candidate = new ReadOnlySpan<byte>(_suffixes, i * PwnedHash.SuffixBytes, PwnedHash.SuffixBytes);
                if (HashPrimitives.FixedTimeEquals(candidate, packedSuffix) && _counts[i] > found)
                    found = _counts[i];
            }
            return found;
        }

        private static bool TryParseCount(byte[] source, int offset, int length, out long count)
        {
            count = 0;
            if (length < 1 || length > MaxCountDigits)
                return false;
            for (int i = 0; i < length; i++)
            {
                byte c = source[offset + i];
                if (c < (byte)'0' || c > (byte)'9')
                    return false;
                count = count * 10 + (c - '0');
            }
            return true;
        }

        private static bool IsSpace(byte c) => c == (byte)' ' || c == (byte)'\t';
    }
}
