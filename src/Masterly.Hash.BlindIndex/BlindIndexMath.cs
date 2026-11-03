using System;

namespace Masterly.Hash.BlindIndex
{
    /// <summary>
    /// Collision arithmetic for choosing <see cref="BlindIndexOptions.OutputBits"/>. A truncated HMAC behaves like a
    /// uniformly random function onto <c>2^bits</c> buckets, so for <c>n</c> distinct values in a column:
    /// a query matches about <c>(n - 1) / 2^bits</c> unrelated values, and the column holds about
    /// <c>n(n - 1) / 2^(bits + 1)</c> colliding pairs.
    /// </summary>
    public static class BlindIndexMath
    {
        /// <summary>
        /// Expected number of other distinct values that share a given value's index, i.e. the false positives one
        /// equality query returns: <c>(n - 1) / 2^bits</c>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Negative <paramref name="distinctValues"/> or invalid <paramref name="outputBits"/>.</exception>
        public static double ExpectedFalsePositivesPerQuery(long distinctValues, int outputBits)
        {
            Validate(distinctValues, outputBits);
            if (distinctValues <= 1)
                return 0;
            return (distinctValues - 1) / Math.Pow(2, outputBits);
        }

        /// <summary>
        /// Expected number of unordered pairs of distinct values whose indexes collide (birthday bound):
        /// <c>n(n - 1) / 2^(bits + 1)</c>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Negative <paramref name="distinctValues"/> or invalid <paramref name="outputBits"/>.</exception>
        public static double ExpectedCollidingPairs(long distinctValues, int outputBits)
        {
            Validate(distinctValues, outputBits);
            if (distinctValues <= 1)
                return 0;
            double n = distinctValues;
            return n * (n - 1) / Math.Pow(2, outputBits + 1);
        }

        /// <summary>
        /// Smallest valid <see cref="BlindIndexOptions.OutputBits"/> for which a query is expected to return at most
        /// <paramref name="maxFalsePositivesPerQuery"/> false positives. Returns 256 if no shorter length suffices.
        /// Prefer the smallest length your application tolerates: fewer bits leak less.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Negative <paramref name="distinctValues"/> or a non-positive target.</exception>
        public static int MinimumOutputBits(long distinctValues, double maxFalsePositivesPerQuery)
        {
            if (distinctValues < 0) throw new ArgumentOutOfRangeException(nameof(distinctValues));
            if (!(maxFalsePositivesPerQuery > 0) || double.IsInfinity(maxFalsePositivesPerQuery))
                throw new ArgumentOutOfRangeException(nameof(maxFalsePositivesPerQuery), "Target must be a positive finite number.");

            for (int bits = BlindIndexOptions.MinOutputBits; bits < BlindIndexOptions.MaxOutputBits; bits += 8)
            {
                if (ExpectedFalsePositivesPerQuery(distinctValues, bits) <= maxFalsePositivesPerQuery)
                    return bits;
            }
            return BlindIndexOptions.MaxOutputBits;
        }

        private static void Validate(long distinctValues, int outputBits)
        {
            if (distinctValues < 0) throw new ArgumentOutOfRangeException(nameof(distinctValues));
            if (!BlindIndexOptions.IsValidOutputBits(outputBits))
                throw new ArgumentOutOfRangeException(nameof(outputBits), outputBits, "OutputBits must be a multiple of 8 from 16 to 256.");
        }
    }
}
