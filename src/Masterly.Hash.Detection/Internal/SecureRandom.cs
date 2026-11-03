using System;
using System.Collections.Generic;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Detection.Internal
{
    /// <summary>Unbiased integers and shuffles from the CSPRNG behind <see cref="HashPrimitives.RandomBytes"/>.</summary>
    internal static class SecureRandom
    {
        /// <summary>Uniform integer in [0, <paramref name="maxExclusive"/>), by rejection sampling.</summary>
        public static int Next(int maxExclusive)
        {
            if (maxExclusive <= 0) throw new ArgumentOutOfRangeException(nameof(maxExclusive));
            if (maxExclusive == 1) return 0;

            uint bound = (uint)maxExclusive;
            // Largest multiple of bound that fits in 2^32; values at or above it are rejected so every residue is equally likely.
            uint limit = uint.MaxValue - (uint.MaxValue % bound);
            while (true)
            {
                byte[] bytes = HashPrimitives.RandomBytes(4);
                uint value = (uint)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
                if (value < limit)
                    return (int)(value % bound);
            }
        }

        /// <summary>Uniform integer in [<paramref name="minInclusive"/>, <paramref name="maxExclusive"/>).</summary>
        public static int Next(int minInclusive, int maxExclusive) => minInclusive + Next(maxExclusive - minInclusive);

        /// <summary>True with probability <paramref name="numerator"/>/<paramref name="denominator"/>.</summary>
        public static bool Chance(int numerator, int denominator) => Next(denominator) < numerator;

        public static char Pick(string alphabet) => alphabet[Next(alphabet.Length)];

        /// <summary>Fisher-Yates shuffle.</summary>
        public static void Shuffle<T>(IList<T> items)
        {
            for (int i = items.Count - 1; i > 0; i--)
            {
                int j = Next(i + 1);
                T tmp = items[i];
                items[i] = items[j];
                items[j] = tmp;
            }
        }
    }
}
