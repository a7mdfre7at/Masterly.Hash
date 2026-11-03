using System;

namespace Masterly.Hash.BlindIndex
{
    /// <summary>Per-index settings: output length and normalizer. Use the same options for writes and queries.</summary>
    public sealed class BlindIndexOptions
    {
        /// <summary>Smallest allowed <see cref="OutputBits"/>.</summary>
        public const int MinOutputBits = 16;

        /// <summary>Largest allowed <see cref="OutputBits"/> (the full HMAC-SHA256 output).</summary>
        public const int MaxOutputBits = 256;

        /// <summary>Default <see cref="OutputBits"/>.</summary>
        public const int DefaultOutputBits = 64;

        private int _outputBits = DefaultOutputBits;
        private IBlindIndexNormalizer _normalizer = BlindIndexNormalizers.Exact;

        /// <summary>
        /// Length of the index in bits: a multiple of 8 from 16 to 256. Default 64. Shorter indexes produce more false
        /// positives (which the application filters after decrypting) and reveal less about the data; see
        /// <see cref="BlindIndexMath"/>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">The value is out of range or not a multiple of 8.</exception>
        public int OutputBits
        {
            get => _outputBits;
            set
            {
                if (!IsValidOutputBits(value))
                    throw new ArgumentOutOfRangeException(nameof(value), value, "OutputBits must be a multiple of 8 from 16 to 256.");
                _outputBits = value;
            }
        }

        /// <summary>The normalizer applied to the value (or each compound part) before hashing. Default <see cref="BlindIndexNormalizers.Exact"/>.</summary>
        /// <exception cref="ArgumentNullException">The value is null.</exception>
        public IBlindIndexNormalizer Normalizer
        {
            get => _normalizer;
            set => _normalizer = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>True if <paramref name="bits"/> is a valid <see cref="OutputBits"/> value.</summary>
        public static bool IsValidOutputBits(int bits) => bits >= MinOutputBits && bits <= MaxOutputBits && bits % 8 == 0;
    }
}
