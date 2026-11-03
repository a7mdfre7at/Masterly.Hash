using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Masterly.Hash.Internal
{
    /// <summary>
    /// Unkeyed BLAKE2b (RFC 7693) with a 1 to 64 byte digest, as Argon2 (RFC 9106) uses it for H and H'.
    /// </summary>
    /// <remarks>
    /// Incremental: <see cref="Update"/> any number of times, then <see cref="Final"/> once. The instance clears its
    /// chaining value and buffer in <see cref="Final"/>, so no secret-derived state outlives the call.
    /// </remarks>
    internal sealed class Blake2b
    {
        private const int BlockBytes = 128;

        private static readonly ulong[] Iv =
        {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
            0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
        };

        private static readonly byte[] Sigma =
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
            11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
            7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
            9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
            2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
            12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
            13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
            6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
            10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
        };

        private readonly ulong[] _h = new ulong[8];
        private readonly byte[] _buffer = new byte[BlockBytes];
        private readonly ulong[] _v = new ulong[16];
        private readonly ulong[] _m = new ulong[16];
        private readonly int _outputLength;
        private ulong _counter;
        private int _bufferLength;

        /// <summary>Starts an unkeyed BLAKE2b computation with a digest of <paramref name="outputLength"/> bytes.</summary>
        public Blake2b(int outputLength)
        {
            if (outputLength < 1 || outputLength > 64)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), outputLength, "BLAKE2b output must be 1 to 64 bytes.");
            }

            _outputLength = outputLength;
            Array.Copy(Iv, _h, 8);
            _h[0] ^= 0x01010000UL ^ (uint)outputLength;
        }

        /// <summary>Computes the BLAKE2b digest of <paramref name="input"/> into <paramref name="output"/>.</summary>
        public static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Blake2b blake = new Blake2b(output.Length);
            blake.Update(input);
            blake.Final(output);
        }

        /// <summary>Absorbs <paramref name="input"/>.</summary>
        public void Update(ReadOnlySpan<byte> input)
        {
            while (input.Length > 0)
            {
                // The last block is compressed with the final flag, so a full buffer is only flushed once more input arrives.
                if (_bufferLength == BlockBytes)
                {
                    _counter += BlockBytes;
                    Compress(_buffer, isLast: false);
                    _bufferLength = 0;
                }

                int take = Math.Min(BlockBytes - _bufferLength, input.Length);
                input.Slice(0, take).CopyTo(_buffer.AsSpan(_bufferLength));
                _bufferLength += take;
                input = input.Slice(take);
            }
        }

        /// <summary>Absorbs <paramref name="value"/> as four little-endian bytes.</summary>
        public void UpdateLittleEndian(uint value)
        {
            Span<byte> bytes = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
            Update(bytes);
        }

        /// <summary>Writes the digest to <paramref name="output"/> (exactly the configured length) and clears the state.</summary>
        public void Final(Span<byte> output)
        {
            if (output.Length != _outputLength)
            {
                throw new ArgumentException($"Output must be {_outputLength} bytes.", nameof(output));
            }

            _counter += (ulong)_bufferLength;
            _buffer.AsSpan(_bufferLength).Clear();
            Compress(_buffer, isLast: true);

            Span<byte> digest = stackalloc byte[64];
            for (int i = 0; i < 8; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(digest.Slice(i * 8), _h[i]);
            }

            digest.Slice(0, _outputLength).CopyTo(output);
            CryptographicOperations.ZeroMemory(digest);
            Clear();
        }

        private void Clear()
        {
            Array.Clear(_h);
            Array.Clear(_v);
            Array.Clear(_m);
            CryptographicOperations.ZeroMemory(_buffer);
            _bufferLength = 0;
            _counter = 0;
        }

        private void Compress(byte[] block, bool isLast)
        {
            ulong[] v = _v;
            ulong[] m = _m;
            for (int i = 0; i < 16; i++)
            {
                m[i] = BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(i * 8));
            }

            Array.Copy(_h, 0, v, 0, 8);
            Array.Copy(Iv, 0, v, 8, 8);
            v[12] ^= _counter;
            if (isLast)
            {
                v[14] = ~v[14];
            }

            for (int round = 0; round < 12; round++)
            {
                int s = (round % 10) * 16;
                Mix(v, 0, 4, 8, 12, m[Sigma[s]], m[Sigma[s + 1]]);
                Mix(v, 1, 5, 9, 13, m[Sigma[s + 2]], m[Sigma[s + 3]]);
                Mix(v, 2, 6, 10, 14, m[Sigma[s + 4]], m[Sigma[s + 5]]);
                Mix(v, 3, 7, 11, 15, m[Sigma[s + 6]], m[Sigma[s + 7]]);
                Mix(v, 0, 5, 10, 15, m[Sigma[s + 8]], m[Sigma[s + 9]]);
                Mix(v, 1, 6, 11, 12, m[Sigma[s + 10]], m[Sigma[s + 11]]);
                Mix(v, 2, 7, 8, 13, m[Sigma[s + 12]], m[Sigma[s + 13]]);
                Mix(v, 3, 4, 9, 14, m[Sigma[s + 14]], m[Sigma[s + 15]]);
            }

            for (int i = 0; i < 8; i++)
            {
                _h[i] ^= v[i] ^ v[i + 8];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mix(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
        {
            v[a] = v[a] + v[b] + x;
            v[d] = BitOperations.RotateRight(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];
            v[b] = BitOperations.RotateRight(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y;
            v[d] = BitOperations.RotateRight(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = BitOperations.RotateRight(v[b] ^ v[c], 63);
        }
    }
}
