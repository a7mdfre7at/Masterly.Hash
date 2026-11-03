using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Masterly.Hash.Internal
{
    /// <summary>Argon2 variant, numbered as the type field <c>y</c> of RFC 9106.</summary>
    internal enum Argon2Type
    {
        /// <summary>Argon2d: data-dependent memory access.</summary>
        Argon2d = 0,

        /// <summary>Argon2i: data-independent memory access.</summary>
        Argon2i = 1,

        /// <summary>Argon2id: data-independent for the first half of the first pass, then data-dependent.</summary>
        Argon2id = 2,
    }

    /// <summary>
    /// Argon2 version 0x13 (RFC 9106), fully managed, computed entirely on the calling thread.
    /// </summary>
    /// <remarks>
    /// <para>
    /// No lane is ever handed to the thread pool or a task. Within one slice the lanes are independent, so they are
    /// filled one after another; this produces exactly the output of a parallel implementation. Running on the caller's
    /// thread is what keeps <see cref="PasswordHasher"/>'s concurrency gate safe: a caller that holds a slot never
    /// needs another thread to finish, so callers waiting for a slot cannot starve it.
    /// </para>
    /// <para>
    /// The memory matrix, H0, every intermediate block and the final block are zeroed before returning.
    /// </para>
    /// </remarks>
    internal static class Argon2Core
    {
        /// <summary>Argon2 version implemented: 0x13 (19).</summary>
        public const int Version = 0x13;

        private const int BlockBytes = 1024;
        private const int QwordsInBlock = BlockBytes / 8;
        private const int SyncPoints = 4;
        private const int AddressesInBlock = 128;
        private const int PrehashDigestLength = 64;
        private const int PrehashSeedLength = PrehashDigestLength + 8;

        /// <summary>
        /// Computes an Argon2 tag. Parameters are trusted to be in range: callers validate them
        /// (<see cref="HashProfile"/>, <see cref="Primitives.HashPrimitives.Argon2"/>).
        /// </summary>
        public static byte[] Derive(
            Argon2Type type,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> secret,
            ReadOnlySpan<byte> associatedData,
            int memoryKiB,
            int iterations,
            int parallelism,
            int tagLength)
        {
            // m' = 4 * p * floor(m / (4 * p)): the largest multiple of 4p not above m.
            int lanes = parallelism;
            int segmentLength = memoryKiB / (lanes * SyncPoints);
            int laneLength = segmentLength * SyncPoints;
            int blockCount = laneLength * lanes;

            byte[] seed = new byte[PrehashSeedLength];
            byte[] blockBytes = new byte[BlockBytes];
            ulong[] memory = GC.AllocateUninitializedArray<ulong>(checked(blockCount * QwordsInBlock));
            Scratch scratch = new Scratch();
            try
            {
                InitialHash(type, password, salt, secret, associatedData, memoryKiB, iterations, parallelism, tagLength, seed);
                FirstBlocks(memory, lanes, laneLength, seed, blockBytes);

                Instance instance = new Instance(type, iterations, lanes, laneLength, segmentLength, blockCount);
                for (int pass = 0; pass < iterations; pass++)
                {
                    for (int slice = 0; slice < SyncPoints; slice++)
                    {
                        for (int lane = 0; lane < lanes; lane++)
                        {
                            FillSegment(memory, instance, pass, lane, slice, scratch);
                        }
                    }
                }

                return Finalize(memory, lanes, laneLength, tagLength, blockBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(memory.AsSpan()));
                CryptographicOperations.ZeroMemory(seed);
                CryptographicOperations.ZeroMemory(blockBytes);
                scratch.Clear();
            }
        }

        /// <summary>
        /// H' of RFC 9106 section 3.3: a BLAKE2b-based hash with an output of any length.
        /// </summary>
        internal static void VariableLengthHash(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Blake2b blake;
            if (output.Length <= 64)
            {
                blake = new Blake2b(output.Length);
                blake.UpdateLittleEndian((uint)output.Length);
                blake.Update(input);
                blake.Final(output);
                return;
            }

            // r = ceil(T / 32) - 2 full 64-byte digests contribute their first 32 bytes; the last digest is T - 32r bytes.
            int r = ((output.Length + 31) / 32) - 2;
            Span<byte> v = stackalloc byte[64];
            blake = new Blake2b(64);
            blake.UpdateLittleEndian((uint)output.Length);
            blake.Update(input);
            blake.Final(v);
            v.Slice(0, 32).CopyTo(output);

            Span<byte> next = stackalloc byte[64];
            for (int i = 1; i < r; i++)
            {
                Blake2b.Hash(v, next);
                next.CopyTo(v);
                v.Slice(0, 32).CopyTo(output.Slice(i * 32));
            }

            int lastLength = output.Length - (32 * r);
            Blake2b.Hash(v, output.Slice(32 * r, lastLength));
            CryptographicOperations.ZeroMemory(v);
            CryptographicOperations.ZeroMemory(next);
        }

        private static void InitialHash(
            Argon2Type type,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> secret,
            ReadOnlySpan<byte> associatedData,
            int memoryKiB,
            int iterations,
            int parallelism,
            int tagLength,
            byte[] seed)
        {
            Blake2b blake = new Blake2b(PrehashDigestLength);
            blake.UpdateLittleEndian((uint)parallelism);
            blake.UpdateLittleEndian((uint)tagLength);
            blake.UpdateLittleEndian((uint)memoryKiB);
            blake.UpdateLittleEndian((uint)iterations);
            blake.UpdateLittleEndian(Version);
            blake.UpdateLittleEndian((uint)type);
            blake.UpdateLittleEndian((uint)password.Length);
            blake.Update(password);
            blake.UpdateLittleEndian((uint)salt.Length);
            blake.Update(salt);
            blake.UpdateLittleEndian((uint)secret.Length);
            blake.Update(secret);
            blake.UpdateLittleEndian((uint)associatedData.Length);
            blake.Update(associatedData);
            blake.Final(seed.AsSpan(0, PrehashDigestLength));
        }

        private static void FirstBlocks(ulong[] memory, int lanes, int laneLength, byte[] seed, byte[] blockBytes)
        {
            // B[i][0] = H'^1024(H0 || LE32(0) || LE32(i)), B[i][1] = H'^1024(H0 || LE32(1) || LE32(i)).
            for (int lane = 0; lane < lanes; lane++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(PrehashDigestLength + 4), (uint)lane);
                for (int column = 0; column < 2; column++)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(PrehashDigestLength), (uint)column);
                    VariableLengthHash(seed, blockBytes);
                    LoadBlock(blockBytes, memory.AsSpan(((lane * laneLength) + column) * QwordsInBlock, QwordsInBlock));
                }
            }
        }

        private static byte[] Finalize(ulong[] memory, int lanes, int laneLength, int tagLength, byte[] blockBytes)
        {
            // C = B[0][q-1] XOR B[1][q-1] XOR ... XOR B[p-1][q-1]; tag = H'^T(C).
            Span<ulong> final = stackalloc ulong[QwordsInBlock];
            memory.AsSpan((laneLength - 1) * QwordsInBlock, QwordsInBlock).CopyTo(final);
            for (int lane = 1; lane < lanes; lane++)
            {
                Xor(final, final, memory.AsSpan((((lane * laneLength) + laneLength) - 1) * QwordsInBlock, QwordsInBlock));
            }

            for (int i = 0; i < QwordsInBlock; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(blockBytes.AsSpan(i * 8), final[i]);
            }

            byte[] tag = new byte[tagLength];
            VariableLengthHash(blockBytes, tag);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(final));
            return tag;
        }

        private static void FillSegment(ulong[] memory, Instance instance, int pass, int lane, int slice, Scratch scratch)
        {
            bool dataIndependent = instance.Type == Argon2Type.Argon2i ||
                (instance.Type == Argon2Type.Argon2id && pass == 0 && slice < SyncPoints / 2);

            Span<ulong> addresses = scratch.Address;
            if (dataIndependent)
            {
                Span<ulong> input = scratch.Input;
                input.Clear();
                input[0] = (ulong)pass;
                input[1] = (ulong)lane;
                input[2] = (ulong)slice;
                input[3] = (ulong)instance.BlockCount;
                input[4] = (ulong)instance.Passes;
                input[5] = (ulong)instance.Type;
            }

            // The first two blocks of every lane were set from H0, so the first segment starts at index 2.
            int startingIndex = 0;
            if (pass == 0 && slice == 0)
            {
                startingIndex = 2;
                if (dataIndependent)
                {
                    NextAddresses(scratch);
                }
            }

            int laneLength = instance.LaneLength;
            int currentOffset = (lane * laneLength) + (slice * instance.SegmentLength) + startingIndex;
            int previousOffset = currentOffset % laneLength == 0 ? currentOffset + laneLength - 1 : currentOffset - 1;

            for (int index = startingIndex; index < instance.SegmentLength; index++, currentOffset++, previousOffset++)
            {
                if (currentOffset % laneLength == 1)
                {
                    previousOffset = currentOffset - 1;
                }

                ulong pseudoRandom;
                if (dataIndependent)
                {
                    if (index % AddressesInBlock == 0)
                    {
                        NextAddresses(scratch);
                    }

                    pseudoRandom = addresses[index % AddressesInBlock];
                }
                else
                {
                    pseudoRandom = memory[previousOffset * QwordsInBlock];
                }

                int referenceLane = (int)((pseudoRandom >> 32) % (ulong)instance.Lanes);
                if (pass == 0 && slice == 0)
                {
                    referenceLane = lane;
                }

                int referenceIndex = IndexAlpha(instance, pass, slice, index, (uint)pseudoRandom, referenceLane == lane);
                int referenceOffset = (laneLength * referenceLane) + referenceIndex;

                FillBlock(
                    memory.AsSpan(previousOffset * QwordsInBlock, QwordsInBlock),
                    memory.AsSpan(referenceOffset * QwordsInBlock, QwordsInBlock),
                    memory.AsSpan(currentOffset * QwordsInBlock, QwordsInBlock),
                    withXor: pass != 0,
                    scratch);
            }
        }

        private static int IndexAlpha(Instance instance, int pass, int slice, int index, uint pseudoRandom, bool sameLane)
        {
            // Size of the window of blocks this position may reference (RFC 9106 section 3.4.2).
            uint referenceAreaSize;
            if (pass == 0)
            {
                if (slice == 0)
                {
                    referenceAreaSize = (uint)(index - 1);
                }
                else if (sameLane)
                {
                    referenceAreaSize = (uint)((slice * instance.SegmentLength) + index - 1);
                }
                else
                {
                    referenceAreaSize = (uint)((slice * instance.SegmentLength) + (index == 0 ? -1 : 0));
                }
            }
            else if (sameLane)
            {
                referenceAreaSize = (uint)(instance.LaneLength - instance.SegmentLength + index - 1);
            }
            else
            {
                referenceAreaSize = (uint)(instance.LaneLength - instance.SegmentLength + (index == 0 ? -1 : 0));
            }

            // Non-uniform mapping that favours recent blocks: x = J1^2 / 2^32, y = |W| * x / 2^32, z = |W| - 1 - y.
            ulong relativePosition = pseudoRandom;
            relativePosition = (relativePosition * relativePosition) >> 32;
            relativePosition = referenceAreaSize - 1 - ((referenceAreaSize * relativePosition) >> 32);

            ulong startPosition = 0;
            if (pass != 0)
            {
                startPosition = slice == SyncPoints - 1 ? 0UL : (ulong)((slice + 1) * instance.SegmentLength);
            }

            return (int)((startPosition + relativePosition) % (ulong)instance.LaneLength);
        }

        private static void NextAddresses(Scratch scratch)
        {
            // address = G(zero, G(zero, input)), with the input block's counter incremented first.
            scratch.Input[6]++;
            FillBlock(scratch.Zero, scratch.Input, scratch.Address, withXor: false, scratch);
            FillBlock(scratch.Zero, scratch.Address, scratch.Address, withXor: false, scratch);
        }

        /// <summary>next = G(previous, reference), or next ^= G(previous, reference) when <paramref name="withXor"/>.</summary>
        private static void FillBlock(ReadOnlySpan<ulong> previous, ReadOnlySpan<ulong> reference, Span<ulong> next, bool withXor, Scratch scratch)
        {
            Span<ulong> r = scratch.R;
            Span<ulong> tmp = scratch.Tmp;

            // Every input is read before next is written, so next may alias reference (address generation does this).
            Xor(r, reference, previous);
            if (withXor)
            {
                Xor(tmp, r, next);
            }
            else
            {
                r.CopyTo(tmp);
            }

            ref ulong v = ref MemoryMarshal.GetReference(r);

            // P on each row of eight 16-byte registers: qwords 16i .. 16i+15 (register j at 16i + 2j).
            for (int i = 0; i < 8; i++)
            {
                Permute(ref Unsafe.Add(ref v, 16 * i), 2);
            }

            // P on each column: register j of column i is qwords 2i + 16j and 2i + 16j + 1.
            for (int i = 0; i < 8; i++)
            {
                Permute(ref Unsafe.Add(ref v, 2 * i), 16);
            }

            Xor(next, tmp, r);
        }

        /// <summary>
        /// The BLAKE2b round P over eight 16-byte registers, register j being the qwords at
        /// <c>j * registerStride</c> and <c>j * registerStride + 1</c> from <paramref name="first"/>.
        /// </summary>
        /// <remarks>The sixteen qwords are worked on in locals, so the eight mixes run in registers, not memory.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Permute(ref ulong first, int registerStride)
        {
            int s = registerStride;
            ulong v0 = first;
            ulong v1 = Unsafe.Add(ref first, 1);
            ulong v2 = Unsafe.Add(ref first, s);
            ulong v3 = Unsafe.Add(ref first, s + 1);
            ulong v4 = Unsafe.Add(ref first, 2 * s);
            ulong v5 = Unsafe.Add(ref first, (2 * s) + 1);
            ulong v6 = Unsafe.Add(ref first, 3 * s);
            ulong v7 = Unsafe.Add(ref first, (3 * s) + 1);
            ulong v8 = Unsafe.Add(ref first, 4 * s);
            ulong v9 = Unsafe.Add(ref first, (4 * s) + 1);
            ulong v10 = Unsafe.Add(ref first, 5 * s);
            ulong v11 = Unsafe.Add(ref first, (5 * s) + 1);
            ulong v12 = Unsafe.Add(ref first, 6 * s);
            ulong v13 = Unsafe.Add(ref first, (6 * s) + 1);
            ulong v14 = Unsafe.Add(ref first, 7 * s);
            ulong v15 = Unsafe.Add(ref first, (7 * s) + 1);

            Mix(ref v0, ref v4, ref v8, ref v12);
            Mix(ref v1, ref v5, ref v9, ref v13);
            Mix(ref v2, ref v6, ref v10, ref v14);
            Mix(ref v3, ref v7, ref v11, ref v15);
            Mix(ref v0, ref v5, ref v10, ref v15);
            Mix(ref v1, ref v6, ref v11, ref v12);
            Mix(ref v2, ref v7, ref v8, ref v13);
            Mix(ref v3, ref v4, ref v9, ref v14);

            first = v0;
            Unsafe.Add(ref first, 1) = v1;
            Unsafe.Add(ref first, s) = v2;
            Unsafe.Add(ref first, s + 1) = v3;
            Unsafe.Add(ref first, 2 * s) = v4;
            Unsafe.Add(ref first, (2 * s) + 1) = v5;
            Unsafe.Add(ref first, 3 * s) = v6;
            Unsafe.Add(ref first, (3 * s) + 1) = v7;
            Unsafe.Add(ref first, 4 * s) = v8;
            Unsafe.Add(ref first, (4 * s) + 1) = v9;
            Unsafe.Add(ref first, 5 * s) = v10;
            Unsafe.Add(ref first, (5 * s) + 1) = v11;
            Unsafe.Add(ref first, 6 * s) = v12;
            Unsafe.Add(ref first, (6 * s) + 1) = v13;
            Unsafe.Add(ref first, 7 * s) = v14;
            Unsafe.Add(ref first, (7 * s) + 1) = v15;
        }

        /// <summary>destination = left XOR right, one block, using the widest SIMD vector the hardware offers.</summary>
        /// <remarks>A block is 128 qwords, which every <see cref="Vector{T}"/> width divides exactly.</remarks>
        private static void Xor(Span<ulong> destination, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
        {
            Span<Vector<ulong>> d = MemoryMarshal.Cast<ulong, Vector<ulong>>(destination.Slice(0, QwordsInBlock));
            ReadOnlySpan<Vector<ulong>> l = MemoryMarshal.Cast<ulong, Vector<ulong>>(left.Slice(0, QwordsInBlock));
            ReadOnlySpan<Vector<ulong>> r = MemoryMarshal.Cast<ulong, Vector<ulong>>(right.Slice(0, QwordsInBlock));
            for (int i = 0; i < d.Length; i++)
            {
                d[i] = l[i] ^ r[i];
            }
        }

        /// <summary>The BLAKE2b mixing function with the BlaMka multiplication (RFC 9106 section 3.6).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mix(ref ulong a, ref ulong b, ref ulong c, ref ulong d)
        {
            a = BlaMka(a, b);
            d = BitOperations.RotateRight(d ^ a, 32);
            c = BlaMka(c, d);
            b = BitOperations.RotateRight(b ^ c, 24);
            a = BlaMka(a, b);
            d = BitOperations.RotateRight(d ^ a, 16);
            c = BlaMka(c, d);
            b = BitOperations.RotateRight(b ^ c, 63);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong BlaMka(ulong x, ulong y) => x + y + (2 * (ulong)(uint)x * (uint)y);

        private static void LoadBlock(ReadOnlySpan<byte> bytes, Span<ulong> block)
        {
            for (int i = 0; i < QwordsInBlock; i++)
            {
                block[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(i * 8));
            }
        }

        private readonly struct Instance
        {
            public Instance(Argon2Type type, int passes, int lanes, int laneLength, int segmentLength, int blockCount)
            {
                Type = type;
                Passes = passes;
                Lanes = lanes;
                LaneLength = laneLength;
                SegmentLength = segmentLength;
                BlockCount = blockCount;
            }

            public Argon2Type Type { get; }

            public int Passes { get; }

            public int Lanes { get; }

            public int LaneLength { get; }

            public int SegmentLength { get; }

            public int BlockCount { get; }
        }

        /// <summary>Per-call working blocks, so the derivation shares no state between threads.</summary>
        private sealed class Scratch
        {
            public ulong[] R { get; } = new ulong[QwordsInBlock];

            public ulong[] Tmp { get; } = new ulong[QwordsInBlock];

            public ulong[] Zero { get; } = new ulong[QwordsInBlock];

            public ulong[] Input { get; } = new ulong[QwordsInBlock];

            public ulong[] Address { get; } = new ulong[QwordsInBlock];

            public void Clear()
            {
                Array.Clear(R);
                Array.Clear(Tmp);
                Array.Clear(Input);
                Array.Clear(Address);
            }
        }
    }
}
