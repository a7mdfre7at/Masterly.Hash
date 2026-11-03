using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static Masterly.Hash.Integrity.Tests.TestUtil;

namespace Masterly.Hash.Integrity.Tests;

public class HashChainTests
{
    private static HashChainLog LogOf(int count, ContentHashAlgorithm? algorithm = null)
    {
        var log = new HashChainLog(algorithm ?? ContentHashAlgorithm.Sha256);
        for (int i = 0; i < count; i++)
            log.Append(Utf8("event-" + i));
        return log;
    }

    private static HashChainEntry Copy(HashChainEntry e, long? sequence = null, byte[]? previous = null, byte[]? payload = null, byte[]? hash = null) =>
        new HashChainEntry(sequence ?? e.Sequence, previous ?? e.PreviousHash.ToArray(), payload ?? e.Payload.ToArray(), hash ?? e.Hash.ToArray());

    /// <summary>Independent transcription of the documented encoding.</summary>
    private static byte[] ReferenceEncoding(string algorithmId, long sequence, byte[] previous, byte[] payload)
    {
        var buffer = new List<byte>();
        void U64(ulong v)
        {
            byte[] b = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(b, v);
            buffer.AddRange(b);
        }
        void Field(byte[] v)
        {
            U64((ulong)v.Length);
            buffer.AddRange(v);
        }
        Field(Utf8("masterly-hash-chain/v1"));
        Field(Utf8(algorithmId));
        U64((ulong)sequence);
        Field(previous);
        Field(payload);
        return buffer.ToArray();
    }

    [Fact]
    public void EntryHash_MatchesDocumentedEncoding()
    {
        byte[] genesis = new byte[32];
        byte[] payload = Utf8("hello");
        byte[] expected = SHA256.HashData(ReferenceEncoding("sha256", 0, genesis, payload));
        Assert.Equal(ToHex(expected), ToHex(HashChain.ComputeEntryHash(genesis, payload, 0)));

        byte[] key = Key("chain");
        byte[] expectedMac = HMACSHA256.HashData(key, ReferenceEncoding("hmac-sha256:audit-1", 7, expected, payload));
        Assert.Equal(ToHex(expectedMac), ToHex(HashChain.ComputeEntryHash(expected, payload, 7, ContentHashAlgorithm.HmacSha256("audit-1", key))));
    }

    [Fact]
    public void EntryHash_BindsEveryField()
    {
        byte[] prev = SHA256.HashData(Utf8("p"));
        byte[] baseline = HashChain.ComputeEntryHash(prev, Utf8("x"), 5);
        Assert.NotEqual(baseline, HashChain.ComputeEntryHash(prev, Utf8("x"), 6));
        Assert.NotEqual(baseline, HashChain.ComputeEntryHash(prev, Utf8("y"), 5));
        Assert.NotEqual(baseline, HashChain.ComputeEntryHash(Flip(prev), Utf8("x"), 5));
        Assert.NotEqual(baseline, HashChain.ComputeEntryHash(prev, Utf8("x"), 5, Hmac("k1")));
        Assert.NotEqual(HashChain.ComputeEntryHash(prev, Utf8("x"), 5, Hmac("k1")), HashChain.ComputeEntryHash(prev, Utf8("x"), 5, Hmac("k2")));
        Assert.Equal(baseline, HashChain.ComputeEntryHash(prev, Utf8("x"), 5));
    }

    [Fact]
    public void ComputeEntryHash_ValidatesArguments()
    {
        Assert.Throws<ArgumentNullException>(() => HashChain.ComputeEntryHash(null!, Array.Empty<byte>(), 0));
        Assert.Throws<ArgumentNullException>(() => HashChain.ComputeEntryHash(new byte[32], null!, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashChain.ComputeEntryHash(new byte[32], Array.Empty<byte>(), -1));
        Assert.Throws<ArgumentException>(() => HashChain.ComputeEntryHash(new byte[31], Array.Empty<byte>(), 0));
        Assert.Throws<ArgumentException>(() => HashChain.ComputeEntryHash(new byte[32], Array.Empty<byte>(), 0, ContentHashAlgorithm.Sha512));
    }

    [Fact]
    public void Log_AppendsLinkedEntries_AndVerifies()
    {
        HashChainLog log = LogOf(5);
        IReadOnlyList<HashChainEntry> entries = log.Entries;
        Assert.Equal(5, log.Count);
        Assert.Equal(new byte[32], entries[0].PreviousHash.ToArray());
        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(i, entries[i].Sequence);
            if (i > 0)
                Assert.Equal(entries[i - 1].Hash.ToArray(), entries[i].PreviousHash.ToArray());
        }

        HashChainVerificationResult result = log.Verify();
        Assert.True(result.IsValid);
        Assert.Equal(HashChainFailure.None, result.Failure);
        Assert.Null(result.FirstBrokenIndex);
        Assert.Equal(5, result.EntriesVerified);
        Assert.Equal(4, result.Head!.Sequence);
        Assert.Equal(log.Head!.Hash.ToArray(), result.Head.Hash.ToArray());
        Assert.True(log.Verify(entries, log.Head).IsValid);
    }

    [Fact]
    public void EmptyChain_IsValid_UnlessHeadExpected()
    {
        Assert.True(HashChain.Verify(Array.Empty<HashChainEntry>()).IsValid);
        Assert.Null(new HashChainLog().Head);
        HashChainLog log = LogOf(2);
        HashChainVerificationResult result = log.Verify(Array.Empty<HashChainEntry>(), log.Head!);
        Assert.False(result.IsValid);
        Assert.Equal(HashChainFailure.Truncated, result.Failure);
    }

    [Fact]
    public void EditedPayload_IsHashMismatch_AtThatIndex()
    {
        var entries = LogOf(6).Entries.ToList();
        entries[3] = Copy(entries[3], payload: Utf8("event-3 (edited)"));
        HashChainVerificationResult result = HashChain.Verify(entries);
        Assert.False(result.IsValid);
        Assert.Equal(HashChainFailure.HashMismatch, result.Failure);
        Assert.Equal(3, result.FirstBrokenIndex);
        Assert.Equal(3, result.BrokenSequence);
        Assert.Equal(3, result.EntriesVerified);
        Assert.DoesNotContain("edited", result.ToString());
    }

    [Fact]
    public void RecomputedEntry_BreaksTheNextLink()
    {
        var entries = LogOf(6).Entries.ToList();
        byte[] forgedPayload = Utf8("forged");
        entries[2] = Copy(entries[2], payload: forgedPayload,
            hash: HashChain.ComputeEntryHash(entries[2].PreviousHash.ToArray(), forgedPayload, 2));
        HashChainVerificationResult result = HashChain.Verify(entries);
        Assert.Equal(HashChainFailure.PreviousHashMismatch, result.Failure);
        Assert.Equal(3, result.FirstBrokenIndex);
    }

    [Fact]
    public void DeletedEntry_IsGap()
    {
        var entries = LogOf(6).Entries.ToList();
        entries.RemoveAt(2);
        HashChainVerificationResult result = HashChain.Verify(entries);
        Assert.Equal(HashChainFailure.Gap, result.Failure);
        Assert.Equal(2, result.FirstBrokenIndex);
        Assert.Equal(3, result.BrokenSequence);

        var noStart = LogOf(3).Entries.Skip(1).ToList();
        Assert.Equal(HashChainFailure.Gap, HashChain.Verify(noStart).Failure);
        Assert.Equal(0, HashChain.Verify(noStart).FirstBrokenIndex);
    }

    [Fact]
    public void SwappedEntries_AreReorder()
    {
        var entries = LogOf(6).Entries.ToList();
        (entries[2], entries[4]) = (entries[4], entries[2]);
        HashChainVerificationResult result = HashChain.Verify(entries);
        Assert.Equal(HashChainFailure.Reorder, result.Failure);
        Assert.Equal(2, result.FirstBrokenIndex);

        var adjacent = LogOf(4).Entries.ToList();
        (adjacent[1], adjacent[2]) = (adjacent[2], adjacent[1]);
        Assert.Equal(HashChainFailure.Reorder, HashChain.Verify(adjacent).Failure);
        Assert.Equal(1, HashChain.Verify(adjacent).FirstBrokenIndex);
    }

    [Fact]
    public void RepeatedEntry_IsDuplicate()
    {
        var entries = LogOf(4).Entries.ToList();
        entries.Insert(2, entries[1]);
        HashChainVerificationResult result = HashChain.Verify(entries);
        Assert.Equal(HashChainFailure.Duplicate, result.Failure);
        Assert.Equal(2, result.FirstBrokenIndex);
    }

    [Fact]
    public void InsertedEntryWithNextSequence_IsCaught()
    {
        var entries = LogOf(4).Entries.ToList();
        // Attacker renumbers everything after an inserted entry; links no longer match.
        HashChainEntry inserted = HashChain.CreateNext(entries[1], Utf8("inserted"), ContentHashAlgorithm.Sha256);
        var tampered = entries.Take(2).Append(inserted).Concat(entries.Skip(2).Select(e => Copy(e, sequence: e.Sequence + 1))).ToList();
        HashChainVerificationResult result = HashChain.Verify(tampered);
        Assert.False(result.IsValid);
        Assert.Equal(3, result.FirstBrokenIndex);
        Assert.Equal(HashChainFailure.PreviousHashMismatch, result.Failure);
    }

    [Fact]
    public void Truncation_IsCaughtOnlyWithTrustedHead()
    {
        HashChainLog log = LogOf(6);
        HashChainCheckpoint head = log.Head!;
        var truncated = log.Entries.Take(4).ToList();
        Assert.True(HashChain.Verify(truncated).IsValid);

        HashChainVerificationResult result = log.Verify(truncated, head);
        Assert.Equal(HashChainFailure.Truncated, result.Failure);
        Assert.Equal(4, result.FirstBrokenIndex);
        Assert.Equal(4, result.EntriesVerified);
    }

    [Fact]
    public void RewrittenTail_IsHeadMismatch()
    {
        HashChainLog log = LogOf(4);
        HashChainCheckpoint head = log.Head!;

        // Attacker without a key drops the last entry and appends a different one, recomputing correctly.
        var entries = log.Entries.Take(3).ToList();
        entries.Add(HashChain.CreateNext(entries[2], Utf8("different"), ContentHashAlgorithm.Sha256));
        Assert.True(HashChain.Verify(entries).IsValid);
        HashChainVerificationResult result = log.Verify(entries, head);
        Assert.Equal(HashChainFailure.HeadMismatch, result.Failure);
        Assert.Equal(3, result.FirstBrokenIndex);

        // Legitimate growth past the checkpoint is fine: the checkpoint only has to still be in the chain.
        var extended = log.Entries.ToList();
        extended.Add(HashChain.CreateNext(extended[3], Utf8("later"), ContentHashAlgorithm.Sha256));
        Assert.True(log.Verify(extended, head).IsValid);
    }

    [Fact]
    public void Checkpoint_SurvivesAppends_AndCatchesRewrittenHistory()
    {
        // The README workflow: save the head, keep appending, verify later against the old checkpoint.
        var log = new HashChainLog();
        log.Append(Utf8("x"));
        HashChainCheckpoint head = log.Head!;
        log.Append(Utf8("y"));
        log.Append(Utf8("z"));
        HashChainVerificationResult ok = log.Verify(log.Entries, head);
        Assert.True(ok.IsValid, ok.ToString());
        Assert.Equal(2, ok.Head!.Sequence);

        // Rewriting history from the start (recomputing a consistent unkeyed chain) is caught at the checkpoint.
        var rewritten = new List<HashChainEntry>();
        HashChainEntry? previous = null;
        foreach (string payload in new[] { "forged", "y", "z" })
        {
            previous = HashChain.CreateNext(previous, Utf8(payload), ContentHashAlgorithm.Sha256);
            rewritten.Add(previous);
        }
        Assert.True(HashChain.Verify(rewritten).IsValid);
        HashChainVerificationResult result = log.Verify(rewritten, head);
        Assert.Equal(HashChainFailure.HeadMismatch, result.Failure);
        Assert.Equal(0, result.FirstBrokenIndex);

        // Truncating to before the checkpoint is still Truncated.
        Assert.Equal(HashChainFailure.Truncated, log.Verify(Array.Empty<HashChainEntry>(), head).Failure);
    }

    [Fact]
    public void Checkpoint_BeforeAnchoredSegment_MustMatchAnchor()
    {
        HashChainLog log = LogOf(6);
        IReadOnlyList<HashChainEntry> all = log.Entries;
        HashChainCheckpoint anchor = all[2].ToCheckpoint();
        var segment = all.Skip(3).ToList();
        // Checkpoint equal to the anchor: covered by the anchor.
        Assert.True(HashChain.Verify(segment, ContentHashAlgorithm.Sha256, anchor, all[2].ToCheckpoint()).IsValid);
        // Checkpoint inside the segment.
        Assert.True(HashChain.Verify(segment, ContentHashAlgorithm.Sha256, anchor, all[4].ToCheckpoint()).IsValid);
        // Checkpoint older than the anchor cannot be confirmed by this segment.
        Assert.Equal(HashChainFailure.HeadMismatch,
            HashChain.Verify(segment, ContentHashAlgorithm.Sha256, anchor, all[1].ToCheckpoint()).Failure);
        // A checkpoint with the right sequence but wrong hash inside the segment.
        Assert.Equal(HashChainFailure.HeadMismatch,
            HashChain.Verify(segment, ContentHashAlgorithm.Sha256, anchor, new HashChainCheckpoint(4, new byte[32])).Failure);
    }

    [Fact]
    public void Keyed_AttackerWithoutKeyCannotRecomputeChain()
    {
        var mac = Hmac("audit-1", "secret");
        HashChainLog log = LogOf(5, mac);
        Assert.True(log.Verify().IsValid);

        // Attacker rewrites entry 2 and recomputes the rest of the chain with a key they control (same key id).
        var forged = new List<HashChainEntry>(log.Entries.Take(2));
        var attackerKey = Hmac("audit-1", "attacker");
        HashChainEntry? previous = forged[1];
        for (int i = 2; i < 5; i++)
        {
            HashChainEntry next = HashChain.CreateNext(previous, Utf8(i == 2 ? "forged" : "event-" + i), attackerKey);
            forged.Add(next);
            previous = next;
        }

        HashChainVerificationResult result = log.Verify(forged);
        Assert.Equal(HashChainFailure.HashMismatch, result.Failure);
        Assert.Equal(2, result.FirstBrokenIndex);

        // Recomputing with plain SHA-256 fails from the first entry.
        Assert.Equal(0, HashChain.Verify(LogOf(5).Entries, mac).FirstBrokenIndex);
        // And a keyed chain does not verify under another key.
        Assert.False(HashChain.Verify(log.Entries, Hmac("audit-1", "other")).IsValid);
    }

    [Fact]
    public void AnchoredSegment_Verifies()
    {
        HashChainLog log = LogOf(10);
        IReadOnlyList<HashChainEntry> all = log.Entries;
        HashChainCheckpoint anchor = all[3].ToCheckpoint();
        var segment = all.Skip(4).ToList();
        Assert.True(HashChain.Verify(segment, ContentHashAlgorithm.Sha256, anchor, log.Head).IsValid);
        Assert.Equal(HashChainFailure.Gap, HashChain.Verify(all.Skip(5), ContentHashAlgorithm.Sha256, anchor, null).Failure);
        Assert.Equal(HashChainFailure.PreviousHashMismatch,
            HashChain.Verify(segment, ContentHashAlgorithm.Sha256, new HashChainCheckpoint(3, new byte[32]), null).Failure);
        // Empty segment right after the anchor that is also the head is valid.
        Assert.True(HashChain.Verify(Array.Empty<HashChainEntry>(), ContentHashAlgorithm.Sha256, log.Head, log.Head).IsValid);
    }

    [Fact]
    public void MalformedEntries_DoNotThrow()
    {
        var entries = LogOf(3).Entries.ToList();
        var withNull = entries.ToList();
        withNull[1] = null!;
        Assert.Equal(HashChainFailure.InvalidEntry, HashChain.Verify(withNull).Failure);

        var shortHash = entries.ToList();
        shortHash[1] = Copy(shortHash[1], hash: new byte[5]);
        Assert.Equal(HashChainFailure.HashMismatch, HashChain.Verify(shortHash).Failure);

        var shortPrev = entries.ToList();
        shortPrev[0] = Copy(shortPrev[0], previous: new byte[3]);
        Assert.Equal(HashChainFailure.PreviousHashMismatch, HashChain.Verify(shortPrev).Failure);

        var huge = entries.ToList();
        huge[2] = Copy(huge[2], sequence: long.MaxValue);
        Assert.Equal(HashChainFailure.Gap, HashChain.Verify(huge).Failure);

        // A chain verified with the wrong algorithm fails cleanly.
        Assert.False(HashChain.Verify(entries, ContentHashAlgorithm.Sha512).IsValid);
    }

    [Fact]
    public void LoadingLog_VerifiesExistingEntries()
    {
        HashChainLog original = LogOf(3);
        var reloaded = new HashChainLog(ContentHashAlgorithm.Sha256, original.Entries);
        reloaded.Append(Utf8("event-3"));
        Assert.True(reloaded.Verify().IsValid);
        Assert.Equal(original.Entries.Last().Hash.ToArray(), reloaded.Entries[2].Hash.ToArray());

        var broken = original.Entries.ToList();
        broken[1] = Copy(broken[1], payload: Utf8("x"));
        Assert.Throws<InvalidDataException>(() => new HashChainLog(ContentHashAlgorithm.Sha256, broken));
    }

    [Fact]
    public async Task ConcurrentAppends_ProduceAValidChain()
    {
        var log = new HashChainLog(Hmac("c"));
        await Task.WhenAll(Enumerable.Range(0, 8).Select(t => Task.Run(() =>
        {
            for (int i = 0; i < 250; i++)
                log.Append(Utf8($"{t}:{i}"));
        })));
        Assert.Equal(2000, log.Count);
        Assert.True(log.Verify().IsValid);
    }

    [Fact]
    public void Entries_AreDefensiveCopies_AndToStringHidesPayload()
    {
        byte[] payload = Utf8("secret-payload");
        var log = new HashChainLog();
        HashChainEntry entry = log.Append(payload);
        payload[0] = (byte)'X';
        Assert.Equal("secret-payload", System.Text.Encoding.UTF8.GetString(entry.Payload.Span));
        Assert.True(log.Verify().IsValid);
        Assert.DoesNotContain("secret", entry.ToString());

        byte[] hash = entry.Hash.ToArray();
        var copy = new HashChainEntry(0, new byte[32], Utf8("secret-payload"), hash);
        hash[0] ^= 1;
        Assert.True(HashChain.Verify(new[] { copy }).IsValid);
    }

    [Fact]
    public void Arguments_AreGuarded()
    {
        Assert.Throws<ArgumentNullException>(() => new HashChainLog(null!));
        Assert.Throws<ArgumentNullException>(() => new HashChainLog().Append(null!));
        Assert.Throws<ArgumentNullException>(() => HashChain.Verify(null!));
        Assert.Throws<ArgumentNullException>(() => HashChain.Verify(Array.Empty<HashChainEntry>(), null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => new HashChainEntry(-1, new byte[32], Array.Empty<byte>(), new byte[32]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new HashChainCheckpoint(-1, new byte[32]));
        Assert.Throws<ArgumentException>(() => HashChain.CreateNext(LogOf(1).Entries[0], Array.Empty<byte>(), ContentHashAlgorithm.Sha512));
    }
}
