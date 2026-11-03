using System.Collections;
using System.Collections.Generic;
using static Masterly.Hash.Integrity.Tests.TestUtil;

namespace Masterly.Hash.Integrity.Tests;

/// <summary>
/// Pins the <c>actual &lt; expected</c> boundary in HashChain's sequence-failure classification. Verify reads the
/// entry at the failing index a second time when it classifies the failure, so the boundary
/// (actual == expected) can be reached only through a caller-supplied <see cref="IReadOnlyList{T}"/> whose
/// contents change between reads, for example a list another thread is writing to.
/// </summary>
public class SequenceBoundaryTests
{
    /// <summary>Returns <c>first</c> on the first read of index 0 and <c>later</c> on every read after that.</summary>
    private sealed class ChangingList : IReadOnlyList<HashChainEntry>
    {
        private readonly HashChainEntry _first;
        private readonly HashChainEntry _later;
        private int _reads;

        public ChangingList(HashChainEntry first, HashChainEntry later)
        {
            _first = first;
            _later = later;
        }

        public int Count => 1;

        public HashChainEntry this[int index] => _reads++ == 0 ? _first : _later;

        public IEnumerator<HashChainEntry> GetEnumerator()
        {
            yield return this[0];
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public void Verify_EntryThatMatchesTheExpectedSequenceOnTheSecondRead_IsClassifiedAsAGap()
    {
        byte[] genesis = HashChain.GenesisHash(ContentHashAlgorithm.Sha256);
        var wrong = new HashChainEntry(5, genesis, Utf8("a"), HashChain.ComputeEntryHash(genesis, Utf8("a"), 5));
        var right = new HashChainEntry(0, genesis, Utf8("a"), HashChain.ComputeEntryHash(genesis, Utf8("a"), 0));

        HashChainVerificationResult result = HashChain.Verify(new ChangingList(wrong, right), ContentHashAlgorithm.Sha256, null, null);

        // actual (0) == expected (0) is not "actual < expected", so it goes to the gap/reorder search.
        // With "<=" it would be "Reorder: Expected sequence 0 but found 0."
        Assert.False(result.IsValid);
        Assert.Equal(HashChainFailure.Gap, result.Failure);
        Assert.Equal(0, result.FirstBrokenIndex);
        Assert.Equal(0, result.EntriesVerified);
        Assert.Equal(0L, result.BrokenSequence);
        Assert.Equal("Sequence 0 to -1 is missing.", result.Reason);
    }
}
