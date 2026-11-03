using System;
using FsCheck.Xunit;
using Masterly.Hash.Primitives;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// <see cref="HashPrimitives.TryFromB64"/> accepts exactly the canonical unpadded encodings produced by
/// <see cref="HashPrimitives.ToB64"/>, so every salt and tag has exactly one string form.
/// Checked against <see cref="Base64Reference"/>, an independent bit-level implementation.
/// </summary>
[Properties(Arbitrary = new[] { typeof(Arbitraries) }, QuietOnSuccess = true)]
public class Base64Properties
{
    [Property(MaxTest = 2000)]
    public void ToB64_matches_the_reference_and_round_trips(NonEmptyBytes bytes)
    {
        string encoded = HashPrimitives.ToB64(bytes.Value);
        Assert.Equal(Base64Reference.Encode(bytes.Value), encoded);
        Assert.Equal(Convert.ToBase64String(bytes.Value).TrimEnd('='), encoded);
        Assert.Equal((bytes.Value.Length * 4 + 2) / 3, encoded.Length);

        Assert.True(HashPrimitives.TryFromB64(encoded, out byte[] decoded));
        Assert.Equal(bytes.Value, decoded);
    }

    [Property(MaxTest = 10000)]
    public void TryFromB64_agrees_with_the_reference_on_any_input(B64Candidate candidate)
    {
        bool expected = Base64Reference.TryDecode(candidate.Value, out byte[] expectedBytes);
        bool actual = HashPrimitives.TryFromB64(candidate.Value, out byte[] actualBytes);

        Assert.Equal(expected, actual);
        if (actual)
        {
            Assert.Equal(expectedBytes, actualBytes);
            // Canonical: the accepted string is the only encoding of those bytes.
            Assert.Equal(candidate.Value, HashPrimitives.ToB64(actualBytes));
        }
        else
        {
            // A rejection never leaks a partial or non-canonical decoding through the out parameter.
            Assert.Empty(actualBytes);
        }
    }

    [Property(MaxTest = 3000)]
    public void TryFromB64_never_throws_on_arbitrary_strings(AnyString value)
    {
        bool expected = Base64Reference.TryDecode(value.Value, out _);
        bool actual = HashPrimitives.TryFromB64(value.Value, out byte[] bytes);
        Assert.Equal(expected, actual);
        if (!actual)
            Assert.Empty(bytes);
    }

    [Theory]
    [InlineData("AA", true)]      // one byte, 4 unused zero bits
    [InlineData("AB", false)]     // unused bits set: non-canonical
    [InlineData("AAA", true)]     // two bytes, 2 unused zero bits
    [InlineData("AAB", false)]
    [InlineData("AAAA", true)]
    [InlineData("A", false)]      // length 1 mod 4 encodes no whole byte
    [InlineData("AAAAA", false)]
    [InlineData("AA==", false)]   // padding is not part of the PHC encoding
    [InlineData("AA=", false)]
    [InlineData("A A", false)]
    [InlineData("AA\n", false)]
    [InlineData("-_", false)]     // base64url alphabet is not accepted
    [InlineData("Zg", true)]      // RFC 4648 §10: "f"
    [InlineData("Zm8", true)]     // "fo"
    [InlineData("Zm9v", true)]    // "foo"
    [InlineData("Zm9vYg", true)]  // "foob"
    [InlineData("Zh", false)]     // "f" with a non-zero trailing bit
    public void Edge_cases(string value, bool accepted)
    {
        Assert.Equal(accepted, HashPrimitives.TryFromB64(value, out byte[] bytes));
        if (!accepted)
            Assert.Empty(bytes);
        Assert.Equal(accepted, Base64Reference.TryDecode(value, out _));
    }

    [Fact]
    public void Empty_input_is_rejected_although_it_is_the_encoding_of_no_bytes()
    {
        // ToB64 is total, TryFromB64 deliberately is not: an empty salt/tag/wp field is never valid.
        Assert.Equal(string.Empty, HashPrimitives.ToB64(Array.Empty<byte>()));
        Assert.False(HashPrimitives.TryFromB64(string.Empty, out byte[] bytes));
        Assert.Empty(bytes);
        Assert.False(HashPrimitives.TryFromB64(null!, out bytes));
        Assert.Empty(bytes);
    }
}
