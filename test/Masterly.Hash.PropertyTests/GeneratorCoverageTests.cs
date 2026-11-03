using System.Collections.Generic;
using System.Linq;
using System.Text;
using FsCheck;
using FsCheck.Fluent;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// Guards against vacuous properties: the generators must actually reach every rejection branch of the parser,
/// the KDF itself, the legacy formats, the length caps and invalid UTF-16 (only where it is meant to appear: the
/// never-throw inputs; every password meant to be hashed is well-formed but still rich in surrogate pairs,
/// combining marks and compatibility characters). If a generator is changed so that a branch is no longer hit,
/// these fail instead of the fuzzers silently testing less.
/// </summary>
public class GeneratorCoverageTests
{
    /// <summary>Fixed seed: these are statements about the generators, so they must not be flaky.</summary>
    private static T[] Sample<T>(Arbitrary<T> arbitrary, int count)
    {
        T[] samples = arbitrary.Generator.Sample(count, new Rnd(20261102UL), 50); // (numberOfSamples, seed, size)
        Assert.Equal(count, samples.Length);
        return samples;
    }

    [Fact]
    public void Arbitrary_stored_hashes_reach_every_verification_outcome()
    {
        AnyString[] samples = Sample(Arbitraries.AnyStrings(), 5000);
        var reasons = new HashSet<VerificationFailureReason>();
        var formats = new HashSet<string>();
        foreach (AnyString s in samples)
        {
            reasons.Add(Fixtures.Everything.Verify("pw", s.Value).FailureReason);
            formats.Add(Fixtures.Everything.Inspect(s.Value).Format);
        }

        Assert.Contains(VerificationFailureReason.NoStoredHash, reasons);
        Assert.Contains(VerificationFailureReason.UnknownFormat, reasons);
        Assert.Contains(VerificationFailureReason.MalformedHash, reasons);
        Assert.Contains(VerificationFailureReason.UnknownProfile, reasons);
        Assert.Contains(VerificationFailureReason.UnknownPepperKey, reasons);
        Assert.Contains(VerificationFailureReason.Mismatch, reasons); // well-formed $mh$ strings reached the KDF
        Assert.Contains("mh", formats);

        Assert.Contains(samples, s => s.Value.Length > 1024);
        Assert.Contains(samples, s => s.Value.Any(char.IsSurrogate));
        Assert.Contains(samples, s => !Fixtures.IsWellFormedUtf16(s.Value));
    }

    [Fact]
    public void Arbitrary_passwords_include_ill_formed_utf16_that_Verify_rejects()
    {
        AnyPassword[] samples = Sample(Arbitraries.AnyPasswords(), 2000);
        Assert.Contains(samples, p => p.Value.Length == 0);
        Assert.Contains(samples, p => p.Value.Length > 1024);
        Assert.True(samples.Count(p => !Fixtures.IsWellFormedUtf16(p.Value)) > samples.Length / 10);
        Assert.True(samples.Count(p => p.Value.Length > 0 && Fixtures.IsWellFormedUtf16(p.Value)) > samples.Length / 4);
        Assert.Contains(samples, p => HasSurrogatePair(p.Value));

        string stored = Fixtures.Plain.Hash("pw");
        var reasons = samples.Select(p => Fixtures.Plain.Verify(p.Value, stored).FailureReason).ToHashSet();
        Assert.Contains(VerificationFailureReason.InvalidPassword, reasons);
        Assert.Contains(VerificationFailureReason.EmptyPassword, reasons);
        Assert.Contains(VerificationFailureReason.PasswordTooLong, reasons);
        Assert.Contains(VerificationFailureReason.Mismatch, reasons);
    }

    [Fact]
    public void Ill_formed_passwords_are_ill_formed_in_every_way()
    {
        IllFormedPassword[] samples = Sample(Arbitraries.IllFormedPasswords(), 500);
        Assert.All(samples, p => Assert.False(Fixtures.IsWellFormedUtf16(p.Value), p.ToString()));
        Assert.All(samples, p => Assert.True(Fixtures.IsWellFormedUtf16(p.Origin) && Fixtures.IsWellFormedUtf16(p.Lossy), p.ToString()));
        Assert.Contains(samples, p => p.Value.Length == p.Origin.Length + 1);                    // a surrogate inserted
        Assert.Contains(samples, p => p.Value.Length == p.Origin.Length - 1);                    // half a pair dropped
        Assert.Contains(samples, p => p.Value.Length == p.Origin.Length && p.Value != p.Origin); // halves swapped
        Assert.Contains(samples, p => p.Value.Any(char.IsHighSurrogate) && p.Value.Any(char.IsLowSurrogate) && !HasSurrogatePair(p.Value));
        Assert.Contains(samples, p => HasSurrogatePair(p.Value)); // a valid pair next to the broken one
    }

    /// <summary>Every generator whose output is fed to Hash produces only well-formed UTF-16.</summary>
    [Fact]
    public void Passwords_meant_to_be_hashed_are_well_formed_and_still_rich()
    {
        string[] passwords = Sample(Arbitraries.ValidPasswords(), 1000).Select(p => p.Value)
            .Concat(Sample(Arbitraries.PasswordPairs(), 1000).SelectMany(p => new[] { p.Password, p.Candidate }))
            .Concat(Sample(Arbitraries.CapPasswords(), 200).Select(p => p.Value))
            .Concat(Sample(Arbitraries.LegacyCases(), 300).Select(c => c.Password))
            .Concat(Sample(Arbitraries.MhMutations(), 300).Select(m => m.Password))
            .Concat(Sample(Arbitraries.KeyRotations(), 300).Select(k => k.Password))
            .Concat(Sample(Arbitraries.EquivalentTexts(), 300).SelectMany(t => new[] { t.Text, t.Variant }))
            .ToArray();
        Assert.All(passwords, p => Assert.True(Fixtures.IsWellFormedUtf16(p), Fixtures.Show(p)));

        string[] valid = Sample(Arbitraries.ValidPasswords(), 1000).Select(p => p.Value).ToArray();
        Assert.Contains(valid, HasSurrogatePair);
        Assert.Contains(valid, p => p.Any(c => c >= '\u0300' && c <= '\u036F'));     // combining marks
        Assert.Contains(valid, p => p.Contains('\uFB01') || p.Contains('\uFB03'));    // ligatures
        Assert.Contains(valid, p => p.Any(c => c >= '\uFF01' && c <= '\uFF5E'));     // fullwidth
        Assert.Contains(valid, p => p.Contains('\uFFFD'));
        Assert.Contains(valid, p => p.Contains('\uFEFF'));
        Assert.Contains(valid, p => p.Contains('\u200B'));
        Assert.Contains(valid, p => p.Contains('\0'));
        Assert.Contains(valid, p => p.Contains('\uFDFA'));
        Assert.Contains(valid, p => !p.IsNormalized(NormalizationForm.FormKC));
        Assert.Contains(valid, p => p.Any(c => c > 0x7F && c < 0xD800));             // random BMP outside ASCII
        Assert.Contains(valid, p => p.Any(c => c > 0xDFFF && c < 0xFFFF));           // random BMP above the surrogates
    }

    [Fact]
    public void Mutations_produce_both_parseable_and_rejected_hashes()
    {
        MhMutation[] samples = Sample(Arbitraries.MhMutations(), 600);
        var reasons = new HashSet<VerificationFailureReason>();
        foreach (MhMutation m in samples)
            reasons.Add(Fixtures.Wrapping.Verify(m.Password, Mutator.Apply(MutationProperties.BuildOriginal(m), m.Ops)).FailureReason);

        Assert.Contains(VerificationFailureReason.Mismatch, reasons);
        Assert.Contains(VerificationFailureReason.MalformedHash, reasons);
        Assert.Contains(VerificationFailureReason.UnknownFormat, reasons);
    }

    [Fact]
    public void Password_pairs_include_matches_and_mismatches()
    {
        PasswordPair[] samples = Sample(Arbitraries.PasswordPairs(), 500);
        Assert.Contains(samples, p => p.Password != p.Candidate && Fixtures.SameEncoding(p.Password, p.Candidate));
        Assert.Contains(samples, p => !Fixtures.SameEncoding(p.Password, p.Candidate));
    }

    [Fact]
    public void Password_pairs_exercise_the_independent_oracle()
    {
        PasswordPair[] samples = Sample(Arbitraries.PasswordPairs(), 1000);
        Assert.All(samples, p => Assert.True(Fixtures.IsWellFormedUtf16(p.Password) && Fixtures.IsWellFormedUtf16(p.Candidate), p.ToString()));
        Assert.Contains(samples, p => p.Password != p.Candidate && Fixtures.NfkcEqual(p.Password, p.Candidate));
        Assert.True(samples.Count(p => !Fixtures.NfkcEqual(p.Password, p.Candidate)) > samples.Length / 4);
        // Surrogate pairs survive the edits: some pairs differ only in or next to an astral character.
        Assert.Contains(samples, p => HasSurrogatePair(p.Password) && HasSurrogatePair(p.Candidate) && p.Password != p.Candidate);
        Assert.Contains(samples, p => HasSurrogatePair(p.Password) != HasSurrogatePair(p.Candidate));
    }

    [Fact]
    public void Legacy_cases_reach_every_kind_success_path_and_length_limit()
    {
        LegacyCase[] samples = Sample(Arbitraries.LegacyCases(), 600);
        for (int kind = 0; kind < Fixtures.LegacyKinds; kind++)
            Assert.Contains(samples, c => c.Kind == kind && Encoding.UTF8.GetByteCount(c.Password) <= Arbitraries.MaxPasswordBytes);
        Assert.Contains(samples, c => Encoding.UTF8.GetByteCount(c.Password) > Arbitraries.MaxPasswordBytes);
        Assert.Contains(samples, c => Encoding.UTF8.GetByteCount(c.Password) > 900 && Encoding.UTF8.GetByteCount(c.Password) <= Arbitraries.MaxPasswordBytes);
        Assert.All(samples, c => Assert.True(Fixtures.IsWellFormedUtf16(c.Password), c.ToString()));
        Assert.Contains(samples, c => HasSurrogatePair(c.Password));
        Assert.Contains(samples, c => !c.Password.IsNormalized(NormalizationForm.FormKC));
        Assert.DoesNotContain(samples, c => Arbitraries.InLegacyRehashLengthGap(c.Password));
    }

    [Fact]
    public void Cap_passwords_straddle_the_limit()
    {
        CapPassword[] samples = Sample(Arbitraries.CapPasswords(), 300);
        Assert.Contains(samples, p => Masterly.Hash.Primitives.HashPrimitives.EncodePassword(p.Value).Length <= Arbitraries.MaxPasswordBytes);
        Assert.Contains(samples, p => Masterly.Hash.Primitives.HashPrimitives.EncodePassword(p.Value).Length > Arbitraries.MaxPasswordBytes);
    }

    [Fact]
    public void Equivalent_texts_are_not_mostly_identical()
    {
        EquivalentText[] samples = Sample(Arbitraries.EquivalentTexts(), 300);
        Assert.True(samples.Count(t => t.Text != t.Variant) > samples.Length / 3);
    }

    private static bool HasSurrogatePair(string value)
    {
        for (int i = 0; i + 1 < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]) && char.IsLowSurrogate(value[i + 1]))
                return true;
        }
        return false;
    }

    [Fact]
    public void Base64_candidates_are_accepted_and_rejected()
    {
        B64Candidate[] samples = Sample(Arbitraries.B64Candidates(), 1000);
        int accepted = samples.Count(c => Masterly.Hash.Primitives.HashPrimitives.TryFromB64(c.Value, out _));
        Assert.InRange(accepted, samples.Length / 10, samples.Length * 9 / 10);
    }
}
