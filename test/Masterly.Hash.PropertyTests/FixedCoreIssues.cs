using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Masterly.Hash.Legacy;
using Masterly.Hash.Primitives;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// Regression tests for core bugs this suite found and core has since fixed (they used to be skipped in
/// <c>NormalizationEdgeCases</c>). Each test pins the behaviour core now promises:
/// <list type="number">
/// <item>Passwords that are not well-formed UTF-16 (an unpaired surrogate) are rejected: Hash throws, Verify reports
/// <see cref="VerificationFailureReason.InvalidPassword"/> before any format is consulted, so lone surrogates can
/// neither collide through U+FFFD nor switch NFKC off.</item>
/// <item><c>$mh$</c> parameters are only accepted in the canonical order p, k, w, wp, so one hash has one string.</item>
/// <item><see cref="HashPrimitives.TryFromB64"/> leaves an empty array behind when it rejects an input.</item>
/// <item>The 1.x format does not claim hex-only strings (unsalted hex digests belong to the hex formats).</item>
/// <item>Exceptions from third-party legacy formats are contained (except cancellation and out-of-memory).</item>
/// </list>
/// Plain Facts rather than [InlineData] where lone surrogates are involved: xunit serializes theory data and would
/// mangle them.
/// </summary>
[Properties(Arbitrary = new[] { typeof(Arbitraries) }, QuietOnSuccess = true)]
public class FixedCoreIssues
{
    private const string InvalidUtf16Message = "Password contains invalid UTF-16 or a code point that cannot be normalized.";

    private static readonly PasswordHasher Hasher = Fixtures.Plain;

    /// <summary>Ill-formed passwords, including the original failing inputs of the two lone-surrogate bugs.</summary>
    private static readonly string[] IllFormed =
    {
        "\uFB01\uD800", "\uD800\uFB01", "A\u030A\uDC00", "\uFF21\uFF22\uDFFF", // used to skip NFKC for the whole string
        "pw\uD800", "pw\uDC00", "\uDBFFpw", "\uDFFFpw", "a\uD800b", "a\uD801b", // used to collide via U+FFFD
        "\uD800", "\uDFFF", "\uDC00\uD800", "x\uD83D", "\uDE00x", "\uD83D\U0001F600", "\U0001F600\uDE00",
    };

    // ---- Lone surrogates -------------------------------------------------------------------------------------

    [Fact]
    public void Hash_and_EncodePassword_reject_unpaired_surrogates()
    {
        foreach (string password in IllFormed)
        {
            string context = Fixtures.Show(password);
            Assert.False(Fixtures.IsWellFormedUtf16(password), context);
            Assert.False(HashPrimitives.IsWellFormedPassword(password), context);
            Assert.Throws<ArgumentException>(() => HashPrimitives.EncodePassword(password));

            foreach (PasswordHasher hasher in Fixtures.AllHashersWithUnpepperedWrap())
            {
                AssertRejected(() => hasher.Hash(password), context);
                AssertRejected(() => hasher.Hash(password, hasher.DefaultProfile), context);
                AssertRejected(() => hasher.HashAsync(password).AsTask().GetAwaiter().GetResult(), context);
            }
        }
    }

    [Fact]
    public void Verify_reports_InvalidPassword_for_unpaired_surrogates_whatever_the_stored_hash()
    {
        string[] stored = StoredHashesFor("fi\uFFFD")
            .Concat(new[] { "$mh$garbage", "not a hash", Fixtures.LegacySeeds[0].Hash, Fixtures.LegacySeeds[^1].Hash })
            .ToArray();

        foreach (string password in IllFormed)
        {
            foreach (PasswordHasher hasher in Fixtures.AllHashersWithUnpepperedWrap())
            {
                foreach (string hash in stored)
                    AssertInvalidPassword(hasher, password, hash);

                // Unknown user: no dummy work is needed for a password that can never be hashed.
                Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy(password, null).FailureReason);
                Assert.Equal(VerificationFailureReason.NoStoredHash, Wait(hasher.VerifyOrDummyAsync(password, null)).FailureReason);

                // The order of the cheap checks: no stored hash, then empty password, then invalid password.
                Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.Verify(password, "").FailureReason);
                Assert.Equal(VerificationFailureReason.EmptyPassword, hasher.Verify("", stored[0]).FailureReason);
            }
        }
    }

    /// <summary>
    /// The collision bug: lossy UTF-8 maps every lone surrogate to U+FFFD, so "pw" + U+D800, "pw" + U+DC00 and
    /// "pw" + U+FFFD used to be the same password. Now only the well-formed one is a password at all; a 1.x hash a
    /// lossy legacy system made from "pw" + U+D800 is, byte for byte, the hash of "pw" + U+FFFD.
    /// </summary>
    [Fact]
    public void Distinct_lone_surrogates_no_longer_collide()
    {
        const string wellFormed = "pw\uFFFD";
        string hash = Hasher.Hash(wellFormed);
        Assert.True(Hasher.Verify(wellFormed, hash).IsMatch);
        foreach (string other in new[] { "pw\uD800", "pw\uDC00", "pw\uDBFF", "pw\uDFFF" })
        {
            Assert.Equal(VerificationFailureReason.InvalidPassword, Hasher.Verify(other, hash).FailureReason);

            string legacy = Fixtures.BuildLegacyHash(0, other, Fixtures.Bytes(16, 7));
            Assert.Equal(Fixtures.BuildLegacyHash(0, wellFormed, Fixtures.Bytes(16, 7)), legacy);
            Assert.Equal(VerificationFailureReason.InvalidPassword, Hasher.Verify(other, legacy).FailureReason);
            Assert.True(Hasher.Verify(wellFormed, legacy).IsMatch, Fixtures.Show(other));
        }
    }

    [Fact]
    public void Surrogate_pairs_are_ordinary_well_formed_passwords()
    {
        string[] passwords =
        {
            "\U0001D11E", "\U0001F600pw", "\U00010000", "\U0010FFFD", "\U0010FC00\U0010FC00",
            "a\U0001F469\u200D\U0001F4BBb", "\uFFFD\uFEFF\u200B\U0001F600",
        };
        foreach (string password in passwords)
        {
            Assert.True(HashPrimitives.IsWellFormedPassword(password), Fixtures.Show(password));
            Assert.Equal(Encoding.UTF8.GetBytes(password.Normalize(NormalizationForm.FormKC)), HashPrimitives.EncodePassword(password));
            string hash = Hasher.Hash(password);
            Assert.Equal(VerificationStatus.Success, Hasher.Verify(password, hash).Status);
            Assert.Equal(VerificationFailureReason.Mismatch, Hasher.Verify(Fixtures.WrongPassword(password), hash).FailureReason);
        }

        // Astral compatibility characters still go through NFKC: MATHEMATICAL BOLD CAPITAL A is "A".
        Assert.True(Hasher.Verify("A", Hasher.Hash("\U0001D400")).IsMatch);
    }

    /// <summary>
    /// Ill-formed passwords are turned away before any format runs: a hasher whose first format throws
    /// <see cref="OperationCanceledException"/> (which core always lets escape) from every member still answers
    /// InvalidPassword without throwing, for every kind of stored hash, while the lossy legacy reading of the same
    /// password (U+FFFD in place of each lone surrogate) is a well-formed password that verifies normally.
    /// </summary>
    [Property(MaxTest = 200)]
    public void Ill_formed_passwords_are_rejected_before_any_format_is_consulted(IllFormedPassword p)
    {
        Assert.False(Fixtures.IsWellFormedUtf16(p.Value), p.ToString());
        Assert.True(Fixtures.IsWellFormedUtf16(p.Lossy), p.ToString());
        Assert.False(HashPrimitives.IsWellFormedPassword(p.Value));
        Assert.Throws<ArgumentException>(() => HashPrimitives.EncodePassword(p.Value));
        AssertRejected(() => Hasher.Hash(p.Value), p.ToString());

        var tripwires = new[]
        {
            Fixtures.WithFormatFirst(new ThrowingFormat(AllPoints, () => new OperationCanceledException()), wrapping: true),
            Fixtures.WithFormatFirst(new ThrowingFormat(AllPoints, () => new OperationCanceledException()), wrapping: false),
        };
        var legacy = Enumerable.Range(0, Fixtures.LegacyKinds).Select(kind => Fixtures.BuildLegacyHash(kind, p.Value, Fixtures.Bytes(16, 3))).ToArray();
        string[] stored = StoredHashesFor(p.Origin).Concat(StoredHashesFor(p.Lossy)).Concat(legacy).ToArray();

        foreach (PasswordHasher hasher in Fixtures.AllHashersWithUnpepperedWrap().Concat(tripwires))
        {
            foreach (string hash in stored)
                AssertInvalidPassword(hasher, p.Value, hash);
        }

        // The legacy system hashed the lossy bytes, so the well-formed U+FFFD reading is what those hashes accept.
        for (int kind = 0; kind < Fixtures.LegacyKinds; kind++)
        {
            Assert.Equal(Fixtures.BuildLegacyHash(kind, p.Lossy, Fixtures.Bytes(16, 3)), legacy[kind]);
            if (Fixtures.Supports(Fixtures.Everything, kind))
                Assert.True(Fixtures.Everything.Verify(p.Lossy, legacy[kind]).IsMatch, $"{Fixtures.LegacyKindName(kind)}: {p}");
        }
    }

    /// <summary>
    /// The old NFKC bug generalized: equivalent text next to a lone surrogate. Both spellings are rejected, and
    /// their lossy readings (U+FFFD in place of the surrogate) are well-formed, equivalent and verify both ways.
    /// </summary>
    [Property(MaxTest = 200)]
    public void Equivalent_text_next_to_a_lone_surrogate_is_rejected_and_its_lossy_reading_stays_equivalent(IllFormedEquivalent text)
    {
        string reference = Hasher.Hash("reference");
        foreach (string password in new[] { text.Text, text.Variant })
        {
            AssertRejected(() => Hasher.Hash(password), text.ToString());
            AssertInvalidPassword(Hasher, password, reference);
        }

        string lossyText = Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(text.Text));
        string lossyVariant = Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(text.Variant));
        Assert.True(Fixtures.NfkcEqual(lossyText, lossyVariant), text.ToString());
        if (Fixtures.NfkcByteCount(lossyText) > Arbitraries.MaxPasswordBytes)
            return; // U+FFFD is 3 bytes: the lossy reading of near-cap text may no longer fit
        Assert.True(Hasher.Verify(lossyVariant, Hasher.Hash(lossyText)).IsMatch, text.ToString());
        Assert.True(Hasher.Verify(lossyText, Hasher.Hash(lossyVariant)).IsMatch, text.ToString());
    }

    // ---- Canonical parameter order ---------------------------------------------------------------------------

    private static readonly PasswordHasher[] MhVerifiers = { Fixtures.Wrapping, Fixtures.WrappingNoPepper, Fixtures.Everything, Fixtures.Plain };

    /// <summary>Every recipe of <see cref="MutationProperties.BuildOriginal"/>: p, p+k, p+w+wp, p+k+w+wp, p=test2.</summary>
    [Fact]
    public void Every_non_canonical_parameter_order_is_malformed()
    {
        int checkedOrders = 0;
        for (int kind = 0; kind <= 4; kind++)
        {
            var recipe = new MhMutation(kind, "password", Fixtures.Bytes(16, 9), Array.Empty<MutationOp>());
            string original = MutationProperties.BuildOriginal(recipe);
            Assert.True(Fixtures.Wrapping.Verify("password", original).IsMatch, original);

            (string head, string[] parameters, string tail) = SplitParameters(original);
            foreach (string[] order in Permutations(parameters))
            {
                string candidate = head + string.Join(",", order) + tail;
                if (order.SequenceEqual(parameters))
                {
                    Assert.Equal(original, candidate);
                    continue;
                }
                AssertMalformed(candidate, "password");
                checkedOrders++;
            }
        }
        Assert.Equal(1 + 5 + 23, checkedOrders); // p+k: 1, p+w+wp: 5, p+k+w+wp: 23 non-canonical orders
    }

    [Fact]
    public void Hand_written_out_of_order_and_duplicate_parameters_are_malformed()
    {
        string original = MutationProperties.BuildOriginal(new MhMutation(3, "password", Fixtures.Bytes(16, 9), Array.Empty<MutationOp>()));
        (string head, string[] p, string tail) = SplitParameters(original); // p, k, w, wp
        string[][] variants =
        {
            new[] { p[0], p[2], p[1], p[3] },          // w before k
            new[] { p[0], p[1], p[2], p[1], p[3] },    // k between w and wp
            new[] { p[0], p[1], p[3], p[2] },          // wp before w
            new[] { p[0], p[0], p[1], p[2], p[3] },    // duplicate p
            new[] { p[0], p[1], p[1], p[2], p[3] },    // duplicate k
            new[] { p[0], p[1], p[2], p[2], p[3] },    // duplicate w
            new[] { p[0], p[1], p[2], p[3], p[3] },    // duplicate wp
            new[] { p[0], p[1], p[3] },                // wp without w
            new[] { p[1], p[2], p[3] },                // no p
        };
        foreach (string[] parameters in variants)
            AssertMalformed(head + string.Join(",", parameters) + tail, "password");
    }

    /// <summary>Random shuffles and duplications of the parameters of random valid hashes.</summary>
    [Property(MaxTest = 300)]
    public Property Reordered_or_duplicated_parameters_never_verify_and_never_throw() =>
        Prop.ForAll(
            (from m in Arbitraries.MhMutations().Generator
             from seed in Gen.Choose(0, int.MaxValue)
             from duplicate in Gen.Elements(false, true)
             select (m, seed, duplicate)).ToArbitrary(),
            t =>
            {
                string original = MutationProperties.BuildOriginal(t.m);
                (string head, string[] parameters, string tail) = SplitParameters(original);
                var random = new Random(t.seed);
                var order = parameters.OrderBy(_ => random.Next()).ToList();
                if (t.duplicate)
                    order.Insert(random.Next(order.Count + 1), parameters[random.Next(parameters.Length)]);

                string candidate = head + string.Join(",", order) + tail;
                if (string.Equals(candidate, original, StringComparison.Ordinal))
                    Assert.True(Fixtures.Wrapping.Verify(t.m.Password, candidate).IsMatch, candidate);
                else
                    AssertMalformed(candidate, t.m.Password);
            });

    // ---- TryFromB64 ------------------------------------------------------------------------------------------

    /// <summary>
    /// Inputs that pass the alphabet and length checks and decode, but are not canonical (unused trailing bits set).
    /// TryFromB64 used to return false and still hand out the decoded bytes.
    /// </summary>
    [Fact]
    public void TryFromB64_clears_the_output_when_it_rejects_a_non_canonical_encoding()
    {
        foreach (string value in new[] { "AB", "AAB", "Zh", "Zm9vYh", "Zm9vYmF", "AAAAAAAAAAAAAAAAAAAAAB" })
        {
            Assert.True(Convert.TryFromBase64String(value.PadRight((value.Length + 3) / 4 * 4, '='), new byte[64], out _), value);
            Assert.False(HashPrimitives.TryFromB64(value, out byte[] bytes), value);
            Assert.Empty(bytes);
        }
    }

    // ---- 1.x and hex digests ---------------------------------------------------------------------------------

    private static readonly ILegacyHashFormat[] V1Formats =
    {
        V1LegacyFormat.Instance,
        new V1LegacyFormat(V1Algorithm.SHA256),
        new V1LegacyFormat(V1Algorithm.SHA384),
        new V1LegacyFormat(V1Algorithm.SHA512),
    };

    private static readonly Gen<string> HexStrings =
        from length in Gen.Frequency(
            (3, Gen.Elements(32, 40, 44, 48, 64, 96, 128, 132, 256)),
            (1, Gen.Choose(11, 64).Select(n => n * 4)))
        from chars in Gen.ArrayOf(Gen.Elements("0123456789abcdefABCDEF".ToCharArray()), length)
        select new string(chars);

    /// <summary>
    /// Hex-only strings (any case, any 1.x-compatible length) are never claimed by any 1.x format, while changing a
    /// single character to a non-hex base64 character makes the same string a 1.x candidate again: the rule is
    /// exactly "hex only", not a length or alphabet side effect.
    /// </summary>
    [Property(MaxTest = 500)]
    public Property The_1x_format_never_claims_a_hex_only_string() =>
        Prop.ForAll(
            (from hex in HexStrings
             from position in Gen.Choose(0, 255)
             from replacement in Gen.Elements('g', 'z', 'G', 'Z', '+', '/')
             select (hex, position, replacement)).ToArbitrary(),
            t =>
            {
                foreach (ILegacyHashFormat v1 in V1Formats)
                {
                    Assert.False(v1.CanHandle(t.hex), Fixtures.Show(t.hex));
                    Assert.False(v1.Verify("password", t.hex));
                    Assert.False(v1.TryExtractWrapInput(t.hex, out _, out _));
                }
                foreach (PasswordHasher hasher in Fixtures.AllHashersWithUnpepperedWrap())
                    Assert.NotEqual("v1", hasher.Inspect(t.hex).Format);

                if (t.hex.Length >= 44) // the shortest 1.x hash (a 32-byte digest, base64)
                {
                    int at = t.position % t.hex.Length;
                    string base64 = t.hex.Remove(at, 1).Insert(at, t.replacement.ToString());
                    Assert.True(V1LegacyFormat.Instance.CanHandle(base64), Fixtures.Show(base64));
                }
            });

    // ---- Third-party formats that throw ----------------------------------------------------------------------

    private const ThrowPoint AllPoints = ThrowPoint.CanHandle | ThrowPoint.Verify | ThrowPoint.TryExtractWrapInput | ThrowPoint.ComputeWrapInput;

    private static readonly Func<Exception>[] Recoverable =
    {
        () => new InvalidOperationException("boom"),
        () => new NullReferenceException(),
        () => new FormatException(),
        () => new ArgumentException("boom"),
        () => new ArgumentNullException("x"),
        () => new IndexOutOfRangeException(),
        () => new System.Security.Cryptography.CryptographicException(),
        () => new NotSupportedException(),
        () => new OverflowException(),
        () => new KeyNotFoundException(),
        () => new Exception("boom"),
        () => new AggregateException(new OperationCanceledException()),
    };

    private static readonly Arbitrary<ThrowingFormat> ThrowingFormats =
        (from points in Gen.Choose(1, 15)
         from exception in Gen.Elements(Recoverable)
         select new ThrowingFormat((ThrowPoint)points, exception)).ToArbitrary();

    /// <summary>
    /// A third-party format that throws from any member never makes the hasher throw. When CanHandle throws, the
    /// format is as good as absent; otherwise it may claim the hash but never makes a password verify.
    /// </summary>
    [Property(MaxTest = 400)]
    public Property A_throwing_third_party_format_is_contained() =>
        Prop.ForAll(ThrowingFormats, Arbitraries.AnyStrings(), Arbitraries.AnyPasswords(), (format, anyStored, anyPassword) =>
        {
            foreach (bool wrapping in new[] { true, false })
            {
                PasswordHasher hasher = Fixtures.WithFormatFirst(format, wrapping);
                PasswordHasher reference = wrapping ? Fixtures.Wrapping : Fixtures.Everything;
                (ILegacyHashFormat seedFormat, string seedPassword, string seed) = Fixtures.LegacySeeds[anyStored.Value.Length % Fixtures.LegacySeeds.Length];
                var cases = new[]
                {
                    (anyPassword.Value, anyStored.Value),
                    (seedPassword, seed),
                    (Fixtures.WrongPassword(seedPassword), seed),
                    ("pw", Hasher.Hash("pw")),
                };

                foreach ((string password, string stored) in cases)
                {
                    string context = $"{format} wrapping={wrapping} {seedFormat.Id}: {Assertions.Context(password, stored)}";
                    PasswordVerificationResult expected = reference.Verify(password, stored);
                    PasswordVerificationResult actual = hasher.Verify(password, stored);
                    PasswordVerificationResult async = hasher.VerifyAsync(password, stored).AsTask().GetAwaiter().GetResult();
                    PasswordVerificationResult dummy = hasher.VerifyOrDummy(password, stored);
                    foreach (PasswordVerificationResult r in new[] { actual, async, dummy })
                    {
                        Assertions.Consistent(r, context);
                        Assert.Equal(actual.FailureReason, r.FailureReason);
                    }
                    Assert.True(expected.IsMatch == actual.IsMatch, $"{context}: {expected} vs {actual}");
                    if (expected.IsMatch)
                        Assert.Equal(expected.Status, actual.Status);

                    HashInfo info = hasher.Inspect(stored);
                    bool needsRehash = hasher.NeedsRehash(stored);
                    bool wrapped = hasher.TryWrap(stored, out string wrappedHash);

                    if ((format.ThrowFrom & ThrowPoint.CanHandle) != 0)
                    {
                        // CanHandle throws: exactly as if the format were not registered.
                        Assert.Equal(expected.FailureReason, actual.FailureReason);
                        HashInfo expectedInfo = reference.Inspect(stored);
                        Assert.Equal(expectedInfo.Format, info.Format);
                        Assert.Equal(expectedInfo.IsRecognized, info.IsRecognized);
                        Assert.Equal(reference.NeedsRehash(stored), needsRehash);
                        Assert.Equal(reference.TryWrap(stored, out string expectedWrap), wrapped);
                        if (wrapped)
                            Assert.Equal(reference.Inspect(expectedWrap).WrappedFormat, hasher.Inspect(wrappedHash).WrappedFormat);
                    }
                    else if ((format.ThrowFrom & ThrowPoint.TryExtractWrapInput) != 0)
                    {
                        // TryWrap skips the format and falls through to the real ones.
                        Assert.Equal(reference.TryWrap(stored, out _), wrapped);
                    }

                    if (wrapped && hasher.Inspect(wrappedHash).WrappedFormat == format.Id)
                    {
                        // A hash wrapped through the throwing format: ComputeWrapInput throwing is MalformedHash.
                        PasswordVerificationResult viaWrap = hasher.Verify(password, wrappedHash);
                        Assertions.Consistent(viaWrap, context);
                        Assert.False(viaWrap.IsMatch, context);
                        if (password.Length > 0 && Fixtures.IsWellFormedUtf16(password) && Encoding.UTF8.GetByteCount(password) <= Arbitraries.MaxPasswordBytes)
                        {
                            Assert.Equal((format.ThrowFrom & ThrowPoint.ComputeWrapInput) != 0
                                ? VerificationFailureReason.MalformedHash
                                : VerificationFailureReason.Mismatch, viaWrap.FailureReason);
                        }
                    }
                }
            }
        });

    /// <summary>Cancellation and out-of-memory are not "this format does not match": they still escape.</summary>
    [Fact]
    public void Cancellation_and_out_of_memory_from_a_format_still_propagate()
    {
        (_, string password, string seed) = Fixtures.LegacySeeds[0];
        foreach (Func<Exception> exception in new Func<Exception>[]
                 {
                     () => new OperationCanceledException(),
                     () => new System.Threading.Tasks.TaskCanceledException(),
                     () => new OutOfMemoryException(),
                 })
        {
            PasswordHasher canHandle = Fixtures.WithFormatFirst(new ThrowingFormat(ThrowPoint.CanHandle, exception), wrapping: true);
            Assert.ThrowsAny<Exception>(() => canHandle.Verify(password, seed));
            Assert.ThrowsAny<Exception>(() => canHandle.Inspect(seed));
            Assert.ThrowsAny<Exception>(() => canHandle.TryWrap(seed, out _));

            PasswordHasher verify = Fixtures.WithFormatFirst(new ThrowingFormat(ThrowPoint.Verify, exception), wrapping: true);
            Exception thrown = Assert.ThrowsAny<Exception>(() => verify.Verify(password, seed));
            Assert.IsType(exception().GetType(), thrown);
            Assert.True(verify.Inspect(seed).IsRecognized); // CanHandle itself is fine
        }
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------

    /// <summary>Stored hashes of every shape for <paramref name="password"/>: native, peppered, wrapped, 1.x, hex.</summary>
    private static IEnumerable<string> StoredHashesFor(string password)
    {
        yield return Fixtures.Plain.Hash(password);
        yield return Fixtures.Wrapping.Hash(password);
        yield return Fixtures.WrappingNoPepper.Hash(password, Fixtures.Fast2);
        string v1 = Fixtures.BuildLegacyHash(0, password, Fixtures.Bytes(16, 5));
        yield return v1;
        Assert.True(Fixtures.Wrapping.TryWrap(v1, out string wrapped));
        yield return wrapped;
        yield return Fixtures.BuildLegacyHash(5, password, Array.Empty<byte>());
    }

    private static T Wait<T>(System.Threading.Tasks.ValueTask<T> task) => task.AsTask().GetAwaiter().GetResult();

    private static void AssertRejected(Action hash, string context)
    {
        ArgumentException ex = Assert.Throws<ArgumentException>(hash);
        Assert.Equal("password", ex.ParamName);
        Assert.StartsWith(InvalidUtf16Message, ex.Message, StringComparison.Ordinal);
        _ = context;
    }

    private static void AssertInvalidPassword(PasswordHasher hasher, string password, string stored)
    {
        string context = $"{Fixtures.Name(hasher)}: {Assertions.Context(password, stored)}";
        foreach (PasswordVerificationResult r in new[]
                 {
                     hasher.Verify(password, stored),
                     hasher.VerifyAsync(password, stored).AsTask().GetAwaiter().GetResult(),
                     hasher.VerifyOrDummy(password, stored),
                     hasher.VerifyOrDummyAsync(password, stored).AsTask().GetAwaiter().GetResult(),
                 })
        {
            Assertions.Consistent(r, context);
            Assert.True(r.FailureReason == VerificationFailureReason.InvalidPassword, $"{context}: {r}");
            Assert.Equal(VerificationStatus.Failed, r.Status);
            Assert.Null(r.Rehash);
        }
    }

    private static void AssertMalformed(string candidate, string password)
    {
        string context = Fixtures.Show(candidate);
        foreach (PasswordHasher hasher in MhVerifiers)
        {
            PasswordVerificationResult result = hasher.Verify(password, candidate);
            Assertions.Consistent(result, context);
            Assert.True(result.FailureReason == VerificationFailureReason.MalformedHash, $"{Fixtures.Name(hasher)} {context}: {result}");
            Assert.Equal(VerificationFailureReason.MalformedHash, hasher.VerifyAsync(password, candidate).AsTask().GetAwaiter().GetResult().FailureReason);
            Assert.Equal(VerificationFailureReason.MalformedHash, hasher.VerifyOrDummy(password, candidate).FailureReason);

            HashInfo info = hasher.Inspect(candidate);
            Assert.Equal(HashInfo.NativeFormat, info.Format);
            Assert.False(info.IsRecognized, context);
            Assert.False(hasher.NeedsRehash(candidate), context);
            Assert.False(hasher.TryWrap(candidate, out _), context);
        }
    }

    /// <summary>Splits <c>$mh$a,b,c$salt$tag</c> into <c>$mh$</c>, the parameters and <c>$salt$tag</c>.</summary>
    private static (string Head, string[] Parameters, string Tail) SplitParameters(string hash)
    {
        const string head = "$mh$";
        int end = hash.IndexOf('$', head.Length);
        return (head, hash.Substring(head.Length, end - head.Length).Split(','), hash.Substring(end));
    }

    private static IEnumerable<string[]> Permutations(string[] items)
    {
        if (items.Length <= 1)
        {
            yield return items;
            yield break;
        }
        for (int i = 0; i < items.Length; i++)
        {
            string[] rest = items.Where((_, j) => j != i).ToArray();
            foreach (string[] tail in Permutations(rest))
                yield return new[] { items[i] }.Concat(tail).ToArray();
        }
    }
}
