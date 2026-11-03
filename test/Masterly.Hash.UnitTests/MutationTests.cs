using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Internal;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.UnitTests;

// Tests written to kill specific surviving Stryker.NET mutants: exact boundaries, exact messages,
// recorded calls, buffer zeroing, ConfigureAwait(false) and the emitted metrics.

/// <summary>Inclusive bounds and exact messages of the <see cref="HashProfile"/> factories.</summary>
public class HashProfileBoundaryTests
{
    [Fact]
    public void Argon2id_MemoryBounds_AreInclusive()
    {
        Assert.Equal(8, HashProfile.Argon2id("x", 8, 1).MemoryKiB);
        Assert.Equal(16, HashProfile.Argon2id("x", 16, 1, parallelism: 2).MemoryKiB);
        Assert.Equal(1024 * 1024, HashProfile.MaxMemoryKiB);
        Assert.Equal(HashProfile.MaxMemoryKiB, HashProfile.Argon2id("x", HashProfile.MaxMemoryKiB, 1).MemoryKiB);
    }

    [Fact]
    public void Argon2id_MemoryMessage_ScalesTheMinimumWithLanes()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", 15, 1, parallelism: 2));
        Assert.Equal("memoryKiB", ex.ParamName);
        Assert.StartsWith("Memory must be between 16 and 1048576 KiB.", ex.Message);
    }

    [Fact]
    public void Argon2id_IterationBound_IsInclusive_AndMessageIsExact()
    {
        Assert.Equal(64, HashProfile.Argon2id("x", 64, 64).Iterations);
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", 64, 65));
        Assert.StartsWith("Iterations must be between 1 and 64.", ex.Message);
    }

    [Fact]
    public void Argon2id_ParallelismMessage_IsExact()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", 1024, 1, parallelism: 17));
        Assert.StartsWith("Parallelism must be between 1 and 16.", ex.Message);
    }

    [Fact]
    public void Pbkdf2_SingleIteration_IsAccepted_AndMessageIsExact()
    {
        Assert.Equal(1, HashProfile.Pbkdf2Sha512("x", 1).Iterations);
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Pbkdf2Sha512("x", 0));
        Assert.StartsWith("Iterations must be between 1 and 10,000,000.", ex.Message);
    }

    [Fact]
    public void InvalidId_MessageIsExact()
    {
        var ex = Assert.Throws<ArgumentException>(() => HashProfile.Pbkdf2Sha512("-x", 1000));
        Assert.StartsWith("Profile id must match ^[a-z0-9][a-z0-9-]{0,31}$.", ex.Message);
    }

    [Fact]
    public void SaltAndTagBounds_AreInclusive_AndMessagesAreExact()
    {
        Assert.Equal(64, HashProfile.Pbkdf2Sha512("x", 1000, saltLength: 64).SaltLength);
        Assert.Equal(64, HashProfile.Argon2id("x", 64, 1, saltLength: 64).SaltLength);
        Assert.Equal(16, HashProfile.Pbkdf2Sha512("x", 1000, tagLength: 16).TagLength);
        Assert.Equal(16, HashProfile.Argon2id("x", 64, 1, tagLength: 16).TagLength);

        Assert.StartsWith("Salt length must be between 16 and 64 bytes.",
            Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Pbkdf2Sha512("x", 1000, saltLength: 65)).Message);
        Assert.StartsWith("Tag length must be between 16 and 64 bytes.",
            Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Pbkdf2Sha512("x", 1000, tagLength: 15)).Message);
    }
}

/// <summary>Direct tests of the internal <see cref="MhHash"/> parser: a rejected string never yields true.</summary>
public class MhHashParserTests
{
    [Theory]
    [InlineData("not-a-hash")]              // no prefix
    [InlineData("$mh$p=x$AAAA")]            // four parts
    [InlineData("$mh$p$AAAA$AAAA")]         // parameter without '='
    [InlineData("$mh$p=x,z=1$AAAA$AAAA")]   // unknown parameter
    [InlineData("$mh$p=x$!!!!$AAAA")]       // invalid salt
    [InlineData("$mh$p=x$AAAA$!!!!")]       // invalid tag
    public void TryParse_Rejects(string value)
    {
        Assert.False(MhHash.TryParse(value, out MhHash? hash));
        Assert.Null(hash);
    }

    [Fact]
    public void TryParse_Null_IsRejected()
    {
        Assert.False(MhHash.TryParse(null!, out MhHash? hash));
        Assert.Null(hash);
    }

    [Theory]
    [InlineData("$mh$p=x,k=a,k=b$AAAA$AAAA")]   // duplicate key id: a valid id after stage 1 is still rejected
    [InlineData("$mh$p=x,k=bad_id$AAAA$AAAA")]  // right position, id outside ^[A-Za-z0-9-]{1,32}$
    [InlineData("$mh$p=x,w=f,k=a$AAAA$AAAA")]   // key id after the wrap format
    public void TryParse_KeyId_MustBeValidAndDirectlyAfterTheProfile(string value)
    {
        Assert.False(MhHash.TryParse(value, out MhHash? hash));
        Assert.Null(hash);
    }

    [Fact]
    public void TryParse_KeyIdAfterProfile_IsAccepted()
    {
        Assert.True(MhHash.TryParse("$mh$p=x,k=a$AAAA$AAAA", out MhHash? hash));
        Assert.Equal("x", hash!.ProfileId);
        Assert.Equal("a", hash.PepperKeyId);
        Assert.Null(hash.WrapFormat);
        Assert.Null(hash.WrapParameter);
        Assert.Equal("$mh$p=x,k=a$AAAA$AAAA", hash.ToString());

        string longest = new string('Z', 32);
        Assert.True(MhHash.TryParse("$mh$p=x,k=" + longest + ",w=f$AAAA$AAAA", out MhHash? wrapped));
        Assert.Equal(longest, wrapped!.PepperKeyId);
        Assert.Equal("f", wrapped.WrapFormat);
        Assert.False(MhHash.TryParse("$mh$p=x,k=" + longest + "Z$AAAA$AAAA", out _));
    }

    [Fact]
    public void Verify_DuplicateKeyId_IsMalformed_NotAnUnknownPepperKey()
    {
        PasswordHasher hasher = TestHashers.Create();
        string stored = hasher.Hash("pw").Replace("$mh$p=" + TestHashers.Fast.Id + "$", "$mh$p=" + TestHashers.Fast.Id + ",k=a,k=b$", StringComparison.Ordinal);
        Assert.Contains(",k=a,k=b$", stored, StringComparison.Ordinal);

        PasswordVerificationResult result = hasher.Verify("pw", stored);

        Assert.Equal(VerificationStatus.Failed, result.Status);
        Assert.Equal(VerificationFailureReason.MalformedHash, result.FailureReason);
        Assert.Null(result.Rehash);
    }

    [Theory]
    [InlineData(",k=a,k=b")]   // a valid id in the wrong place
    [InlineData(",k=bad_id")]  // an invalid id in the right place
    public void Inspect_MisplacedOrInvalidKeyId_IsAnUnparsedNativeHash(string keyPart)
    {
        // The pepper knows both ids, so a parser that accepted either string would report a recognized hash
        // with profile and key id instead of the unparsed shape.
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("a", "a", "b"));
        string stored = TestHashers.Create().Hash("pw");
        string mangled = stored.Replace("$mh$p=" + TestHashers.Fast.Id + "$", "$mh$p=" + TestHashers.Fast.Id + keyPart + "$", StringComparison.Ordinal);
        Assert.Contains(keyPart + "$", mangled, StringComparison.Ordinal);

        HashInfo info = hasher.Inspect(mangled);

        Assert.Equal(HashInfo.NativeFormat, info.Format);
        Assert.False(info.IsRecognized);
        Assert.Null(info.ProfileId);
        Assert.Null(info.Profile);
        Assert.Null(info.PepperKeyId);
        Assert.Null(info.WrappedFormat);
        Assert.Equal(RehashReason.None, info.RehashReason);
        Assert.Equal(VerificationFailureReason.MalformedHash, hasher.Verify("pw", mangled).FailureReason);
    }

    [Fact]
    public void TryParse_MinimalHash_IsAccepted()
    {
        Assert.True(MhHash.TryParse("$mh$p=x$AAAA$AAAA", out MhHash? hash));
        Assert.Equal("x", hash!.ProfileId);
        Assert.Equal(new byte[3], hash.Salt);
    }

    [Fact]
    public void TryParse_LengthLimit_IsInclusive()
    {
        string atLimit = "$mh$p=x$" + new string('A', 23) + "$" + new string('A', 992);
        string overLimit = "$mh$p=x$" + new string('A', 22) + "$" + new string('A', 994);
        Assert.Equal(MhHash.MaxLength, atLimit.Length);
        Assert.Equal(MhHash.MaxLength + 1, overLimit.Length);

        Assert.True(MhHash.TryParse(atLimit, out MhHash? hash));
        Assert.Equal(744, hash!.Tag.Length);
        Assert.False(MhHash.TryParse(overLimit, out _));
    }
}

/// <summary>Boundaries of the 1.x format: wrap parameters, maximum length and hex detection.</summary>
public class V1LegacyFormatBoundaryTests
{
    [Fact]
    public void ComputeWrapInput_AlgorithmByteOnly_MeansEmptySalt()
    {
        byte[] input = new V1LegacyFormat(V1Algorithm.SHA512).ComputeWrapInput("pw", new[] { (byte)V1Algorithm.SHA512 });

        Assert.Equal(SHA512.HashData(Encoding.UTF8.GetBytes("pw")), input);
    }

    [Fact]
    public void ComputeWrapInput_InvalidParameter_MessageIsExact()
    {
        var format = new V1LegacyFormat(V1Algorithm.SHA512);
        Assert.Equal("Invalid v1 wrap parameter.", Assert.Throws<FormatException>(() => format.ComputeWrapInput("pw", Array.Empty<byte>())).Message);
        Assert.Equal("Invalid v1 wrap parameter.", Assert.Throws<FormatException>(() => format.ComputeWrapInput("pw", new byte[] { 3 })).Message);
    }

    [Fact]
    public void StoredLengthLimit_IsInclusive()
    {
        byte[] salt = Enumerable.Range(0, 704).Select(i => (byte)(i * 7 + 3)).ToArray();
        string atLimit = TestHashers.Original1x("pw", salt, V1Algorithm.SHA512);
        string overLimit = TestHashers.Original1x("pw", salt.Concat(new byte[] { 1, 2, 3 }).ToArray(), V1Algorithm.SHA512);
        Assert.Equal(1024, atLimit.Length);
        Assert.Equal(1028, overLimit.Length);

        Assert.True(V1LegacyFormat.Instance.CanHandle(atLimit));
        Assert.True(V1LegacyFormat.Instance.Verify("pw", atLimit));
        Assert.False(V1LegacyFormat.Instance.CanHandle(overLimit));
    }

    [Theory]
    [InlineData('A')]
    [InlineData('F')]
    public void UppercaseHexBoundaryLetters_CountAsHex(char c)
    {
        Assert.False(V1LegacyFormat.Instance.CanHandle(new string(c, 44)));
    }

    [Fact]
    public void UppercaseHexString_IsLeftToOtherFormats()
    {
        Assert.False(V1LegacyFormat.Instance.CanHandle(string.Concat(Enumerable.Repeat("ABCDEF", 8)).Substring(0, 44)));
    }

    [Theory]
    [InlineData('G')]
    [InlineData('Z')]
    public void UppercaseNonHexLetters_AreBase64(char c)
    {
        Assert.True(V1LegacyFormat.Instance.CanHandle(new string(c, 44)));
    }
}

/// <summary>PBKDF2 block arithmetic, argument order and exact messages.</summary>
public class Pbkdf2MutationTests
{
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("password");
    private static readonly byte[] Salt = Encoding.UTF8.GetBytes("saltsalt");

    [Fact]
    public void Primitives_Pbkdf2_ValidatesArgumentsBeforeThePrf()
    {
        HashAlgorithmName md5 = HashAlgorithmName.MD5;
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => HashPrimitives.Pbkdf2(md5, null!, Salt, 1, 1)).ParamName);
        Assert.Equal("salt", Assert.Throws<ArgumentNullException>(() => HashPrimitives.Pbkdf2(md5, Password, null!, 1, 1)).ParamName);
        Assert.Equal("iterations", Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(md5, Password, Salt, 0, 1)).ParamName);
        Assert.Equal("length", Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(md5, Password, Salt, 1, 0)).ParamName);

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(md5, Password, Salt, 1, 1));
        Assert.Equal("prf", ex.ParamName);
        Assert.StartsWith("Supported PRFs are SHA1, SHA256 and SHA512.", ex.Message);
    }

    [Fact]
    public void Primitives_Pbkdf2_SingleByteOutput_IsAllowed()
    {
        Assert.Equal(
            Rfc2898DeriveBytes.Pbkdf2(Password, Salt, 1, HashAlgorithmName.SHA256, 1),
            HashPrimitives.Pbkdf2(HashAlgorithmName.SHA256, Password, Salt, 1, 1));
    }

    [Fact]
    public void Primitives_DeriveKey_MessagesAreExact()
    {
        HashProfile profile = HashProfile.Pbkdf2Sha512("kdf-test", 10);
        Assert.StartsWith("Input cannot be empty.",
            Assert.Throws<ArgumentException>(() => HashPrimitives.DeriveKey(profile, Array.Empty<byte>(), new byte[8])).Message);
        Assert.StartsWith("Salt must be at least 8 bytes.",
            Assert.Throws<ArgumentException>(() => HashPrimitives.DeriveKey(profile, new byte[] { 1 }, new byte[7])).Message);
    }

    [Fact]
    public void Kdf_UnknownAlgorithm_IsNotSupported()
    {
        // Unreachable through the public factories; built through the private constructor.
        ConstructorInfo ctor = typeof(HashProfile).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance, null,
            new[] { typeof(string), typeof(HashAlgorithmKind), typeof(int), typeof(int), typeof(int), typeof(int), typeof(int) }, null)!;
        var profile = (HashProfile)ctor.Invoke(new object[] { "bogus", (HashAlgorithmKind)99, 0, 1, 1, 16, 32 });

        var ex = Assert.Throws<NotSupportedException>(() => Kdf.Derive(profile, new byte[] { 1 }, new byte[16]));
        Assert.Equal("Unsupported algorithm 99.", ex.Message);
    }
}

/// <summary>Exact messages of the <see cref="HmacPepper"/> guards.</summary>
public class HmacPepperMessageTests
{
    [Fact]
    public void Guards_HaveExactMessages()
    {
        Assert.StartsWith("Key id must match ^[A-Za-z0-9-]{1,32}$.",
            Assert.Throws<ArgumentException>(() => new HmacPepper("bad id", new byte[32])).Message);
        Assert.StartsWith("Pepper key 'k1' must be at least 32 bytes.",
            Assert.Throws<ArgumentException>(() => new HmacPepper("k1", new byte[31])).Message);
        Assert.StartsWith("Current key 'k2' is not in the key ring.",
            Assert.Throws<ArgumentException>(() => new HmacPepper("k2", new Dictionary<string, byte[]> { ["k1"] = new byte[32] })).Message);
    }
}

/// <summary>
/// <see cref="PasswordHasher"/> behaviour that the broader suites leave unpinned: sync vs async pepper calls,
/// zeroing of buffers handed to the pepper, inclusive length limits and exact messages.
/// </summary>
public class PasswordHasherMutationTests
{
    [Fact]
    public void SyncApis_CallTheSynchronousPepper()
    {
        var pepper = new TrackingPepper();
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);

        string stored = hasher.Hash("pw");
        Assert.Equal(new[] { "Apply" }, pepper.Drain());

        Assert.True(hasher.Verify("pw", stored).IsMatch);
        Assert.Equal(new[] { "Apply" }, pepper.Drain());

        Assert.True(hasher.VerifyOrDummy("pw", stored).IsMatch);
        Assert.Equal(new[] { "Apply" }, pepper.Drain());

        // Unknown user: exactly the work of a real verification, every time (no first-call dummy creation).
        Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy("pw", null).FailureReason);
        Assert.Equal(new[] { "Apply" }, pepper.Drain());
        Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy("pw", null).FailureReason);
        Assert.Equal(new[] { "Apply" }, pepper.Drain());
    }

    [Fact]
    public async Task AsyncApis_CallTheAsynchronousPepper()
    {
        var pepper = new TrackingPepper();
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);
        string stored = hasher.Hash("pw");
        pepper.Drain();

        Assert.StartsWith("$mh$p=test-fast,k=t1$", await hasher.HashAsync("pw"));
        Assert.Equal(new[] { "ApplyAsync" }, pepper.Drain());

        Assert.True((await hasher.VerifyAsync("pw", stored)).IsMatch);
        Assert.Equal(new[] { "ApplyAsync" }, pepper.Drain());

        Assert.True((await hasher.VerifyOrDummyAsync("pw", stored)).IsMatch);
        Assert.Equal(new[] { "ApplyAsync" }, pepper.Drain());

        Assert.Equal(VerificationFailureReason.NoStoredHash, (await hasher.VerifyOrDummyAsync("pw", null)).FailureReason);
        Assert.Equal(new[] { "ApplyAsync" }, pepper.Drain()); // the dummy verify only: never a blocking sync call
        Assert.Equal(VerificationFailureReason.NoStoredHash, (await hasher.VerifyOrDummyAsync("pw", null)).FailureReason);
        Assert.Equal(new[] { "ApplyAsync" }, pepper.Drain());
    }

    [Fact]
    public void BuffersPassedToAndReturnedByThePepper_AreZeroed()
    {
        var pepper = new TrackingPepper();
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);

        string stored = hasher.Hash("pw");
        AssertZeroed(pepper.LastInput, 2);
        AssertZeroed(pepper.LastOutput, 32);

        Assert.True(hasher.Verify("pw", stored).IsMatch);
        AssertZeroed(pepper.LastInput, 2);
        AssertZeroed(pepper.LastOutput, 32);
    }

    [Fact]
    public void WrappedVerify_PasswordAtMaxBytes_IsAccepted()
    {
        PasswordHasher hasher = TestHashers.Create(o =>
        {
            o.MaxPasswordBytes = 64;
            o.ComputeRehashOnVerify = false;
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA512));
        });
        string password = new string('a', 64);
        Assert.True(hasher.TryWrap(TestHashers.Original1x(password, new byte[16], V1Algorithm.SHA512), out string wrapped));

        PasswordVerificationResult result = hasher.Verify(password, wrapped);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.Wrapped, result.RehashReason);
        Assert.Equal(VerificationFailureReason.PasswordTooLong, hasher.Verify(password + "a", wrapped).FailureReason);
    }

    [Fact]
    public void LegacyRehash_PasswordAtMaxBytes_IsComputed()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.MaxPasswordBytes = 64);
        string password = new string('a', 64);

        PasswordVerificationResult result = hasher.Verify(password, TestHashers.Original1x(password, new byte[8], V1Algorithm.SHA512));

        Assert.Equal(RehashReason.LegacyFormat, result.RehashReason);
        Assert.NotNull(result.Rehash);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(password, result.Rehash!).Status);
    }

    [Fact]
    public void LegacyVerify_StopsAtTheFirstMatchingFormat()
    {
        var first = new FakeFormat("fa", result: true);
        var second = new FakeFormat("fb", result: true);
        PasswordHasher hasher = TestHashers.Create(o =>
        {
            o.ComputeRehashOnVerify = false;
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(first);
            o.LegacyFormats.Add(second);
        });

        Assert.True(hasher.Verify("pw", FakeFormat.Marker).IsMatch);

        Assert.Equal(1, first.VerifyCalls);
        Assert.Equal(0, second.VerifyCalls);
    }

    [Fact]
    public void HashGuards_HaveExactParamNamesAndMessages()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.MaxPasswordBytes = 64);

        var empty = Assert.Throws<ArgumentException>(() => hasher.Hash(""));
        Assert.Equal("password", empty.ParamName);
        Assert.StartsWith("Password cannot be empty.", empty.Message);

        var invalid = Assert.Throws<ArgumentException>(() => hasher.Hash("a\uD800"));
        Assert.Equal("password", invalid.ParamName);
        Assert.StartsWith("Password contains invalid UTF-16 or a code point that cannot be normalized.", invalid.Message);

        var tooLong = Assert.Throws<ArgumentException>(() => hasher.Hash(new string('a', 65)));
        Assert.Equal("password", tooLong.ParamName);
        Assert.StartsWith("Password exceeds 64 bytes.", tooLong.Message);

        var unregistered = Assert.Throws<ArgumentException>(() => hasher.Hash("pw", HashProfile.Argon2id("other", 64, 1)));
        Assert.Equal("profile", unregistered.ParamName);
        Assert.StartsWith("Profile 'other' is not registered with this hasher.", unregistered.Message);
    }

    [Fact]
    public void ConstructorGuards_HaveExactMessages()
    {
        var weak = Assert.Throws<ArgumentException>(() => new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestHashers.Fast }));
        Assert.Equal("Profile test-fast (Argon2id m=64KiB t=1 p=1) is below the OWASP minimum. Set AllowWeakProfiles only in tests.", weak.Message);

        var duplicate = Assert.Throws<ArgumentException>(() => TestHashers.Create(o => o.AdditionalProfiles.Add(HashProfile.Argon2id("test-fast", 128, 1))));
        Assert.Equal("Profile id 'test-fast' is already registered with different parameters. Profile ids are permanent; pick a new id.", duplicate.Message);

        var maxBytes = Assert.Throws<ArgumentOutOfRangeException>(() => TestHashers.Create(o => o.MaxPasswordBytes = 63));
        Assert.Equal("options", maxBytes.ParamName);
        Assert.StartsWith("MaxPasswordBytes must be between 64 and 1048576.", maxBytes.Message);
    }

    [Fact]
    public void EncodePassword_InvalidUtf16_MessageIsExact()
    {
        // HashPrimitives.EncodePassword is public and documents the ArgumentException; its message is the caller's diagnostic.
        var ex = Assert.Throws<ArgumentException>(() => HashPrimitives.EncodePassword("a\uD800b"));
        Assert.Equal("password", ex.ParamName);
        Assert.Equal("Password contains invalid UTF-16 or a code point that cannot be normalized. (Parameter 'password')", ex.Message);
    }

    [Fact]
    public void BusyException_MessageIsExact()
    {
        Assert.Equal("The password hasher is at its concurrency limit. Try again later.", new PasswordHasherBusyException().Message);
    }

    private static void AssertZeroed(byte[]? buffer, int expectedLength)
    {
        Assert.NotNull(buffer);
        Assert.Equal(expectedLength, buffer!.Length);
        Assert.All(buffer, b => Assert.Equal(0, b));
    }
}

/// <summary>
/// Every await in the library uses ConfigureAwait(false), so a caller's SynchronizationContext never sees a post,
/// and async calls wait on the gate asynchronously while sync calls block.
/// </summary>
public class AsyncContextTests
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task HashAsync_SuspendedInPepper_DoesNotPostToCallerContext()
    {
        var pepper = new TrackingPepper(deferAsync: true);
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);

        Assert.Equal(0, await PostsWhileRunning(() => hasher.HashAsync("pw"), pepper.Release));
    }

    [Fact]
    public async Task VerifyAsync_LegacyRehashSuspendedInPepper_DoesNotPostToCallerContext()
    {
        var pepper = new TrackingPepper(deferAsync: true);
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);
        string legacy = TestHashers.Original1x("pw", new byte[8], V1Algorithm.SHA512);

        Assert.Equal(0, await PostsWhileRunning(() => hasher.VerifyAsync("pw", legacy), pepper.Release));
    }

    [Fact]
    public async Task VerifyAsync_SuspendedInPepper_DoesNotPostToCallerContext()
    {
        var pepper = new TrackingPepper(deferAsync: true);
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);
        string stored = hasher.Hash("pw");

        Assert.Equal(0, await PostsWhileRunning(() => hasher.VerifyAsync("pw", stored), pepper.Release));
    }

    [Fact]
    public async Task VerifyOrDummyAsync_KnownUser_SuspendedInPepper_DoesNotPostToCallerContext()
    {
        var pepper = new TrackingPepper(deferAsync: true);
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);
        string stored = hasher.Hash("pw");

        Assert.Equal(0, await PostsWhileRunning(() => hasher.VerifyOrDummyAsync("pw", stored), pepper.Release));
    }

    [Fact]
    public async Task VerifyOrDummyAsync_UnknownUser_SuspendedInPepper_DoesNotPostToCallerContext()
    {
        var pepper = new TrackingPepper(deferAsync: true);
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);

        Assert.Equal(0, await PostsWhileRunning(() => hasher.VerifyOrDummyAsync("pw", null), pepper.Release));
    }

    [Fact]
    public async Task VerifyAsync_NativeRehashSuspendedInPepper_DoesNotPostToCallerContext()
    {
        // The stored hash has no pepper key, so the verification itself runs synchronously on the caller's
        // context; only the rehash under the current key suspends in the pepper.
        string stored = TestHashers.Create().Hash("pw");
        var pepper = new TrackingPepper(deferAsync: true);
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);
        Task<PasswordVerificationResult>? pending = null;

        Assert.Equal(0, await PostsWhileRunning(() =>
        {
            pending = hasher.VerifyAsync("pw", stored).AsTask();
            return new ValueTask<PasswordVerificationResult>(pending);
        }, pepper.Release));

        PasswordVerificationResult result = await pending!;
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(VerificationFailureReason.None, result.FailureReason);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        Assert.StartsWith("$mh$p=" + TestHashers.Fast.Id + ",k=t1$", result.Rehash, StringComparison.Ordinal);
        // Only the rehash went through the pepper, and only on the async path.
        Assert.Equal(new[] { "ApplyAsync" }, pepper.Drain());
        Assert.Equal(VerificationStatus.Success, hasher.Verify("pw", result.Rehash!).Status);
    }

    [Fact]
    public async Task HashAsync_WaitingForTheGate_DoesNotPostToCallerContext()
    {
        var blocker = new BlockingFormat();
        PasswordHasher hasher = GatedHasher(blocker);
        await HoldingTheGate(hasher, blocker, async () =>
            Assert.Equal(0, await PostsWhileRunning(() => hasher.HashAsync("pw"), blocker.Release.Set)));
    }

    [Fact]
    public async Task VerifyAsync_WaitingForTheGate_DoesNotPostToCallerContext()
    {
        var blocker = new BlockingFormat();
        PasswordHasher hasher = GatedHasher(blocker);
        string stored = hasher.Hash("pw");
        await HoldingTheGate(hasher, blocker, async () =>
            Assert.Equal(0, await PostsWhileRunning(() => hasher.VerifyAsync("pw", stored), blocker.Release.Set)));
    }

    [Fact]
    public async Task VerifyAsync_Legacy_WaitingForTheGate_DoesNotPostToCallerContext()
    {
        var blocker = new BlockingFormat();
        PasswordHasher hasher = GatedHasher(blocker);
        string legacy = TestHashers.Original1x("pw", new byte[8], V1Algorithm.SHA512);
        await HoldingTheGate(hasher, blocker, async () =>
            Assert.Equal(0, await PostsWhileRunning(() => hasher.VerifyAsync("pw", legacy), blocker.Release.Set)));
    }

    [Fact]
    public async Task SyncCallsBlockOnTheGate_AsyncCallsQueueOnIt()
    {
        var blocker = new BlockingFormat();
        PasswordHasher hasher = GatedHasher(blocker);
        var gate = (SemaphoreSlim)typeof(PasswordHasher).GetField("_gate", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(hasher)!;
        FieldInfo syncWaiters = typeof(SemaphoreSlim).GetField("m_waitCount", BindingFlags.NonPublic | BindingFlags.Instance)!;
        FieldInfo asyncHead = typeof(SemaphoreSlim).GetField("m_asyncHead", BindingFlags.NonPublic | BindingFlags.Instance)!;
        Assert.NotNull(syncWaiters);
        Assert.NotNull(asyncHead);
        (int Sync, bool Async) Waiters() => ((int)syncWaiters.GetValue(gate)!, asyncHead.GetValue(gate) != null);

        await HoldingTheGate(hasher, blocker, async () =>
        {
            Task<string> sync = Task.Factory.StartNew(() => hasher.Hash("pw"), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            Assert.True(SpinWait.SpinUntil(() => Waiters() != (0, false), Generous));
            Assert.Equal((1, false), Waiters());

            Task<string> queued = Task.Run(() => hasher.HashAsync("pw").AsTask());
            Assert.True(SpinWait.SpinUntil(() => Waiters() != (1, false), Generous));
            Assert.Equal((1, true), Waiters());

            blocker.Release.Set();
            Assert.StartsWith("$mh$", await sync.WaitAsync(Generous));
            Assert.StartsWith("$mh$", await queued.WaitAsync(Generous));
        });
    }

    private static PasswordHasher GatedHasher(BlockingFormat blocker) => TestHashers.Create(o =>
    {
        o.MaxConcurrency = 1;
        o.ConcurrencyTimeout = TimeSpan.FromSeconds(5);
        o.LegacyFormats.Add(blocker);
    });

    /// <summary>Runs <paramref name="body"/> while another thread holds the hasher's only slot.</summary>
    private static async Task HoldingTheGate(PasswordHasher hasher, BlockingFormat blocker, Func<Task> body)
    {
        Task holder = Task.Run(() => hasher.Verify("pw", BlockingFormat.Marker));
        try
        {
            Assert.True(blocker.Entered.Wait(Generous));
            await body();
        }
        finally
        {
            blocker.Release.Set();
            await holder.WaitAsync(Generous);
        }
    }

    /// <summary>
    /// Starts an operation with a counting SynchronizationContext installed, checks that it suspended, releases
    /// it and returns how many continuations were posted to that context.
    /// </summary>
    private static async Task<int> PostsWhileRunning<T>(Func<ValueTask<T>> start, Action release)
    {
        var context = new CountingSynchronizationContext();
        SynchronizationContext? previous = SynchronizationContext.Current;
        ValueTask<T> pending;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            pending = start();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }

        bool suspended = !pending.IsCompleted;
        release();
        await pending.AsTask().WaitAsync(Generous);
        Assert.True(suspended, "The operation must suspend for this test to be meaningful.");
        return context.Posts;
    }

    private sealed class CountingSynchronizationContext : SynchronizationContext
    {
        private int _posts;
        public int Posts => Volatile.Read(ref _posts);

        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }

        public override void Send(SendOrPostCallback d, object? state) => d(state);
    }
}

/// <summary>The instruments, tags and values written to the <c>Masterly.Hash</c> meter.</summary>
public class MetricsTests
{
    private static readonly HashProfile Timed = HashProfile.Pbkdf2Sha512("mt-metrics", 2000);

    [Fact]
    public void Instruments_HaveStableNamesUnitsAndDescriptions()
    {
        using var capture = new MetricsCapture();

        Assert.Equal(
            new[]
            {
                "masterly.hash.busy_rejections|{rejection}|Calls rejected at the concurrency limit.",
                "masterly.hash.duration|ms|Time spent computing a password hash or verification.",
                "masterly.hash.hashes|{hash}|New password hashes by profile.",
                "masterly.hash.verifications|{verification}|Password verifications by format and outcome.",
            },
            capture.Instruments);
    }

    [Fact]
    public void Hash_RecordsCountAndDuration_TaggedWithProfile()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.DefaultProfile = Timed);
        hasher.Hash("warm-up");
        using var capture = new MetricsCapture();

        long start = Stopwatch.GetTimestamp();
        hasher.Hash("pw");
        double outerMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

        Measured count = Assert.Single(capture.Of("masterly.hash.hashes"));
        Assert.Equal(1d, count.Value);
        Assert.Equal(new[] { "profile=mt-metrics" }, count.Tags);

        Measured duration = Assert.Single(capture.Of("masterly.hash.duration"));
        Assert.Equal(new[] { "operation=hash", "profile=mt-metrics" }, duration.Tags);
        Assert.InRange(duration.Value, outerMs / 1000, outerMs + 1);
    }

    [Fact]
    public void Verify_Mismatch_RecordsFailureReason_AndDuration()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.DefaultProfile = Timed);
        string stored = hasher.Hash("pw");
        hasher.Verify("warm-up", stored);
        using var capture = new MetricsCapture();

        long start = Stopwatch.GetTimestamp();
        Assert.False(hasher.Verify("wrong", stored).IsMatch);
        double outerMs = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

        Measured count = Assert.Single(capture.Of("masterly.hash.verifications"));
        Assert.Equal(1d, count.Value);
        Assert.Equal(new[] { "format=mh", "outcome=Failed", "reason=Mismatch" }, count.Tags);

        Measured duration = Assert.Single(capture.Of("masterly.hash.duration"));
        Assert.Equal(new[] { "format=mh", "operation=verify" }, duration.Tags);
        Assert.InRange(duration.Value, outerMs / 1000, outerMs + 1);
    }

    [Fact]
    public void Verify_Success_RecordsNoReason()
    {
        PasswordHasher hasher = TestHashers.Create();
        string stored = hasher.Hash("pw");
        using var capture = new MetricsCapture();

        Assert.True(hasher.Verify("pw", stored).IsMatch);

        Assert.Equal(new[] { "format=mh", "outcome=Success", "reason=None" }, Assert.Single(capture.Of("masterly.hash.verifications")).Tags);
    }

    [Fact]
    public void Verify_RehashNeeded_RecordsTheRehashReason()
    {
        PasswordHasher hasher = TestHashers.Create(o =>
        {
            o.AdditionalProfiles.Add(TestHashers.Fast2);
            o.ComputeRehashOnVerify = false;
        });
        string stored = hasher.Hash("pw", TestHashers.Fast2);
        using var capture = new MetricsCapture();

        Assert.Equal(RehashReason.OutdatedProfile, hasher.Verify("pw", stored).RehashReason);

        Assert.Equal(new[] { "format=mh", "outcome=SuccessRehashNeeded", "reason=OutdatedProfile" }, Assert.Single(capture.Of("masterly.hash.verifications")).Tags);
    }

    [Fact]
    public void Verify_Legacy_RecordsTheLegacyFormatId()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.ComputeRehashOnVerify = false);
        using var capture = new MetricsCapture();

        Assert.True(hasher.Verify("pw", TestHashers.Original1x("pw", new byte[8], V1Algorithm.SHA512)).IsMatch);

        Assert.Equal(new[] { "format=v1", "outcome=SuccessRehashNeeded", "reason=LegacyFormat" }, Assert.Single(capture.Of("masterly.hash.verifications")).Tags);
        Assert.Equal(new[] { "format=v1", "operation=verify" }, Assert.Single(capture.Of("masterly.hash.duration")).Tags);
    }

    [Fact]
    public void Verify_UnknownFormat_IsTaggedUnknown()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.LegacyFormats.Clear());
        using var capture = new MetricsCapture();

        Assert.Equal(VerificationFailureReason.UnknownFormat, hasher.Verify("pw", "not-a-hash").FailureReason);

        Assert.Equal(new[] { "format=unknown", "outcome=Failed", "reason=UnknownFormat" }, Assert.Single(capture.Of("masterly.hash.verifications")).Tags);
        Assert.Equal(new[] { "format=unknown", "operation=verify" }, Assert.Single(capture.Of("masterly.hash.duration")).Tags);
    }

    [Fact]
    public async Task Busy_RecordsARejection()
    {
        var blocker = new BlockingFormat();
        PasswordHasher hasher = TestHashers.Create(o =>
        {
            o.MaxConcurrency = 1;
            o.ConcurrencyTimeout = TimeSpan.FromMilliseconds(1);
            o.LegacyFormats.Add(blocker);
        });
        Task holder = Task.Run(() => hasher.Verify("pw", BlockingFormat.Marker));
        try
        {
            Assert.True(blocker.Entered.Wait(TimeSpan.FromSeconds(30)));
            using var capture = new MetricsCapture();

            Assert.Throws<PasswordHasherBusyException>(() => hasher.Hash("pw"));

            Measured rejection = Assert.Single(capture.Of("masterly.hash.busy_rejections"));
            Assert.Equal(1d, rejection.Value);
            Assert.Empty(rejection.Tags);
        }
        finally
        {
            blocker.Release.Set();
            await holder.WaitAsync(TimeSpan.FromSeconds(30));
        }
    }
}

/// <summary>
/// The unknown-user dummy hash is created once, with the pepper key current at that moment. Peppers such as
/// <c>AzureKeyVaultPepper</c> rotate and revoke keys at run time, so the dummy can fall behind.
/// </summary>
public class DummyHashPepperRotationTests
{
    [Fact]
    public void VerifyOrDummy_AfterKeyRotation_DoesNotRehashTheDummy()
    {
        var pepper = new RotatingPepper("k1", "k1", "k2");
        PasswordHasher hasher = TestHashers.Create(o =>
        {
            o.Pepper = pepper;
            o.ComputeRehashOnVerify = true;
        });
        string realK1 = hasher.Hash("pw");
        Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy("pw", null).FailureReason); // creates the dummy under k1
        pepper.CurrentKeyId = "k2";
        pepper.Drain();

        // A real k1 hash now needs a rehash, and Verify computes it under k2: the scenario is live.
        PasswordVerificationResult real = hasher.Verify("pw", realK1);
        Assert.Equal(RehashReason.OutdatedPepperKey, real.RehashReason);
        Assert.StartsWith("$mh$p=test-fast,k=k2$", real.Rehash);
        Assert.Equal(new[] { "Apply:k1", "Apply:k2" }, pepper.Drain());

        using var capture = new MetricsCapture();
        PasswordVerificationResult dummy = hasher.VerifyOrDummy("pw", null);

        Assert.Equal(VerificationStatus.Failed, dummy.Status);
        Assert.Equal(VerificationFailureReason.NoStoredHash, dummy.FailureReason);
        Assert.Null(dummy.Rehash);
        Assert.Equal(new[] { "Apply:k2" }, pepper.Drain()); // one dummy verify under the current key; no replacement hash
        Assert.Empty(capture.Of("masterly.hash.hashes"));
    }

    // Regression: the dummy hash used to be cached under the key current at first use; after that key was revoked,
    // VerifyOrDummy skipped the pepper and KDF and unknown users became measurably cheaper.
    [Fact]
    public void VerifyOrDummy_AfterTheDummysKeyIsRevoked_StillDoesTheWork()
    {
        var pepper = new RotatingPepper("k1", "k1", "k2");
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = pepper);
        Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy("pw", null).FailureReason); // creates the dummy under k1
        pepper.CurrentKeyId = "k2";
        pepper.Revoke("k1");
        pepper.Drain();

        Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy("pw", null).FailureReason);

        // A known user with a k2 hash costs one pepper call plus one KDF run; an unknown user must cost the same.
        Assert.Contains("Apply:k2", pepper.Drain());
    }
}

/// <summary>Pepper whose current key and key ring change at run time, recording <c>Apply:keyId</c> per call.</summary>
internal sealed class RotatingPepper : IPasswordPepper
{
    private readonly HmacPepper _inner;
    private readonly ConcurrentDictionary<string, bool> _known = new ConcurrentDictionary<string, bool>(StringComparer.Ordinal);
    private readonly ConcurrentQueue<string> _calls = new ConcurrentQueue<string>();
    private volatile string _current;

    public RotatingPepper(string currentKeyId, params string[] keyIds)
    {
        _inner = TestHashers.Pepper(currentKeyId, keyIds);
        _current = currentKeyId;
        foreach (string id in keyIds)
            _known[id] = true;
    }

    public string CurrentKeyId
    {
        get => _current;
        set => _current = value;
    }

    public void Revoke(string keyId) => _known.TryRemove(keyId, out _);

    public bool IsKnownKey(string keyId) => _known.ContainsKey(keyId);

    public byte[] Apply(string keyId, byte[] input)
    {
        _calls.Enqueue("Apply:" + keyId);
        return _inner.Apply(keyId, input);
    }

    public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)
    {
        _calls.Enqueue("ApplyAsync:" + keyId);
        return new ValueTask<byte[]>(_inner.Apply(keyId, input));
    }

    public string[] Drain()
    {
        var drained = new List<string>();
        while (_calls.TryDequeue(out string? call))
            drained.Add(call);
        return drained.ToArray();
    }
}

/// <summary>A measurement: instrument name, value and tags as sorted <c>key=value</c> strings.</summary>
internal sealed record Measured(string Instrument, double Value, IReadOnlyList<string> Tags);

/// <summary>Captures <c>Masterly.Hash</c> measurements recorded on the creating thread (sync calls only).</summary>
internal sealed class MetricsCapture : IDisposable
{
    private readonly MeterListener _listener = new MeterListener();
    private readonly int _threadId = Environment.CurrentManagedThreadId;
    private readonly ConcurrentQueue<Measured> _measurements = new ConcurrentQueue<Measured>();
    private readonly ConcurrentDictionary<string, bool> _instruments = new ConcurrentDictionary<string, bool>();

    public MetricsCapture()
    {
        RuntimeHelpers.RunClassConstructor(typeof(HashMetrics).TypeHandle);
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name != PasswordHasher.MeterName)
                return;
            _instruments[$"{instrument.Name}|{instrument.Unit}|{instrument.Description}"] = true;
            listener.EnableMeasurementEvents(instrument);
        };
        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) => Record(instrument, value, tags));
        _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Record(instrument, value, tags));
        _listener.Start();
    }

    public IReadOnlyList<string> Instruments => _instruments.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray();

    public IReadOnlyList<Measured> Of(string instrument) => _measurements.Where(m => m.Instrument == instrument).ToArray();

    private void Record(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        if (Environment.CurrentManagedThreadId != _threadId)
            return;
        var list = new List<string>();
        foreach (KeyValuePair<string, object?> tag in tags)
            list.Add(tag.Key + "=" + tag.Value);
        list.Sort(StringComparer.Ordinal);
        _measurements.Enqueue(new Measured(instrument.Name, value, list));
    }

    public void Dispose() => _listener.Dispose();
}

/// <summary>
/// Pepper that records which method was called and keeps the buffers it saw. With <c>deferAsync</c>,
/// <see cref="ApplyAsync"/> does not complete until <see cref="Release"/> is called.
/// </summary>
internal sealed class TrackingPepper : IPasswordPepper
{
    private readonly HmacPepper _inner = new HmacPepper("t1", Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());
    private readonly TaskCompletionSource _release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentQueue<string> _calls = new ConcurrentQueue<string>();
    private readonly bool _deferAsync;

    public TrackingPepper(bool deferAsync = false) => _deferAsync = deferAsync;

    public byte[]? LastInput { get; private set; }
    public byte[]? LastOutput { get; private set; }
    public string CurrentKeyId => _inner.CurrentKeyId;
    public bool IsKnownKey(string keyId) => _inner.IsKnownKey(keyId);

    public byte[] Apply(string keyId, byte[] input)
    {
        _calls.Enqueue("Apply");
        return Track(keyId, input);
    }

    public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)
    {
        _calls.Enqueue("ApplyAsync");
        byte[] output = Track(keyId, input);
        return _deferAsync
            ? new ValueTask<byte[]>(_release.Task.ContinueWith(_ => output, CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default))
            : new ValueTask<byte[]>(output);
    }

    public void Release() => _release.TrySetResult();

    public string[] Drain()
    {
        var drained = new List<string>();
        while (_calls.TryDequeue(out string? call))
            drained.Add(call);
        return drained.ToArray();
    }

    private byte[] Track(string keyId, byte[] input)
    {
        LastInput = input;
        byte[] output = _inner.Apply(keyId, input);
        LastOutput = output;
        return output;
    }
}

/// <summary>Legacy format whose <see cref="Verify"/> holds the hasher's slot until released.</summary>
internal sealed class BlockingFormat : ILegacyHashFormat
{
    public const string Marker = "hold-the-gate";
    public readonly ManualResetEventSlim Entered = new ManualResetEventSlim();
    public readonly ManualResetEventSlim Release = new ManualResetEventSlim();

    public string Id => "blocking";
    public bool CanHandle(string storedHash) => storedHash == Marker;

    public bool Verify(string password, string storedHash)
    {
        Entered.Set();
        Release.Wait(TimeSpan.FromSeconds(30));
        return false;
    }

    public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
    {
        digest = parameter = Array.Empty<byte>();
        return false;
    }

    public byte[] ComputeWrapInput(string password, byte[] parameter) => throw new NotSupportedException();
}

/// <summary>Legacy format that accepts <see cref="Marker"/> with a fixed result and counts verifications.</summary>
internal sealed class FakeFormat : ILegacyHashFormat
{
    public const string Marker = "fake-hash";
    private readonly bool _result;
    private int _verifyCalls;

    public FakeFormat(string id, bool result)
    {
        Id = id;
        _result = result;
    }

    public string Id { get; }
    public int VerifyCalls => Volatile.Read(ref _verifyCalls);
    public bool CanHandle(string storedHash) => storedHash == Marker;

    public bool Verify(string password, string storedHash)
    {
        Interlocked.Increment(ref _verifyCalls);
        return _result;
    }

    public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
    {
        digest = parameter = Array.Empty<byte>();
        return false;
    }

    public byte[] ComputeWrapInput(string password, byte[] parameter) => throw new NotSupportedException();
}
