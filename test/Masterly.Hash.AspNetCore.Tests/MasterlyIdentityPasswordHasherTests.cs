using System;
using System.Diagnostics;
using Masterly.Hash.Legacy;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using IdentityCompatibilityMode = Microsoft.AspNetCore.Identity.PasswordHasherCompatibilityMode;
using IdentityResult = Microsoft.AspNetCore.Identity.PasswordVerificationResult;

namespace Masterly.Hash.AspNetCore.Tests;

public class MasterlyIdentityPasswordHasherTests
{
    private const string Password = "correct horse battery staple";
    private static readonly TestUser User = new();

    // 60 x U+FDFA: 180 raw UTF-8 bytes (what legacy formats measure) but 1,980 bytes after NFKC (what new hashes measure).
    private static readonly string NfkcExpanding = new('ﷺ', 60);

    [Fact]
    public void Constructors_ValidateArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new MasterlyIdentityPasswordHasher<TestUser>(null!, 1024));
        Assert.Throws<ArgumentNullException>(() => new MasterlyIdentityPasswordHasher<TestUser>(null!, Options.Create(new PasswordHasherOptions())));
        Assert.Throws<ArgumentNullException>(() => new MasterlyIdentityPasswordHasher<TestUser>(new BusyHasher(), (IOptions<PasswordHasherOptions>)null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => new MasterlyIdentityPasswordHasher<TestUser>(new BusyHasher(), 0));
    }

    [Fact]
    public void Verify_HugeNfkcExpandingPassword_FailsWithoutNormalizing()
    {
        // A 4 MB form value (FormOptions.ValueLengthLimit) of U+FDFA would normalize to ~25M chars before the core's check.
        var adapter = TestHashers.CreateAdapter();
        string stored = adapter.HashPassword(User, Password);
        string hostile = new('ﷺ', 1_400_000);

        long before = GC.GetAllocatedBytesForCurrentThread();
        IdentityResult result = adapter.VerifyHashedPassword(User, stored, hostile);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(IdentityResult.Failed, result);
        Assert.True(allocated < 100_000, $"Verify allocated {allocated} bytes; it must reject from the length alone.");
    }

    [Fact]
    public void HashPassword_HugeNfkcExpandingPassword_ThrowsWithoutNormalizing()
    {
        var adapter = TestHashers.CreateAdapter();
        string hostile = new('ﷺ', 1_400_000);

        long before = GC.GetAllocatedBytesForCurrentThread();
        ArgumentException ex = Assert.Throws<ArgumentException>(() => adapter.HashPassword(User, hostile));
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.DoesNotContain("ﷺ", ex.Message, StringComparison.Ordinal);
        Assert.True(allocated < 1_000_000, $"HashPassword allocated {allocated} bytes; it must reject from the length alone.");
    }

    [Fact]
    public void HashPassword_OverLimitAfterNfkc_Throws() =>
        Assert.Throws<ArgumentException>(() => TestHashers.CreateAdapter().HashPassword(User, NfkcExpanding));

    [Theory]
    [InlineData(IdentityCompatibilityMode.IdentityV3)]
    [InlineData(IdentityCompatibilityMode.IdentityV2)]
    public void Verify_LegacyHashOfPasswordThatCannotBeRehashed_ReturnsSuccess_SoUserManagerKeepsIt(IdentityCompatibilityMode mode)
    {
        string microsoftHash = TestHashers.Microsoft(mode).HashPassword(User, NfkcExpanding);
        var adapter = TestHashers.CreateAdapter();

        // Re-hashing would throw, so SuccessRehashNeeded would make UserManager throw on every login.
        Assert.Throws<ArgumentException>(() => adapter.HashPassword(User, NfkcExpanding));
        Assert.Equal(IdentityResult.Success, adapter.VerifyHashedPassword(User, microsoftHash, NfkcExpanding));
        Assert.Equal(IdentityResult.Failed, adapter.VerifyHashedPassword(User, microsoftHash, NfkcExpanding + "x"));
    }

    [Fact]
    public void Verify_LegacyPasswordOverRawLimit_Fails_UnlessLimitRaised()
    {
        string longPassword = new('a', 1500);
        string microsoftHash = TestHashers.Microsoft(IdentityCompatibilityMode.IdentityV3).HashPassword(User, longPassword);

        Assert.Equal(IdentityResult.Failed, TestHashers.CreateAdapter().VerifyHashedPassword(User, microsoftHash, longPassword));
        Assert.Equal(IdentityResult.SuccessRehashNeeded,
            TestHashers.CreateAdapter(o => o.MaxPasswordBytes = 2048).VerifyHashedPassword(User, microsoftHash, longPassword));
    }

    [Fact]
    public void HashPassword_ProducesMasterlyHash_ThatVerifiesAsSuccess()
    {
        var adapter = TestHashers.CreateAdapter();

        string hash = adapter.HashPassword(User, Password);

        Assert.StartsWith("$mh$p=test$", hash, StringComparison.Ordinal);
        Assert.Equal(IdentityResult.Success, adapter.VerifyHashedPassword(User, hash, Password));
        Assert.Equal(IdentityResult.Failed, adapter.VerifyHashedPassword(User, hash, Password + "!"));
    }

    [Fact]
    public void HashPassword_SaltsEveryHash()
    {
        var adapter = TestHashers.CreateAdapter();
        Assert.NotEqual(adapter.HashPassword(User, Password), adapter.HashPassword(User, Password));
    }

    [Fact]
    public void User_IsNotRequired()
    {
        var adapter = TestHashers.CreateAdapter();
        string hash = adapter.HashPassword(null!, Password);
        Assert.Equal(IdentityResult.Success, adapter.VerifyHashedPassword(null!, hash, Password));
    }

    [Fact]
    public void HashPassword_NullPassword_Throws() =>
        Assert.Throws<ArgumentNullException>(() => TestHashers.CreateAdapter().HashPassword(User, null!));

    [Fact]
    public void HashPassword_EmptyPassword_Throws() =>
        Assert.Throws<ArgumentException>(() => TestHashers.CreateAdapter().HashPassword(User, ""));

    [Fact]
    public void Verify_NullProvidedPassword_Throws()
    {
        var adapter = TestHashers.CreateAdapter();
        string hash = adapter.HashPassword(User, Password);
        Assert.Throws<ArgumentNullException>(() => adapter.VerifyHashedPassword(User, hash, null!));
    }

    [Fact]
    public void Verify_EmptyProvidedPassword_Fails()
    {
        var adapter = TestHashers.CreateAdapter();
        string hash = adapter.HashPassword(User, Password);
        Assert.Equal(IdentityResult.Failed, adapter.VerifyHashedPassword(User, hash, ""));
    }

    [Theory]
    [InlineData(IdentityCompatibilityMode.IdentityV3)]
    [InlineData(IdentityCompatibilityMode.IdentityV2)]
    public void Verify_HashFromMicrosoftHasher_SucceedsWithRehash(IdentityCompatibilityMode mode)
    {
        string microsoftHash = TestHashers.Microsoft(mode).HashPassword(User, Password);
        var adapter = TestHashers.CreateAdapter();

        Assert.Equal(IdentityResult.SuccessRehashNeeded, adapter.VerifyHashedPassword(User, microsoftHash, Password));
        Assert.Equal(IdentityResult.Failed, adapter.VerifyHashedPassword(User, microsoftHash, "wrong password"));
        Assert.Equal(IdentityResult.Failed, adapter.VerifyHashedPassword(User, microsoftHash, Password.ToUpperInvariant()));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10_000)]
    [InlineData(600_000)]
    public void Verify_MicrosoftV3HashWithCustomIterationCount_Succeeds(int iterations)
    {
        string microsoftHash = TestHashers.Microsoft(IdentityCompatibilityMode.IdentityV3, iterations).HashPassword(User, Password);
        Assert.Equal(IdentityResult.SuccessRehashNeeded, TestHashers.CreateAdapter().VerifyHashedPassword(User, microsoftHash, Password));
    }

    [Theory]
    [InlineData(IdentityCompatibilityMode.IdentityV3, "pässwörd 你好 🔑")]
    [InlineData(IdentityCompatibilityMode.IdentityV2, "pässwörd 你好 🔑")]
    [InlineData(IdentityCompatibilityMode.IdentityV3, "x")]
    public void Verify_NonAsciiAndShortMicrosoftHashes_Succeed(IdentityCompatibilityMode mode, string password)
    {
        string microsoftHash = TestHashers.Microsoft(mode).HashPassword(User, password);
        Assert.Equal(IdentityResult.SuccessRehashNeeded, TestHashers.CreateAdapter().VerifyHashedPassword(User, microsoftHash, password));
    }

    // Known-answer payloads from the ASP.NET Core repository, src/Identity/test/Identity.Test/PasswordHasherTest.cs
    // (VerifyHashedPassword_Version2CompatMode_SuccessCases / Version3CompatMode_SuccessCases), password "my password".
    // Each vector is also checked against Microsoft's own PasswordHasher<TUser>, so a mistyped vector cannot pass.
    [Theory]
    [InlineData("ANXrDknc7fGPpigibZXXZFMX4aoqz44JveK6jQuwY3eH/UyPhvr5xTPeGYEckLxz9A==")] // V2: SHA1, 1000 iterations, 128-bit salt, 256-bit subkey
    [InlineData("AQAAAAAAAAD6AAAAEAhftMyfTJylOlZT+eEotFXd1elee8ih5WsjXaR3PA9M")] // V3: SHA1, 250 iterations, 128-bit salt, 128-bit subkey
    [InlineData("AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg+yWU7rLgUwPZb1Itsmra7cbxw2EFpwpVFIEtP+JIuUEw==")] // V3: SHA256, 10000 iterations, 128-bit salt, 256-bit subkey
    public void Verify_MicrosoftKnownAnswerVectors(string hash)
    {
        IdentityResult microsoft = TestHashers.Microsoft(IdentityCompatibilityMode.IdentityV3).VerifyHashedPassword(User, hash, "my password");
        IdentityResult masterly = TestHashers.CreateAdapter().VerifyHashedPassword(User, hash, "my password");

        Assert.NotEqual(IdentityResult.Failed, microsoft);
        Assert.Equal(IdentityResult.SuccessRehashNeeded, masterly);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("not a hash")]
    [InlineData("$mh$")]
    [InlineData("$mh$p=nope$AAAA$AAAA")]
    [InlineData("$mh$p=test$!!!$???")]
    [InlineData("$2b$10$invalidbcrypt")]
    [InlineData("AA==")]
    [InlineData("AQ==")]
    [InlineData("AAABAgMEBQYHCAkKCwwNDg+ukCEMDf0yyQ29NYubggE=")] // V2 too short (ASP.NET Core PasswordHasherTest failure case)
    [InlineData("AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4A=")] // V3 too short (ASP.NET Core PasswordHasherTest failure case)
    [InlineData("AAABAgMEBQYHCAkKCwwNDg+uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")] // V2 incorrect subkey
    public void Verify_MalformedOrForeignStoredHash_FailsWithoutThrowing(string? stored)
    {
        var adapter = TestHashers.CreateAdapter();
        Assert.Equal(IdentityResult.Failed, adapter.VerifyHashedPassword(User, stored!, "my password"));
    }

    [Fact]
    public void Verify_V3HashWithHugeIterationCount_FailsFast()
    {
        // 0x01 | PRF=SHA512 | iterations=0x7FFFFFFF | salt length 16 | salt | 32-byte subkey: far over the DoS cap.
        byte[] payload = new byte[13 + 16 + 32];
        payload[0] = 0x01;
        payload[4] = 2;
        payload[5] = 0x7F; payload[6] = 0xFF; payload[7] = 0xFF; payload[8] = 0xFF;
        payload[12] = 16;
        string hostile = Convert.ToBase64String(payload);

        var stopwatch = Stopwatch.StartNew();
        IdentityResult result = TestHashers.CreateAdapter().VerifyHashedPassword(User, hostile, Password);
        stopwatch.Stop();

        Assert.Equal(IdentityResult.Failed, result);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5), "A hostile iteration count must be refused, not computed.");
    }

    [Fact]
    public void Verify_OutdatedProfile_RequestsRehash()
    {
        var old = TestHashers.CreateAdapter(o => o.DefaultProfile = TestHashers.Fast2);
        string hash = old.HashPassword(User, Password);

        var current = TestHashers.CreateAdapter(o => o.AdditionalProfiles.Add(TestHashers.Fast2));

        Assert.Equal(IdentityResult.SuccessRehashNeeded, current.VerifyHashedPassword(User, hash, Password));
    }

    [Fact]
    public void Verify_ComputeRehashOnVerifyEnabled_StillMapsToSuccessRehashNeeded()
    {
        var adapter = TestHashers.CreateAdapter(o => o.ComputeRehashOnVerify = true);
        string microsoftHash = TestHashers.Microsoft(IdentityCompatibilityMode.IdentityV3).HashPassword(User, Password);
        Assert.Equal(IdentityResult.SuccessRehashNeeded, adapter.VerifyHashedPassword(User, microsoftHash, Password));
    }

    [Fact]
    public void Verify_WithoutIdentityFormats_DoesNotAcceptMicrosoftV3Hashes()
    {
        // Documents why AddAspNetIdentityFormats matters: a bare hasher does not know the Identity formats.
        var bare = new MasterlyIdentityPasswordHasher<TestUser>(new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestHashers.Fast, AllowWeakProfiles = true }), 1024);
        string microsoftHash = TestHashers.Microsoft(IdentityCompatibilityMode.IdentityV3).HashPassword(User, Password);
        Assert.Equal(IdentityResult.Failed, bare.VerifyHashedPassword(User, microsoftHash, Password));
    }

    [Fact]
    public void UpgradedHash_IsMasterly_AndNoLongerNeedsRehash()
    {
        var adapter = TestHashers.CreateAdapter();
        string microsoftHash = TestHashers.Microsoft(IdentityCompatibilityMode.IdentityV2).HashPassword(User, Password);
        Assert.Equal(IdentityResult.SuccessRehashNeeded, adapter.VerifyHashedPassword(User, microsoftHash, Password));

        // What UserManager does on SuccessRehashNeeded.
        string upgraded = adapter.HashPassword(User, Password);

        Assert.StartsWith("$mh$", upgraded, StringComparison.Ordinal);
        Assert.Equal(IdentityResult.Success, adapter.VerifyHashedPassword(User, upgraded, Password));
    }

    [Fact]
    public void BusyHasher_PropagatesBusyException()
    {
        var adapter = new MasterlyIdentityPasswordHasher<TestUser>(new BusyHasher(), 1024);
        Assert.Throws<PasswordHasherBusyException>(() => adapter.HashPassword(User, Password));
        Assert.Throws<PasswordHasherBusyException>(() => adapter.VerifyHashedPassword(User, "$mh$p=test$AAAA$AAAA", Password));
    }

    [Theory]
    [InlineData(VerificationStatus.Success, IdentityResult.Success)]
    [InlineData(VerificationStatus.SuccessRehashNeeded, IdentityResult.SuccessRehashNeeded)]
    [InlineData(VerificationStatus.Failed, IdentityResult.Failed)]
    [InlineData((VerificationStatus)99, IdentityResult.Failed)]
    public void Map_CoversEveryStatus_AndFailsClosed(VerificationStatus status, IdentityResult expected) =>
        Assert.Equal(expected, MasterlyIdentityPasswordHasher<TestUser>.Map(status));

    [Fact]
    public void AddAspNetIdentityFormats_AddsBothFormatsAheadOfV1_AndIsIdempotent()
    {
        var options = new PasswordHasherOptions();
        options.AddAspNetIdentityFormats().AddAspNetIdentityFormats();

        Assert.Equal(3, options.LegacyFormats.Count);
        Assert.Same(AspNetIdentityV3Format.Default, options.LegacyFormats[0]);
        Assert.Same(AspNetIdentityV2Format.Instance, options.LegacyFormats[1]);
        Assert.Same(V1LegacyFormat.Instance, options.LegacyFormats[2]);
    }

    [Fact]
    public void AddAspNetIdentityFormats_KeepsCustomFormatWithSameId()
    {
        var custom = new AspNetIdentityV3Format(1_000_000);
        var options = new PasswordHasherOptions();
        options.AddLegacyFormats(custom);

        options.AddAspNetIdentityFormats();

        Assert.Contains(custom, options.LegacyFormats);
        Assert.DoesNotContain(AspNetIdentityV3Format.Default, options.LegacyFormats);
        Assert.Contains(AspNetIdentityV2Format.Instance, options.LegacyFormats);
    }

    [Fact]
    public void AddAspNetIdentityFormats_NullOptions_Throws() =>
        Assert.Throws<ArgumentNullException>(() => AspNetIdentityPasswordHasherOptionsExtensions.AddAspNetIdentityFormats(null!));

    [Fact]
    public void Inspect_ReportsIdentityFormats()
    {
        PasswordHasher hasher = TestHashers.CreateForIdentity();
        Assert.Equal("aspnet-identity-v3", hasher.Inspect(TestHashers.Microsoft(IdentityCompatibilityMode.IdentityV3).HashPassword(User, Password)).Format);
        Assert.Equal("aspnet-identity-v2", hasher.Inspect(TestHashers.Microsoft(IdentityCompatibilityMode.IdentityV2).HashPassword(User, Password)).Format);
    }
}
