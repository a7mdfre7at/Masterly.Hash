using System;

namespace Masterly.Hash.Detection.Tests;

/// <summary>The core hasher rejects unpaired surrogates; Detection must agree and must never throw on them while observing.</summary>
public class IllFormedPasswordTests
{
    // Built in code: xunit would mangle lone surrogates in [InlineData].
    private static readonly string LoneHigh = "pw" + (char)0xD800;
    private static readonly string LoneLow = "pw" + (char)0xDC00;

    [Fact]
    public void Honeywords_RejectIllFormedPasswords_LikeTheHasher()
    {
        HoneywordService service = TestSupport.Service();
        Assert.Throws<ArgumentException>(() => service.Create(LoneHigh));

        HoneywordRecord record = service.Create("pw�");
        Assert.Equal(HoneywordVerificationStatus.InvalidPassword, service.VerifyDetailed(LoneHigh, record.StoredHash).Status);
        Assert.Equal(-1, service.Verify(LoneLow, record.StoredHash));
    }

    [Fact]
    public void StuffingDetector_FingerprintsIllFormedPasswords_WithoutCollisions()
    {
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 2 });

        Assert.False(detector.RecordFailedLogin("a", LoneHigh));
        Assert.False(detector.RecordFailedLogin("b", LoneLow));   // distinct from LoneHigh
        Assert.False(detector.RecordFailedLogin("c", "pw�")); // distinct from both
        Assert.True(detector.RecordFailedLogin("d", LoneHigh));
    }
}
