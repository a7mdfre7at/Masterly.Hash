using System.Linq;
using System.Threading.Tasks;
using Amazon.KeyManagementService.Model;
using Masterly.Hash.Pepper.AwsKms;

namespace Masterly.Hash.Pepper.AwsKms.Tests;

public class EndToEndTests
{
    private const string Pw = "Tr0ub4dor&3";
    private const string KeyA = "arn:aws:kms:us-east-1:111122223333:key/aaaaaaaa-0000-0000-0000-000000000001";
    private const string KeyB = "arn:aws:kms:us-east-1:111122223333:key/bbbbbbbb-0000-0000-0000-000000000002";

    [Fact]
    public async Task HashAndVerify_ThroughKms()
    {
        var kms = new FakeKms(KeyA);
        var hasher = FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("2026-01", ("2026-01", KeyA))));

        string stored = await hasher.HashAsync(Pw);

        Assert.StartsWith("$mh$p=test,k=2026-01$", stored);
        Assert.Equal(VerificationStatus.Success, (await hasher.VerifyAsync(Pw, stored)).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, (await hasher.VerifyAsync("wrong", stored)).FailureReason);
        Assert.Equal(3, kms.Calls.Count);
        Assert.All(kms.Calls, c => Assert.Equal(KeyA, c.KeyId));
    }

    [Fact]
    public void SyncHasherApi_Works()
    {
        var kms = new FakeKms(KeyA);
        var hasher = FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("a", ("a", KeyA))));
        string stored = hasher.Hash(Pw);
        Assert.True(hasher.Verify(Pw, stored).IsMatch);
    }

    [Fact]
    public async Task Rotation_OldKeyVerifies_AndRehashesToNewKmsKey()
    {
        var kms = new FakeKms(KeyA, KeyB);
        string stored = await FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("a", ("a", KeyA)))).HashAsync(Pw);

        var rotated = FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("b", ("a", KeyA), ("b", KeyB))));
        PasswordVerificationResult result = await rotated.VerifyAsync(Pw, stored);

        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        Assert.StartsWith("$mh$p=test,k=b$", result.Rehash);
        Assert.Equal(VerificationStatus.Success, (await rotated.VerifyAsync(Pw, result.Rehash!)).Status);
        Assert.Equal(new[] { KeyA, KeyA, KeyB, KeyB }, kms.Calls.Select(c => c.KeyId).ToArray());
    }

    [Fact]
    public async Task RemovedKeyId_FailsAsUnknownKey_WithoutCallingKms()
    {
        var kms = new FakeKms(KeyA, KeyB);
        string stored = await FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("a", ("a", KeyA)))).HashAsync(Pw);
        kms.Calls.Clear();

        var retired = FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("b", ("b", KeyB))));
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, (await retired.VerifyAsync(Pw, stored)).FailureReason);
        Assert.Empty(kms.Calls);
    }

    [Fact]
    public async Task RemappedKeyId_Mismatches()
    {
        var kms = new FakeKms(KeyA, KeyB);
        string stored = await FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("a", ("a", KeyA)))).HashAsync(Pw);
        var remapped = FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("a", ("a", KeyB))));
        Assert.Equal(VerificationFailureReason.Mismatch, (await remapped.VerifyAsync(Pw, stored)).FailureReason);
    }

    [Fact]
    public async Task KmsDown_HashAndVerifyThrowUnavailable_NotMismatch()
    {
        var kms = new FakeKms(KeyA);
        var hasher = FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("a", ("a", KeyA))));
        string stored = await hasher.HashAsync(Pw);
        kms.Override = (_, _) => throw new DisabledException("disabled") { ErrorCode = "DisabledException" };

        await Assert.ThrowsAsync<PepperUnavailableException>(() => hasher.VerifyAsync(Pw, stored).AsTask());
        await Assert.ThrowsAsync<PepperUnavailableException>(() => hasher.HashAsync(Pw).AsTask());
        Assert.Throws<PepperUnavailableException>(() => hasher.Verify(Pw, stored));
    }

    [Fact]
    public async Task MalformedStoredHash_NeverCallsKms()
    {
        var kms = new FakeKms(KeyA);
        var hasher = FakeKms.Hasher(new AwsKmsPepper(kms.Client, FakeKms.Options("a", ("a", KeyA))));
        foreach (string bad in new[] { "", "$mh$", "$mh$p=test,k=a$", "$mh$p=test,k=zz$AAAAAAAAAAAAAAAAAAAAAA$AAAA", "garbage" })
            Assert.False((await hasher.VerifyAsync(Pw, bad)).IsMatch);
        Assert.Empty(kms.Calls);
    }
}
