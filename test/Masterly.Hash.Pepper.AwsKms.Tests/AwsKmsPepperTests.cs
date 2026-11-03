using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Masterly.Hash.Pepper.AwsKms;

namespace Masterly.Hash.Pepper.AwsKms.Tests;

public class AwsKmsPepperTests
{
    private const string Arn1 = "arn:aws:kms:us-east-1:111122223333:key/0b1f2c3d-aaaa-bbbb-cccc-000000000001";
    private const string Arn2 = "arn:aws:kms:us-east-1:111122223333:key/0b1f2c3d-aaaa-bbbb-cccc-000000000002";
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");

    private static AwsKmsPepper Pepper(FakeKms kms, Action<AwsKmsPepperOptions>? configure = null)
    {
        AwsKmsPepperOptions o = FakeKms.Options("k1", ("k1", Arn1), ("k2", Arn2));
        configure?.Invoke(o);
        return new AwsKmsPepper(kms.Client, o);
    }

    [Fact]
    public async Task ApplyAsync_CallsGenerateMac_WithMappedKeyAndHmacSha256()
    {
        var kms = new FakeKms(Arn1, Arn2);
        var pepper = Pepper(kms);

        byte[] mac1 = await pepper.ApplyAsync("k1", Input);
        byte[] mac2 = await pepper.ApplyAsync("k2", Input);

        Assert.Equal(kms.Expected(Arn1, Input), mac1);
        Assert.Equal(kms.Expected(Arn2, Input), mac2);
        Assert.NotEqual(mac1, mac2);
        KmsCall call = kms.Calls.First();
        Assert.Equal(Arn1, call.KeyId);
        Assert.Equal("HMAC_SHA_256", call.MacAlgorithm);
        Assert.Equal(Input, call.Message);
        Assert.True(call.GrantTokens == null || call.GrantTokens.Count == 0);
    }

    [Fact]
    public async Task GrantTokens_AreSent()
    {
        var kms = new FakeKms(Arn1);
        var pepper = Pepper(kms, o => { o.GrantTokens.Add("grant-a"); o.GrantTokens.Add("grant-b"); });
        await pepper.ApplyAsync("k1", Input);
        Assert.Equal(new[] { "grant-a", "grant-b" }, Assert.Single(kms.Calls).GrantTokens);
    }

    // RFC 4231, section 4.7 (test case 6): HMAC-SHA-256 with a 131-byte key of 0xaa.
    // KMS GenerateMac with HMAC_SHA_256 is standard RFC 2104 HMAC, so the pepper must return exactly these bytes.
    [Fact]
    public async Task KnownAnswer_Rfc4231TestCase6_PassesThroughUnchanged()
    {
        var kms = new FakeKms();
        kms.SetKey(Arn1, Enumerable.Repeat((byte)0xaa, 131).ToArray());
        byte[] mac = await Pepper(kms).ApplyAsync("k1", Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First"));
        Assert.Equal(Convert.FromHexString("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"), mac);
    }

    [Fact]
    public void Apply_Sync_MatchesAsync()
    {
        var kms = new FakeKms(Arn1, Arn2);
        Assert.Equal(kms.Expected(Arn1, Input), Pepper(kms).Apply("k1", Input));
    }

    [Fact]
    public async Task ReturnedMacBuffer_IsZeroed()
    {
        var kms = new FakeKms(Arn1);
        byte[] mac = await Pepper(kms).ApplyAsync("k1", Input);

        Assert.Equal(kms.Expected(Arn1, Input), mac);
        byte[] buffer = Assert.Single(kms.ReturnedBuffers);
        Assert.All(buffer, b => Assert.Equal(0, b));
    }

    [Fact]
    public void IsKnownKey_UsesKeyMap_WithoutNetwork()
    {
        var kms = new FakeKms();
        var pepper = Pepper(kms);
        Assert.Equal("k1", pepper.CurrentKeyId);
        Assert.True(pepper.IsKnownKey("k1"));
        Assert.True(pepper.IsKnownKey("k2"));
        Assert.False(pepper.IsKnownKey("k3"));
        Assert.False(pepper.IsKnownKey("K1"));
        Assert.False(pepper.IsKnownKey(null!));
        Assert.False(pepper.IsKnownKey(""));
        Assert.Empty(kms.Calls);
    }

    [Fact]
    public async Task UnknownKey_ThrowsKeyNotFound_WithoutNetwork()
    {
        var kms = new FakeKms(Arn1);
        var pepper = Pepper(kms);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => pepper.ApplyAsync("k3", Input).AsTask());
        await Assert.ThrowsAsync<KeyNotFoundException>(() => pepper.ApplyAsync(null!, Input).AsTask());
        Assert.Throws<KeyNotFoundException>(() => pepper.Apply("nope", Input));
        await Assert.ThrowsAsync<ArgumentNullException>(() => pepper.ApplyAsync("k1", null!).AsTask());
        Assert.Throws<ArgumentNullException>(() => pepper.Apply("k1", null!));
        Assert.Empty(kms.Calls);
    }

    [Fact]
    public async Task InputSize_IsLimitedToKmsMaximum()
    {
        var kms = new FakeKms(Arn1);
        var pepper = Pepper(kms);

        Assert.Equal(32, (await pepper.ApplyAsync("k1", new byte[AwsKmsPepper.MaxInputBytes])).Length);
        await Assert.ThrowsAsync<ArgumentException>(() => pepper.ApplyAsync("k1", new byte[AwsKmsPepper.MaxInputBytes + 1]).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() => pepper.ApplyAsync("k1", Array.Empty<byte>()).AsTask());
        Assert.Single(kms.Calls);
    }

    public static IEnumerable<object[]> ServiceErrors() => new[]
    {
        new object[] { new NotFoundException("Key 'x' does not exist") { ErrorCode = "NotFoundException", StatusCode = HttpStatusCode.BadRequest }, "NotFoundException" },
        new object[] { new DisabledException("key is disabled") { ErrorCode = "DisabledException", StatusCode = HttpStatusCode.BadRequest }, "DisabledException" },
        new object[] { new KMSInvalidStateException("pending deletion") { ErrorCode = "KMSInvalidStateException" }, "KMSInvalidStateException" },
        new object[] { new InvalidKeyUsageException("not an HMAC key") { ErrorCode = "InvalidKeyUsageException" }, "InvalidKeyUsageException" },
        new object[] { new KeyUnavailableException("unavailable") { ErrorCode = "KeyUnavailableException", StatusCode = HttpStatusCode.InternalServerError }, "KeyUnavailableException" },
        new object[] { new DependencyTimeoutException("timeout") { ErrorCode = "DependencyTimeoutException", StatusCode = HttpStatusCode.ServiceUnavailable }, "DependencyTimeoutException" },
        new object[] { new KMSInternalException("internal") { ErrorCode = "KMSInternalException", StatusCode = HttpStatusCode.InternalServerError }, "KMSInternalException" },
        new object[] { new AmazonKeyManagementServiceException("Rate exceeded") { ErrorCode = "ThrottlingException", StatusCode = (HttpStatusCode)429 }, "ThrottlingException" },
        new object[] { new AmazonServiceException("User is not authorized") { ErrorCode = "AccessDeniedException", StatusCode = HttpStatusCode.Forbidden }, "AccessDeniedException" },
        new object[] { new AmazonServiceException("weird") { ErrorCode = "bad code\r\nwith " + Convert.ToBase64String(Input) }, "unknown error" },
    };

    [Theory]
    [MemberData(nameof(ServiceErrors))]
    public async Task ServiceErrors_AreUnavailable(Exception error, string expectedCode)
    {
        var kms = new FakeKms(Arn1) { Override = (_, _) => throw error };
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());
        Assert.Contains(expectedCode, ex.Message);
        Assert.Same(error, ex.InnerException);
        Assert.DoesNotContain(Convert.ToBase64String(Input), ex.Message);
        Assert.DoesNotContain("correct horse", ex.ToString());
    }

    [Fact]
    public async Task FaultedTask_IsUnavailable()
    {
        var kms = new FakeKms(Arn1) { Override = (_, _) => Task.FromException<GenerateMacResponse>(new KMSInternalException("x") { ErrorCode = "KMSInternalException" }) };
        await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());
    }

    public static IEnumerable<object[]> ClientErrors() => new[]
    {
        new object[] { new AmazonClientException("Unable to get IAM security credentials") },
        new object[] { new HttpRequestException("No such host is known") },
        new object[] { new IOException("connection reset") },
        // AWSSDK.Core unwraps its own HttpClient timeout (ClientConfig.Timeout) into a System.TimeoutException.
        new object[] { new TimeoutException("The operation has timed out.", new TaskCanceledException()) },
        new object[] { new ObjectDisposedException("AmazonKeyManagementServiceClient") },
        new object[] { new InvalidOperationException("SDK pipeline failure") },
    };

    [Fact]
    public void SdkTimeout_ThroughSyncApplyAndHasher_IsUnavailable()
    {
        var kms = new FakeKms(Arn1) { Override = (_, _) => throw new TimeoutException("The operation has timed out.") };
        var pepper = Pepper(kms);
        var ex = Assert.Throws<PepperUnavailableException>(() => pepper.Apply("k1", Input));
        Assert.IsType<TimeoutException>(ex.InnerException);

        var hasher = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = HashProfile.Argon2id("test", 64, 1), AllowWeakProfiles = true, Pepper = pepper });
        Assert.Throws<PepperUnavailableException>(() => hasher.Hash("correct horse battery staple"));
    }

    [Theory]
    [MemberData(nameof(ClientErrors))]
    public async Task ClientAndNetworkErrors_AreUnavailable(Exception error)
    {
        var kms = new FakeKms(Arn1) { Override = (_, _) => throw error };
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());
        Assert.Same(error, ex.InnerException);
    }

    [Fact]
    public async Task Timeout_IsUnavailable()
    {
        var kms = new FakeKms(Arn1)
        {
            Override = async (_, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); },
        };
        var pepper = Pepper(kms, o => o.Timeout = TimeSpan.FromMilliseconds(100));
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("k1", Input).AsTask());
        Assert.Contains("timeout", ex.Message);
    }

    [Fact]
    public async Task CallerCancellation_IsOperationCanceled_NotUnavailable()
    {
        var kms = new FakeKms(Arn1)
        {
            Override = async (_, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new InvalidOperationException(); },
        };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Pepper(kms).ApplyAsync("k1", Input, cts.Token).AsTask());
        Assert.IsNotType<PepperUnavailableException>(ex);
    }

    [Fact]
    public async Task AlreadyCancelled_DoesNotCallKms()
    {
        var kms = new FakeKms(Arn1);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Pepper(kms).ApplyAsync("k1", Input, new CancellationToken(true)).AsTask());
        Assert.Empty(kms.Calls);
    }

    [Fact]
    public async Task BadResponses_AreUnavailable()
    {
        var kms = new FakeKms(Arn1);
        var pepper = Pepper(kms);
        var bad = new Func<GenerateMacResponse?>[]
        {
            () => null,
            () => new GenerateMacResponse(),
            () => kms.Response(new byte[16], MacAlgorithmSpec.HMAC_SHA_256),
            () => kms.Response(new byte[64], MacAlgorithmSpec.HMAC_SHA_256),
            () => kms.Response(Array.Empty<byte>(), MacAlgorithmSpec.HMAC_SHA_256),
            () => kms.Response(new byte[32], MacAlgorithmSpec.HMAC_SHA_512),
        };
        foreach (var make in bad)
        {
            kms.Override = (_, _) => Task.FromResult(make()!);
            await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.ApplyAsync("k1", Input).AsTask());
        }
    }

    [Fact]
    public async Task ResponseWithoutAlgorithm_IsAccepted()
    {
        var kms = new FakeKms(Arn1);
        byte[] mac = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        kms.Override = (_, _) => Task.FromResult(kms.Response(mac, null));
        Assert.Equal(mac, await Pepper(kms).ApplyAsync("k1", Input));
    }

    [Fact]
    public async Task ConcurrentCalls_AreIndependent()
    {
        var kms = new FakeKms(Arn1, Arn2);
        var pepper = Pepper(kms);
        byte[][] inputs = Enumerable.Range(0, 64).Select(i => Encoding.UTF8.GetBytes("pw-" + i)).ToArray();
        byte[][] macs = await Task.WhenAll(inputs.Select(i => pepper.ApplyAsync("k1", i).AsTask()));
        for (int i = 0; i < inputs.Length; i++)
            Assert.Equal(kms.Expected(Arn1, inputs[i]), macs[i]);
    }

    [Fact]
    public void Constructor_RejectsNulls()
    {
        var kms = new FakeKms();
        Assert.Throws<ArgumentNullException>(() => new AwsKmsPepper(null!, FakeKms.Options("k1", ("k1", Arn1))));
        Assert.Throws<ArgumentNullException>(() => new AwsKmsPepper(kms.Client, null!));
    }

    public static IEnumerable<object[]> InvalidOptions()
    {
        var cases = new (string Name, Action<AwsKmsPepperOptions> Configure)[]
        {
            ("no current", o => o.CurrentKeyId = null),
            ("current not mapped", o => o.CurrentKeyId = "k9"),
            ("no keys", o => { o.Keys.Clear(); }),
            ("bad key id", o => o.Keys["bad id"] = Arn1),
            ("long key id", o => o.Keys[new string('a', 33)] = Arn1),
            ("empty key id", o => o.Keys[""] = Arn1),
            ("null kms key", o => o.Keys["k1"] = null!),
            ("empty kms key", o => o.Keys["k1"] = ""),
            ("whitespace kms key", o => o.Keys["k1"] = "alias/my key"),
            ("newline kms key", o => o.Keys["k1"] = "alias/x\n"),
            ("huge kms key", o => o.Keys["k1"] = new string('a', 2049)),
            ("empty grant", o => o.GrantTokens.Add("")),
            ("null grant", o => o.GrantTokens.Add(null!)),
            ("zero timeout", o => o.Timeout = TimeSpan.Zero),
            ("infinite timeout", o => o.Timeout = Timeout.InfiniteTimeSpan),
            ("huge timeout", o => o.Timeout = TimeSpan.FromHours(1)),
        };
        return cases.Select(c => new object[] { c.Name, c.Configure });
    }

    [Theory]
    [MemberData(nameof(InvalidOptions))]
    public void Constructor_RejectsInvalidOptions(string name, Action<AwsKmsPepperOptions> configure)
    {
        AwsKmsPepperOptions o = FakeKms.Options("k1", ("k1", Arn1));
        configure(o);
        var ex = Assert.Throws<ArgumentException>(() => new AwsKmsPepper(new FakeKms().Client, o));
        Assert.Equal("options", ex.ParamName);
        _ = name;
    }

    [Fact]
    public void Constructor_AcceptsAliasesAndKeyIds()
    {
        var o = FakeKms.Options("a", ("a", "alias/password-pepper"), ("b", "1234abcd-12ab-34cd-56ef-1234567890ab"), ("c", "arn:aws:kms:eu-west-1:111122223333:alias/pepper"));
        Assert.True(new AwsKmsPepper(new FakeKms().Client, o).IsKnownKey("c"));
    }

    [Fact]
    public async Task Constructor_CopiesOptions()
    {
        var kms = new FakeKms(Arn1, Arn2);
        AwsKmsPepperOptions o = FakeKms.Options("k1", ("k1", Arn1));
        var pepper = new AwsKmsPepper(kms.Client, o);
        o.Keys["k1"] = Arn2;
        o.Keys["k2"] = Arn2;
        o.CurrentKeyId = "k2";
        o.GrantTokens.Add("late");

        Assert.Equal("k1", pepper.CurrentKeyId);
        Assert.False(pepper.IsKnownKey("k2"));
        Assert.Equal(kms.Expected(Arn1, Input), await pepper.ApplyAsync("k1", Input));
        Assert.True(Assert.Single(kms.Calls).GrantTokens is null or { Count: 0 });
    }

    [Fact]
    public void UnimplementedClientMembers_AreNeverUsed()
    {
        var kms = new FakeKms(Arn1);
        _ = Pepper(kms).Apply("k1", Input);
        Assert.Throws<NotImplementedException>(() => { _ = kms.Client.ListKeysAsync(new ListKeysRequest()); });
    }
}
