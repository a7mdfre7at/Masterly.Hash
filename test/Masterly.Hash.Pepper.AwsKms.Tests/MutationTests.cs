using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Masterly.Hash.Pepper.AwsKms;

namespace Masterly.Hash.Pepper.AwsKms.Tests;

/// <summary>Exact boundaries, messages and cleanup behaviour pinned down so that code mutations are detected.</summary>
public class MutationTests
{
    private const string Arn1 = "arn:aws:kms:us-east-1:111122223333:key/0b1f2c3d-aaaa-bbbb-cccc-000000000001";
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");

    private static AwsKmsPepper Pepper(FakeKms kms) => new(kms.Client, FakeKms.Options("k1", ("k1", Arn1)));

    private static ArgumentException Rejected(AwsKmsPepperOptions options)
    {
        var ex = Assert.Throws<ArgumentException>(() => new AwsKmsPepper(new FakeKms().Client, options));
        Assert.Equal("options", ex.ParamName);
        return ex;
    }

    [Fact]
    public void Invalid_pepper_key_id_message_names_the_id_and_pattern()
    {
        ArgumentException ex = Rejected(FakeKms.Options("k1", ("k1", Arn1), ("bad id", Arn1)));
        Assert.StartsWith("Pepper key id 'bad id' must match ^[A-Za-z0-9-]{1,32}$.", ex.Message);
    }

    [Fact]
    public void Invalid_kms_key_message_names_the_pepper_key_id()
    {
        ArgumentException ex = Rejected(FakeKms.Options("k1", ("k1", "alias/my key")));
        Assert.StartsWith("KMS key for pepper key id 'k1' must be a non-empty key ARN, key id or alias without whitespace.", ex.Message);
    }

    [Fact]
    public void Missing_current_key_message()
    {
        ArgumentException ex = Rejected(FakeKms.Options("k9", ("k1", Arn1)));
        Assert.StartsWith("CurrentKeyId is required and must be a key in Keys.", ex.Message);
    }

    [Fact]
    public void Empty_grant_token_message()
    {
        AwsKmsPepperOptions o = FakeKms.Options("k1", ("k1", Arn1));
        o.GrantTokens.Add("");
        Assert.StartsWith("GrantTokens cannot contain null or empty entries.", Rejected(o).Message);
    }

    [Fact]
    public void Out_of_range_timeout_message()
    {
        AwsKmsPepperOptions o = FakeKms.Options("k1", ("k1", Arn1));
        o.Timeout = TimeSpan.Zero;
        Assert.StartsWith("Timeout must be greater than zero and at most 10 minutes.", Rejected(o).Message);
    }

    [Fact]
    public async Task Timeout_of_exactly_ten_minutes_is_accepted_and_one_tick_more_is_rejected()
    {
        var kms = new FakeKms(Arn1);
        AwsKmsPepperOptions o = FakeKms.Options("k1", ("k1", Arn1));
        o.Timeout = TimeSpan.FromMinutes(10);
        var pepper = new AwsKmsPepper(kms.Client, o);
        Assert.Equal(kms.Expected(Arn1, Input), await pepper.ApplyAsync("k1", Input));

        AwsKmsPepperOptions over = FakeKms.Options("k1", ("k1", Arn1));
        over.Timeout = TimeSpan.FromMinutes(10) + TimeSpan.FromTicks(1);
        Rejected(over);
    }

    [Fact]
    public void Kms_key_of_exactly_2048_characters_is_accepted_and_2049_is_rejected()
    {
        string max = "alias/" + new string('a', 2048 - 6);
        Assert.Equal(2048, max.Length);
        Assert.True(new AwsKmsPepper(new FakeKms().Client, FakeKms.Options("k1", ("k1", max))).IsKnownKey("k1"));

        Rejected(FakeKms.Options("k1", ("k1", max + "a")));
    }

    [Fact]
    public void Kms_key_with_printable_ascii_boundaries_is_accepted_and_outside_is_rejected()
    {
        // '!' (0x21) and '~' (0x7E) are the first and last accepted characters.
        Assert.True(new AwsKmsPepper(new FakeKms().Client, FakeKms.Options("k1", ("k1", "alias/!pepper~"))).IsKnownKey("k1"));

        Rejected(FakeKms.Options("k1", ("k1", "alias/pepper\u007f")));
        Rejected(FakeKms.Options("k1", ("k1", "alias/pepper ")));
    }

    [Theory]
    [InlineData("Z")]
    [InlineData("ZzAa09._-")]
    public async Task Service_error_code_with_uppercase_Z_is_kept(string code)
    {
        var error = new AmazonServiceException("x") { ErrorCode = code, StatusCode = HttpStatusCode.BadRequest };
        var kms = new FakeKms(Arn1) { Override = (_, _) => throw error };

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());

        Assert.Equal($"AWS KMS GenerateMac failed ({code}, HTTP 400).", ex.Message);
    }

    [Fact]
    public async Task Service_error_code_of_exactly_64_characters_is_kept_whole()
    {
        string code = new string('Q', 64);
        var error = new AmazonServiceException("x") { ErrorCode = code, StatusCode = HttpStatusCode.BadRequest };
        var kms = new FakeKms(Arn1) { Override = (_, _) => throw error };

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());

        Assert.Equal($"AWS KMS GenerateMac failed ({code}, HTTP 400).", ex.Message);
    }

    [Fact]
    public async Task Null_response_reports_no_mac()
    {
        var kms = new FakeKms(Arn1) { Override = (_, _) => Task.FromResult<GenerateMacResponse>(null!) };
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());
        Assert.Equal("AWS KMS returned no MAC.", ex.Message);
        Assert.Null(ex.InnerException);
    }

    [Fact]
    public async Task Response_without_mac_reports_no_mac()
    {
        var kms = new FakeKms(Arn1) { Override = (_, _) => Task.FromResult(new GenerateMacResponse()) };
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());
        Assert.Equal("AWS KMS returned no MAC.", ex.Message);
    }

    [Fact]
    public async Task Different_algorithm_is_reported_and_mac_buffer_is_still_cleared_and_disposed()
    {
        var kms = new FakeKms(Arn1);
        GenerateMacResponse response = kms.Response(new byte[32] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }, MacAlgorithmSpec.HMAC_SHA_512);
        kms.Override = (_, _) => Task.FromResult(response);

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());

        Assert.Equal("AWS KMS answered with a different MAC algorithm than requested.", ex.Message);
        Assert.All(Assert.Single(kms.ReturnedBuffers), b => Assert.Equal(0, b));
        Assert.False(response.Mac.CanRead);
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public async Task Wrong_mac_length_is_reported(int length)
    {
        var kms = new FakeKms(Arn1);
        kms.Override = (_, _) => Task.FromResult(kms.Response(new byte[length], MacAlgorithmSpec.HMAC_SHA_256));
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());
        Assert.Equal("AWS KMS returned a MAC of unexpected length.", ex.Message);
    }

    [Fact]
    public async Task Mac_stream_is_disposed_after_success()
    {
        var kms = new FakeKms(Arn1);
        GenerateMacResponse? response = null;
        kms.Override = (_, _) =>
        {
            response = kms.Response(kms.Expected(Arn1, Input), MacAlgorithmSpec.HMAC_SHA_256);
            return Task.FromResult(response);
        };

        Assert.Equal(kms.Expected(Arn1, Input), await Pepper(kms).ApplyAsync("k1", Input));

        Assert.NotNull(response);
        Assert.False(response!.Mac.CanRead);
        Assert.Throws<ObjectDisposedException>(() => response.Mac.ReadByte());
    }

    [Fact]
    public async Task Mac_stream_reporting_a_buffer_without_array_is_not_cleared()
    {
        var kms = new FakeKms(Arn1);
        byte[] expected = kms.Expected(Arn1, Input);
        var stream = new ArraylessBufferStream((byte[])expected.Clone());
        kms.Override = (_, _) => Task.FromResult(new GenerateMacResponse { Mac = stream, MacAlgorithm = MacAlgorithmSpec.HMAC_SHA_256 });

        Assert.Equal(expected, await Pepper(kms).ApplyAsync("k1", Input));
        Assert.False(stream.CanRead);
    }

    [Fact]
    public async Task Mac_stream_without_exposable_buffer_is_returned_and_disposed()
    {
        var kms = new FakeKms(Arn1);
        byte[] expected = kms.Expected(Arn1, Input);
        var stream = new MemoryStream((byte[])expected.Clone());
        kms.Override = (_, _) => Task.FromResult(new GenerateMacResponse { Mac = stream, MacAlgorithm = MacAlgorithmSpec.HMAC_SHA_256 });

        Assert.Equal(expected, await Pepper(kms).ApplyAsync("k1", Input));
        Assert.False(stream.CanRead);
    }

    [Fact]
    public void Sync_apply_rejects_null_input_on_the_calling_thread_without_entering_ApplyAsync()
    {
        var kms = new FakeKms(Arn1);

        var ex = Assert.Throws<ArgumentNullException>(() => Pepper(kms).Apply("k1", null!));

        Assert.Equal("input", ex.ParamName);
        // Apply guards before hopping to the thread pool: the exception must not originate inside ApplyAsync.
        Assert.NotNull(ex.StackTrace);
        Assert.DoesNotContain("AwsKmsPepper.ApplyAsync", ex.StackTrace, StringComparison.Ordinal);
        Assert.Empty(kms.Calls);
    }

    /// <summary>A stream whose <see cref="MemoryStream.TryGetBuffer"/> claims success but hands back no array.</summary>
    private sealed class ArraylessBufferStream : MemoryStream
    {
        public ArraylessBufferStream(byte[] data) : base(data) { }

        public override bool TryGetBuffer(out ArraySegment<byte> buffer)
        {
            buffer = default;
            return true;
        }
    }
}
