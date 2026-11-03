using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Amazon.Runtime;
using Masterly.Hash.Pepper.AwsKms;

namespace Masterly.Hash.Pepper.AwsKms.Tests;

/// <summary>Edge paths not reached by the scenario tests.</summary>
public class CoverageGapTests
{
    private const string Arn1 = "arn:aws:kms:us-east-1:111122223333:key/0b1f2c3d-aaaa-bbbb-cccc-000000000001";
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");

    private static AwsKmsPepper Pepper(FakeKms kms) => new(kms.Client, FakeKms.Options("k1", ("k1", Arn1)));

    [Fact]
    public void Exception_constructors_set_message_and_inner_exception()
    {
        var plain = new PepperUnavailableException();
        Assert.Equal("The AWS KMS pepper is unavailable.", plain.Message);
        Assert.Null(plain.InnerException);

        Assert.Equal("custom", new PepperUnavailableException("custom").Message);

        var inner = new TimeoutException();
        var wrapped = new PepperUnavailableException("outer", inner);
        Assert.Equal("outer", wrapped.Message);
        Assert.Same(inner, wrapped.InnerException);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Service_error_without_a_code_is_reported_as_unknown_error(string? code)
    {
        var error = new AmazonServiceException("no code") { ErrorCode = code, StatusCode = HttpStatusCode.BadGateway };
        var kms = new FakeKms(Arn1) { Override = (_, _) => throw error };

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());

        Assert.Equal("AWS KMS GenerateMac failed (unknown error, HTTP 502).", ex.Message);
        Assert.Same(error, ex.InnerException);
    }

    [Fact]
    public async Task Long_service_error_code_is_truncated_to_64_characters()
    {
        string code = "Code." + new string('x', 100);
        var error = new AmazonServiceException("long code") { ErrorCode = code, StatusCode = HttpStatusCode.BadRequest };
        var kms = new FakeKms(Arn1) { Override = (_, _) => throw error };

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());

        Assert.Equal($"AWS KMS GenerateMac failed ({code.Substring(0, 64)}, HTTP 400).", ex.Message);
    }

    [Theory]
    [InlineData("Code_with-all.allowed_0-9")]
    [InlineData("ABCxyz")]
    public async Task Service_error_codes_with_allowed_characters_are_kept(string code)
    {
        var error = new AmazonServiceException("x") { ErrorCode = code, StatusCode = HttpStatusCode.Forbidden };
        var kms = new FakeKms(Arn1) { Override = (_, _) => throw error };

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Pepper(kms).ApplyAsync("k1", Input).AsTask());

        Assert.Equal($"AWS KMS GenerateMac failed ({code}, HTTP 403).", ex.Message);
    }
}
