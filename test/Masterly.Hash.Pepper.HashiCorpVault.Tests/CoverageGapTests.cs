using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.HashiCorpVault;

namespace Masterly.Hash.Pepper.HashiCorpVault.Tests;

/// <summary>Edge paths not reached by the scenario tests.</summary>
public class CoverageGapTests
{
    private const string UnexpectedMessage = "HashiCorp Vault returned an unexpected Transit HMAC response.";
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");
    private static readonly string GoodHmac = "vault:v1:" + Convert.ToBase64String(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());

    [Fact]
    public void Exception_constructors_set_message_and_inner_exception()
    {
        var plain = new PepperUnavailableException();
        Assert.Equal("The HashiCorp Vault pepper is unavailable.", plain.Message);
        Assert.Null(plain.InnerException);

        Assert.Equal("custom", new PepperUnavailableException("custom").Message);

        var inner = new TimeoutException();
        var wrapped = new PepperUnavailableException("outer", inner);
        Assert.Equal("outer", wrapped.Message);
        Assert.Same(inner, wrapped.InnerException);
    }

    [Theory]
    [InlineData("{\"data\"")]                                   // ends after a root property name
    [InlineData("{\"data\":{\"hmac\"")]                         // ends after a data property name
    [InlineData("{\"data\":{\"hmac\":\"vault:v1:AAAA\"")]       // data object never closed
    [InlineData("{\"data\":{}")]                                // root object never closed
    [InlineData("{\"data\":{}} {}")]                           // a second document after the root
    [InlineData("{\"data\":{}}/* comment */")]                  // trailing comment
    [InlineData("{} x")]                                        // trailing garbage
    [InlineData("[]")]                                          // root is not an object
    [InlineData("")]                                            // empty body
    public void ParseHmac_RejectsTruncatedOrTrailingJson(string json)
    {
        var ex = Assert.Throws<PepperUnavailableException>(() => HashiCorpVaultPepper.ParseHmac(Encoding.UTF8.GetBytes(json), 1));
        Assert.Equal(UnexpectedMessage, ex.Message);
    }

    [Fact]
    public void ParseHmac_AcceptsTrailingWhitespace()
    {
        string json = "{\"data\":{\"hmac\":\"" + GoodHmac + "\"}}\r\n  ";
        Assert.Equal(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(), HashiCorpVaultPepper.ParseHmac(Encoding.UTF8.GetBytes(json), 1));
    }

    [Fact]
    public async Task MountPathAndKeyName_AcceptEveryAllowedCharacterClass()
    {
        var handler = new FakeTransitHandler(1);
        var pepper = Vault.Pepper(handler, 1, o =>
        {
            o.MountPath = "Team.A_9-z/transit";
            o.KeyName = "Pepper.key_2-Z";
        });

        Assert.Equal("https://vault.test:8200/v1/Team.A_9-z/transit/hmac/Pepper.key_2-Z/sha2-256", pepper.Endpoint.AbsoluteUri);
        Assert.Equal(handler.Expected(1, Input), await pepper.ApplyAsync("v1", Input));
    }

    // MaxResponseBytes is an inclusive limit, both for a declared Content-Length and for the body actually read.
    [Fact]
    public async Task ResponseOfExactlyMaxResponseBytes_IsAccepted()
    {
        string prefix = "{\"data\":{\"hmac\":\"" + GoodHmac + "\"},\"pad\":\"";
        string suffix = "\"}";
        string json = prefix + new string('a', HashiCorpVaultPepper.MaxResponseBytes - prefix.Length - suffix.Length) + suffix;
        Assert.Equal(HashiCorpVaultPepper.MaxResponseBytes, Encoding.UTF8.GetByteCount(json));
        var handler = new FakeTransitHandler(1) { Override = (_, _) => Task.FromResult(FakeTransitHandler.Json(HttpStatusCode.OK, json)) };

        byte[] mac = await Vault.Pepper(handler).ApplyAsync("v1", Input);

        Assert.Equal(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(), mac);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    public async Task ResponseWithoutContentLength_LimitIsInclusive(int overLimit, bool accepted)
    {
        string prefix = "{\"data\":{\"hmac\":\"" + GoodHmac + "\"},\"pad\":\"";
        string suffix = "\"}";
        string json = prefix + new string('a', HashiCorpVaultPepper.MaxResponseBytes + overLimit - prefix.Length - suffix.Length) + suffix;
        Assert.Equal(HashiCorpVaultPepper.MaxResponseBytes + overLimit, Encoding.UTF8.GetByteCount(json));
        var handler = new FakeTransitHandler(1)
        {
            Override = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new UnknownLengthStream(Encoding.UTF8.GetBytes(json))),
            }),
        };

        if (accepted)
        {
            Assert.Equal(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(), await Vault.Pepper(handler).ApplyAsync("v1", Input));
        }
        else
        {
            var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Vault.Pepper(handler).ApplyAsync("v1", Input).AsTask());
            Assert.Equal("HashiCorp Vault returned an oversized response.", ex.Message);
        }
    }

    [Fact]
    public async Task ResponseOneByteUnderMaxResponseBytes_IsAccepted()
    {
        string prefix = "{\"data\":{\"hmac\":\"" + GoodHmac + "\"},\"pad\":\"";
        string suffix = "\"}";
        string json = prefix + new string('a', HashiCorpVaultPepper.MaxResponseBytes - 1 - prefix.Length - suffix.Length) + suffix;
        var handler = new FakeTransitHandler(1) { Override = (_, _) => Task.FromResult(FakeTransitHandler.Json(HttpStatusCode.OK, json)) };

        byte[] mac = await Vault.Pepper(handler).ApplyAsync("v1", Input);

        Assert.Equal(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(), mac);
    }

    [Fact]
    public async Task ResponseWithoutContentLength_LargerThanTheInitialBuffer_Parses()
    {
        string json = "{\"data\":{\"hmac\":\"" + GoodHmac + "\"},\"pad\":\"" + new string('a', 5000) + "\"}";
        var handler = new FakeTransitHandler(1)
        {
            Override = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new UnknownLengthStream(Encoding.UTF8.GetBytes(json))),
            }),
        };

        byte[] mac = await Vault.Pepper(handler).ApplyAsync("v1", Input);

        Assert.Equal(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(), mac);
    }

    /// <summary>A readable stream that cannot report its length, so HttpContent declares no Content-Length.</summary>
    private sealed class UnknownLengthStream : System.IO.MemoryStream
    {
        public UnknownLengthStream(byte[] data) : base(data) { }

        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
    }
}
