using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Masterly.Hash.Pwned.Internal;

namespace Masterly.Hash.Pwned.Tests;

/// <summary>Tests for mutants that survived the earlier mutation pass.</summary>
public class SurvivingMutantTests
{
    private const string PasswordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    // ---- RangeResponse.TryParse: a bad count must fail the parse itself, not just leave the response null ----

    [Theory]
    [InlineData(PasswordSuffix + ":")]                       // empty count
    [InlineData(PasswordSuffix + ":12x")]                    // non-digit
    [InlineData(PasswordSuffix + ":-1")]                     // sign
    [InlineData(PasswordSuffix + ":1234567890123456789")]    // 19 digits: one over the limit
    [InlineData(PasswordSuffix + ":5\r\n" + PasswordSuffix + ":/")] // bad count on a later line
    public void Bad_count_makes_TryParse_return_false_with_no_response(string text)
    {
        byte[] body = Encoding.ASCII.GetBytes(text);
        Assert.False(RangeResponse.TryParse(body, body.Length, out RangeResponse? range));
        Assert.Null(range);
    }

    [Fact]
    public void Count_of_exactly_18_digits_is_accepted()
    {
        byte[] body = Encoding.ASCII.GetBytes(PasswordSuffix + ":123456789012345678");
        Assert.True(RangeResponse.TryParse(body, body.Length, out RangeResponse? range));
        Assert.Equal(123456789012345678L, range!.Lookup(PwnedHashTests.Pack(PasswordSuffix)));
    }

    // ---- ReadLimitedAsync: the buffer doubles from 16 KiB, it does not jump straight to the limit ----

    [Fact]
    public async Task Read_buffer_grows_by_doubling_from_16_KiB()
    {
        // 40,000 bytes needs 16 KiB -> 32 KiB -> 64 KiB. Jumping to the 1 MiB + 1 cap on the first resize
        // would allocate a megabyte for every small range.
        byte[] body = WellFormedBody(40_000);
        var stream = new BufferRecordingStream(body);
        var api = new FakeRangeApi((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new DirectContent(stream) }));
        var client = new PwnedPasswordsClient(api.CreateClient(), new PwnedPasswordsOptions { FailureMode = PwnedPasswordsFailureMode.Throw });

        BreachCheckResult result = await client.CheckAsync("password");

        Assert.Equal(12, result.Occurrences);
        // Exact read sequence: each read fills the buffer, the third reads the 7,232-byte tail, the fourth sees end of body.
        Assert.Equal(new[] { 16 * 1024, 32 * 1024, 64 * 1024, 64 * 1024 }, stream.BufferLengths.ToArray());
    }

    [Fact]
    public async Task Read_buffer_reaches_the_cap_through_every_doubling_step()
    {
        byte[] body = WellFormedBody(PwnedPasswordsClient.MaxResponseBytes);
        var stream = new BufferRecordingStream(body);
        var api = new FakeRangeApi((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new DirectContent(stream) }));
        var client = new PwnedPasswordsClient(api.CreateClient(), new PwnedPasswordsOptions { FailureMode = PwnedPasswordsFailureMode.Throw });

        BreachCheckResult result = await client.CheckAsync("password");

        Assert.Equal(12, result.Occurrences);
        Assert.Equal(
            new[] { 16 * 1024, 32 * 1024, 64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024, 1024 * 1024 + 1 },
            stream.BufferLengths.ToArray());
    }

    private static byte[] WellFormedBody(int length)
    {
        const string padding = "0000000000000000000000000000000000A:0\r\n";
        string tail = PasswordSuffix + ":12";
        int lines = (length - tail.Length) / padding.Length;
        int blanks = length - tail.Length - lines * padding.Length;
        byte[] body = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(padding, lines)) + new string('\n', blanks) + tail);
        Assert.Equal(length, body.Length);
        return body;
    }

    /// <summary>Content that hands out the given stream as is (no wrapper, no buffering, no length).</summary>
    private sealed class DirectContent : HttpContent
    {
        private readonly Stream _stream;

        public DirectContent(Stream stream) => _stream = stream;

        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult(_stream);

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => _stream.CopyToAsync(stream);

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    /// <summary>Serves its data synchronously and records the length of the array behind every read.</summary>
    private sealed class BufferRecordingStream : Stream
    {
        private readonly byte[] _data;
        private int _position;

        public BufferRecordingStream(byte[] data) => _data = data;

        public List<int> BufferLengths { get; } = new();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            BufferLengths.Add(buffer.Length);
            int n = Math.Min(count, _data.Length - _position);
            Buffer.BlockCopy(_data, _position, buffer, offset, n);
            _position += n;
            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            Task.FromResult(Read(buffer, offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Assert.True(MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out ArraySegment<byte> segment));
            return new ValueTask<int>(Read(segment.Array!, segment.Offset, segment.Count));
        }
    }
}
