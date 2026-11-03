using System;

namespace Masterly.Hash.Tokens
{
    /// <summary>Options for <see cref="SignedTokenService"/>. They are copied when the service is created.</summary>
    public sealed class SignedTokenOptions
    {
        /// <summary>Largest allowed <see cref="ClockSkew"/>.</summary>
        public static readonly TimeSpan MaxClockSkew = TimeSpan.FromHours(1);

        /// <summary>
        /// Source of the current time. Defaults to <see cref="DateTimeOffset.UtcNow"/>; replace it in tests
        /// (on .NET 8+ you can pass <c>() =&gt; timeProvider.GetUtcNow()</c>).
        /// </summary>
        public Func<DateTimeOffset> Clock { get; set; } = () => DateTimeOffset.UtcNow;

        /// <summary>
        /// Tolerance for clock differences between the servers that create and validate tokens: a token is still
        /// accepted up to this long after its expiry, and may be issued up to this far in the future.
        /// Default 30 seconds; at most <see cref="MaxClockSkew"/>.
        /// </summary>
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Tokens longer than this many characters are rejected as <see cref="SignedTokenStatus.Malformed"/> before
        /// decoding, and <see cref="SignedTokenService.Create"/> refuses to produce one. Default 1024 (fits in a URL);
        /// 256 to 16384.
        /// </summary>
        public int MaxTokenLength { get; set; } = 1024;

        /// <summary>Maximum subject size in UTF-8 bytes. Default 512; 1 to 4096.</summary>
        public int MaxSubjectBytes { get; set; } = 512;

        /// <summary>Longest lifetime <see cref="SignedTokenService.Create"/> accepts. Default 30 days.</summary>
        public TimeSpan MaxLifetime { get; set; } = TimeSpan.FromDays(30);
    }
}
