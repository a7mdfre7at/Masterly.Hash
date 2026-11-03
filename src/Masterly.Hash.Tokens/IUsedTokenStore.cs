using System;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// Records the nonces of tokens that have been used, so a signed token can be redeemed only once.
    /// </summary>
    /// <remarks>
    /// Signed tokens are stateless: without a store, a token stays valid until it expires, however many times it
    /// is presented. <see cref="TryMarkUsedAsync"/> must be atomic across every server that validates tokens:
    /// e.g. Redis <c>SET nonce 1 NX PXAT retainUntil</c>, or an <c>INSERT</c> into a table with a unique key
    /// on the nonce. <see cref="InMemoryUsedTokenStore"/> is suitable only for a single process.
    /// </remarks>
    public interface IUsedTokenStore
    {
        /// <summary>
        /// Atomically records <paramref name="nonce"/>. Returns true if it was not recorded before (the token may be
        /// used), false if it was. The record may be deleted after <paramref name="retainUntil"/>. Use it as given
        /// (e.g. Redis <c>PXAT retainUntil</c>): <see cref="SignedTokenService.ConsumeAsync"/> already sets it to the
        /// token's expiry plus twice the clock skew plus a margin, so that servers whose clocks disagree by up to the
        /// tolerated skew have all stopped accepting the token. Never delete the record earlier.
        /// </summary>
        ValueTask<bool> TryMarkUsedAsync(string nonce, DateTimeOffset retainUntil, CancellationToken cancellationToken = default);
    }
}
