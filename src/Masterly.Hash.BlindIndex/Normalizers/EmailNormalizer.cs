using System;

namespace Masterly.Hash.BlindIndex.Normalizers
{
    /// <summary>
    /// Normalizes an email address: NFKC, trims, lower-cases (invariant) and drops a trailing dot from the domain.
    /// Provider-specific rewriting is opt-in because it merges addresses that some providers treat as distinct.
    /// </summary>
    public sealed class EmailNormalizer : IBlindIndexNormalizer
    {
        /// <summary>Creates an email normalizer.</summary>
        /// <param name="stripPlusTags">
        /// Remove a <c>+tag</c> sub-address from the local part, for every domain (<c>a+news@x.com</c> becomes
        /// <c>a@x.com</c>). Off by default.
        /// </param>
        /// <param name="stripGmailDots">
        /// For <c>gmail.com</c> and <c>googlemail.com</c> only: remove dots from the local part and map
        /// <c>googlemail.com</c> to <c>gmail.com</c>. Off by default.
        /// </param>
        public EmailNormalizer(bool stripPlusTags = false, bool stripGmailDots = false)
        {
            StripPlusTags = stripPlusTags;
            StripGmailDots = stripGmailDots;
        }

        /// <summary>Whether <c>+tag</c> sub-addresses are removed.</summary>
        public bool StripPlusTags { get; }

        /// <summary>Whether Gmail dots are removed and <c>googlemail.com</c> is mapped to <c>gmail.com</c>.</summary>
        public bool StripGmailDots { get; }

        /// <inheritdoc />
        /// <exception cref="ArgumentException">The value has no <c>@</c>, or an empty local part or domain.</exception>
        public string Normalize(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            string email = UnicodeText.Nfkc(value, nameof(value)).Trim().ToLowerInvariant();

            // The last '@' separates the domain; a quoted local part may itself contain '@'.
            int at = email.LastIndexOf('@');
            if (at <= 0 || at == email.Length - 1)
                throw new ArgumentException("Value is not an email address.", nameof(value));

            string local = email.Substring(0, at);
            string domain = email.Substring(at + 1);
            if (domain.EndsWith(".", StringComparison.Ordinal))
                domain = domain.Substring(0, domain.Length - 1);
            if (domain.Length == 0)
                throw new ArgumentException("Value is not an email address.", nameof(value));

            if (StripPlusTags)
            {
                int plus = local.IndexOf('+');
                if (plus > 0)
                    local = local.Substring(0, plus);
            }

            if (StripGmailDots && (domain == "gmail.com" || domain == "googlemail.com"))
            {
                domain = "gmail.com";
                local = local.Replace(".", string.Empty);
                if (local.Length == 0)
                    throw new ArgumentException("Value is not an email address.", nameof(value));
            }

            return local + "@" + domain;
        }
    }
}
