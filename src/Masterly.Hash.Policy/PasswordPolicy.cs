using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy.Internal;

namespace Masterly.Hash.Policy
{
    /// <summary>
    /// Password quality checks aligned with NIST SP 800-63B rev. 4: length in code points after NFKC, a blocklist of
    /// common passwords, context words, repetitive and sequential patterns, a strength score and an optional
    /// breached-password lookup. Thread-safe; create one and reuse it.
    /// </summary>
    /// <example>
    /// <code>
    /// var policy = new PasswordPolicy();
    /// var result = await policy.EvaluateAsync(input, new PasswordContext { UserName = user.Name, Email = user.Email });
    /// if (!result.IsAcceptable)
    ///     return BadRequest(result.Violations.Select(v => v.Message));
    /// </code>
    /// </example>
    public sealed class PasswordPolicy : IPasswordPolicy
    {
        private readonly int _minLength;
        private readonly int _maxLength;
        private readonly bool _blockCommonPasswords;
        private readonly RankedDictionary? _blockedPasswords;
        private readonly int _minimumScore;
        private readonly bool _checkContextWords;
        private readonly string[] _contextWords;
        private readonly int _minContextWordLength;
        private readonly bool _rejectRepetitiveOrSequential;
        private readonly int _minimumBreachOccurrences;
        private readonly int? _referenceYear;
        private readonly IBreachedPasswordChecker? _breachedPasswordChecker;

        /// <summary>Creates a policy with the default options and no breach lookup.</summary>
        public PasswordPolicy()
            : this(new PasswordPolicyOptions(), null)
        {
        }

        /// <summary>Creates a policy with no breach lookup. The options are copied; later changes have no effect.</summary>
        public PasswordPolicy(PasswordPolicyOptions options)
            : this(options, null)
        {
        }

        /// <summary>
        /// Creates a policy. <paramref name="breachedPasswordChecker"/> is consulted by the <c>EvaluateAsync</c>
        /// overloads only. The options are copied; later changes have no effect.
        /// </summary>
        public PasswordPolicy(PasswordPolicyOptions options, IBreachedPasswordChecker? breachedPasswordChecker)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (options.MaxLength < PasswordPolicyOptions.MinimumAllowedMaxLength || options.MaxLength > PasswordPolicyOptions.MaximumAllowedMaxLength)
                throw new ArgumentOutOfRangeException(nameof(options), options.MaxLength,
                    "MaxLength must be between 64 and 4096 (NIST SP 800-63B: permit at least 64 characters).");
            if (options.MinLength < PasswordPolicyOptions.MinimumAllowedMinLength || options.MinLength > options.MaxLength)
                throw new ArgumentOutOfRangeException(nameof(options), options.MinLength,
                    "MinLength must be at least 8 (NIST SP 800-63B) and at most MaxLength.");
            if (options.MinimumScore < 0 || options.MinimumScore > 4)
                throw new ArgumentOutOfRangeException(nameof(options), options.MinimumScore, "MinimumScore must be between 0 and 4.");
            if (options.MinContextWordLength < 1 || options.MinContextWordLength > 64)
                throw new ArgumentOutOfRangeException(nameof(options), options.MinContextWordLength, "MinContextWordLength must be between 1 and 64.");
            if (options.MinimumBreachOccurrences < 1)
                throw new ArgumentOutOfRangeException(nameof(options), options.MinimumBreachOccurrences, "MinimumBreachOccurrences must be at least 1.");
            if (options.ReferenceYear is int year && (year < 1000 || year > 9999))
                throw new ArgumentOutOfRangeException(nameof(options), year, "ReferenceYear must have four digits.");

            _minLength = options.MinLength;
            _maxLength = options.MaxLength;
            _blockCommonPasswords = options.BlockCommonPasswords;
            _minimumScore = options.MinimumScore;
            _checkContextWords = options.CheckContextWords;
            _minContextWordLength = options.MinContextWordLength;
            _rejectRepetitiveOrSequential = options.RejectRepetitiveOrSequential;
            _minimumBreachOccurrences = options.MinimumBreachOccurrences;
            _referenceYear = options.ReferenceYear;
            _breachedPasswordChecker = breachedPasswordChecker;

            var blocked = new List<string>();
            foreach (string? entry in options.BlockedPasswords)
            {
                if (!string.IsNullOrEmpty(entry))
                    blocked.Add(TextUtil.Truncate(entry!, _maxLength * 2));
            }
            _blockedPasswords = blocked.Count == 0 ? null : new RankedDictionary(DictionaryKind.CommonPasswords, blocked);

            var contextWords = new List<string>();
            foreach (string? word in options.ContextWords)
                AddWords(contextWords, word, splitDomain: false);
            _contextWords = contextWords.ToArray();
        }

        /// <summary>A policy with the default options (minimum 15 code points, score 3, blocklist on), no breach lookup.</summary>
        public static PasswordPolicy Default { get; } = new PasswordPolicy();

        /// <inheritdoc />
        public PasswordPolicyResult Evaluate(string password, PasswordContext? context = null)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return EvaluateLocal(password, context).ToResult(null);
        }

        /// <inheritdoc />
        public PasswordPolicyResult Evaluate(SensitiveString password, PasswordContext? context = null)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return Evaluate(password.Reveal(), context);
        }

        /// <inheritdoc />
        public ValueTask<PasswordPolicyResult> EvaluateAsync(SensitiveString password, PasswordContext? context = null, CancellationToken cancellationToken = default)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return EvaluateAsync(password.Reveal(), context, cancellationToken);
        }

        /// <inheritdoc />
        public ValueTask<PasswordPolicyResult> EvaluateAsync(string password, PasswordContext? context = null, CancellationToken cancellationToken = default)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            cancellationToken.ThrowIfCancellationRequested();

            Evaluation evaluation = EvaluateLocal(password, context);
            if (_breachedPasswordChecker == null || evaluation.LengthRejected)
                return new ValueTask<PasswordPolicyResult>(evaluation.ToResult(null));
            return CheckBreachAsync(evaluation, _breachedPasswordChecker, cancellationToken);
        }

        private async ValueTask<PasswordPolicyResult> CheckBreachAsync(Evaluation evaluation, IBreachedPasswordChecker checker, CancellationToken cancellationToken)
        {
            BreachCheckResult breach;
            try
            {
                breach = await checker.CheckAsync(evaluation.Normalized, cancellationToken).ConfigureAwait(false) ?? BreachCheckResult.Unavailable;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // An outage of the breach corpus must not block sign-ups; it is reported in BreachCheck instead.
                // The exception is not surfaced: it may have been built from the request, which contains the password.
                breach = BreachCheckResult.Unavailable;
            }

            if (breach.Status == BreachCheckStatus.Ok && breach.IsBreached && breach.Occurrences >= _minimumBreachOccurrences)
            {
                evaluation.Add(PasswordViolationCode.Breached,
                    "This password has appeared in a data breach and must not be used.",
                    "Choose a password you have not used anywhere else.");
            }
            return evaluation.ToResult(breach);
        }

        private Evaluation EvaluateLocal(string password, PasswordContext? context)
        {
            // Bound the work done on attacker-sized input: NFKC never shrinks text by more than a few units per code
            // point, so anything this long is too long whatever it normalizes to.
            int hardCap = _maxLength * 4;
            bool oversized = password.Length > hardCap;
            string normalized = TextUtil.Normalize(oversized ? TextUtil.Truncate(password, hardCap) : password);
            int length = oversized ? TextUtil.CountCodePoints(password) : TextUtil.CountCodePoints(normalized);
            string lower = normalized.ToLowerInvariant();

            var evaluation = new Evaluation(normalized, length);

            if (length < _minLength)
            {
                evaluation.LengthRejected = true;
                evaluation.Add(PasswordViolationCode.TooShort,
                    string.Format(CultureInfo.InvariantCulture, "The password must be at least {0} characters long.", _minLength),
                    string.Format(CultureInfo.InvariantCulture, "Use at least {0} characters. A few unrelated words make a long password that is easy to remember.", _minLength));
            }
            else if (length > _maxLength)
            {
                evaluation.LengthRejected = true;
                evaluation.Add(PasswordViolationCode.TooLong,
                    string.Format(CultureInfo.InvariantCulture, "The password must be at most {0} characters long.", _maxLength),
                    string.Format(CultureInfo.InvariantCulture, "Use at most {0} characters.", _maxLength));
            }

            if (IsBlocked(lower))
            {
                evaluation.Add(PasswordViolationCode.CommonPassword,
                    "This is one of the most commonly used passwords.",
                    "Avoid common passwords and simple variations of them.");
            }

            var words = new List<string>(_contextWords);
            CollectContextWords(context, words);

            if (_checkContextWords && ContainsContextWord(lower, words))
            {
                evaluation.Add(PasswordViolationCode.ContainsContextWord,
                    "The password contains your user name, email address, name or the name of this service.",
                    "Avoid your name, user name, email address and the name of this service.");
            }

            // Skipped for a password already rejected as too long, which bounds the work; it covers the whole password otherwise.
            if (_rejectRepetitiveOrSequential && length <= _maxLength && RepetitionCheck.IsRepetitiveOrSequential(normalized))
            {
                evaluation.Add(PasswordViolationCode.RepetitiveOrSequential,
                    "The password consists only of repeated characters, sequences or keyboard patterns.",
                    "Avoid repeated characters, sequences like \"abc\" or \"1234\", and keyboard patterns like \"qwerty\".");
            }

            StrengthEstimate estimate = PasswordStrengthEstimator.Estimate(normalized, words, _referenceYear ?? DateTime.UtcNow.Year);
            evaluation.Estimate = estimate;
            if (estimate.Score < _minimumScore)
            {
                string message = estimate.Warning.Length > 0
                    ? "The password is too easy to guess. " + estimate.Warning
                    : "The password is too easy to guess.";
                evaluation.Add(PasswordViolationCode.TooWeak, message, null);
            }
            foreach (string suggestion in estimate.Suggestions)
                evaluation.AddSuggestion(suggestion);

            return evaluation;
        }

        private bool IsBlocked(string lower)
        {
            if (lower.Length == 0)
                return false;
            if (_blockCommonPasswords)
            {
                RankedDictionary common = EmbeddedDictionaries.CommonPasswords;
                if (lower.Length <= common.MaxWordLength && common.ContainsWithSubstitutions(lower))
                    return true;
            }
            return _blockedPasswords != null && lower.Length <= _blockedPasswords.MaxWordLength && _blockedPasswords.ContainsWithSubstitutions(lower);
        }

        private bool ContainsContextWord(string lower, List<string> words)
        {
            foreach (string word in words)
            {
                if (TextUtil.CountCodePoints(word) < _minContextWordLength)
                    continue;
                // l33t is ignored on both sides: "j0hnd03" blocks "johndoe", and "johndoe" blocks "j0hnd03".
                if (L33t.ContainsEquivalent(lower, word) || L33t.ContainsEquivalent(lower, TextUtil.Reverse(word)))
                    return true;
            }
            return false;
        }

        private static void CollectContextWords(PasswordContext? context, List<string> words)
        {
            if (context == null)
                return;
            AddWords(words, context.UserName, splitDomain: false);
            AddWords(words, context.DisplayName, splitDomain: false);
            AddWords(words, context.ApplicationName, splitDomain: false);
            foreach (string? word in context.AdditionalWords)
                AddWords(words, word, splitDomain: false);

            string? email = context.Email;
            if (!string.IsNullOrWhiteSpace(email))
            {
                int at = email!.LastIndexOf('@');
                if (at < 0)
                {
                    AddWords(words, email, splitDomain: false);
                }
                else
                {
                    AddWords(words, email.Substring(0, at), splitDomain: false);
                    AddWords(words, email.Substring(at + 1), splitDomain: true);
                }
            }
        }

        /// <summary>Adds the whole value and each of its parts (split on anything that is not a letter, digit or mark), lower-cased.</summary>
        private static void AddWords(List<string> words, string? value, bool splitDomain)
        {
            if (string.IsNullOrWhiteSpace(value))
                return;
            // Context values come from the caller, but bound them anyway.
            string normalized = TextUtil.Normalize(TextUtil.Truncate(value!.Trim(), 256)).ToLowerInvariant();

            var parts = new List<string>();
            int start = -1;
            for (int k = 0; k <= normalized.Length; k++)
            {
                bool wordChar = k < normalized.Length && IsWordChar(normalized[k]);
                if (wordChar && start < 0)
                {
                    start = k;
                }
                else if (!wordChar && start >= 0)
                {
                    parts.Add(normalized.Substring(start, k - start));
                    start = -1;
                }
            }

            if (splitDomain)
            {
                // "mail.example.com": check "mail" and "example", not the top-level domain.
                if (parts.Count > 1)
                    parts.RemoveAt(parts.Count - 1);
            }
            else
            {
                Add(words, normalized);
                Add(words, Compact(parts));
            }
            foreach (string part in parts)
                Add(words, part);
        }

        private static string Compact(List<string> parts) => parts.Count > 1 ? string.Concat(parts) : string.Empty;

        private static void Add(List<string> words, string word)
        {
            if (word.Length > 0 && !words.Contains(word))
                words.Add(word);
        }

        private static bool IsWordChar(char c)
        {
            if (char.IsLetterOrDigit(c) || char.IsSurrogate(c))
                return true;
            UnicodeCategory category = CharUnicodeInfo.GetUnicodeCategory(c);
            return category == UnicodeCategory.NonSpacingMark || category == UnicodeCategory.SpacingCombiningMark;
        }

        /// <summary>Accumulates violations and suggestions while a password is checked.</summary>
        private sealed class Evaluation
        {
            private readonly List<PasswordViolation> _violations = new List<PasswordViolation>();
            private readonly List<string> _suggestions = new List<string>();

            public Evaluation(string normalized, int length)
            {
                Normalized = normalized;
                Length = length;
            }

            public string Normalized { get; }

            public int Length { get; }

            public bool LengthRejected { get; set; }

            public StrengthEstimate? Estimate { get; set; }

            public void Add(PasswordViolationCode code, string message, string? suggestion)
            {
                _violations.Add(new PasswordViolation(code, message));
                if (suggestion != null)
                    AddSuggestion(suggestion);
            }

            public void AddSuggestion(string suggestion)
            {
                if (!_suggestions.Contains(suggestion))
                    _suggestions.Add(suggestion);
            }

            public PasswordPolicyResult ToResult(BreachCheckResult? breach)
            {
                // Breached is found last but reported in enum order, like the others.
                var violations = new List<PasswordViolation>(_violations);
                violations.Sort((a, b) => a.Code.CompareTo(b.Code));
                return new PasswordPolicyResult(Length, violations.AsReadOnly(), Array.AsReadOnly(_suggestions.ToArray()), Estimate!, breach);
            }
        }
    }
}
