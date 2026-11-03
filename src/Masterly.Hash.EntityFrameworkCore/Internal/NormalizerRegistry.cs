using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using Masterly.Hash.BlindIndex;
using Masterly.Hash.BlindIndex.Normalizers;

namespace Masterly.Hash.EntityFrameworkCore.Internal
{
    /// <summary>
    /// Maps normalizers to the string ids stored in model annotations. Annotations must hold scaffoldable values
    /// (strings, numbers) or <c>dotnet ef migrations add</c> fails, so the normalizer instance itself is never stored
    /// in the model.
    /// </summary>
    /// <remarks>
    /// The normalizers shipped with Masterly.Hash.BlindIndex get ids that encode their configuration, so they resolve
    /// the same way in every process (web app, worker, design-time tools) without any registration. Other types are
    /// identified by their full name and resolved from a process-wide registry filled by <c>HasBlindIndex</c>.
    /// </remarks>
    internal static class NormalizerRegistry
    {
        private const string ExactId = "exact";
        private const string TrimId = "trim";
        private const string CaseInsensitiveId = "case-insensitive";
        private const string EmailId = "email";
        private const string PhoneId = "phone";
        private const string StripPlusTagsFlag = "strip-plus-tags";
        private const string StripGmailDotsFlag = "strip-gmail-dots";
        private const string CountryCodePrefix = "phone:cc=";

        private static readonly Dictionary<string, IBlindIndexNormalizer> BuiltInById = new Dictionary<string, IBlindIndexNormalizer>(StringComparer.Ordinal)
        {
            [ExactId] = BlindIndexNormalizers.Exact,
            [TrimId] = BlindIndexNormalizers.Trim,
            [CaseInsensitiveId] = BlindIndexNormalizers.CaseInsensitive,
            [EmailId] = BlindIndexNormalizers.Email,
            [PhoneId] = BlindIndexNormalizers.Phone,
        };

        // Custom normalizers passed to HasBlindIndex. OnModelCreating runs before the first SaveChanges of every
        // process, so the entry is always present at runtime; design-time tooling only sees the id.
        private static readonly ConcurrentDictionary<string, IBlindIndexNormalizer> Custom = new ConcurrentDictionary<string, IBlindIndexNormalizer>(StringComparer.Ordinal);

        // Custom normalizers per model being built, to reject two differently configured instances of one type in the
        // same model: they would share one id, so one of the indexes would silently use the other's normalizer.
        private static readonly ConditionalWeakTable<object, Dictionary<string, IBlindIndexNormalizer>> ByModel = new ConditionalWeakTable<object, Dictionary<string, IBlindIndexNormalizer>>();

        /// <summary>Returns the id to store for <paramref name="normalizer"/>, registering custom types.</summary>
        /// <param name="normalizer">The normalizer passed to <c>HasBlindIndex</c>.</param>
        /// <param name="model">The model being built, used to detect conflicting instances within it.</param>
        /// <exception cref="ArgumentException">The model already uses a differently configured instance of the same custom type.</exception>
        public static string Register(IBlindIndexNormalizer normalizer, object model)
        {
            switch (normalizer)
            {
                case ExactNormalizer:
                    return ExactId;
                case TrimNormalizer:
                    return TrimId;
                case CaseInsensitiveNormalizer:
                    return CaseInsensitiveId;
                case EmailNormalizer email:
                    return FormatEmailId(email.StripPlusTags, email.StripGmailDots);
                case PhoneNormalizer phone:
                    return phone.DefaultCountryCode == null ? PhoneId : CountryCodePrefix + phone.DefaultCountryCode;
            }

            Type type = normalizer.GetType();
            string id = type.FullName ?? type.Name;
            Dictionary<string, IBlindIndexNormalizer> inModel = ByModel.GetOrCreateValue(model);
            lock (inModel)
            {
                if (inModel.TryGetValue(id, out IBlindIndexNormalizer? existing) && !AreInterchangeable(existing, normalizer))
                    throw new ArgumentException(
                        $"This model already uses another instance of normalizer type '{id}'. Custom normalizers are identified by type, so two "
                        + "differently configured instances would share one id. Reuse one instance, use a separate type per configuration, "
                        + "or override Equals so that equally configured instances compare equal.",
                        nameof(normalizer));
                inModel[id] = normalizer;
            }
            Custom[id] = normalizer;
            return id;
        }

        public static bool TryResolve(string id, IReadOnlyDictionary<string, IBlindIndexNormalizer> overrides, out IBlindIndexNormalizer normalizer)
        {
            if (overrides.TryGetValue(id, out IBlindIndexNormalizer? fromOptions) && fromOptions != null)
            {
                normalizer = fromOptions;
                return true;
            }
            if (BuiltInById.TryGetValue(id, out IBlindIndexNormalizer? builtIn))
            {
                normalizer = builtIn;
                return true;
            }
            if (TryParseConfigured(id, out IBlindIndexNormalizer? configured))
            {
                normalizer = configured;
                return true;
            }
            if (Custom.TryGetValue(id, out IBlindIndexNormalizer? custom))
            {
                normalizer = custom;
                return true;
            }
            normalizer = BlindIndexNormalizers.Exact;
            return false;
        }

        private static string FormatEmailId(bool stripPlusTags, bool stripGmailDots)
        {
            if (!stripPlusTags && !stripGmailDots)
                return EmailId;
            if (stripPlusTags && stripGmailDots)
                return EmailId + ":" + StripPlusTagsFlag + "," + StripGmailDotsFlag;
            return EmailId + ":" + (stripPlusTags ? StripPlusTagsFlag : StripGmailDotsFlag);
        }

        private static bool TryParseConfigured(string id, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out IBlindIndexNormalizer? normalizer)
        {
            normalizer = null;
            if (id.StartsWith(EmailId + ":", StringComparison.Ordinal))
            {
                bool plus = false, dots = false;
                foreach (string flag in id.Substring(EmailId.Length + 1).Split(','))
                {
                    if (string.Equals(flag, StripPlusTagsFlag, StringComparison.Ordinal) && !plus)
                        plus = true;
                    else if (string.Equals(flag, StripGmailDotsFlag, StringComparison.Ordinal) && !dots)
                        dots = true;
                    else
                        return false;
                }
                // Only the canonical spelling resolves, so one configuration never has two ids.
                if (!string.Equals(FormatEmailId(plus, dots), id, StringComparison.Ordinal))
                    return false;
                normalizer = new EmailNormalizer(plus, dots);
                return true;
            }

            if (id.StartsWith(CountryCodePrefix, StringComparison.Ordinal))
            {
                string code = id.Substring(CountryCodePrefix.Length);
                if (code.Length < 1 || code.Length > 3 || code[0] == '0')
                    return false;
                foreach (char c in code)
                {
                    if (c < '0' || c > '9')
                        return false;
                }
                normalizer = new PhoneNormalizer(code);
                return true;
            }
            return false;
        }

        // Instances of a type without instance fields cannot differ in configuration.
        private static bool AreInterchangeable(IBlindIndexNormalizer a, IBlindIndexNormalizer b)
        {
            if (ReferenceEquals(a, b) || a.Equals(b))
                return true;
            Type type = a.GetType();
            if (type != b.GetType())
                return false;
            for (Type? t = type; t != null && t != typeof(object); t = t.BaseType)
            {
                if (t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly).Length > 0)
                    return false;
            }
            return true;
        }
    }
}
