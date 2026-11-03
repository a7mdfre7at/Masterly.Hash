using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;

namespace Masterly.Hash.Policy.Internal
{
    /// <summary>Lower-case words mapped to their 1-based frequency rank.</summary>
    internal sealed class RankedDictionary
    {
        private readonly Dictionary<string, int> _ranks;
        private readonly HashSet<string> _words;
        private readonly Dictionary<int, List<string>> _byLength;

        public RankedDictionary(DictionaryKind kind, IEnumerable<string> wordsInRankOrder)
        {
            Kind = kind;
            _ranks = new Dictionary<string, int>(StringComparer.Ordinal);
            _words = new HashSet<string>(StringComparer.Ordinal);
            _byLength = new Dictionary<int, List<string>>();
            int rank = 0;
            foreach (string raw in wordsInRankOrder)
            {
                if (raw == null)
                    continue;
                string word = TextUtil.Normalize(raw.Trim()).ToLowerInvariant();
                if (word.Length == 0 || _ranks.ContainsKey(word))
                    continue;
                _ranks[word] = ++rank;
                _words.Add(word);
                if (!_byLength.TryGetValue(word.Length, out List<string>? bucket))
                    _byLength[word.Length] = bucket = new List<string>();
                bucket.Add(word);
                if (word.Length > MaxWordLength)
                    MaxWordLength = word.Length;
            }
        }

        public DictionaryKind Kind { get; }

        public int Count => _ranks.Count;

        /// <summary>Longest entry in UTF-16 units; substrings longer than this cannot match.</summary>
        public int MaxWordLength { get; }

        public bool Contains(string lowerWord) => _words.Contains(lowerWord);

        public bool TryGetRank(string lowerWord, out int rank) => _ranks.TryGetValue(lowerWord, out rank);

        /// <summary>True if <paramref name="lowerText"/> equals an entry, allowing l33t substitutions.</summary>
        public bool ContainsWithSubstitutions(string lowerText)
        {
            if (_words.Contains(lowerText))
                return true;
            if (!_byLength.TryGetValue(lowerText.Length, out List<string>? bucket))
                return false;
            foreach (string word in bucket)
            {
                if (L33t.EqualsWithSubstitutions(lowerText, word))
                    return true;
            }
            return false;
        }
    }

    /// <summary>The embedded word lists, each loaded once on first use.</summary>
    internal static class EmbeddedDictionaries
    {
        private static readonly Lazy<RankedDictionary> s_commonPasswords = new Lazy<RankedDictionary>(
            () => new RankedDictionary(DictionaryKind.CommonPasswords, ReadResource("Masterly.Hash.Policy.common-passwords-10k.txt")),
            LazyThreadSafetyMode.ExecutionAndPublication);

        private static readonly Lazy<RankedDictionary> s_englishWords = new Lazy<RankedDictionary>(
            () => new RankedDictionary(DictionaryKind.EnglishWords, ReadResource("Masterly.Hash.Policy.english-words.txt")),
            LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>SecLists 10k-most-common.txt, ranked by line number.</summary>
        public static RankedDictionary CommonPasswords => s_commonPasswords.Value;

        /// <summary>Small list of common English words, roughly by frequency.</summary>
        public static RankedDictionary EnglishWords => s_englishWords.Value;

        private static List<string> ReadResource(string name)
        {
            using Stream stream = typeof(EmbeddedDictionaries).GetTypeInfo().Assembly.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException($"Embedded resource '{name}' is missing.");
            using var reader = new StreamReader(stream, Encoding.UTF8);
            var lines = new List<string>();
            string? line;
            while ((line = reader.ReadLine()) != null)
                lines.Add(line);
            return lines;
        }
    }
}
