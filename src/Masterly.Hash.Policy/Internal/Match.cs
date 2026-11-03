using System.Collections.Generic;

namespace Masterly.Hash.Policy.Internal
{
    /// <summary>A candidate pattern covering <c>password[I..J]</c> (inclusive). Mutable; scoring caches <see cref="Guesses"/>.</summary>
    internal sealed class Match
    {
        public Match(PatternKind pattern, int i, int j, string token)
        {
            Pattern = pattern;
            I = i;
            J = j;
            Token = token;
        }

        public PatternKind Pattern { get; }
        public int I { get; set; }
        public int J { get; set; }
        public string Token { get; set; }

        // Dictionary
        public string MatchedWord { get; set; } = string.Empty;
        public int Rank { get; set; }
        public DictionaryKind Dictionary { get; set; }
        public bool Reversed { get; set; }
        public bool L33t { get; set; }
        public Dictionary<char, char>? Sub { get; set; }

        // Spatial
        public string Graph { get; set; } = string.Empty;
        public int Turns { get; set; }
        public int ShiftedCount { get; set; }

        // Repeat
        public string BaseToken { get; set; } = string.Empty;
        public double BaseGuesses { get; set; }
        public int RepeatCount { get; set; }

        // Sequence
        public bool Ascending { get; set; }

        // Year / date
        public int Year { get; set; }
        public int Month { get; set; }
        public int Day { get; set; }
        public string Separator { get; set; } = string.Empty;

        /// <summary>Set by <see cref="Scoring.EstimateGuesses"/>.</summary>
        public double? Guesses { get; set; }
    }
}
