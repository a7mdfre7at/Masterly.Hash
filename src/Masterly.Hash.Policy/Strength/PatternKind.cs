namespace Masterly.Hash.Policy
{
    /// <summary>Kind of guessable pattern the strength estimator found.</summary>
    public enum PatternKind
    {
        /// <summary>No recognisable pattern; estimated as random characters.</summary>
        Bruteforce,

        /// <summary>A word from a dictionary (possibly reversed, capitalised or with l33t substitutions).</summary>
        Dictionary,

        /// <summary>A run of adjacent keys on a QWERTY keyboard or numeric keypad, e.g. <c>qwerty</c> or <c>7896</c>.</summary>
        Spatial,

        /// <summary>A repeated character or block, e.g. <c>aaa</c> or <c>abcabc</c>.</summary>
        Repeat,

        /// <summary>A sequence with a constant step, e.g. <c>abc</c>, <c>6543</c> or <c>aceg</c>.</summary>
        Sequence,

        /// <summary>A year between 1900 and 2099.</summary>
        Year,

        /// <summary>A calendar date, with or without separators, e.g. <c>1/1/91</c> or <c>19910101</c>.</summary>
        Date,
    }

    /// <summary>Dictionary a <see cref="PatternKind.Dictionary"/> pattern came from.</summary>
    public enum DictionaryKind
    {
        /// <summary>Not a dictionary pattern.</summary>
        None,

        /// <summary>The embedded list of the 10,000 most common passwords (SecLists).</summary>
        CommonPasswords,

        /// <summary>The embedded list of common English words.</summary>
        EnglishWords,

        /// <summary>Words specific to the user or the service (user name, email, site name, ...).</summary>
        ContextWords,
    }
}
