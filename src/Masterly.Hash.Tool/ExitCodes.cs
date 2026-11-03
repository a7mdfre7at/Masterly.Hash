namespace Masterly.Hash.Tool
{
    /// <summary>Process exit codes of <c>masterly-hash</c>.</summary>
    public static class ExitCodes
    {
        /// <summary>The command succeeded (verify: the password matches; policy: acceptable; inspect: recognized).</summary>
        public const int Success = 0;

        /// <summary>A negative answer (verify: mismatch; policy: rejected; inspect: not recognized).</summary>
        public const int Failure = 1;

        /// <summary>Bad arguments, unreadable input, or a stored hash that cannot be used.</summary>
        public const int Error = 2;

        /// <summary>Cancelled with Ctrl+C.</summary>
        public const int Cancelled = 130;
    }
}
