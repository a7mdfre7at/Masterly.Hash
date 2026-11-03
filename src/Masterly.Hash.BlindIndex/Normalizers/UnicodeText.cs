using System;
using System.Text;

namespace Masterly.Hash.BlindIndex.Normalizers
{
    internal static class UnicodeText
    {
        /// <summary>NFKC; throws <see cref="ArgumentException"/> without echoing the value for invalid UTF-16.</summary>
        public static string Nfkc(string value, string paramName)
        {
            try
            {
                return value.Normalize(NormalizationForm.FormKC);
            }
            catch (ArgumentException)
            {
                throw new ArgumentException("Value contains invalid UTF-16 (a lone surrogate).", paramName);
            }
        }
    }
}
