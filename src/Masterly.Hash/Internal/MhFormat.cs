using System;
using System.Text;

namespace Masterly.Hash.Internal
{
    /// <summary>
    /// The Masterly hash string, a PHC-format string:
    /// <c>$mh$p=&lt;profile&gt;[,k=&lt;pepperKey&gt;][,w=&lt;legacyFormat&gt;,wp=&lt;b64&gt;]$&lt;salt b64&gt;$&lt;tag b64&gt;</c>.
    /// Cost parameters are never stored: <c>p</c> is looked up in a compiled-in allowlist.
    /// </summary>
    internal sealed class MhHash
    {
        public const string Prefix = "$mh$";
        public const int MaxLength = 1024;


        public MhHash(string profileId, string? pepperKeyId, string? wrapFormat, byte[]? wrapParameter, byte[] salt, byte[] tag)
        {
            ProfileId = profileId;
            PepperKeyId = pepperKeyId;
            WrapFormat = wrapFormat;
            WrapParameter = wrapParameter;
            Salt = salt;
            Tag = tag;
        }

        public string ProfileId { get; }
        public string? PepperKeyId { get; }
        public string? WrapFormat { get; }
        public byte[]? WrapParameter { get; }
        public byte[] Salt { get; }
        public byte[] Tag { get; }

        public static bool IsValidKeyId(string keyId) => Identifiers.IsValidKeyId(keyId);
        public static bool IsValidFormatId(string formatId) => Identifiers.IsValidLowercaseId(formatId);

        public override string ToString()
        {
            var sb = new StringBuilder(Prefix);
            sb.Append("p=").Append(ProfileId);
            if (PepperKeyId != null)
                sb.Append(",k=").Append(PepperKeyId);
            if (WrapFormat != null)
            {
                sb.Append(",w=").Append(WrapFormat);
                if (WrapParameter != null && WrapParameter.Length > 0)
                    sb.Append(",wp=").Append(CryptoUtil.ToB64(WrapParameter));
            }
            sb.Append('$').Append(CryptoUtil.ToB64(Salt));
            sb.Append('$').Append(CryptoUtil.ToB64(Tag));
            return sb.ToString();
        }

        public static bool TryParse(string value, out MhHash? hash)
        {
            hash = null;
            if (value == null || value.Length > MaxLength || !value.StartsWith(Prefix, StringComparison.Ordinal))
                return false;

            string[] parts = value.Split('$');
            // "", "mh", params, salt, tag
            if (parts.Length != 5 || parts[0].Length != 0 || parts[1] != "mh")
                return false;

            string? profileId = null, keyId = null, wrap = null;
            byte[]? wrapParameter = null;

            // Parameters must appear exactly once each, in canonical order (p, k, w, wp), so that one hash
            // has exactly one string form.
            int stage = 0;
            foreach (string pair in parts[2].Split(','))
            {
                int eq = pair.IndexOf('=');
                if (eq <= 0)
                    return false;
                string name = pair.Substring(0, eq);
                string val = pair.Substring(eq + 1);

                switch (name)
                {
                    case "p" when stage < 1 && HashProfile.IsValidId(val):
                        profileId = val;
                        stage = 1;
                        break;
                    case "k" when stage == 1 && IsValidKeyId(val):
                        keyId = val;
                        stage = 2;
                        break;
                    case "w" when (stage == 1 || stage == 2) && IsValidFormatId(val):
                        wrap = val;
                        stage = 3;
                        break;
                    case "wp" when stage == 3 && CryptoUtil.TryFromB64(val, out byte[] wp):
                        wrapParameter = wp;
                        stage = 4;
                        break;
                    default:
                        return false; // unknown, duplicate, out-of-order or invalid parameter
                }
            }

            if (profileId == null || (wrapParameter != null && wrap == null))
                return false;

            if (!CryptoUtil.TryFromB64(parts[3], out byte[] salt) || !CryptoUtil.TryFromB64(parts[4], out byte[] tag))
                return false;

            hash = new MhHash(profileId, keyId, wrap, wrapParameter, salt, tag);
            return true;
        }
    }
}
