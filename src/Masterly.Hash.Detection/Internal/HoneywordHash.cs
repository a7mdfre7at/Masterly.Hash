using System;
using System.Text;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Detection.Internal
{
    /// <summary>
    /// <c>$mhw$p=&lt;profileId&gt;[,k=&lt;pepperKeyId&gt;]$&lt;salt&gt;$&lt;tag1&gt;,&lt;tag2&gt;,...,&lt;tagk&gt;</c>, all base64
    /// without padding. Parsing is strict and never throws.
    /// </summary>
    internal sealed class HoneywordHash
    {
        public const string Prefix = "$mhw$";


        public HoneywordHash(string profileId, string? pepperKeyId, byte[] salt, byte[][] tags)
        {
            ProfileId = profileId;
            PepperKeyId = pepperKeyId;
            Salt = salt;
            Tags = tags;
        }

        public string ProfileId { get; }

        public string? PepperKeyId { get; }

        public byte[] Salt { get; }

        public byte[][] Tags { get; }

        public static bool IsValidKeyId(string? keyId) => keyId != null && HashPrimitives.IsValidKeyId(keyId);

        /// <summary>Upper bound on the length of a well-formed hash with at most <paramref name="maxTags"/> tags.</summary>
        public static int MaxLength(int maxTags) => 256 + (maxTags * 87);

        public static bool TryParse(string value, int maxTags, out HoneywordHash? hash)
        {
            hash = null;
            if (value == null || value.Length > MaxLength(maxTags) || !value.StartsWith(Prefix, StringComparison.Ordinal))
                return false;

            string[] parts = value.Substring(Prefix.Length).Split('$');
            if (parts.Length != 3)
                return false;

            string[] parameters = parts[0].Split(',');
            if (parameters.Length < 1 || parameters.Length > 2)
                return false;
            if (!parameters[0].StartsWith("p=", StringComparison.Ordinal))
                return false;
            string profileId = parameters[0].Substring(2);
            if (!HashPrimitives.IsValidProfileId(profileId))
                return false;

            string? keyId = null;
            if (parameters.Length == 2)
            {
                if (!parameters[1].StartsWith("k=", StringComparison.Ordinal))
                    return false;
                keyId = parameters[1].Substring(2);
                if (!IsValidKeyId(keyId))
                    return false;
            }

            if (parts[1].Length == 0 || !HashPrimitives.TryFromB64(parts[1], out byte[] salt))
                return false;

            string[] encodedTags = parts[2].Split(',');
            if (encodedTags.Length < 2 || encodedTags.Length > maxTags)
                return false;

            var tags = new byte[encodedTags.Length][];
            for (int i = 0; i < encodedTags.Length; i++)
            {
                if (encodedTags[i].Length == 0 || !HashPrimitives.TryFromB64(encodedTags[i], out tags[i]))
                    return false;
            }

            hash = new HoneywordHash(profileId, keyId, salt, tags);
            return true;
        }

        public override string ToString()
        {
            var sb = new StringBuilder(MaxLength(Tags.Length));
            sb.Append(Prefix).Append("p=").Append(ProfileId);
            if (PepperKeyId != null)
                sb.Append(",k=").Append(PepperKeyId);
            sb.Append('$').Append(HashPrimitives.ToB64(Salt)).Append('$');
            for (int i = 0; i < Tags.Length; i++)
            {
                if (i > 0)
                    sb.Append(',');
                sb.Append(HashPrimitives.ToB64(Tags[i]));
            }
            return sb.ToString();
        }
    }
}
