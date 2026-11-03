using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.PropertyTests.Support;

/// <summary>Shared hashers, peppers and legacy seeds. Every profile here is deliberately weak so properties run fast.</summary>
internal static class Fixtures
{
    /// <summary>The fast default profile (Argon2id m=64 KiB, t=1).</summary>
    public static readonly HashProfile Fast = HashProfile.Argon2id("test", 64, 1);

    /// <summary>A second registered profile with the same salt/tag lengths, so a profile-id swap reaches the KDF.</summary>
    public static readonly HashProfile Fast2 = HashProfile.Argon2id("test2", 128, 1);

    /// <summary>Pool of pepper key ids used by the rotation properties.</summary>
    public static readonly string[] KeyIdPool = { "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7" };

    /// <summary>
    /// Legacy formats with low cost caps, so a random mutation of a cost field can never turn into a slow test.
    /// </summary>
    public static ILegacyHashFormat[] CappedFormats() => new ILegacyHashFormat[]
    {
        new BCryptFormat(6),
        new WordPressBcryptFormat(6),
        new ExternalArgon2Format(1024, 3, 4),
        new PhpassFormat(12),
        new DjangoPbkdf2Format(20_000),
        new AspNetIdentityV3Format(20_000),
    };

    /// <summary>Every format instance the format-level fuzzers exercise (capped and cheap ones).</summary>
    public static readonly ILegacyHashFormat[] FuzzFormats = BuildFuzzFormats();

    /// <summary>Plain hasher: fast profile, no pepper, default legacy formats (1.x only).</summary>
    public static readonly PasswordHasher Plain = Create();

    /// <summary>
    /// Hasher with everything switched on: two profiles, a pepper with two keys, every legacy format (capped).
    /// Used by the never-throw properties.
    /// </summary>
    public static readonly PasswordHasher Everything = Create(o =>
    {
        o.AdditionalProfiles.Add(Fast2);
        o.Pepper = Pepper("key1", "key1", "key2");
        o.AddLegacyFormats(CappedFormats()).AddAllLegacyFormats();
    });

    /// <summary>
    /// Like <see cref="Everything"/>, but the 1.x format is restricted to SHA-512 so that it can onion-wrap.
    /// </summary>
    public static readonly PasswordHasher Wrapping = Create(o =>
    {
        o.AdditionalProfiles.Add(Fast2);
        o.Pepper = Pepper("key1", "key1", "key2");
        o.LegacyFormats.Clear();
        o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA512));
        o.AddLegacyFormats(CappedFormats()).AddAllLegacyFormats();
    });

    /// <summary>Same as <see cref="Wrapping"/> without a pepper, to produce unpeppered wrapped hashes.</summary>
    public static readonly PasswordHasher WrappingNoPepper = Create(o =>
    {
        o.AdditionalProfiles.Add(Fast2);
        o.LegacyFormats.Clear();
        o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA512));
        o.AddLegacyFormats(CappedFormats()).AddAllLegacyFormats();
    });

    public static PasswordHasher Create(Action<PasswordHasherOptions>? configure = null)
    {
        var options = new PasswordHasherOptions { DefaultProfile = Fast, AllowWeakProfiles = true };
        configure?.Invoke(options);
        return new PasswordHasher(options);
    }

    /// <summary>Deterministic 32-byte key per id, so the same id always means the same key across hashers.</summary>
    public static byte[] KeyFor(string keyId) => SHA256.HashData(Encoding.UTF8.GetBytes("pepper-key-" + keyId));

    public static HmacPepper Pepper(string currentKeyId, params string[] keyIds)
    {
        var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (string id in keyIds)
            keys[id] = KeyFor(id);
        return new HmacPepper(currentKeyId, keys);
    }

    /// <summary>A valid stored hash per legacy format, with the password that verifies against it.</summary>
    public static readonly (ILegacyHashFormat Format, string Password, string Hash)[] LegacySeeds = BuildSeeds();

    private static ILegacyHashFormat[] BuildFuzzFormats()
    {
        var list = new List<ILegacyHashFormat>(CappedFormats())
        {
            AspNetIdentityV2Format.Instance,
            UnsaltedDigestFormat.Md5,
            UnsaltedDigestFormat.Sha1,
            UnsaltedDigestFormat.Sha256,
            UnsaltedDigestFormat.Sha512,
            V1LegacyFormat.Instance,
            new V1LegacyFormat(V1Algorithm.SHA256),
            new V1LegacyFormat(V1Algorithm.SHA384),
            new V1LegacyFormat(V1Algorithm.SHA512),
        };
        return list.ToArray();
    }

    private static (ILegacyHashFormat, string, string)[] BuildSeeds()
    {
        const string pw = "password";
        byte[] pwBytes = Encoding.UTF8.GetBytes(pw);
        byte[] salt16 = Bytes(16, 7);
        ILegacyHashFormat[] capped = CappedFormats();

        // Masterly.Hash 1.x: base64(SHA-512(utf8(pw) || salt) || salt).
        byte[] v1Digest = SHA512.HashData(Concat(pwBytes, salt16));
        string v1 = Convert.ToBase64String(Concat(v1Digest, salt16));

        // ASP.NET Identity v2: base64(0x00 || salt16 || PBKDF2-HMAC-SHA1(pw, salt, 1000, 32)).
        byte[] v2Subkey = Rfc2898DeriveBytes.Pbkdf2(pwBytes, salt16, 1000, HashAlgorithmName.SHA1, 32);
        string identityV2 = Convert.ToBase64String(Concat(new byte[] { 0 }, Concat(salt16, v2Subkey)));

        // ASP.NET Identity v3: 0x01 || prf(BE32) || iterations(BE32) || saltLen(BE32) || salt || subkey.
        byte[] v3Subkey = Rfc2898DeriveBytes.Pbkdf2(pwBytes, salt16, 1000, HashAlgorithmName.SHA256, 32);
        byte[] v3 = new byte[13 + 16 + 32];
        v3[0] = 0x01;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(v3.AsSpan(1), 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(v3.AsSpan(5), 1000);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(v3.AsSpan(9), 16);
        Buffer.BlockCopy(salt16, 0, v3, 13, 16);
        Buffer.BlockCopy(v3Subkey, 0, v3, 29, 32);
        string identityV3 = Convert.ToBase64String(v3);

        // Django: pbkdf2_sha256$<iterations>$<salt>$<base64(PBKDF2-HMAC-SHA256)>.
        byte[] django = Rfc2898DeriveBytes.Pbkdf2(pwBytes, Encoding.UTF8.GetBytes("seasalt"), 1000, HashAlgorithmName.SHA256, 32);
        string djangoHash = "pbkdf2_sha256$1000$seasalt$" + Convert.ToBase64String(django);

        string bcrypt = BCrypt.Net.BCrypt.HashPassword(pw, "$2a$04$CCCCCCCCCCCCCCCCCCCCC.");

        // WordPress 6.8: '$wp' . bcrypt(base64(HMAC-SHA384(key "wp-sha384", password))).
        string preHash = Convert.ToBase64String(HMACSHA384.HashData(Encoding.ASCII.GetBytes("wp-sha384"), pwBytes));
        string wordpress = "$wp" + BCrypt.Net.BCrypt.HashPassword(preHash, "$2y$04$CCCCCCCCCCCCCCCCCCCCC.");

        return new (ILegacyHashFormat, string, string)[]
        {
            (capped[0], pw, bcrypt),
            (capped[1], pw, wordpress),
            // phc-winner-argon2 reference vector (argon2i, m=256, t=2, p=1, salt "somesalt").
            (capped[2], pw, "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8"),
            // Openwall phpass test.php vector.
            (capped[3], "test12345", "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0"),
            (capped[4], pw, djangoHash),
            (capped[5], pw, identityV3),
            (AspNetIdentityV2Format.Instance, pw, identityV2),
            (UnsaltedDigestFormat.Md5, pw, Hex(MD5.HashData(pwBytes))),
            (UnsaltedDigestFormat.Sha1, pw, Hex(SHA1.HashData(pwBytes))),
            (UnsaltedDigestFormat.Sha256, pw, Hex(SHA256.HashData(pwBytes))),
            (UnsaltedDigestFormat.Sha512, pw, Hex(SHA512.HashData(pwBytes))),
            (V1LegacyFormat.Instance, pw, v1),
            (new V1LegacyFormat(V1Algorithm.SHA512), pw, v1),
        };
    }

    public static byte[] Bytes(int length, byte seed)
    {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++)
            result[i] = (byte)(seed + i);
        return result;
    }

    public static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    /// <summary>Number of legacy hash kinds <see cref="BuildLegacyHash"/> can produce.</summary>
    public const int LegacyKinds = 9;

    /// <summary>Human-readable name of a <see cref="BuildLegacyHash"/> kind.</summary>
    public static string LegacyKindName(int kind) => kind switch
    {
        0 => "v1-sha512",
        1 => "v1-sha256",
        2 => "md5",
        3 => "sha1",
        4 => "sha256",
        5 => "sha512",
        6 => "aspnet-identity-v2",
        7 => "aspnet-identity-v3",
        _ => "django-pbkdf2-sha256",
    };

    /// <summary>
    /// Builds a legacy hash of <paramref name="password"/> from the published algorithm of each system, using only
    /// BCL primitives (not the formats under test). Every legacy system hashes the raw UTF-8 bytes.
    /// </summary>
    /// <param name="kind">0..<see cref="LegacyKinds"/>-1, see <see cref="LegacyKindName"/>.</param>
    /// <param name="password">The password.</param>
    /// <param name="salt">Salt bytes (v1: any length; Identity: first 16 bytes; Django: hex-encoded, non-empty).</param>
    public static string BuildLegacyHash(int kind, string password, byte[] salt)
    {
        byte[] pw = Encoding.UTF8.GetBytes(password);
        byte[] salt16 = new byte[16];
        Buffer.BlockCopy(salt, 0, salt16, 0, Math.Min(16, salt.Length));
        switch (kind)
        {
            case 0: return Convert.ToBase64String(Concat(SHA512.HashData(Concat(pw, salt)), salt));
            case 1: return Convert.ToBase64String(Concat(SHA256.HashData(Concat(pw, salt)), salt));
            case 2: return Hex(MD5.HashData(pw));
            case 3: return Hex(SHA1.HashData(pw));
            case 4: return Hex(SHA256.HashData(pw));
            case 5: return Hex(SHA512.HashData(pw));
            case 6:
            {
                byte[] subkey = Rfc2898DeriveBytes.Pbkdf2(pw, salt16, 1000, HashAlgorithmName.SHA1, 32);
                return Convert.ToBase64String(Concat(new byte[] { 0 }, Concat(salt16, subkey)));
            }
            case 7:
            {
                byte[] subkey = Rfc2898DeriveBytes.Pbkdf2(pw, salt16, 1000, HashAlgorithmName.SHA256, 32);
                byte[] v3 = new byte[13 + 16 + 32];
                v3[0] = 0x01;
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(v3.AsSpan(1), 1);
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(v3.AsSpan(5), 1000);
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(v3.AsSpan(9), 16);
                Buffer.BlockCopy(salt16, 0, v3, 13, 16);
                Buffer.BlockCopy(subkey, 0, v3, 29, 32);
                return Convert.ToBase64String(v3);
            }
            default:
            {
                string djangoSalt = salt.Length == 0 ? "s" : Hex(salt);
                byte[] derived = Rfc2898DeriveBytes.Pbkdf2(pw, Encoding.ASCII.GetBytes(djangoSalt), 1000, HashAlgorithmName.SHA256, 32);
                return "pbkdf2_sha256$1000$" + djangoSalt + "$" + Convert.ToBase64String(derived);
            }
        }
    }

    /// <summary>
    /// Whether <paramref name="hasher"/> has a format that verifies <paramref name="kind"/>: <see cref="Plain"/>
    /// only knows 1.x, the wrapping hashers restrict 1.x to SHA-512, <see cref="Everything"/> knows all.
    /// </summary>
    public static bool Supports(PasswordHasher hasher, int kind)
    {
        if (ReferenceEquals(hasher, Plain))
            return kind <= 1;
        if (ReferenceEquals(hasher, Wrapping) || ReferenceEquals(hasher, WrappingNoPepper))
            return kind != 1;
        return true;
    }

    /// <summary>
    /// Whether <see cref="PasswordHasher.TryWrap"/> must succeed for <paramref name="kind"/>: <see cref="Plain"/>
    /// and <see cref="Everything"/> only have the unrestricted 1.x format (which cannot wrap).
    /// </summary>
    public static bool CanWrap(PasswordHasher hasher, int kind)
    {
        if (ReferenceEquals(hasher, Plain))
            return false;
        if (ReferenceEquals(hasher, Wrapping) || ReferenceEquals(hasher, WrappingNoPepper))
            return kind != 1;
        return kind >= 2;
    }

    /// <summary>Name of a shared hasher, for failure messages.</summary>
    public static string Name(PasswordHasher hasher) =>
        ReferenceEquals(hasher, Plain) ? nameof(Plain)
        : ReferenceEquals(hasher, Everything) ? nameof(Everything)
        : ReferenceEquals(hasher, Wrapping) ? nameof(Wrapping)
        : ReferenceEquals(hasher, WrappingNoPepper) ? nameof(WrappingNoPepper)
        : "custom";

    /// <summary>
    /// Independent well-formedness check (no core code): every high surrogate is followed by a low surrogate and
    /// every low surrogate is preceded by a high one.
    /// </summary>
    public static bool IsWellFormedUtf16(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]))
            {
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]))
                    return false;
                i++;
            }
            else if (char.IsLowSurrogate(value[i]))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Reference oracle for well-formed passwords, independent of the core encoder: two passwords are the same
    /// password iff their NFKC forms are ordinal-equal (NIST SP 800-63B §5.1.1.2; UTF-8 is injective on valid text).
    /// </summary>
    public static bool NfkcEqual(string a, string b) =>
        string.Equals(a.Normalize(NormalizationForm.FormKC), b.Normalize(NormalizationForm.FormKC), StringComparison.Ordinal);

    /// <summary>Reference length rule for well-formed passwords: UTF-8 byte count of the NFKC form.</summary>
    public static int NfkcByteCount(string value) => Encoding.UTF8.GetByteCount(value.Normalize(NormalizationForm.FormKC));

    /// <summary>
    /// A different password with no more raw UTF-8 bytes: the first code point replaced by an ASCII character, so a
    /// well-formed password stays well-formed. Differs from <paramref name="password"/> in raw bytes and after NFKC.
    /// </summary>
    public static string WrongPassword(string password)
    {
        string head = password[0] == '!' ? "?" : "!";
        int first = password.Length > 1 && char.IsHighSurrogate(password[0]) && char.IsLowSurrogate(password[1]) ? 2 : 1;
        return head + password.Substring(first);
    }

    /// <summary>
    /// <see cref="Wrapping"/> (or <see cref="Everything"/>) with a third-party <paramref name="format"/> registered
    /// first, so that it is consulted before every real format.
    /// </summary>
    public static PasswordHasher WithFormatFirst(ILegacyHashFormat format, bool wrapping) => Create(o =>
    {
        o.AdditionalProfiles.Add(Fast2);
        o.Pepper = Pepper("key1", "key1", "key2");
        if (wrapping)
        {
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA512));
        }
        o.AddLegacyFormats(CappedFormats()).AddAllLegacyFormats();
        o.LegacyFormats.Insert(0, format);
    });

    public static PasswordHasher[] AllHashersWithUnpepperedWrap() => new[] { Plain, Everything, Wrapping, WrappingNoPepper };

    /// <summary>True if the two passwords feed identical bytes to the KDF (according to the core encoder itself).</summary>
    public static bool SameEncoding(string a, string b) =>
        HashPrimitives.EncodePassword(a).AsSpan().SequenceEqual(HashPrimitives.EncodePassword(b));

    /// <summary>Readable, copy-pasteable rendering of a string for failure messages.</summary>
    public static string Show(string? value)
    {
        if (value == null)
            return "null";
        var sb = new StringBuilder("\"");
        int limit = Math.Min(value.Length, 300);
        for (int i = 0; i < limit; i++)
        {
            char c = value[i];
            if (c >= 0x20 && c < 0x7F && c != '"' && c != '\\')
                sb.Append(c);
            else
                sb.Append("\\u").Append(((int)c).ToString("X4"));
        }
        sb.Append('"');
        if (value.Length > limit)
            sb.Append("...(length ").Append(value.Length).Append(')');
        return sb.ToString();
    }

    public static PasswordHasher[] AllHashers() => new[] { Plain, Everything, Wrapping };
}
