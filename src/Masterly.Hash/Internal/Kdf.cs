using System;
using System.Security.Cryptography;

namespace Masterly.Hash.Internal
{
    internal static class Kdf
    {
        public static byte[] Derive(HashProfile profile, byte[] input, byte[] salt)
        {
            switch (profile.Algorithm)
            {
                case HashAlgorithmKind.Argon2id:
                    // Runs on the calling thread: PasswordHasher holds a concurrency slot around this call.
                    return Argon2Core.Derive(
                        Argon2Type.Argon2id, input, salt, default, default,
                        profile.MemoryKiB, profile.Iterations, profile.Parallelism, profile.TagLength);

                case HashAlgorithmKind.Pbkdf2Sha512:
                    return Pbkdf2.Derive(HashAlgorithmName.SHA512, input, salt, profile.Iterations, profile.TagLength);

                default:
                    throw new NotSupportedException($"Unsupported algorithm {profile.Algorithm}.");
            }
        }
    }
}
