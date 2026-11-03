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
                    using (var argon2 = new Konscious.Security.Cryptography.Argon2id(input))
                    {
                        argon2.Salt = salt;
                        argon2.MemorySize = profile.MemoryKiB;
                        argon2.Iterations = profile.Iterations;
                        argon2.DegreeOfParallelism = profile.Parallelism;
                        return argon2.GetBytes(profile.TagLength);
                    }

                case HashAlgorithmKind.Pbkdf2Sha512:
                    return Pbkdf2.Derive(HashAlgorithmName.SHA512, input, salt, profile.Iterations, profile.TagLength);

                default:
                    throw new NotSupportedException($"Unsupported algorithm {profile.Algorithm}.");
            }
        }
    }
}
