using System;
using System.Security.Cryptography;
using System.Text;

namespace Masterly.Hash
{
    public class Hash : IHash
    {
        public string ComputeHash(string plainText, SupportedHash hash = SupportedHash.SHA512)
        {
            int minSaltLength = 4, maxSaltLength = 16;

            var random = new Random();
            int saltLength = random.Next(minSaltLength, maxSaltLength);
            byte[] saltBytes = new byte[saltLength];

            using (var rng = new RNGCryptoServiceProvider())
                rng.GetNonZeroBytes(saltBytes);

            string hashedText = ComputeHash(plainText, saltBytes, hash);
            return hashedText;
        }

        public string ComputeHash(string plainText, string salt, SupportedHash hash = SupportedHash.SHA512)
        {
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            return ComputeHash(plainText, saltBytes, hash);
        }

        public string ComputeHash(string plainText, byte[] saltBytes, SupportedHash hash = SupportedHash.SHA512)
        {
            byte[] plainData = Encoding.UTF8.GetBytes(plainText);
            byte[] plainDataWithSalt = new byte[plainData.Length + saltBytes.Length];

            for (int x = 0; x < plainData.Length; x++)
                plainDataWithSalt[x] = plainData[x];

            for (int n = 0; n < saltBytes.Length; n++)
                plainDataWithSalt[plainData.Length + n] = saltBytes[n];

            byte[] hashValue;

            switch (hash)
            {
                case SupportedHash.SHA256:
                    hashValue = ComputeHashSHA256(plainDataWithSalt);
                    break;
                case SupportedHash.SHA384:
                    hashValue = ComputeHashSHA384(plainDataWithSalt);
                    break;
                default:
                    hashValue = ComputeHashSHA512(plainDataWithSalt);
                    break;
            }

            byte[] result = new byte[hashValue.Length + saltBytes.Length];

            for (int x = 0; x < hashValue.Length; x++)
                result[x] = hashValue[x];

            for (int n = 0; n < saltBytes.Length; n++)
                result[hashValue.Length + n] = saltBytes[n];

            return Convert.ToBase64String(result);
        }

        private byte[] ComputeHashSHA512(byte[] plainDataWithSalt)
        {
            using (var sha512 = new SHA512Managed())
            {
                byte[] hashValue = sha512.ComputeHash(plainDataWithSalt);
                return hashValue;
            }
        }

        private byte[] ComputeHashSHA384(byte[] plainDataWithSalt)
        {
            using (var sha384 = new SHA384Managed())
            {
                byte[] hashValue = sha384.ComputeHash(plainDataWithSalt);
                return hashValue;
            }
        }

        private byte[] ComputeHashSHA256(byte[] plainDataWithSalt)
        {
            using (var sha256 = new SHA256Managed())
            {
                byte[] hashValue = sha256.ComputeHash(plainDataWithSalt);
                return hashValue;
            }
        }

        public bool Verify(string plainText, string hashValue, SupportedHash hash = SupportedHash.SHA512)
        {
            byte[] hashBytes = Convert.FromBase64String(hashValue);
            int hashSize;

            switch (hash)
            {
                case SupportedHash.SHA256:
                    hashSize = 32;
                    break;
                case SupportedHash.SHA384:
                    hashSize = 48;
                    break;
                default:
                    hashSize = 64;
                    break;
            }

            byte[] saltBytes = new byte[hashBytes.Length - hashSize];

            for (int x = 0; x < saltBytes.Length; x++)
                saltBytes[x] = hashBytes[hashSize + x];

            string newHash = ComputeHash(plainText, saltBytes, hash);

            return (hashValue == newHash);
        }
    }
}
