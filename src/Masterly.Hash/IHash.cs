using Masterly.DependencyInjection.Abstraction;

namespace Masterly.Hash
{
    public interface IHash : IScopedDependency
    {
        string ComputeHash(string plainText, SupportedHash hash = SupportedHash.SHA512);
        string ComputeHash(string plainText, byte[] saltBytes, SupportedHash hash = SupportedHash.SHA512);
        string ComputeHash(string plainText, string salt, SupportedHash hash = SupportedHash.SHA512);
        bool Verify(string plainText, string hashValue, SupportedHash hash = SupportedHash.SHA512);
    }
}
