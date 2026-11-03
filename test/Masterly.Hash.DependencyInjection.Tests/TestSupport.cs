using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy;
using Masterly.Hash.Primitives;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Masterly.Hash.DependencyInjection.Tests;

internal static class TestSupport
{
    /// <summary>Weak profile so tests run fast. Never use outside tests.</summary>
    public static readonly HashProfile Fast = HashProfile.Argon2id("test", 64, 1);

    public static readonly HashProfile Fast2 = HashProfile.Argon2id("test2", 128, 1);

    public static void UseFast(PasswordHasherOptions options)
    {
        options.DefaultProfile = Fast;
        options.AllowWeakProfiles = true;
    }

    /// <summary>Deterministic 32-byte key for a key id.</summary>
    public static byte[] Key(string id) => SHA256.HashData(Encoding.UTF8.GetBytes("di-pepper-" + id));

    public static string KeyB64(string id) => Convert.ToBase64String(Key(id));

    public static IConfiguration Config(IDictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    public static IConfiguration Json(string json) =>
        new ConfigurationBuilder().AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json))).Build();

    /// <summary>Config section with fast hashing configured in code (config cannot select custom profiles).</summary>
    public static ServiceProvider BuildFromConfig(IDictionary<string, string?> values, Action<MasterlyHashBuilder>? extra = null)
    {
        var services = new ServiceCollection();
        MasterlyHashBuilder builder = services.AddMasterlyHash(Config(values).GetSection("MasterlyHash"), UseFast);
        extra?.Invoke(builder);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    /// <summary>Collects the messages of an exception and all of its inner exceptions.</summary>
    public static string AllMessages(Exception ex)
    {
        var sb = new StringBuilder();
        void Walk(Exception e)
        {
            sb.AppendLine(e.Message);
            if (e is AggregateException agg)
            {
                foreach (Exception inner in agg.InnerExceptions)
                    Walk(inner);
            }
            else if (e.InnerException != null)
            {
                Walk(e.InnerException);
            }
        }
        Walk(ex);
        return sb.ToString();
    }
}

/// <summary>Toy legacy format: <c>tsha$&lt;hex SHA-256 of the password&gt;</c>.</summary>
internal sealed class TestShaFormat : ILegacyHashFormat
{
    public TestShaFormat(string id = "test-sha") => Id = id;

    public string Id { get; }

    public static string Create(string password) =>
        "tsha$" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password)));

    public bool CanHandle(string storedHash) => storedHash.StartsWith("tsha$", StringComparison.Ordinal);

    public bool Verify(string password, string storedHash)
    {
        byte[] expected = Convert.FromHexString(storedHash.Substring(5));
        byte[] actual = SHA256.HashData(Encoding.UTF8.GetBytes(password));
        return HashPrimitives.FixedTimeEquals(expected, actual);
    }

    public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
    {
        digest = Array.Empty<byte>();
        parameter = Array.Empty<byte>();
        return false;
    }

    public byte[] ComputeWrapInput(string password, byte[] parameter) => throw new NotSupportedException();
}

/// <summary>Stand-in for an app service (e.g. a secret-store client) a pepper factory depends on.</summary>
internal sealed class FakeKeyStore
{
    public int Calls;

    public byte[] GetKey(string id)
    {
        System.Threading.Interlocked.Increment(ref Calls);
        return TestSupport.Key(id);
    }
}
