namespace Masterly.Hash.Analyzers.Tests.Infrastructure;

/// <summary>
/// Source stubs for the types the analyzers match by metadata name. The analyzer has no compile-time reference
/// to Masterly.Hash or Microsoft.Extensions.Logging, so stubs with the same full names behave identically.
/// </summary>
internal static class Stubs
{
    public const string MasterlyHash = """
        namespace Masterly.Hash
        {
            public static class Password
            {
                public static string Hash(string password) => password;
                public static string Hash(SensitiveString password) => password.Reveal();
            }

            public sealed class SensitiveString
            {
                private readonly string _value;
                public SensitiveString(string value) { _value = value; }
                public string Reveal() => _value;
                public override string ToString() => "***";
            }

            public enum SupportedHash { SHA256, SHA384, SHA512 }

            public interface IHash
            {
                string ComputeHash(string plainText, SupportedHash hash = SupportedHash.SHA512);
                string ComputeHash(string plainText, byte[] saltBytes, SupportedHash hash = SupportedHash.SHA512);
                bool Verify(string plainText, string hashValue, SupportedHash hash = SupportedHash.SHA512);
            }

            public class Hash : IHash
            {
                public string ComputeHash(string plainText, SupportedHash hash = SupportedHash.SHA512) => plainText;
                public string ComputeHash(string plainText, byte[] saltBytes, SupportedHash hash = SupportedHash.SHA512) => plainText;
                public bool Verify(string plainText, string hashValue, SupportedHash hash = SupportedHash.SHA512) => true;
            }
        }

        namespace Masterly.Hash.Pepper
        {
            using System.Collections.Generic;

            public sealed class HmacPepper
            {
                public HmacPepper(string currentKeyId, IReadOnlyDictionary<string, byte[]> keys) { }
                public HmacPepper(string keyId, byte[] key) { }
                public static HmacPepper FromBase64(string currentKeyId, IReadOnlyDictionary<string, string> base64Keys) => null!;
                public static byte[] GenerateKey() => new byte[32];
            }
        }
        """;

    public const string Logging = """
        namespace Microsoft.Extensions.Logging
        {
            using System;

            public enum LogLevel { Trace, Debug, Information, Warning, Error, Critical, None }

            public readonly struct EventId
            {
                public EventId(int id) { Id = id; }
                public int Id { get; }
                public static implicit operator EventId(int i) => new EventId(i);
            }

            public interface ILogger
            {
                void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter);
                bool IsEnabled(LogLevel logLevel);
                IDisposable? BeginScope<TState>(TState state) where TState : notnull;
            }

            public static class LoggerExtensions
            {
                public static void LogInformation(this ILogger logger, string? message, params object?[] args) { }
                public static void LogWarning(this ILogger logger, string? message, params object?[] args) { }
                public static void LogError(this ILogger logger, Exception? exception, string? message, params object?[] args) { }
                public static void Log(this ILogger logger, LogLevel logLevel, string? message, params object?[] args) { }
                public static IDisposable? BeginScope(this ILogger logger, string messageFormat, params object?[] args) => null;
            }
        }
        """;
}
