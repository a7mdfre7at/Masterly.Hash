using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Analyzers.CodeFixes;
using Masterly.Hash.Analyzers.Internal;
using Masterly.Hash.Analyzers.Tests.Infrastructure;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;
using VerifyFastHash = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.FastHashOnPasswordAnalyzer>;
using VerifyFastHashFix = Masterly.Hash.Analyzers.Tests.Infrastructure.CodeFixVerifier<
    Masterly.Hash.Analyzers.FastHashOnPasswordAnalyzer,
    Masterly.Hash.Analyzers.CodeFixes.FastHashOnPasswordCodeFixProvider>;
using VerifyComparison = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.NonConstantTimeComparisonAnalyzer>;
using VerifyComparisonFix = Masterly.Hash.Analyzers.Tests.Infrastructure.CodeFixVerifier<
    Masterly.Hash.Analyzers.NonConstantTimeComparisonAnalyzer,
    Masterly.Hash.Analyzers.CodeFixes.FixedTimeEqualsCodeFixProvider>;
using VerifyPepper = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.HardCodedPepperAnalyzer>;
using VerifyLogging = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.PasswordLoggingAnalyzer>;
using VerifyObsolete = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.ObsoleteApiAnalyzer>;
using VerifyObsoleteFix = Masterly.Hash.Analyzers.Tests.Infrastructure.CodeFixVerifier<
    Masterly.Hash.Analyzers.ObsoleteApiAnalyzer,
    Masterly.Hash.Analyzers.CodeFixes.ObsoleteApiCodeFixProvider>;

namespace Masterly.Hash.Analyzers.Tests;

/// <summary>
/// Tests written against surviving Stryker.NET mutants: each one pins a behavior (an exact message argument, a
/// boundary, a branch of a compound condition) that the scenario tests executed without checking.
/// </summary>
public class MutationTests
{
    // ================================================================ helpers

    /// <summary>
    /// Runs <paramref name="analyzer"/> over <paramref name="sources"/> compiled against the .NET 8 reference
    /// assemblies, with the Masterly.Hash stubs when <paramref name="withMasterlyHash"/>. Fails on compiler errors and
    /// on analyzer exceptions, and returns the analyzer's diagnostics (including their properties, which the
    /// verifier does not compare).
    /// </summary>
    private static async Task<ImmutableArray<Diagnostic>> AnalyzeNet80Async(
        DiagnosticAnalyzer analyzer, bool withMasterlyHash, params string[] sources)
    {
        ImmutableArray<MetadataReference> references =
            await References.Net80.ResolveAsync(LanguageNames.CSharp, CancellationToken.None);
        IEnumerable<string> all = withMasterlyHash ? sources.Append(Stubs.MasterlyHash) : sources;
        return await AnalyzeAsync(analyzer, references, all);
    }

    /// <summary>
    /// Like <see cref="AnalyzeNet80Async"/>, against the running runtime's own assemblies (net10.0), for APIs newer
    /// than the .NET 8 reference assemblies the tests can resolve offline.
    /// </summary>
    private static Task<ImmutableArray<Diagnostic>> AnalyzeRuntimeAsync(DiagnosticAnalyzer analyzer, params string[] sources)
    {
        string runtimeDirectory = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        ImmutableArray<MetadataReference> references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            .Where(p => string.Equals(Path.GetDirectoryName(p), runtimeDirectory, StringComparison.OrdinalIgnoreCase))
            .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p))
            .ToImmutableArray();
        return AnalyzeAsync(analyzer, references, sources.Append(Stubs.MasterlyHash));
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(
        DiagnosticAnalyzer analyzer, ImmutableArray<MetadataReference> references, IEnumerable<string> sources)
    {
        CSharpCompilation compilation = CSharpCompilation.Create(
            "MutationTests",
            sources.Select(s => CSharpSyntaxTree.ParseText(s, new CSharpParseOptions(LanguageVersion.CSharp12))),
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));
        Assert.Empty(compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error));

        var exceptions = new List<Exception>();
        var options = new CompilationWithAnalyzersOptions(
            new AnalyzerOptions(ImmutableArray<AdditionalText>.Empty),
            (exception, _, _) => exceptions.Add(exception),
            concurrentAnalysis: false,
            logAnalyzerExecutionTime: false);
        ImmutableArray<Diagnostic> diagnostics = await compilation
            .WithAnalyzers(ImmutableArray.Create(analyzer), options)
            .GetAnalyzerDiagnosticsAsync(CancellationToken.None);
        Assert.Empty(exceptions);
        return diagnostics;
    }

    /// <summary>Runs an analyzer with only the given extra sources (no default Masterly.Hash or logging stubs).</summary>
    private static Task VerifyWithOwnStubsAsync<TAnalyzer>(string source, string stubs, params DiagnosticResult[] expected)
        where TAnalyzer : DiagnosticAnalyzer, new()
    {
        var test = new CSharpAnalyzerTest<TAnalyzer, DefaultVerifier>
        {
            TestCode = source,
            ReferenceAssemblies = References.Net80,
        };
        test.TestState.Sources.Add(("/0/OwnStubs.cs", stubs));
        test.ExpectedDiagnostics.AddRange(expected);
        return test.RunAsync();
    }

    private static Task VerifyFixWithOwnStubsAsync<TAnalyzer, TCodeFix>(string source, string fixedSource, string stubs)
        where TAnalyzer : DiagnosticAnalyzer, new()
        where TCodeFix : CodeFixProvider, new()
    {
        var test = new CSharpCodeFixTest<TAnalyzer, TCodeFix, DefaultVerifier>
        {
            TestCode = source,
            FixedCode = fixedSource,
            ReferenceAssemblies = References.Net80,
        };
        test.TestState.Sources.Add(("/0/OwnStubs.cs", stubs));
        test.FixedState.Sources.Add(("/0/OwnStubs.cs", stubs));
        return test.RunAsync();
    }

    /// <summary><c>a ? "" : a ? "" : ... inner</c>: <paramref name="levels"/> conditionals, each one level deeper.</summary>
    private static string WhenFalseChain(int levels, string inner) =>
        string.Concat(Enumerable.Repeat("a ? \"\" : ", levels)) + inner;

    private static string Mark(string text, bool reported, string id) => reported ? "{|" + id + ":" + text + "|}" : text;

    // ================================================================ Descriptors

    [Theory]
    [InlineData("MH0001", "Fast hash used on a password",
        "'{0}' is a fast hash and must not be used on the password '{1}'; use Masterly.Hash.Password.Hash")]
    [InlineData("MH0002", "Non-constant-time comparison of secrets",
        "'{0}' looks like a secret and is compared with '{1}', which returns early on the first difference; use CryptographicOperations.FixedTimeEquals")]
    [InlineData("MH0003", "Hard-coded pepper or key",
        "The {0} is hard-coded; load it from a secret store or configuration instead")]
    [InlineData("MH0004", "Password may be logged",
        "'{0}' may be written to a log by '{1}'; never log passwords")]
    [InlineData("MH0005", "Weak PBKDF2 parameters",
        "Weak PBKDF2 parameters: {0}")]
    [InlineData("MH0006", "Obsolete Masterly.Hash 1.x API",
        "'{0}' is the Masterly.Hash 1.x API, which produces fast single-pass hashes; use '{1}' instead")]
    public void Descriptor_TitleAndMessageFormat_AreExact(string id, string title, string messageFormat)
    {
        DiagnosticDescriptor descriptor = typeof(FastHashOnPasswordAnalyzer).Assembly.GetTypes()
            .Where(t => !t.IsAbstract && typeof(DiagnosticAnalyzer).IsAssignableFrom(t))
            .SelectMany(t => ((DiagnosticAnalyzer)Activator.CreateInstance(t)!).SupportedDiagnostics)
            .Single(d => d.Id == id);

        Assert.Equal(title, descriptor.Title.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(messageFormat, descriptor.MessageFormat.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    // ================================================================ NameMatcher

    private static string Capitalize(string word) => char.ToUpperInvariant(word[0]) + word.Substring(1);

    private static readonly string[] PasswordQualifiers =
    {
        "policy", "policies", "length", "len", "rule", "rules", "hint", "hints", "strength", "option", "options",
        "settings", "config", "configuration", "requirement", "requirements", "validator", "validation", "regex",
        "pattern", "expiry", "expiration", "expires", "expired", "age", "count", "attempt", "attempts", "field",
        "label", "prompt", "placeholder", "token", "reset", "changed", "date", "time", "timestamp", "version",
        "format", "id", "min", "max", "salt", "iterations", "enabled", "required", "history", "error", "errors",
        "message", "type", "mode", "provider", "hasher", "hash", "hashed", "hashes", "manager", "service",
        "url", "uri", "path", "file", "name", "visible", "visibility", "char", "chars", "encrypted",
        "salted", "digest", "mac",
    };

    private static readonly string[] SecretQualifiers =
    {
        "algorithm", "algorithms", "alg", "name", "names", "type", "types", "kind", "length", "len", "size",
        "count", "id", "code", "set", "table", "map", "provider", "options", "settings", "address",
        "expiry", "expiration", "expires", "lifetime", "header", "prefix", "format", "version", "mode", "field",
        "label", "url", "uri", "endpoint", "path", "file", "enabled", "required", "scheme", "policy", "handler",
        "service", "manager", "factory", "builder", "generator", "validator", "parameters", "params", "status",
        "state", "source", "location", "claim", "claims",
    };

    private static readonly string[] KeyQualifiers =
    {
        "id", "ids", "name", "names", "length", "len", "size", "path", "file", "options", "provider", "version",
        "env", "variable", "config", "configuration", "setting", "settings", "location", "uri", "url", "count",
        "enabled", "required", "section", "store", "vault",
    };

    [Fact]
    public void Password_EveryQualifierWord_SuppressesTheMatch()
    {
        Assert.True(NameMatcher.Password.IsMatch("passwordValue"));
        foreach (string qualifier in PasswordQualifiers)
            Assert.False(NameMatcher.Password.IsMatch("password" + Capitalize(qualifier)), "password" + Capitalize(qualifier));
    }

    [Fact]
    public void Secret_EveryQualifierWord_SuppressesTheMatch()
    {
        Assert.True(NameMatcher.Secret.IsMatch("tokenValue"));
        foreach (string qualifier in SecretQualifiers)
            Assert.False(NameMatcher.Secret.IsMatch("token" + Capitalize(qualifier)), "token" + Capitalize(qualifier));
    }

    [Fact]
    public void Key_EveryQualifierWord_SuppressesTheMatch()
    {
        Assert.True(NameMatcher.Key.IsMatch("pepperValue"));
        foreach (string qualifier in KeyQualifiers)
            Assert.False(NameMatcher.Key.IsMatch("pepper" + Capitalize(qualifier)), "pepper" + Capitalize(qualifier));
    }

    [Theory]
    [InlineData("hashed")]
    [InlineData("encrypted")]
    [InlineData("salted")]
    [InlineData("masked")]
    [InlineData("redacted")]
    public void Password_EveryPrefixQualifier_SuppressesTheMatch(string prefix)
    {
        Assert.True(NameMatcher.Password.IsMatch("plainPassword"));
        Assert.False(NameMatcher.Password.IsMatch(prefix + "Password"));
    }

    [Fact]
    public void Patterns_SpanAtMostThreeWords()
    {
        // PaSsWord = pa + ss + word (3 words) spells password; PaSsWoRd = pa + ss + wo + rd needs 4.
        Assert.Equal(new[] { "pa", "ss", "word" }, NameMatcher.SplitWords("PaSsWord"));
        Assert.True(NameMatcher.Password.IsMatch("PaSsWord"));
        Assert.Equal(new[] { "pa", "ss", "wo", "rd" }, NameMatcher.SplitWords("PaSsWoRd"));
        Assert.False(NameMatcher.Password.IsMatch("PaSsWoRd"));
    }

    // ================================================================ FastHashOnPasswordAnalyzer

    [Theory]
    [InlineData("MD5", false)]
    [InlineData("SHA1", false)]
    [InlineData("SHA256", false)]
    [InlineData("SHA384", false)]
    [InlineData("SHA512", false)]
    [InlineData("SHA3_256", false)]
    [InlineData("SHA3_384", false)]
    [InlineData("SHA3_512", false)]
    [InlineData("HMACMD5", true)]
    [InlineData("HMACSHA1", true)]
    [InlineData("HMACSHA256", true)]
    [InlineData("HMACSHA384", true)]
    [InlineData("HMACSHA512", true)]
    [InlineData("HMACSHA3_256", true)]
    [InlineData("HMACSHA3_384", true)]
    [InlineData("HMACSHA3_512", true)]
    public Task FastHash_EveryStaticHashType_ReportsWithItsName(string type, bool keyed) => VerifyFastHash.VerifyAsync($$"""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(byte[] key, string password) => {|#0:{{type}}.HashData({{(keyed ? "key, " : "")}}Encoding.UTF8.GetBytes(password))|};
        }
        """,
        VerifyFastHash.Diagnostic().WithLocation(0).WithArguments(type, "password"));

    [Fact]
    public Task FastHash_TryHashDataAndAsyncVariants_Report() => VerifyFastHash.VerifyAsync("""
        using System.IO;
        using System.Security.Cryptography;
        using System.Text;
        using System.Threading.Tasks;

        class C
        {
            bool Try(string password, byte[] destination) =>
                {|#0:SHA256.TryHashData(Encoding.UTF8.GetBytes(password), destination, out _)|};

            ValueTask<byte[]> Static(Stream passwordStream) => {|#1:SHA512.HashDataAsync(passwordStream)|};

            Task<byte[]> Instance(Stream pinStream)
            {
                using var sha = SHA384.Create();
                return {|#2:sha.ComputeHashAsync(pinStream)|};
            }
        }
        """,
        VerifyFastHash.Diagnostic().WithLocation(0).WithArguments("SHA256", "password"),
        VerifyFastHash.Diagnostic().WithLocation(1).WithArguments("SHA512", "passwordStream"),
        VerifyFastHash.Diagnostic().WithLocation(2).WithArguments("SHA384", "pinStream"));

    [Fact]
    public Task FastHash_OtherStaticMembersOfAHashType_DoNotReport() => VerifyFastHash.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
        #pragma warning disable SYSLIB0045
            // SHA256.Create(string) takes an algorithm name; only HashData/TryHashData/HashDataAsync hash their input.
            object? M(string password) => SHA256.Create(password);
        #pragma warning restore SYSLIB0045
        }
        """);

    [Fact]
    public Task FastHash_InstanceCall_NamesTheReceiverType() => VerifyFastHash.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string password)
            {
                // ComputeHash is declared on HashAlgorithm; the message names the receiver's type.
                using var sha = SHA256.Create();
                return {|#0:sha.ComputeHash(Encoding.UTF8.GetBytes(password))|};
            }
        }
        """,
        VerifyFastHash.Diagnostic().WithLocation(0).WithArguments("SHA256", "password"));

    [Fact]
    public Task FastHash_CustomHmacSubclass_IsAnHmac() => VerifyFastHash.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class MyHmac : HMAC
        {
            public MyHmac(byte[] key) { Key = key; }
            protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
            protected override byte[] HashFinal() => new byte[0];
            public override void Initialize() { }
        }

        class C
        {
            HMAC M(string password) => {|#0:new MyHmac(Encoding.UTF8.GetBytes(password))|};
        }
        """,
        VerifyFastHash.Diagnostic().WithLocation(0).WithArguments("MyHmac", "password"));

    [Fact]
    public Task FastHash_CancellationTokenArgument_IsNotTheHashedInput() => VerifyFastHash.VerifyAsync("""
        using System.IO;
        using System.Security.Cryptography;
        using System.Threading;
        using System.Threading.Tasks;

        class C
        {
            ValueTask<byte[]> M(Stream payload, CancellationToken pinEntry) => SHA256.HashDataAsync(payload, pinEntry);
        }
        """);

    [Fact]
    public async Task FastHash_HashAlgorithmWithoutStaticHashTypes_StillReportsInstanceCalls()
    {
        // A framework exposing the HashAlgorithm hierarchy but none of the one-shot static types is still analyzed.
        CSharpCompilation compilation = CoreLibOnly.Compile("""
            namespace System.Security.Cryptography
            {
                public abstract class HashAlgorithm { public byte[] ComputeHash(byte[] buffer) => buffer; }
                public sealed class Fnv1a : HashAlgorithm { }
            }

            class C
            {
                byte[] M(byte[] passwordBytes) => new System.Security.Cryptography.Fnv1a().ComputeHash(passwordBytes);
            }
            """);

        Diagnostic diagnostic = Assert.Single(await CoreLibOnly.AnalyzeAsync(new FastHashOnPasswordAnalyzer(), compilation));
        Assert.Equal(
            "'Fnv1a' is a fast hash and must not be used on the password 'passwordBytes'; use Masterly.Hash.Password.Hash",
            diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture));
    }

    private const string Base64OfSha256 = """
        using System;
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            string M(string password) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
        }
        """;

    [Fact]
    public async Task FastHash_FixProperty_SetOnlyWhenPasswordHashExists()
    {
        Diagnostic withHash = Assert.Single(await AnalyzeNet80Async(new FastHashOnPasswordAnalyzer(), true, Base64OfSha256));
        Assert.Equal(FastHashOnPasswordAnalyzer.FixReplaceWrapper, withHash.Properties[FastHashOnPasswordAnalyzer.FixKey]);

        Diagnostic withoutHash = Assert.Single(await AnalyzeNet80Async(new FastHashOnPasswordAnalyzer(), false, Base64OfSha256));
        Assert.False(withoutHash.Properties.ContainsKey(FastHashOnPasswordAnalyzer.FixKey));
    }

    [Fact]
    public async Task FastHash_ToHexStringLowerWrapper_IsAStringWrapper()
    {
        // Convert.ToHexStringLower is .NET 9+, so this compiles against the running runtime's assemblies.
        Diagnostic diagnostic = Assert.Single(await AnalyzeRuntimeAsync(new FastHashOnPasswordAnalyzer(), """
            using System;
            using System.Security.Cryptography;
            using System.Text;

            class C
            {
                string M(string password) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
            }
            """));
        Assert.Equal(FastHashOnPasswordAnalyzer.FixReplaceWrapper, diagnostic.Properties[FastHashOnPasswordAnalyzer.FixKey]);
    }

    private static Task AssertNoFastHashFix(string source) => VerifyFastHashFix.VerifyAsync(source, source);

    [Fact]
    public Task FastHash_Fix_NotOffered_ForOtherConvertOrToStringMethods() => AssertNoFastHashFix("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        static class Hex
        {
            public static string ToString(byte[] digest) => digest.Length.ToString();
        }

        class C
        {
            // Convert.ToString(object) prints "System.Byte[]"; Hex.ToString is not BitConverter.ToString.
            string? A(string password) => Convert.ToString({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
            string B(string password) => Hex.ToString({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
        }
        """);

    [Fact]
    public Task FastHash_Fix_NotOffered_ForCustomEncodingMethods() => AssertNoFastHashFix("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class Utf8Codec : UTF8Encoding
        {
            public byte[] Encode(string text) => GetBytes(text.Normalize());
        }

        class C
        {
            // Only Encoding.GetBytes(string) is known to be what Password.Hash(string) does to its input.
            string M(string password) => Convert.ToBase64String({|MH0001:SHA256.HashData(new Utf8Codec().Encode(password))|});
        }
        """);

    [Fact]
    public Task FastHash_LocalFromOtherEncodingMember_IsNotFollowed() => VerifyFastHash.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M()
            {
                // An Encoding member that is not GetBytes(string) has no argument to trace.
                byte[] bytes = Encoding.UTF8.GetPreamble();
                return SHA256.HashData(bytes);
            }
        }
        """);

    // ================================================================ CodeFixHelpers (using directives, qualification)

    [Fact]
    public Task Using_FileWithOnlyANamespace_GoesAboveTheNamespace() => VerifyObsoleteFixAsync("""
        namespace App
        {
            class C
            {
                string M(Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
            }
        }
        """, """
        using Masterly.Hash;

        namespace App
        {
            class C
            {
                string M(Masterly.Hash.IHash hasher, string plain) => Password.Hash(plain);
            }
        }
        """);

    [Fact]
    public Task Using_CompilationUnitUsingsWin_OverNamespaceUsings() => VerifyObsoleteFixAsync("""
        using System;

        namespace App
        {
            using System.Text;

            class C
            {
                string M(Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
            }
        }
        """, """
        using System;
        using Masterly.Hash;

        namespace App
        {
            using System.Text;

            class C
            {
                string M(Masterly.Hash.IHash hasher, string plain) => Password.Hash(plain);
            }
        }
        """);

    [Fact]
    public Task Using_AliasToTheNamespace_DoesNotCountAsTheUsing() => VerifyObsoleteFixAsync("""
        using MH = Masterly.Hash;

        class C
        {
            string M(MH.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
        }
        """, """
        using Masterly.Hash;
        using MH = Masterly.Hash;

        class C
        {
            string M(MH.IHash hasher, string plain) => Password.Hash(plain);
        }
        """);

    [Fact]
    public Task Using_CaseInsensitiveTie_InsertedBeforeTheExistingUsing() => VerifyObsoleteFixAsync("""
        using masterly.hash;

        namespace masterly.hash { public class Marker { } }

        class C
        {
            string M(Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
        }
        """, """
        using Masterly.Hash;
        using masterly.hash;

        namespace masterly.hash { public class Marker { } }

        class C
        {
            string M(Masterly.Hash.IHash hasher, string plain) => Password.Hash(plain);
        }
        """);

    [Fact]
    public Task Qualification_IsGlobal_SoALocalTypeNamedMasterlyDoesNotCaptureIt() => VerifyObsoleteFixAsync("""
        namespace App
        {
            class Masterly { }

            class C
            {
                string M(global::Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
            }
        }
        """, """
        using Masterly.Hash;

        namespace App
        {
            class Masterly { }

            class C
            {
                string M(global::Masterly.Hash.IHash hasher, string plain) => Password.Hash(plain);
            }
        }
        """);

    [Fact]
    public Task Using_NotAdded_WhenTheSimpleNameIsAlreadyAmbiguous() => VerifyObsoleteFixAsync("""
        using A;
        using B;

        namespace A { public class Password { } }
        namespace B { public class Password { } }

        class C
        {
            string M(Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
        }
        """, """
        using A;
        using B;

        namespace A { public class Password { } }
        namespace B { public class Password { } }

        class C
        {
            string M(Masterly.Hash.IHash hasher, string plain) => Masterly.Hash.Password.Hash(plain);
        }
        """);

    private static Task VerifyObsoleteFixAsync(string source, string fixedSource) =>
        VerifyObsoleteFix.VerifyAsync(source, fixedSource);

    // ================================================================ code fix providers

    [Fact]
    public async Task FixedTimeEquals_WrongFixMode_NoFix()
    {
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync("""
            using System.Linq;

            class C
            {
                bool A(byte[] computed, byte[] expectedMac) => computed.SequenceEqual(expectedMac);
            }
            """);
        var provider = new FixedTimeEqualsCodeFixProvider();
        Diagnostic good = await probe.DiagnosticAtAsync(Descriptors.NonConstantTimeComparison, "computed.SequenceEqual(expectedMac)",
            NonConstantTimeComparisonAnalyzer.FixKey, NonConstantTimeComparisonAnalyzer.FixFixedTimeEquals);
        Diagnostic other = await probe.DiagnosticAtAsync(Descriptors.NonConstantTimeComparison, "computed.SequenceEqual(expectedMac)",
            NonConstantTimeComparisonAnalyzer.FixKey, "Other");

        Assert.Single(await probe.GetActionsAsync(provider, good));
        Assert.Empty(await probe.GetActionsAsync(provider, other));
    }

    [Fact]
    public async Task ObsoleteApi_WrongFixMode_NoFix()
    {
        const string source = """
            using Masterly.Hash;

            class C
            {
                string M(IHash hasher, string plain) => hasher.ComputeHash(plain);
            }
            """;
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync(source);
        var provider = new ObsoleteApiCodeFixProvider();
        Diagnostic good = await probe.DiagnosticAtAsync(Descriptors.ObsoleteApi, "hasher.ComputeHash(plain)",
            ObsoleteApiAnalyzer.FixKey, ObsoleteApiAnalyzer.FixPasswordHash);
        Diagnostic other = await probe.DiagnosticAtAsync(Descriptors.ObsoleteApi, "hasher.ComputeHash(plain)",
            ObsoleteApiAnalyzer.FixKey, "Other");

        CodeAction action = Assert.Single(await probe.GetActionsAsync(provider, good));
        Assert.Equal(
            source.Replace("=> hasher.ComputeHash(plain);", "=> Password.Hash(plain);", StringComparison.Ordinal),
            await probe.ApplyAsync(action));
        Assert.Empty(await probe.GetActionsAsync(provider, other));
    }

    [Fact]
    public Task FixedTimeEquals_CallPassedAsAnArgument_IsFixed() => VerifyComparisonFix.VerifyAsync("""
        using System.Linq;

        #nullable enable
        class C
        {
            static bool Id(bool value) => value;
            bool M(byte[] computed, byte[] expectedMac) => Id({|MH0002:computed.SequenceEqual(expectedMac)|});
        }
        """, """
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            static bool Id(bool value) => value;
            bool M(byte[] computed, byte[] expectedMac) => Id(CryptographicOperations.FixedTimeEquals(computed, expectedMac));
        }
        """);

    [Fact]
    public Task ObsoleteApi_CallPassedAsAnArgument_IsFixed() => VerifyObsoleteFix.VerifyAsync("""
        using Masterly.Hash;

        class C
        {
            static string Id(string value) => value;
            string M(IHash hasher, string plain) => Id({|MH0006:hasher.ComputeHash(plain)|});
        }
        """, """
        using Masterly.Hash;

        class C
        {
            static string Id(string value) => value;
            string M(IHash hasher, string plain) => Id(Password.Hash(plain));
        }
        """);

    // ================================================================ OperationHelpers

    [Fact]
    public Task ArrayEmpty_IsAnEmptyOperand() => VerifyComparison.VerifyAsync("""
        using System;
        using System.Linq;

        class C
        {
            bool M(byte[] expectedMac) => expectedMac.SequenceEqual(Array.Empty<byte>());
        }
        """);

    // ================================================================ NonConstantTimeComparisonAnalyzer

    [Theory]
    [InlineData("Convert.ToBase64String(mac) == header", "mac", "==")]
    [InlineData("Convert.ToHexString(mac) == header", "mac", "==")]
    [InlineData("Hex.ToHexStringLower(mac) == header", "mac", "==")]
    [InlineData("Encoding.UTF8.GetString(mac) == header", "mac", "==")]
    [InlineData("Encoding.UTF8.GetBytes(token).SequenceEqual(bytes)", "token", "SequenceEqual")]
    [InlineData("token.ToString() == header", "token", "==")]
    [InlineData("token.AsSpan().SequenceEqual(header)", "token", "SequenceEqual")]
    [InlineData("token.AsMemory().ToString() == header", "token", "==")]
    [InlineData("mac.ToArray().SequenceEqual(bytes)", "mac", "SequenceEqual")]
    [InlineData("token.ToCharArray().SequenceEqual(chars)", "token", "SequenceEqual")]
    [InlineData("token.Trim() == header", "token", "==")]
    [InlineData("token.TrimStart() == header", "token", "==")]
    [InlineData("token.TrimEnd() == header", "token", "==")]
    [InlineData("token.ToLower() == header", "token", "==")]
    [InlineData("token.ToLowerInvariant() == header", "token", "==")]
    [InlineData("token.ToUpper() == header", "token", "==")]
    [InlineData("token.ToUpperInvariant() == header", "token", "==")]
    public Task Comparison_LooksThroughEveryValuePreservingMethod(string comparison, string secret, string kind) =>
        VerifyComparison.VerifyAsync($$"""
            using System;
            using System.Linq;
            using System.Text;

            static class Hex
            {
                public static string ToHexStringLower(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();
            }

            class C
            {
                bool M(byte[] mac, string token, string header, byte[] bytes, char[] chars) => {|#0:{{comparison}}|};
            }
            """,
            VerifyComparison.Diagnostic().WithLocation(0).WithArguments(secret, kind));

    [Fact]
    public Task Comparison_ReportsTheOperatorAndMethodNames() => VerifyComparison.VerifyAsync("""
        class C
        {
            void M(string signature, string header)
            {
                _ = {|#0:header != signature|};
                _ = {|#1:string.Compare(signature, header)|};
                _ = {|#2:string.CompareOrdinal(signature, header)|};
                _ = {|#3:signature.Equals(header)|};
            }
        }
        """,
        VerifyComparison.Diagnostic().WithLocation(0).WithArguments("signature", "!="),
        VerifyComparison.Diagnostic().WithLocation(1).WithArguments("signature", "string.Compare"),
        VerifyComparison.Diagnostic().WithLocation(2).WithArguments("signature", "string.CompareOrdinal"),
        VerifyComparison.Diagnostic().WithLocation(3).WithArguments("signature", "string.Equals"));

    [Fact]
    public Task Comparison_UserDefinedOperatorWithANonStringOperand_DoesNotReport() => VerifyComparison.VerifyAsync("""
        #pragma warning disable CS0660, CS0661
        class Pattern
        {
            public static bool operator ==(string text, Pattern pattern) => false;
            public static bool operator !=(string text, Pattern pattern) => true;
        }

        class C
        {
            bool M(string token, Pattern pattern) => token == pattern;
        }
        """);

    [Fact]
    public Task Comparison_StringComparisonArgument_IsNotAnOperand() => VerifyComparison.VerifyAsync("""
        using System;

        class C
        {
            bool M(string userName, string other, StringComparison tokenComparison) =>
                string.Equals(userName, other, tokenComparison);
        }
        """);

    [Fact]
    public Task Comparison_OtherLinqMethodsAndNonByteElements_DoNotReport() => VerifyComparison.VerifyAsync("""
        using System.Linq;

        class C
        {
            void M(byte[] expectedMac, int[] mac, int[] other)
            {
                _ = expectedMac.Contains((byte)1);
                _ = mac.SequenceEqual(other);
            }
        }
        """);

    [Fact]
    public Task Comparison_SequenceEqualOperands_AreInParameterOrder() => VerifyComparison.VerifyAsync("""
        using System.Linq;

        class C
        {
            bool M(byte[] expectedMac, byte[] providedMac) => {|#0:Enumerable.SequenceEqual(second: providedMac, first: expectedMac)|};
        }
        """,
        VerifyComparison.Diagnostic().WithLocation(0).WithArguments("expectedMac", "SequenceEqual"));

    [Fact]
    public Task Comparison_SequenceEqualWithComparer_Reports() => VerifyComparison.VerifyAsync("""
        using System.Collections.Generic;
        using System.Linq;

        class C
        {
            bool M(byte[] expectedMac, byte[] other) => {|#0:expectedMac.SequenceEqual(other, EqualityComparer<byte>.Default)|};
        }
        """,
        VerifyComparison.Diagnostic().WithLocation(0).WithArguments("expectedMac", "SequenceEqual"));

    [Fact]
    public Task Comparison_NestedConditionalAccess_NamesTheInnerReceiver() => VerifyComparison.VerifyAsync("""
        using System.Linq;

        class Holder { public byte[]? Mac { get; set; } }

        class C
        {
            bool? M(Holder? holder, byte[] other) => holder?.Mac?{|#0:.SequenceEqual(other)|};
        }
        """,
        VerifyComparison.Diagnostic().WithLocation(0).WithArguments("Mac", "SequenceEqual"));

    [Theory]
    [InlineData(3, true)]
    [InlineData(4, false)]
    public Task Comparison_InstanceUnwrapping_StopsAfterThreeCalls(int calls, bool reported) => VerifyComparison.VerifyAsync(
        "class C { bool M(string token, string other) => "
        + Mark("token" + string.Concat(Enumerable.Repeat(".Trim()", calls)) + " == other", reported, "MH0002") + "; }");

    [Theory]
    [InlineData(3, true)]
    [InlineData(4, false)]
    public Task Comparison_ArgumentUnwrapping_StopsAfterThreeCalls(int calls, bool reported) => VerifyComparison.VerifyAsync(
        "using System.Linq; class C { bool M(byte[] mac, byte[] other) => "
        + Mark("mac" + string.Concat(Enumerable.Repeat(".ToArray()", calls)) + ".SequenceEqual(other)", reported, "MH0002") + "; }");

    private const string TwoOverloadPolyfill = """
        namespace System.Security.Cryptography
        {
            public static class CryptographicOperations
            {
                public static bool FixedTimeEquals(byte[] left) => left.Length == 0;
                public static bool FixedTimeEquals(byte[] left, byte[] right) => left.Length == right.Length;
            }
        }
        """;

    [Fact]
    public Task Comparison_PolyfillWithAnyMatchingOverload_IsUsed()
    {
        var test = new CSharpCodeFixTest<NonConstantTimeComparisonAnalyzer, FixedTimeEqualsCodeFixProvider, DefaultVerifier>
        {
            TestCode = """
                using System.Linq;

                #nullable enable
                class C
                {
                    bool M(byte[] computed, byte[] expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac)|};
                }
                """,
            FixedCode = """
                using System.Linq;
                using System.Security.Cryptography;

                #nullable enable
                class C
                {
                    bool M(byte[] computed, byte[] expectedMac) => CryptographicOperations.FixedTimeEquals(computed, expectedMac);
                }
                """,
            ReferenceAssemblies = References.NetStandard20,
        };
        test.TestState.Sources.Add(("/0/Polyfill.cs", TwoOverloadPolyfill));
        test.FixedState.Sources.Add(("/0/Polyfill.cs", TwoOverloadPolyfill));
        return test.RunAsync();
    }

    [Fact]
    public Task Comparison_Fix_NotOffered_WhenAnOperandIsNotAByteBuffer() => VerifyComparisonFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;

        class C
        {
            bool M(ReadOnlySpan<byte> expectedMac, ArraySegment<byte> computed) => {|MH0002:expectedMac.SequenceEqual(computed)|};
        }
        """, """
        using System;
        using System.Security.Cryptography;

        class C
        {
            bool M(ReadOnlySpan<byte> expectedMac, ArraySegment<byte> computed) => {|MH0002:expectedMac.SequenceEqual(computed)|};
        }
        """);

    [Fact]
    public Task Comparison_Fix_NotOffered_ForSuppressionOutsideParentheses() => VerifyComparisonFix.VerifyAsync("""
        using System.Linq;

        #nullable enable
        class C
        {
            bool M(byte[] expectedMac, byte[] computed) => {|MH0002:computed.SequenceEqual(((expectedMac))!)|};
        }
        """, """
        using System.Linq;

        #nullable enable
        class C
        {
            bool M(byte[] expectedMac, byte[] computed) => {|MH0002:computed.SequenceEqual(((expectedMac))!)|};
        }
        """);

    [Fact]
    public Task Comparison_Fix_Offered_WhenOnlyAnEnclosingExpressionIsSuppressed() => VerifyComparisonFix.VerifyAsync("""
        using System.Linq;

        #nullable enable
        class C
        {
            // The '!' applies to the comparison result, not to either operand.
            bool M(byte[] expectedMac, byte[] computed) => ({|MH0002:computed.SequenceEqual(expectedMac)|})!;
        }
        """, """
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            // The '!' applies to the comparison result, not to either operand.
            bool M(byte[] expectedMac, byte[] computed) => (CryptographicOperations.FixedTimeEquals(computed, expectedMac))!;
        }
        """);

    // ================================================================ HardCodedPepperAnalyzer

    [Fact]
    public Task Pepper_OtherConstructors_AreNotPepperArguments() => VerifyPepper.VerifyAsync("""
        class Envelope { public Envelope(byte[] payload) { } }

        class C
        {
            object M() => new Envelope(new byte[] { 1, 2, 3 });
        }
        """);

    private const string PepperStubs = """
        namespace Masterly.Hash.Pepper
        {
            public sealed class HmacPepper
            {
                public HmacPepper(string keyId, byte[] key) { }
                public static HmacPepper FromBase64(string keyId, byte[] key) => new HmacPepper(keyId, key);
                public static HmacPepper FromBytes(string keyId, byte[] key) => new HmacPepper(keyId, key);
                public void Rotate(byte[] key) { }
            }
        }
        """;

    [Fact]
    public Task Pepper_OnlyTheStaticFromBase64Factory_IsInspected() => VerifyWithOwnStubsAsync<HardCodedPepperAnalyzer>("""
        using Masterly.Hash.Pepper;

        class C
        {
            void M(HmacPepper pepper)
            {
                _ = HmacPepper.FromBase64("k1", {|#0:new byte[] { 1, 2, 3 }|});
                _ = HmacPepper.FromBytes("k1", new byte[] { 1, 2, 3 });
                pepper.Rotate(new byte[] { 1, 2, 3 });
            }
        }
        """, PepperStubs,
        VerifyPepper.Diagnostic().WithLocation(0).WithArguments("pepper key"));

    [Fact]
    public Task Pepper_ByteArrayParameter_IsNotInspectedAsAKeyRing() => VerifyPepper.VerifyAsync("""
        using System.Collections.Generic;
        using Masterly.Hash.Pepper;

        class KeyBuilder : List<string>
        {
            public static implicit operator byte[](KeyBuilder builder) => new byte[builder.Count];
        }

        class C
        {
            HmacPepper M() => new HmacPepper("k1", new KeyBuilder { "not-a-key" });
        }
        """);

    [Fact]
    public Task Pepper_ZeroFilledKeyRingEntry_ReportsPepperKey() => VerifyPepper.VerifyAsync("""
        using System.Collections.Generic;
        using Masterly.Hash.Pepper;

        class C
        {
            HmacPepper M() => new HmacPepper("k1", new Dictionary<string, byte[]> { ["k1"] = {|#0:new byte[32]|} });
        }
        """,
        VerifyPepper.Diagnostic().WithLocation(0).WithArguments("pepper key"));

    [Fact]
    public Task Pepper_NamedTargets_AreQuotedInTheMessage() => VerifyPepper.VerifyAsync("""
        class Options
        {
            public string SigningKey { get; set; } = {|#0:"super-secret-signing-key"|};
            public string? SecretKey { get; set; }
        }

        class C
        {
            private const string Pepper = {|#1:"pepper-in-source"|};

            void M(Options options)
            {
                byte[] pepper = {|#2:[1, 2, 3]|};
                string hmacKey;
                hmacKey = {|#3:"x"|};
                options.SecretKey = {|#4:"assigned"|};
            }
        }
        """,
        VerifyPepper.Diagnostic().WithLocation(0).WithArguments("'SigningKey'"),
        VerifyPepper.Diagnostic().WithLocation(1).WithArguments("'Pepper'"),
        VerifyPepper.Diagnostic().WithLocation(2).WithArguments("'pepper'"),
        VerifyPepper.Diagnostic().WithLocation(3).WithArguments("'hmacKey'"),
        VerifyPepper.Diagnostic().WithLocation(4).WithArguments("'SecretKey'"));

    [Fact]
    public Task Pepper_EmptyOrDerivedArrays_AreNotKeys() => VerifyPepper.VerifyAsync("""
        using System;
        using System.Collections.Generic;
        using Masterly.Hash.Pepper;

        class KeyRing : Dictionary<string, byte[]>
        {
            public void Add(string keyId, byte[,] material) { }
        }

        class C
        {
            void M()
            {
                _ = new HmacPepper("k1", ""u8.ToArray());
                _ = new HmacPepper("k1", new byte[0]);
                // A copy of a zero-filled buffer is not the zero-filled array passed directly.
                _ = new HmacPepper("k1", ((ReadOnlySpan<byte>)new byte[32]).ToArray());
                // Only a one-dimensional zero-filled array is a key.
                _ = new HmacPepper("k1", new KeyRing { { "k1", new byte[2, 16] } });
                byte[] pepper = ""u8.ToArray();
            }
        }
        """);

    [Fact]
    public Task Pepper_FromHexString_IsADecoder_ButLookalikesAndOtherConvertMethodsAreNot() => VerifyPepper.VerifyAsync("""
        using System;

        static class Codec
        {
            public static byte[] FromBase64String(string text) => Convert.FromBase64String(text);
        }

        class C
        {
            void M()
            {
                byte[] pepper = {|#0:Convert.FromHexString("00112233445566778899aabbccddeeff")|};
                byte[] signingKey = Codec.FromBase64String("c2VjcmV0");
                bool hmacKey = Convert.ToBoolean("true");
            }
        }
        """,
        VerifyPepper.Diagnostic().WithLocation(0).WithArguments("'pepper'"));

    [Theory]
    [InlineData(8, true)]
    [InlineData(9, false)]
    public Task Pepper_ConditionalWhenTrueChain_StopsAtDepthLimit(int levels, bool reported)
    {
        string chain = "\"literal\"";
        for (int i = 0; i < levels; i++)
            chain = i == levels - 1 ? "b ? " + chain + " : s" : "(b ? " + chain + " : s)";
        return VerifyPepper.VerifyAsync("class C { void M(bool b, string s) { string pepper = " + Mark(chain, reported, "MH0003") + "; } }");
    }

    [Theory]
    [InlineData(8, true)]
    [InlineData(9, false)]
    public Task Pepper_ConditionalWhenFalseChain_StopsAtDepthLimit(int levels, bool reported)
    {
        string chain = string.Concat(Enumerable.Repeat("b ? s : ", levels)) + "\"literal\"";
        return VerifyPepper.VerifyAsync("class C { void M(bool b, string s) { string pepper = " + Mark(chain, reported, "MH0003") + "; } }");
    }

    [Theory]
    [InlineData(7, true)]
    [InlineData(8, false)]
    public Task Pepper_ToArrayAfterFallbacks_CountsTowardTheDepthLimit(int fallbacks, bool reported)
    {
        string chain = string.Concat(Enumerable.Repeat("a ?? ", fallbacks)) + "\"literal\"u8.ToArray()";
        return VerifyPepper.VerifyAsync("class C { void M(byte[]? a) { byte[]? pepper = " + Mark(chain, reported, "MH0003") + "; } }");
    }

    [Theory]
    [InlineData(7, true)]
    [InlineData(8, false)]
    public Task Pepper_DecoderAfterFallbacks_CountsTowardTheDepthLimit(int fallbacks, bool reported)
    {
        string chain = string.Concat(Enumerable.Repeat("a ?? ", fallbacks)) + "System.Convert.FromBase64String(\"AAECAwQFBgcICQoLDA0ODw==\")";
        return VerifyPepper.VerifyAsync("class C { void M(byte[]? a) { byte[]? pepper = " + Mark(chain, reported, "MH0003") + "; } }");
    }

    // ================================================================ PasswordLoggingAnalyzer

    private const string LoggingStubs = """
        namespace Microsoft.Extensions.Logging
        {
            using System;

            public interface ILogger
            {
                void Log(string message);
                void Flush(string reason);
                IDisposable? BeginScope<TState>(TState state) where TState : notnull;
            }

            public static class LoggerExtensions
            {
                public static void LogInformation(this ILogger logger, string message) { }
                public static string Redact(this ILogger logger, string value) => "***";
            }
        }
        """;

    [Fact]
    public Task Logging_OnlyLogAndBeginScopeMembers_AreSinks() => VerifyWithOwnStubsAsync<PasswordLoggingAnalyzer>("""
        using Microsoft.Extensions.Logging;

        class C
        {
            void M(ILogger logger, string password)
            {
                logger.Log({|#0:password|});
                logger.LogInformation({|#1:password|});
                using (logger.BeginScope({|#2:password|})) { }
                logger.Flush(password);
                _ = logger.Redact(password);
            }
        }
        """, LoggingStubs,
        VerifyLogging.Diagnostic().WithLocation(0).WithArguments("password", "ILogger.Log"),
        VerifyLogging.Diagnostic().WithLocation(1).WithArguments("password", "LoggerExtensions.LogInformation"),
        VerifyLogging.Diagnostic().WithLocation(2).WithArguments("password", "ILogger.BeginScope"));

    [Fact]
    public async Task Logging_OnlyWriteAndTraceMembersOfTrace_AreSinks()
    {
        // System.Diagnostics.Trace is not in CoreLib, so a project-defined one with extra members can be used.
        CSharpCompilation compilation = CoreLibOnly.Compile("""
            namespace System.Diagnostics
            {
                public static class Trace
                {
                    public static void WriteLine(string message) { }
                    public static void TraceInformation(string message) { }
                    public static void Annotate(string note) { }
                }
            }

            class C
            {
                void M(string password)
                {
                    System.Diagnostics.Trace.WriteLine(password);
                    System.Diagnostics.Trace.TraceInformation(password);
                    System.Diagnostics.Trace.Annotate(password);
                }
            }
            """);

        string[] messages = (await CoreLibOnly.AnalyzeAsync(new PasswordLoggingAnalyzer(), compilation))
            .Select(d => d.GetMessage(System.Globalization.CultureInfo.InvariantCulture))
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            new[]
            {
                "'password' may be written to a log by 'Trace.TraceInformation'; never log passwords",
                "'password' may be written to a log by 'Trace.WriteLine'; never log passwords",
            },
            messages);
    }

    [Fact]
    public Task Logging_StringConcatAndJoin_Report() => VerifyLogging.VerifyAsync("""
        using System;

        class C
        {
            void M(string user, string password)
            {
                Console.WriteLine(string.Concat("pw=", {|#0:password|}));
                Console.WriteLine(string.Join(",", user, {|#1:password|}));
            }
        }
        """,
        VerifyLogging.Diagnostic().WithLocation(0).WithArguments("password", "Console.WriteLine"),
        VerifyLogging.Diagnostic().WithLocation(1).WithArguments("password", "Console.WriteLine"));

    [Fact]
    public Task Logging_RevealMustBeOnSensitiveString() => VerifyLogging.VerifyAsync("""
        using System;
        using Masterly.Hash;

        class Envelope { public string Reveal() => "sealed"; }

        class C
        {
            void M(Envelope envelope, SensitiveString secret)
            {
                Console.WriteLine(envelope.Reveal());
                Console.WriteLine(secret.ToString());
            }
        }
        """);

    // Depth limit (8): each construct below adds one level. The first case of each pair reaches the password at
    // depth 8 (reported), the second at depth 9 (not followed).

    [Theory]
    [InlineData(7, true)]
    [InlineData(8, false)]
    public Task Logging_Depth_ConcatenationTerm(int levels, bool reported) => VerifyLogging.VerifyAsync(
        "using System; class C { void M(bool a, string password) => Console.WriteLine(\"x\" + ("
        + WhenFalseChain(levels, Mark("password", reported, "MH0004")) + ")); }");

    [Theory]
    [InlineData(6, true)]
    [InlineData(7, false)]
    public Task Logging_Depth_InterpolatedStringHandler(int levels, bool reported) => VerifyLogging.VerifyAsync(
        "using System.Diagnostics; class C { void M(bool a, string password) => Debug.WriteLineIf(a, $\"{("
        + WhenFalseChain(levels, Mark("password", reported, "MH0004")) + ")}\"); }");

    [Theory]
    [InlineData(7, true)]
    [InlineData(8, false)]
    public Task Logging_Depth_Interpolation(int levels, bool reported) => VerifyLogging.VerifyAsync(
        "using System; class C { void M(bool a, string password) => Console.WriteLine($\"{("
        + WhenFalseChain(levels, Mark("password", reported, "MH0004")) + ")}\"); }");

    [Theory]
    [InlineData(7, true)]
    [InlineData(8, false)]
    public Task Logging_Depth_ArrayElement(int levels, bool reported) => VerifyLogging.VerifyAsync(
        "using System; class C { void M(bool a, string password) => Console.WriteLine(\"{0}\", new object[] { "
        + WhenFalseChain(levels, Mark("password", reported, "MH0004")) + " }); }");

    [Theory]
    [InlineData(8, true)]
    [InlineData(9, false)]
    public Task Logging_Depth_ConditionalWhenTrue(int levels, bool reported)
    {
        string chain = Mark("password", reported, "MH0004");
        for (int i = 0; i < levels; i++)
            chain = "(a ? " + chain + " : \"\")";
        return VerifyLogging.VerifyAsync("using System; class C { void M(bool a, string password) => Console.WriteLine(" + chain + "); }");
    }

    [Theory]
    [InlineData(8, true)]
    [InlineData(9, false)]
    public Task Logging_Depth_CoalesceValue(int levels, bool reported)
    {
        string chain = Mark("password", reported, "MH0004");
        for (int i = 0; i < levels; i++)
            chain = "(" + chain + " ?? u)";
        return VerifyLogging.VerifyAsync("using System; class C { void M(string? u, string? password) => Console.WriteLine(" + chain + "); }");
    }

    [Theory]
    [InlineData(8, true)]
    [InlineData(9, false)]
    public Task Logging_Depth_CoalesceWhenNull(int levels, bool reported) => VerifyLogging.VerifyAsync(
        "using System; class C { void M(string? u, string? password) => Console.WriteLine("
        + string.Concat(Enumerable.Repeat("u ?? ", levels)) + Mark("password", reported, "MH0004") + "); }");

    [Theory]
    [InlineData(8, true)]
    [InlineData(9, false)]
    public Task Logging_Depth_StringMethodReceiver(int levels, bool reported) => VerifyLogging.VerifyAsync(
        "using System; class C { void M(string password) => Console.WriteLine("
        + Mark("password", reported, "MH0004") + string.Concat(Enumerable.Repeat(".Trim()", levels)) + "); }");

    [Theory]
    [InlineData(8, true)]
    [InlineData(9, false)]
    public Task Logging_Depth_StringConcatArgument(int levels, bool reported)
    {
        string chain = Mark("password", reported, "MH0004");
        for (int i = 0; i < levels; i++)
            chain = "string.Concat(\"\", " + chain + ")";
        return VerifyLogging.VerifyAsync("using System; class C { void M(string password) => Console.WriteLine(" + chain + "); }");
    }

    // ================================================================ ObsoleteApiAnalyzer

    [Fact]
    public Task Obsolete_ClassOnly_WithoutTheInterface_Reports() => VerifyWithOwnStubsAsync<ObsoleteApiAnalyzer>("""
        class C
        {
            string M(string plain) => {|#0:new Masterly.Hash.Hash().ComputeHash(plain)|};
        }
        """, """
        namespace Masterly.Hash
        {
            public class Hash { public string ComputeHash(string plainText) => plainText; }
        }
        """,
        VerifyObsolete.Diagnostic().WithLocation(0).WithSeverity(DiagnosticSeverity.Info).WithArguments("Hash.ComputeHash", "Password.Hash"));

    [Fact]
    public Task Obsolete_Fix_Offered_ForSubclassOverloadWithoutDefaults() => VerifyObsoleteFix.VerifyAsync("""
        using Masterly.Hash;

        class LegacyHash : Hash
        {
            public string ComputeHash(string plainText) => plainText;
        }

        class C
        {
            string M(LegacyHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
        }
        """, """
        using Masterly.Hash;

        class LegacyHash : Hash
        {
            public string ComputeHash(string plainText) => plainText;
        }

        class C
        {
            string M(LegacyHash hasher, string plain) => Password.Hash(plain);
        }
        """);

    [Fact]
    public Task Obsolete_Fix_NotOffered_WhenThePlainTextIsNotTheFirstParameter()
    {
        const string source = """
            using Masterly.Hash;

            class LegacyHash : Hash
            {
                public string ComputeHash(SupportedHash algorithm = SupportedHash.SHA512, string plainText = "") => plainText;
            }

            class C
            {
                string M(LegacyHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plainText: plain)|};
            }
            """;
        return VerifyObsoleteFix.VerifyAsync(source, source);
    }

    // ================================================================ WeakPbkdf2Analyzer

    [Fact]
    public async Task Pbkdf2_OnlyStaticPbkdf2AndConstructors_AreAnalyzed()
    {
        CSharpCompilation compilation = CoreLibOnly.Compile("""
            namespace System.Security.Cryptography
            {
                public readonly struct HashAlgorithmName { }

                public class Rfc2898DeriveBytes
                {
                    public static byte[] Pbkdf2(byte[] password, byte[] salt) => salt;
                    public static byte[] Pbkdf2(byte[] password, byte[] salt, int iterations) => salt;
                    public static byte[] Stretch(byte[] password, int iterations) => password;
                    public byte[] Derive(int iterations) => new byte[iterations];
                }
            }

            class C
            {
                void M(byte[] password, byte[] salt, System.Security.Cryptography.Rfc2898DeriveBytes kdf)
                {
                    // A static call has no constructor defaults to report.
                    _ = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(password, salt);
                    _ = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(password, salt, 1);
                    _ = System.Security.Cryptography.Rfc2898DeriveBytes.Stretch(password, 1);
                    _ = kdf.Derive(1);
                }
            }
            """);

        Diagnostic diagnostic = Assert.Single(await CoreLibOnly.AnalyzeAsync(new WeakPbkdf2Analyzer(), compilation));
        Assert.Equal(
            "Weak PBKDF2 parameters: 1 iterations is below the minimum of 100,000",
            diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture));
    }

    // ================================================================ refuted "equivalent" mutants

    // A second review found inputs that tell these mutants apart: an `__arglist` argument has no parameter, a user
    // conversion can turn an object initializer into a string argument, Convert.FromHexString also takes a span, and
    // project-defined types with the BCL metadata names (looked up in the source assembly first) can declare overloads
    // the BCL does not have.

    private static readonly MetadataReference CoreLibReference =
        MetadataReference.CreateFromFile(typeof(object).Assembly.Location);

    /// <summary>Like <see cref="AnalyzeNet80Async"/>, against System.Private.CoreLib only (no cryptography, no LINQ).</summary>
    private static Task<ImmutableArray<Diagnostic>> AnalyzeCoreLibAsync(DiagnosticAnalyzer analyzer, params string[] sources) =>
        AnalyzeAsync(analyzer, ImmutableArray.Create(CoreLibReference), sources);

    private static string Message(Diagnostic diagnostic) => diagnostic.GetMessage(System.Globalization.CultureInfo.InvariantCulture);

    private static string LocatedText(Diagnostic diagnostic) =>
        diagnostic.Location.SourceTree!.GetText().ToString(diagnostic.Location.SourceSpan);

    [Fact]
    public async Task Pepper_ArglistArgument_HasNoParameter_AndIsSkipped()
    {
        // The `__arglist(...)` argument has a null Parameter; it must be skipped, while the byte[] key is still checked.
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeNet80Async(new HardCodedPepperAnalyzer(), false, """
            namespace Masterly.Hash.Pepper
            {
                public sealed class HmacPepper
                {
                    public HmacPepper(string keyId, byte[] key, __arglist) { }
                }
            }

            class C
            {
                object M() => new Masterly.Hash.Pepper.HmacPepper("k1", new byte[] { 1, 2, 3 }, __arglist(1, "x"));
            }
            """);

        Diagnostic diagnostic = Assert.Single(diagnostics);
        Assert.Equal("MH0003", diagnostic.Id);
        Assert.Equal("new byte[] { 1, 2, 3 }", LocatedText(diagnostic));
    }

    [Fact]
    public Task Pepper_StringParameter_IsNeverInspected_EvenWhenConvertedFromAnInitializedObject() => VerifyPepper.VerifyAsync("""
        using Masterly.Hash.Pepper;

        class KeyId
        {
            public string Value { get; set; } = "";
            public static implicit operator string(KeyId id) => id.Value;
        }

        class C
        {
            // The key id is an identifier, not key material, however it is built.
            HmacPepper M(byte[] key) => new HmacPepper(new KeyId { Value = "k1" }, key);
        }
        """);

    [Fact]
    public Task Pepper_DecoderArgument_IsNotAZeroFilledKey() => VerifyPepper.VerifyAsync("""
        using System;
        using Masterly.Hash.Pepper;

        class C
        {
            void M()
            {
                // new char[64] is the decoder's input, not key material; only a zero-filled array passed directly is a key.
                byte[] pepper = Convert.FromHexString(new char[64]);
                _ = new HmacPepper("k1", Convert.FromHexString(new char[64]));
                _ = new HmacPepper("k1", {|#0:new byte[32]|});
            }
        }
        """,
        VerifyPepper.Diagnostic().WithLocation(0).WithArguments("pepper key"));

    [Fact]
    public async Task Pbkdf2_ArglistArgument_HasNoParameter_AndIsSkipped()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeCoreLibAsync(new WeakPbkdf2Analyzer(), """
            namespace System.Security.Cryptography
            {
                public readonly struct HashAlgorithmName
                {
                    public static HashAlgorithmName SHA256 => default;
                }

                public class Rfc2898DeriveBytes
                {
                    public Rfc2898DeriveBytes(string password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm, __arglist) { }
                }
            }

            class C
            {
                object M(string password, byte[] salt) =>
                    new System.Security.Cryptography.Rfc2898DeriveBytes(
                        password, salt, 1, System.Security.Cryptography.HashAlgorithmName.SHA256, __arglist(1));
            }
            """);

        Diagnostic diagnostic = Assert.Single(diagnostics);
        Assert.Equal("Weak PBKDF2 parameters: 1 iterations is below the minimum of 100,000", Message(diagnostic));
    }

    private const string ProjectLinq = """
        namespace System.Linq
        {
            public static class Enumerable
            {
                public static bool SequenceEqual<T>(T[] first) => first.Length == 0;
                public static bool SequenceEqual<T>(T[] first, params T[] second) => first.Length == second.Length;
            }
        }

        namespace System.Security.Cryptography
        {
            public static class CryptographicOperations
            {
                public static bool FixedTimeEquals(byte[] left, byte[] right) => left.Length == right.Length;
            }
        }
        """;

    [Fact]
    public async Task Comparison_SingleArgumentSequenceEqual_IsNotAComparison()
    {
        Assert.Empty(await AnalyzeCoreLibAsync(new NonConstantTimeComparisonAnalyzer(), ProjectLinq, """
            class C
            {
                bool M(byte[] mac) => System.Linq.Enumerable.SequenceEqual<byte>(mac);
            }
            """));
    }

    [Fact]
    public async Task Comparison_Fix_RequiresEveryArgumentToBeExplicit()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeCoreLibAsync(new NonConstantTimeComparisonAnalyzer(), ProjectLinq, """
            class C
            {
                bool Explicit(byte[] mac, byte[] other) => System.Linq.Enumerable.SequenceEqual<byte>(mac, other);

                // The second argument is a params array built by the compiler (ArgumentKind.ParamArray).
                bool Params(byte[] mac) => System.Linq.Enumerable.SequenceEqual<byte>(mac, 1, 2);
            }
            """);

        Diagnostic[] ordered = diagnostics.OrderBy(d => d.Location.SourceSpan.Start).ToArray();
        Assert.Equal(2, ordered.Length);
        Assert.Equal("System.Linq.Enumerable.SequenceEqual<byte>(mac, other)", LocatedText(ordered[0]));
        Assert.Equal("System.Linq.Enumerable.SequenceEqual<byte>(mac, 1, 2)", LocatedText(ordered[1]));
        Assert.Equal(NonConstantTimeComparisonAnalyzer.FixFixedTimeEquals, ordered[0].Properties[NonConstantTimeComparisonAnalyzer.FixKey]);
        Assert.False(ordered[1].Properties.ContainsKey(NonConstantTimeComparisonAnalyzer.FixKey));
    }

    private const string ProjectCryptography = """
        namespace System.Security.Cryptography
        {
            public abstract class HashAlgorithm
            {
                public byte[] ComputeHash(byte[] buffer) => buffer;
            }

            public sealed class Fnv : HashAlgorithm
            {
                // Same name as the span-based BCL method, but with the shape of ComputeHash.
                public byte[] TryComputeHash(byte[] buffer) => buffer;
            }

            public static class SHA256
            {
                public static byte[] HashData(byte[] source) => source;
                public static byte[] TryHashData(byte[] source) => source;
            }

            public static class SHA384
            {
                public static string HashData(byte[] source) => "";
            }

            public static class SHA512
            {
                public static byte[] HashData(byte[] source, int rounds = 1) => source;
            }
        }
        """;

    [Fact]
    public async Task FastHash_Fix_NotOffered_ForTryMethods_ExtraArgumentsOrNonByteArrayResults()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeCoreLibAsync(new FastHashOnPasswordAnalyzer(), ProjectCryptography, Stubs.MasterlyHash, """
            using System;
            using System.Security.Cryptography;
            using System.Text;

            class C
            {
                string Control(string password) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
                string StaticTry(string password) => Convert.ToBase64String(SHA256.TryHashData(Encoding.UTF8.GetBytes(password)));
                string InstanceTry(Fnv fnv, string password) => Convert.ToBase64String(fnv.TryComputeHash(Encoding.UTF8.GetBytes(password)));
                string DefaultedArgument(string password) => Convert.ToBase64String(SHA512.HashData(Encoding.UTF8.GetBytes(password)));
                string StringResult(string password)
                {
                    var hash = SHA384.HashData(Encoding.UTF8.GetBytes(password));
                    return hash;
                }
                byte[] CallControl(string password)
                {
                    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(password));
                    return hash;
                }
            }
            """);

        Diagnostic[] ordered = diagnostics.OrderBy(d => d.Location.SourceSpan.Start).ToArray();
        Assert.Equal(
            new[]
            {
                "'SHA256' is a fast hash and must not be used on the password 'password'; use Masterly.Hash.Password.Hash",
                "'SHA256' is a fast hash and must not be used on the password 'password'; use Masterly.Hash.Password.Hash",
                "'Fnv' is a fast hash and must not be used on the password 'password'; use Masterly.Hash.Password.Hash",
                "'SHA512' is a fast hash and must not be used on the password 'password'; use Masterly.Hash.Password.Hash",
                "'SHA384' is a fast hash and must not be used on the password 'password'; use Masterly.Hash.Password.Hash",
                "'SHA256' is a fast hash and must not be used on the password 'password'; use Masterly.Hash.Password.Hash",
            },
            ordered.Select(Message).ToArray());

        string?[] fixes = ordered
            .Select(d => d.Properties.TryGetValue(FastHashOnPasswordAnalyzer.FixKey, out string? fix) ? fix : null)
            .ToArray();
        Assert.Equal(
            new string?[] { FastHashOnPasswordAnalyzer.FixReplaceWrapper, null, null, null, null, FastHashOnPasswordAnalyzer.FixReplaceCall },
            fixes);
    }

    // ================================================================ third pass

    [Theory]
    [InlineData(false, "no fix property")]
    [InlineData(true, "a fix property with a null value")]
    public async Task FastHash_DiagnosticWithoutAFixMode_IsSkippedBeforeTheDocumentIsRead(bool withNullMode, string reason)
    {
        // A stale diagnostic (computed on a longer version of the document) whose span is now past the end of the
        // text. Without a fix mode the provider must move on without looking at the syntax: FindNode would throw on
        // the out-of-range span, and only diagnostics that carry a mode are worth rewriting.
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync("""
            class C
            {
            }
            """);
        SyntaxTree tree = (await probe.Document.GetSyntaxTreeAsync())!;
        int length = (await tree.GetTextAsync()).Length;
        ImmutableDictionary<string, string?> properties = withNullMode
            ? ImmutableDictionary<string, string?>.Empty.Add(FastHashOnPasswordAnalyzer.FixKey, null)
            : ImmutableDictionary<string, string?>.Empty;
        Diagnostic stale = Diagnostic.Create(
            Descriptors.FastHashOnPassword,
            Location.Create(tree, new Microsoft.CodeAnalysis.Text.TextSpan(length + 100, 20)),
            properties);

        IReadOnlyList<CodeAction> actions = await probe.GetActionsAsync(new FastHashOnPasswordCodeFixProvider(), stale);

        Assert.True(actions.Count == 0, reason);
    }

    [Fact]
    public async Task FastHash_DiagnosticWithAFixMode_ReadsTheDocument()
    {
        // Control for the test above: with a mode, the same stale span does reach the syntax lookup.
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync("""
            class C
            {
            }
            """);
        SyntaxTree tree = (await probe.Document.GetSyntaxTreeAsync())!;
        int length = (await tree.GetTextAsync()).Length;
        Diagnostic stale = Diagnostic.Create(
            Descriptors.FastHashOnPassword,
            Location.Create(tree, new Microsoft.CodeAnalysis.Text.TextSpan(length + 100, 20)),
            ImmutableDictionary<string, string?>.Empty.Add(FastHashOnPasswordAnalyzer.FixKey, FastHashOnPasswordAnalyzer.FixReplaceCall));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => probe.GetActionsAsync(new FastHashOnPasswordCodeFixProvider(), stale));
    }

    /// <summary>
    /// A self-contained core library: compiled with no references, its System.String is the special string type,
    /// so it can declare an instance method whose name is a password word (the BCL string has none).
    /// </summary>
    private const string CoreLibWithPinMethod = """
        namespace System
        {
            public class Object { }
            public abstract class ValueType { }
            public struct Void { }
            public struct Boolean { }
            public struct Int32 { }

            public sealed class String
            {
                public string Pin() => this;
            }

            public static class Console
            {
                public static void WriteLine(string value) { }
            }
        }
        """;

    [Fact]
    public async Task Logging_StringInstanceMethod_FollowsOnlyTheReceiver_NotTheMethodName()
    {
        // password.Pin() keeps the password's value (reported once, by the receiver's name); name.Pin() is a string
        // method on a non-password value, so the method name 'Pin' is not a password getter.
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(new PasswordLoggingAnalyzer(), ImmutableArray<MetadataReference>.Empty, new[]
        {
            CoreLibWithPinMethod,
            """
            class C
            {
                void M(string password, string name)
                {
                    System.Console.WriteLine(password.Pin());
                    System.Console.WriteLine(name.Pin());
                }
            }
            """,
        });

        Diagnostic diagnostic = Assert.Single(diagnostics);
        Assert.Equal("'password' may be written to a log by 'Console.WriteLine'; never log passwords", Message(diagnostic));
        Assert.Equal("password", LocatedText(diagnostic));
    }
}
