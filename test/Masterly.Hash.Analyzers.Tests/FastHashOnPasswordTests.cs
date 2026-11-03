using System.Threading.Tasks;
using Masterly.Hash.Analyzers.CodeFixes;
using Masterly.Hash.Analyzers.Tests.Infrastructure;
using Verify = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.FastHashOnPasswordAnalyzer>;
using VerifyFix = Masterly.Hash.Analyzers.Tests.Infrastructure.CodeFixVerifier<
    Masterly.Hash.Analyzers.FastHashOnPasswordAnalyzer,
    Masterly.Hash.Analyzers.CodeFixes.FastHashOnPasswordCodeFixProvider>;

namespace Masterly.Hash.Analyzers.Tests;

public class FastHashOnPasswordTests
{
    // ---------------------------------------------------------------- positives

    [Fact]
    public Task StaticHashData_OnPasswordBytes_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string password) => {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
        }
        """);

    [Fact]
    public Task Message_NamesAlgorithmAndSymbol() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string userPassword) => {|#0:MD5.HashData(Encoding.ASCII.GetBytes(userPassword))|};
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("MD5", "userPassword"));

    [Theory]
    [InlineData("SHA1")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public Task EveryStaticHashType_Reports(string type) => Verify.VerifyAsync($$"""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string pwd) => {|MH0001:{{type}}.HashData(Encoding.UTF8.GetBytes(pwd))|};
        }
        """);

    [Fact]
    public Task InstanceComputeHash_OnPasswordProperty_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class User { public string Password { get; set; } = ""; }

        class C
        {
            byte[] M(User user)
            {
                using var sha = SHA256.Create();
                return {|MH0001:sha.ComputeHash(Encoding.UTF8.GetBytes(user.Password))|};
            }
        }
        """);

    [Fact]
    public Task HashAlgorithmCreate_ComputeHash_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string passphrase) =>
                {|MH0001:HashAlgorithm.Create("SHA256")!.ComputeHash(Encoding.UTF8.GetBytes(passphrase))|};
        }
        """);

    [Fact]
    public Task TryComputeHash_Reports() => Verify.VerifyAsync("""
        using System;
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            bool M(string password, byte[] destination)
            {
                using var sha = SHA512.Create();
                return {|MH0001:sha.TryComputeHash(Encoding.UTF8.GetBytes(password), destination, out _)|};
            }
        }
        """);

    [Fact]
    public Task LocalBytesFromGetBytes_AreFollowed() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string pin)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(pin);
                return {|MH0001:SHA1.HashData(bytes)|};
            }
        }
        """);

    [Fact]
    public Task ConcatenationWithSalt_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string password, string salt) => {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(salt + password))|};
        }
        """);

    [Fact]
    public Task HmacConstructedWithPasswordKey_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            HMAC M(string password) => {|MH0001:new HMACSHA256(Encoding.UTF8.GetBytes(password))|};
        }
        """);

    [Fact]
    public Task HmacStaticHashData_WithPassword_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(byte[] key, string passwd) => {|MH0001:HMACSHA512.HashData(key, Encoding.UTF8.GetBytes(passwd))|};
        }
        """);

    [Fact]
    public Task MethodNamedLikePassword_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            byte[] GetPasswordBytes() => new byte[1];
            byte[] M() => {|MH0001:SHA256.HashData(GetPasswordBytes())|};
        }
        """);

    // ---------------------------------------------------------------- negatives

    [Fact]
    public Task NonPasswordInput_DoesNotReport() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string fileContents, byte[] payload)
            {
                SHA256.HashData(payload);
                return SHA256.HashData(Encoding.UTF8.GetBytes(fileContents));
            }
        }
        """);

    /// <summary>
    /// Decision: names whose last word qualifies the password (policy, length, hash, hint, ...) describe metadata,
    /// not the password, and do not match. Hashing a stored <c>passwordHash</c> again is not a password-hashing
    /// mistake either. Word boundaries keep <c>spinner</c>/<c>pinned</c>/<c>opinion</c> from matching <c>pin</c>.
    /// </summary>
    [Theory]
    [InlineData("passwordPolicy")]
    [InlineData("maxPasswordLength")]
    [InlineData("passwordHash")]
    [InlineData("passwordHint")]
    [InlineData("passwordSaltBytes")]
    [InlineData("storedPasswordHashBase64")]
    [InlineData("hashedPassword")]
    [InlineData("spinner")]
    [InlineData("pinned")]
    [InlineData("opinion")]
    [InlineData("compass")]
    public Task MetadataAndNonWordMatches_DoNotReport(string name) => Verify.VerifyAsync($$"""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string {{name}}) => SHA256.HashData(Encoding.UTF8.GetBytes({{name}}));
        }
        """);

    [Fact]
    public Task PasswordNamedOutputBuffer_DoesNotReport() => Verify.VerifyAsync("""
        using System;
        using System.Security.Cryptography;

        class C
        {
            void M(byte[] data, byte[] passwordBytes, byte[] payload, byte[] pinBuffer)
            {
                // The destination buffer receives the digest; its name says nothing about the input.
                SHA256.HashData(data, passwordBytes);
                SHA256.TryHashData(payload, pinBuffer, out _);
                using var sha = SHA512.Create();
                sha.TryComputeHash(payload, pinBuffer, out int pwdBytesWritten);
            }
        }
        """);

    [Fact]
    public Task PasswordSource_WithDestinationBuffer_StillReports() => Verify.VerifyAsync("""
        using System;
        using System.Security.Cryptography;

        class C
        {
            int M(byte[] passwordBytes, byte[] destination) => {|MH0001:SHA256.HashData(passwordBytes, destination)|};
        }
        """);

    [Fact]
    public Task NameOf_DoesNotReport() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string password) => SHA256.HashData(Encoding.UTF8.GetBytes(nameof(password)));
        }
        """);

    [Fact]
    public Task NonCryptoComputeHash_DoesNotReport() => Verify.VerifyAsync("""
        class Hasher { public byte[] ComputeHash(byte[] data) => data; }

        class C
        {
            byte[] M(byte[] password) => new Hasher().ComputeHash(password);
        }
        """);

    [Fact]
    public Task HmacKeyedWithRandomKey_DoesNotReport() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            HMAC M(byte[] key) => new HMACSHA256(key);
        }
        """);

    // ---------------------------------------------------------------- code fix

    [Fact]
    public Task Fix_Base64Wrapper_ReplacedWithPasswordHash_AndUsingAdded() => VerifyFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            string M(string password)
            {
                return Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
            }
        }
        """, """
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            string M(string password)
            {
                return Password.Hash(password);
            }
        }
        """);

    [Fact]
    public Task Fix_HexWrapperOnInstanceCall_ExistingUsingKept() => VerifyFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            string M(string password)
            {
                using var sha = SHA512.Create();
                string stored = Convert.ToHexString({|MH0001:sha.ComputeHash(Encoding.UTF8.GetBytes(password))|});
                return stored;
            }
        }
        """, """
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            string M(string password)
            {
                using var sha = SHA512.Create();
                string stored = Password.Hash(password);
                return stored;
            }
        }
        """);

    [Fact]
    public Task Fix_VarLocal_UsedAsString() => VerifyFix.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            object M(string password)
            {
                var hashed = {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
                return hashed;
            }
        }
        """, """
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            object M(string password)
            {
                var hashed = Password.Hash(password);
                return hashed;
            }
        }
        """);

    [Fact]
    public Task Fix_VarLocal_UsedAsBytes_NotOffered() => VerifyFix.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string password)
            {
                var digest = {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
                return digest;
            }
        }
        """, """
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            byte[] M(string password)
            {
                var digest = {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
                return digest;
            }
        }
        """);

    [Fact]
    public Task Fix_ExplicitByteArrayTarget_NotOffered() => VerifyFix.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            void M(string password)
            {
                byte[] digest = {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
            }
        }
        """, """
        using System.Security.Cryptography;
        using System.Text;

        class C
        {
            void M(string password)
            {
                byte[] digest = {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
            }
        }
        """);

    [Fact]
    public Task Fix_PasswordNameTakenByProperty_StaysQualified() => VerifyFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;
        using System.Text;

        class User
        {
            public string Password { get; set; } = "";

            public string Hash() => Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(Password))|});
        }
        """, """
        using System;
        using System.Security.Cryptography;
        using System.Text;

        class User
        {
            public string Password { get; set; } = "";

            public string Hash() => Masterly.Hash.Password.Hash(Password);
        }
        """);

    [Fact]
    public Task Fix_AssignedToProperty_Offered() => VerifyFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class User { public string PasswordHash { get; set; } = ""; }

        class C
        {
            void M(User user, string password)
            {
                user.PasswordHash = Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
            }
        }
        """, """
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class User { public string PasswordHash { get; set; } = ""; }

        class C
        {
            void M(User user, string password)
            {
                user.PasswordHash = Password.Hash(password);
            }
        }
        """);

    // Password.Hash is randomly salted: wherever the legacy digest is compared or fed onward, the rewrite would
    // compile but never match again (every login fails), so the fix must not be offered.

    [Fact]
    public Task Fix_NotOffered_WhenWrapperIsComparedWithStoredHash() => AssertNoFix("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            bool Login(string password, string stored)
            {
                bool ok = Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|}) == stored;
                return ok;
            }

            bool Check(string stored, string password) =>
                stored != Convert.ToHexString({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
        }
        """);

    [Fact]
    public Task Fix_NotOffered_WhenWrapperIsPassedToEqualsOrCompare() => AssertNoFix("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            bool A(string stored, string password) =>
                stored.Equals(Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|}));

            bool B(string stored, string password) =>
                string.CompareOrdinal(stored, Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|})) == 0;
        }
        """);

    [Fact]
    public Task Fix_NotOffered_WhenLocalHoldingTheHashIsCompared() => AssertNoFix("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            bool A(string stored, string password)
            {
                string computed = Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
                return computed == stored;
            }

            bool B(object stored, string password)
            {
                var digest = {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
                return digest.Equals(stored);
            }
        }
        """);

    [Fact]
    public Task Fix_NotOffered_WhenHashIsPassedToAnotherCallOrLambda() => AssertNoFix("""
        using System;
        using System.Collections.Generic;
        using System.Linq;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class User { public string PasswordHash { get; set; } = ""; }

        class C
        {
            static string Bcrypt(string prehash) => prehash;

            string Prehash(string password) =>
                Bcrypt(Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|}));

            Func<string, string> Legacy() =>
                pwd => Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(pwd))|});

            IEnumerable<User> Find(IEnumerable<User> users, string password) =>
                users.Where(u => u.PasswordHash == Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|}));
        }
        """);

    [Fact]
    public Task Fix_NotOffered_ForKeyedHmac() => AssertNoFix("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            string M(byte[] key, string password)
            {
                // Rewriting to Password.Hash would silently drop the HMAC key (the pepper).
                using var hmac = new HMACSHA256(key);
                return Convert.ToBase64String({|MH0001:hmac.ComputeHash(Encoding.UTF8.GetBytes(password))|});
            }
        }
        """);

    private static Task AssertNoFix(string source) => VerifyFix.VerifyAsync(source, source);

    [Fact]
    public Task Fix_WithoutMasterlyHashReference_NotOffered()
    {
        // No stubs: Password.Hash does not exist in the compilation, so the analyzer adds no fix property.
        const string source = """
            using System;
            using System.Security.Cryptography;
            using System.Text;

            class C
            {
                string M(string password) => Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
            }
            """;
        var test = new Microsoft.CodeAnalysis.CSharp.Testing.CSharpCodeFixTest<
            FastHashOnPasswordAnalyzer, FastHashOnPasswordCodeFixProvider, Microsoft.CodeAnalysis.Testing.DefaultVerifier>
        {
            TestCode = source,
            FixedCode = source,
            ReferenceAssemblies = References.Net80,
        };
        return test.RunAsync();
    }

    // ---------------------------------------------------------------- what the analyzer follows

    [Fact]
    public Task ForeachVariable_IsNotTracedToItsSource() => Verify.VerifyAsync("""
        using System.Collections.Generic;
        using System.Security.Cryptography;

        class C
        {
            // Only a local's own initializer is followed; a foreach variable has none.
            void M(IEnumerable<byte[]> encoded)
            {
                foreach (byte[] bytes in encoded)
                    _ = SHA256.HashData(bytes);
            }
        }
        """);

    [Fact]
    public Task ValueTypeAndUnrelatedCreations_DoNotReport() => Verify.VerifyAsync("""
        using System.Text;

        struct Buffer { }

        class C
        {
            void M(string password)
            {
                _ = new int();
                _ = new Buffer();
                _ = new StringBuilder(password);
            }
        }
        """);

    // ---------------------------------------------------------------- code fix: where the digest goes

    [Fact]
    public Task Fix_BitConverterWrapper_Replaced() => VerifyFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            string M(string password) => BitConverter.ToString({|MH0001:SHA1.HashData(Encoding.UTF8.GetBytes(password))|});
        }
        """, """
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            string M(string password) => Password.Hash(password);
        }
        """);

    [Fact]
    public Task Fix_NotOffered_ForWrapperOverloadsAndOtherConversions() => AssertNoFix("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            // Two-argument overload: the line-break option has no Password.Hash equivalent.
            string Base64(string password) =>
                Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|}, Base64FormattingOptions.InsertLineBreaks);

            // Not a byte-to-text encoding of the digest.
            string Text(string password) => Encoding.UTF8.GetString({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});

            // Handed to a constructor or a void method: the bytes are consumed, not stored as text.
            object Wrapped(string password) => new StoredDigest({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
            void Persisted(string password) => Persist({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});

            static void Persist(byte[] digest) { }
        }

        class StoredDigest
        {
            public StoredDigest(byte[] digest) { }
        }
        """);

    [Fact]
    public Task Fix_AssignedToFieldOrLocal_Offered() => VerifyFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            private string _stored = "";

            void Store(string password)
            {
                _stored = Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
            }

            string Create(string password)
            {
                string created;
                created = Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
                return created;
            }
        }
        """, """
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            private string _stored = "";

            void Store(string password)
            {
                _stored = Password.Hash(password);
            }

            string Create(string password)
            {
                string created;
                created = Password.Hash(password);
                return created;
            }
        }
        """);

    [Fact]
    public Task Fix_FieldAndPropertyInitializers_Offered() => VerifyFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class Seed
        {
            const string DefaultPassword = "change-me";

            static readonly string DefaultAdminHash =
                Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(DefaultPassword))|});

            public string GuestHash { get; } =
                Convert.ToHexString({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(DefaultPassword))|});
        }
        """, """
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class Seed
        {
            const string DefaultPassword = "change-me";

            static readonly string DefaultAdminHash =
                Password.Hash(DefaultPassword);

            public string GuestHash { get; } =
                Password.Hash(DefaultPassword);
        }
        """);

    [Fact]
    public Task Fix_NotOffered_WhenAssignmentIsAValueOrTargetIsAnElement() => AssertNoFix("""
        using System;
        using System.Collections.Generic;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            private string _last = "";

            // The assignment's value flows on into the caller (possibly a comparison).
            string Chained(string password) =>
                _last = Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});

            void Elements(string[] hashes, Dictionary<string, string> byUser, string user, string password)
            {
                hashes[0] = Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
                byUser[user] = Convert.ToBase64String({|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|});
            }
        }
        """);

    [Fact]
    public Task Fix_CopiedThroughLocalsWithinDepth_Offered() => VerifyFix.VerifyAsync("""
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            object M(string password)
            {
                var digest = {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
                var copy = digest;
                var result = copy;
                return result;
            }
        }
        """, """
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            object M(string password)
            {
                var digest = Password.Hash(password);
                var copy = digest;
                var result = copy;
                return result;
            }
        }
        """);

    [Fact]
    public Task Fix_NotOffered_WhenCopyChainIsTooLongToFollow() => AssertNoFix("""
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            object M(string password)
            {
                var digest = {|MH0001:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
                var a = digest;
                var b = a;
                var c = b;
                return c;
            }
        }
        """);
}
