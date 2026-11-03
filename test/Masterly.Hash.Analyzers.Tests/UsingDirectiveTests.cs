using System.Threading.Tasks;
using VerifyEquals = Masterly.Hash.Analyzers.Tests.Infrastructure.CodeFixVerifier<
    Masterly.Hash.Analyzers.NonConstantTimeComparisonAnalyzer,
    Masterly.Hash.Analyzers.CodeFixes.FixedTimeEqualsCodeFixProvider>;
using VerifyObsolete = Masterly.Hash.Analyzers.Tests.Infrastructure.CodeFixVerifier<
    Masterly.Hash.Analyzers.ObsoleteApiAnalyzer,
    Masterly.Hash.Analyzers.CodeFixes.ObsoleteApiCodeFixProvider>;

namespace Masterly.Hash.Analyzers.Tests;

/// <summary>
/// Where the code fixes put the <c>using</c> directive they add: next to the existing usings (compilation unit or
/// namespace), System namespaces first, then alphabetically, after global usings and before aliases and static usings.
/// </summary>
public class UsingDirectiveTests
{
    [Fact]
    public Task SingleLineFile_UsesCrLf() => VerifyObsolete.VerifyAsync(
        "class C { string M(Masterly.Hash.IHash h, string s) => {|MH0006:h.ComputeHash(s)|}; }",
        "using Masterly.Hash;\r\n\r\nclass C { string M(Masterly.Hash.IHash h, string s) => Password.Hash(s); }");

    [Fact]
    public Task FileWithLfLineEndings_KeepsLf() => VerifyObsolete.VerifyAsync(
        "using System;\n\nclass C\n{\n    string M(Masterly.Hash.IHash h, string s) => {|MH0006:h.ComputeHash(s)|};\n}\n",
        "using System;\nusing Masterly.Hash;\n\nclass C\n{\n    string M(Masterly.Hash.IHash h, string s) => Password.Hash(s);\n}\n");

    [Fact]
    public Task UsingsInsideFileScopedNamespace_AddedThere() => VerifyObsolete.VerifyAsync("""
        namespace App;

        using System;

        class C
        {
            string M(Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
        }
        """, """
        namespace App;

        using System;
        using Masterly.Hash;

        class C
        {
            string M(Masterly.Hash.IHash hasher, string plain) => Password.Hash(plain);
        }
        """);

    [Fact]
    public Task UsingsInsideBlockNamespace_AddedThere() => VerifyObsolete.VerifyAsync("""
        namespace App
        {
            using System;

            class C
            {
                string M(Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
            }
        }
        """, """
        namespace App
        {
            using System;
            using Masterly.Hash;

            class C
            {
                string M(Masterly.Hash.IHash hasher, string plain) => Password.Hash(plain);
            }
        }
        """);

    [Fact]
    public Task UsingPresentOnlyInAnotherNamespace_StaysQualified() => VerifyObsolete.VerifyAsync("""
        namespace App.Data
        {
            using Masterly.Hash;

            class Repository { IHash? _hasher; }
        }

        namespace App.Web
        {
            class C
            {
                string M(Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
            }
        }
        """, """
        namespace App.Data
        {
            using Masterly.Hash;

            class Repository { IHash? _hasher; }
        }

        namespace App.Web
        {
            class C
            {
                string M(Masterly.Hash.IHash hasher, string plain) => Masterly.Hash.Password.Hash(plain);
            }
        }
        """);

    [Fact]
    public Task AfterGlobalAndPlainUsings_BeforeStaticAndAlias() => VerifyObsolete.VerifyAsync("""
        global using System.Text;
        using System;
        using App.Models;
        using static System.Math;
        using Sha = System.Security.Cryptography.SHA256;

        namespace App.Models { public class User { } }

        class C
        {
            string M(Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
        }
        """, """
        global using System.Text;
        using System;
        using App.Models;
        using Masterly.Hash;
        using static System.Math;
        using Sha = System.Security.Cryptography.SHA256;

        namespace App.Models { public class User { } }

        class C
        {
            string M(Masterly.Hash.IHash hasher, string plain) => Password.Hash(plain);
        }
        """);

    [Fact]
    public Task SystemNamespace_InsertedBeforeNonSystemUsings() => VerifyEquals.VerifyAsync("""
        using System.Linq;
        using App.Security;

        namespace App.Security { public static class Marker { } }

        #nullable enable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac)|};
        }
        """, """
        using System.Linq;
        using System.Security.Cryptography;
        using App.Security;

        namespace App.Security { public static class Marker { } }

        #nullable enable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => CryptographicOperations.FixedTimeEquals(computed, expectedMac);
        }
        """);
}
