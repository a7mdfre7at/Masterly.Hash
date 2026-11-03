using System.Threading.Tasks;
using Verify = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.HardCodedPepperAnalyzer>;

namespace Masterly.Hash.Analyzers.Tests;

public class HardCodedPepperTests
{
    // ---------------------------------------------------------------- HmacPepper arguments

    [Fact]
    public Task HmacPepper_FromBase64Literal_Reports() => Verify.VerifyAsync("""
        using System;
        using Masterly.Hash.Pepper;

        class C
        {
            HmacPepper M() => new HmacPepper("k1", {|#0:Convert.FromBase64String("c2VjcmV0LXBlcHBlci1rZXktdGhhdC1pcy0zMi1ieXRlcw==")|});
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("pepper key"));

    [Fact]
    public Task HmacPepper_ByteArrayInitializer_Reports() => Verify.VerifyAsync("""
        using Masterly.Hash.Pepper;

        class C
        {
            HmacPepper M() => new HmacPepper("k1", {|MH0003:new byte[] { 1, 2, 3, 4 }|});
        }
        """);

    [Fact]
    public Task HmacPepper_Utf8LiteralAndGetBytes_Report() => Verify.VerifyAsync("""
        using System.Text;
        using Masterly.Hash.Pepper;

        class C
        {
            void M()
            {
                _ = new HmacPepper("k1", {|MH0003:"0123456789abcdef0123456789abcdef"u8.ToArray()|});
                _ = new HmacPepper("k1", {|MH0003:Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef")|});
            }
        }
        """);

    [Fact]
    public Task HmacPepper_KeyRingWithLiteral_Reports() => Verify.VerifyAsync("""
        using System.Collections.Generic;
        using Masterly.Hash.Pepper;

        class C
        {
            HmacPepper M(byte[] fromVault) => new HmacPepper("k2", new Dictionary<string, byte[]>
            {
                ["k1"] = fromVault,
                ["k2"] = {|MH0003:new byte[] { 9, 9, 9 }|},
            });
        }
        """);

    [Fact]
    public Task HmacPepperFromBase64_LiteralValues_Report() => Verify.VerifyAsync("""
        using System.Collections.Generic;
        using Masterly.Hash.Pepper;

        class C
        {
            HmacPepper M() => HmacPepper.FromBase64("k1", new Dictionary<string, string>
            {
                { "k1", {|MH0003:"c2VjcmV0LXBlcHBlci1rZXktdGhhdC1pcy0zMi1ieXRlcw=="|} },
            });
        }
        """);

    // ---------------------------------------------------------------- named assignments

    [Fact]
    public Task FieldsPropertiesAndLocals_NamedLikeKeys_Report() => Verify.VerifyAsync("""
        using System;

        class Options
        {
            public string SigningKey { get; set; } = {|MH0003:"super-secret-signing-key"|};
            public string? SecretKey { get; set; }
        }

        class C
        {
            private const string Pepper = {|MH0003:"pepper-in-source"|};
            private static readonly byte[] HmacKey = {|MH0003:Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==")|};

            void M(Options options)
            {
                options.SecretKey = {|MH0003:"assigned-later"|};
                byte[] pepper = {|MH0003:[1, 2, 3]|};
                string hmacKey;
                hmacKey = {|MH0003:"x"|};
            }
        }
        """);

    // ---------------------------------------------------------------- fallbacks, zero keys, members

    [Fact]
    public Task LiteralFallbackAfterCoalesceOrInConditional_Reports() => Verify.VerifyAsync("""
        using System;
        using Masterly.Hash.Pepper;

        class C
        {
            void M(bool isDevelopment, string fromConfig)
            {
                byte[] pepper = {|MH0003:Convert.FromBase64String(Environment.GetEnvironmentVariable("PEPPER") ?? "ZmFsbGJhY2tmYWxsYmFjaw==")|};
                string hmacKey = {|MH0003:Environment.GetEnvironmentVariable("P") ?? "dev-pepper-value"|};
                string signingKey = {|MH0003:isDevelopment ? "dev-signing-key" : fromConfig|};
                _ = new HmacPepper("k1", {|MH0003:LoadKey() ?? new byte[] { 1, 2, 3 }|});
            }

            static byte[]? LoadKey() => null;
        }
        """);

    [Fact]
    public Task ZeroFilledArrayPassedAsPepperKey_Reports() => Verify.VerifyAsync("""
        using Masterly.Hash.Pepper;

        class C
        {
            // new byte[32] is an all-zero key, and long enough to pass HmacPepper's minimum key length.
            HmacPepper M() => new HmacPepper("k1", {|MH0003:new byte[32]|});
        }
        """);

    [Fact]
    public Task PropertiesAndMethodsReturningLiterals_Report() => Verify.VerifyAsync("""
        using System;

        class C
        {
            static byte[] Pepper => {|MH0003:Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==")|};
            static string SigningKey => {|#0:"super-secret-signing-key"|};
            string HmacKey { get { return {|MH0003:"getter-literal"|}; } }
            string GetSecretKey() { return {|MH0003:"method-literal"|}; }
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("'SigningKey'"));

    [Fact]
    public Task MembersReturningRuntimeValues_DoNotReport() => Verify.VerifyAsync("""
        using System;
        using System.Collections.Generic;

        class C
        {
            private readonly IReadOnlyDictionary<string, string> _config = new Dictionary<string, string>();
            string Pepper => _config["Pepper"];
            string PepperKeyId => "k1";
            static string Greeting => "hello";
            Func<string> LoadSigningKey() => () => "lambda-belongs-to-the-delegate";
            byte[] NewPepper()
            {
                // Zero-filled then randomized: not a hard-coded key.
                byte[] pepper = new byte[32];
                System.Security.Cryptography.RandomNumberGenerator.Fill(pepper);
                return pepper;
            }

            string HmacKey(bool b, string a, string c) => b ? a : c;
        }
        """);

    // ---------------------------------------------------------------- negatives

    [Fact]
    public Task KeysFromRuntimeSources_DoNotReport() => Verify.VerifyAsync("""
        using System;
        using System.Collections.Generic;
        using Masterly.Hash.Pepper;

        class C
        {
            void M(IReadOnlyDictionary<string, string> config, byte[] fromVault)
            {
                _ = new HmacPepper("k1", HmacPepper.GenerateKey());
                _ = new HmacPepper("k1", fromVault);
                _ = new HmacPepper("k1", Convert.FromBase64String(Environment.GetEnvironmentVariable("PEPPER")!));
                _ = HmacPepper.FromBase64("k1", config);
                byte[] pepper = new byte[32];
                string signingKey = config["SigningKey"];
                string secretKey = "";
            }
        }
        """);

    [Fact]
    public Task KeyIdsAndMetadataNames_DoNotReport() => Verify.VerifyAsync("""
        class C
        {
            private const string PepperKeyId = "k1";
            private const string SigningKeyName = "jwt-signing";
            private const string SecretKeyPath = "/run/secrets/key";

            void M()
            {
                string pepperId = "k2";
                string pepperVersion = "v3";
                string description = "pepper";
            }
        }
        """);

    [Fact]
    public Task UnrelatedHardCodedStrings_DoNotReport() => Verify.VerifyAsync("""
        class C
        {
            private const string Greeting = "hello";
            private static readonly byte[] Magic = { 0x4D, 0x48 };
            void M() { string peppermint = "candy"; }
        }
        """);

    // ---------------------------------------------------------------- literal shapes

    [Fact]
    public Task CollectionExpressionsOfLiterals_Report() => Verify.VerifyAsync("""
        class C
        {
            void M()
            {
                byte[] pepper = {|MH0003:[(byte)0x01, (byte)0x02, 0x03]|};
                byte[] signingKey = {|MH0003:(byte[])[1, 2, 3]|};
                sbyte[] hmacKey = {|MH0003:[-1, -2, 3]|};
            }
        }
        """);

    [Fact]
    public Task EmptyOrComputedCollections_DoNotReport() => Verify.VerifyAsync("""
        class C
        {
            void M(byte seed, byte[] fromVault)
            {
                byte[] pepper = [];
                byte[] hmacKey = [1, seed];
                byte[] signingKey = [.. fromVault];
                byte[] secretKey = new byte[] { };
                byte[] pepperBytes = new byte[] { 1, seed };
                int[] secretKeyWords = [-seed, ~1];
            }
        }
        """);

    [Fact]
    public Task EmptyOrComputedArraysAsPepperKey_DoNotReport() => Verify.VerifyAsync("""
        using Masterly.Hash.Pepper;

        class C
        {
            void M(int size, byte seed)
            {
                // Empty and non-constant-length arrays are not a fixed key (HmacPepper rejects short keys at run time).
                _ = new HmacPepper("k1", new byte[] { });
                _ = new HmacPepper("k1", new byte[size]);
                _ = new HmacPepper("k1", new byte[] { seed, 1 });
            }
        }
        """);

    [Fact]
    public Task NullAndRuntimeEncodings_DoNotReport() => Verify.VerifyAsync("""
        using System;

        class C
        {
            void M(byte[] seed)
            {
                string? pepper = null;
                string signingKey = Convert.ToBase64String(seed);
            }
        }
        """);

    [Fact]
    public Task DeeplyNestedFallbacks_StopAtDepthLimit() => Verify.VerifyAsync("""
        class C
        {
            // The walk is bounded (8 levels): a literal behind nine '??' fallbacks is not followed.
            void M(string? a)
            {
                string? pepper = a ?? a ?? a ?? a ?? a ?? a ?? a ?? a ?? a ?? "literal-behind-nine-fallbacks";
                string? hmacKey = {|MH0003:a ?? a ?? a ?? a ?? a ?? a ?? a ?? a ?? "literal-behind-eight-fallbacks"|};
            }
        }
        """);

    [Fact]
    public Task KeyRingWithMemberInitializer_InspectsOnlyKeyEntries() => Verify.VerifyAsync("""
        using System.Collections.Generic;
        using Masterly.Hash.Pepper;

        class KeyRing : Dictionary<string, byte[]>
        {
            public List<string> Retired { get; } = new List<string>();
        }

        class C
        {
            HmacPepper M(byte[] fromVault) => new HmacPepper("k2", new KeyRing
            {
                Retired = { "k0" },
                ["k1"] = fromVault,
                ["k2"] = {|MH0003:new byte[] { 9, 9, 9 }|},
            });
        }
        """);

    [Fact]
    public Task UnrelatedPropertyInitializersAndBareReturns_DoNotReport() => Verify.VerifyAsync("""
        class C
        {
            public string Name { get; } = "service";
            public string Pepper { get; set; } = "";

            void RotatePepper(bool skip)
            {
                if (skip)
                    return;
            }
        }
        """);
}
