using System.Threading.Tasks;
using Verify = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.PasswordLoggingAnalyzer>;

namespace Masterly.Hash.Analyzers.Tests;

public class PasswordLoggingTests
{
    // ---------------------------------------------------------------- positives

    [Fact]
    public Task Console_DirectConcatAndInterpolation_Report() => Verify.VerifyAsync("""
        using System;

        class C
        {
            void M(string password, string user)
            {
                Console.WriteLine({|#0:password|});
                Console.Write("pw=" + {|MH0004:password|});
                Console.WriteLine($"{user} logged in with {{|MH0004:password|}}");
            }
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("password", "Console.WriteLine"));

    [Fact]
    public Task LoggerExtensions_TemplateArguments_Report() => Verify.VerifyAsync("""
        using System;
        using Microsoft.Extensions.Logging;

        class Request { public string Password { get; set; } = ""; public string UserName { get; set; } = ""; }

        class C
        {
            void M(ILogger logger, Request request, Exception ex, string pwd)
            {
                logger.LogInformation("Login {User} {Password}", request.UserName, {|MH0004:request.Password|});
                logger.LogError(ex, "Failed for {Pwd}", {|MH0004:pwd|});
                logger.Log(LogLevel.Warning, $"pass={{|MH0004:pwd|}}");
                using (logger.BeginScope("{P}", {|MH0004:pwd|})) { }
            }
        }
        """);

    [Fact]
    public Task ILoggerLog_Reports() => Verify.VerifyAsync("""
        using Microsoft.Extensions.Logging;

        class C
        {
            void M(ILogger logger, string passphrase)
            {
                logger.Log(LogLevel.Information, 0, {|MH0004:passphrase|}, null, (s, e) => s);
            }
        }
        """);

    [Fact]
    public Task DebugAndTrace_Report() => Verify.VerifyAsync("""
        using System.Diagnostics;

        class C
        {
            void M(string password)
            {
                Debug.WriteLine({|MH0004:password|});
                Trace.TraceInformation("{0}", {|MH0004:password|});
                Trace.WriteLine(string.Format("pw {0}", {|MH0004:password|}));
            }
        }
        """);

    [Fact]
    public Task SensitiveStringReveal_Reports_RegardlessOfName() => Verify.VerifyAsync("""
        using System;
        using Masterly.Hash;

        class C
        {
            void M(SensitiveString input)
            {
                Console.WriteLine({|#0:input.Reveal()|});
            }
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("input.Reveal()", "Console.WriteLine"));

    [Fact]
    public Task StringMethodsOnPassword_AndConditional_Report() => Verify.VerifyAsync("""
        using System;

        class C
        {
            void M(string password, bool verbose)
            {
                Console.WriteLine({|MH0004:password|}.Trim());
                Console.WriteLine(verbose ? {|MH0004:password|} : "***");
            }
        }
        """);

    [Fact]
    public Task MethodReturningPassword_Reports() => Verify.VerifyAsync("""
        using System;

        class C
        {
            string GetPassword() => "x";
            void M() => Console.WriteLine({|MH0004:GetPassword()|});
        }
        """);

    // ---------------------------------------------------------------- negatives

    [Fact]
    public Task SafeUses_DoNotReport() => Verify.VerifyAsync("""
        using System;
        using Masterly.Hash;
        using Microsoft.Extensions.Logging;

        class C
        {
            void M(ILogger logger, string password, string passwordHash, string passwordPolicy, SensitiveString secret, bool isPasswordValid)
            {
                Console.WriteLine(password.Length);
                Console.WriteLine(passwordHash);
                Console.WriteLine(passwordPolicy);
                Console.WriteLine(secret);
                Console.WriteLine(isPasswordValid);
                Console.WriteLine(nameof(password));
                Console.WriteLine("Password changed");
                logger.LogInformation("Password changed for {User}", "alice");
                logger.LogInformation("{Secret}", secret);
            }
        }
        """);

    [Fact]
    public Task LongConcatenation_PasswordEarly_Reports() => Verify.VerifyAsync("""
        using System;

        class C
        {
            void M(string pwd, string user, string host, int port, string db, string app, string timeout)
            {
                // A logged connection string: pwd is near the bottom of a deep left-nested '+' tree.
                Console.WriteLine("Pwd=" + {|MH0004:pwd|} + ";User=" + user + ";Host=" + host + ";Port=" + port + ";Db=" + db
                    + ";App=" + app + ";Timeout=" + timeout + ";Pooling=true" + ";Ssl=on" + ";Encrypt=yes" + ";End");
            }
        }
        """);

    [Fact]
    public Task HashedPasswordName_DoesNotReport() => Verify.VerifyAsync("""
        using Microsoft.Extensions.Logging;

        class C
        {
            // hashedPassword is the stored hash (ASP.NET Identity naming), not the password.
            void M(ILogger logger, string hashedPassword) => logger.LogInformation("stored {H}", hashedPassword);
        }
        """);

    [Fact]
    public Task NonLoggingSinks_DoNotReport() => Verify.VerifyAsync("""
        using System.IO;
        using System.Text;

        class C
        {
            void M(string password, TextWriter writer)
            {
                var sb = new StringBuilder();
                sb.Append(password);
                writer.WriteLine(password.Length);
            }
        }
        """);

    // ---------------------------------------------------------------- more flows

    [Fact]
    public Task LocalPasswordVariable_Reports() => Verify.VerifyAsync("""
        using System;

        class C
        {
            void M(Func<string> prompt)
            {
                string password = prompt();
                char[] pin = password.ToCharArray();
                Console.WriteLine({|#0:password|});
                Console.WriteLine({|#1:pin|});
            }
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("password", "Console.WriteLine"),
        Verify.Diagnostic().WithLocation(1).WithArguments("pin", "Console.WriteLine"));

    [Fact]
    public Task InterpolatedStringHandlerArgument_Reports() => Verify.VerifyAsync("""
        using System.Diagnostics;

        class C
        {
            // Debug.WriteLineIf(bool, ref WriteIfInterpolatedStringHandler): the interpolation binds to a handler.
            void M(bool verbose, string user, string password)
            {
                Debug.WriteLineIf(verbose, $"login {user} with {{|#0:password|}}");
                Debug.WriteIf(verbose, $"{user}");
            }
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("password", "Debug.WriteLineIf"));

    [Fact]
    public Task NullCoalescingFallback_ReportsTheSecretSide() => Verify.VerifyAsync("""
        using System;

        class C
        {
            void M(string? password, string? fallbackPassword, string? user)
            {
                Console.WriteLine({|MH0004:password|} ?? "<none>");
                Console.WriteLine(user ?? {|MH0004:fallbackPassword|});
                Console.WriteLine(user ?? "anonymous");
            }
        }
        """);

    [Fact]
    public Task RevealOnAnExpression_NamesSensitiveString() => Verify.VerifyAsync("""
        using System;
        using Masterly.Hash;

        class C
        {
            void M(string input) => Console.WriteLine({|#0:new SensitiveString(input).Reveal()|});
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("SensitiveString.Reveal()", "Console.WriteLine"));

    [Fact]
    public Task PasswordGetterOnAnObject_Reports() => Verify.VerifyAsync("""
        using System.Diagnostics;

        class Credentials { public string GetPassword() => ""; }

        class C
        {
            void M(Credentials credentials)
            {
                Debug.Print({|MH0004:credentials.GetPassword()|});
                Debug.Fail({|MH0004:credentials.GetPassword()|});
                Trace.TraceWarning({|MH0004:credentials.GetPassword()|});
            }
        }
        """);

    [Fact]
    public Task NonSinkMembersAndNonTextResults_DoNotReport() => Verify.VerifyAsync("""
        using System;
        using System.Diagnostics;
        using Microsoft.Extensions.Logging;

        class C
        {
            void M(ILogger logger, string password)
            {
                _ = logger.IsEnabled(LogLevel.Debug);
                Debug.Assert(password.Length > 0);
                Debug.Indent();
                Console.WriteLine(password.GetHashCode());
                Console.WriteLine(password.Length.ToString());
            }
        }
        """);

    [Fact]
    public Task DeeplyNestedExpression_StopsAtDepthLimit() => Verify.VerifyAsync("""
        using System;

        class C
        {
            // The walk is bounded (8 levels): a password buried deeper than that is not followed.
            void M(bool a, string password)
            {
                Console.WriteLine(a ? "" : a ? "" : a ? "" : a ? "" : a ? "" : a ? "" : a ? "" : a ? "" : {|MH0004:password|});
                Console.WriteLine(a ? "" : a ? "" : a ? "" : a ? "" : a ? "" : a ? "" : a ? "" : a ? "" : a ? "" : password);
            }
        }
        """);

    [Fact]
    public Task CharArrayFromPassword_Reports() => Verify.VerifyAsync("""
        using System;

        class C
        {
            void M(string password) => Console.WriteLine({|MH0004:password|}.ToCharArray());
        }
        """);
}
