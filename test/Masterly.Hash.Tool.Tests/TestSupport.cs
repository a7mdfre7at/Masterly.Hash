using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Policy;

namespace Masterly.Hash.Tool.Tests;

/// <summary>In-memory console: scripted stdin and prompt answers, captured stdout and stderr.</summary>
internal sealed class FakeConsole : IToolConsole
{
    private readonly Queue<string?> _secrets;
    private readonly StringWriter _out = new StringWriter();
    private readonly StringWriter _error = new StringWriter();

    public FakeConsole(string stdin, bool redirected, IEnumerable<string?> secrets)
        : this(new StringReader(stdin), redirected, secrets)
    {
    }

    public FakeConsole(TextReader stdin, bool redirected, IEnumerable<string?> secrets)
    {
        In = stdin;
        IsInputRedirected = redirected;
        _secrets = new Queue<string?>(secrets);
    }

    public TextReader In { get; }
    public TextWriter Out => _out;
    public TextWriter Error => _error;
    public bool IsInputRedirected { get; }
    public List<string> Prompts { get; } = new List<string>();

    public string OutText => _out.ToString();
    public string ErrorText => _error.ToString();

    public string? ReadSecret(string prompt)
    {
        Prompts.Add(prompt);
        return _secrets.Count > 0 ? _secrets.Dequeue() : null;
    }
}

internal sealed record ToolRun(int ExitCode, string Out, string Error, FakeConsole Console)
{
    public string All => Out + Error;
}

/// <summary>Runs the whole tool in-process.</summary>
internal static class Tool
{
    /// <summary>Runs with stdin redirected (as in a pipe) and the weak test profile.</summary>
    public static Task<ToolRun> RunAsync(string[] args, string stdin = "", Action<ToolEnvironment>? configure = null) =>
        RunCoreAsync(args, new FakeConsole(stdin, redirected: true, Array.Empty<string?>()), configure);

    /// <summary>Runs as if on a terminal: each prompt is answered with the next secret.</summary>
    public static Task<ToolRun> RunInteractiveAsync(string[] args, string?[] secrets, Action<ToolEnvironment>? configure = null) =>
        RunCoreAsync(args, new FakeConsole(string.Empty, redirected: false, secrets), configure);

    /// <summary>Runs with a terminal (not redirected) whose typed input would arrive on stdin as <paramref name="stdin"/>.</summary>
    public static Task<ToolRun> RunOnTerminalAsync(string[] args, string stdin, Action<ToolEnvironment>? configure = null) =>
        RunCoreAsync(args, new FakeConsole(stdin, redirected: false, Array.Empty<string?>()), configure);

    /// <summary>Runs with stdin redirected from raw bytes, decoded the way the real console decodes a pipe.</summary>
    public static Task<ToolRun> RunWithStdinBytesAsync(string[] args, byte[] stdin, Action<ToolEnvironment>? configure = null) =>
        RunCoreAsync(args, new FakeConsole(SystemConsole.CreateUtf8Reader(new MemoryStream(stdin)), redirected: true, Array.Empty<string?>()), configure);

    internal static async Task<ToolRun> RunCoreAsync(string[] args, FakeConsole console, Action<ToolEnvironment>? configure)
    {
        var environment = new ToolEnvironment(console)
        {
            HasherOptionsFactory = TestHashers.Options,
            BreachCheckerFactory = () => throw new InvalidOperationException("Tests must not touch the network."),
            MeasureMilliseconds = _ => throw new InvalidOperationException("Bench tests must inject a clock."),
            GetEnvironmentVariable = _ => null,
        };
        configure?.Invoke(environment);
        int exitCode = await ToolApp.RunAsync(args, environment);
        return new ToolRun(exitCode, console.OutText, console.ErrorText, console);
    }
}

internal static class TestHashers
{
    public static readonly HashProfile Profile = HashProfile.Argon2id("test", 64, 1);

    public static PasswordHasherOptions Options() =>
        new PasswordHasherOptions { DefaultProfile = Profile, AllowWeakProfiles = true };

    /// <summary>The same view of hashes the tool has: test profile plus every legacy format.</summary>
    public static PasswordHasher Hasher() => new PasswordHasher(Options().AddAllLegacyFormats());

    /// <summary>Byte-for-byte the Masterly.Hash 1.x algorithm: base64(SHA-2(utf8(password) || salt) || salt).</summary>
    public static string V1(string password, byte[] salt, V1Algorithm algorithm)
    {
        byte[] plain = Encoding.UTF8.GetBytes(password);
        byte[] data = new byte[plain.Length + salt.Length];
        plain.CopyTo(data, 0);
        salt.CopyTo(data, plain.Length);
        byte[] digest = algorithm switch
        {
            V1Algorithm.SHA256 => SHA256.HashData(data),
            V1Algorithm.SHA384 => SHA384.HashData(data),
            _ => SHA512.HashData(data),
        };
        byte[] result = new byte[digest.Length + salt.Length];
        digest.CopyTo(result, 0);
        salt.CopyTo(result, digest.Length);
        return Convert.ToBase64String(result);
    }

    public static string Md5Hex(string password) =>
        Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
}

/// <summary>Breach checker that answers from memory and records what it was asked.</summary>
internal sealed class FakeBreachChecker : IBreachedPasswordChecker, IDisposable
{
    private readonly BreachCheckResult _answer;

    public FakeBreachChecker(BreachCheckResult answer)
    {
        _answer = answer;
    }

    public List<string> Checked { get; } = new List<string>();
    public bool Disposed { get; private set; }

    public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken)
    {
        Checked.Add(password);
        return new ValueTask<BreachCheckResult>(_answer);
    }

    public void Dispose() => Disposed = true;
}

/// <summary>A temporary directory deleted at the end of the test.</summary>
internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "mh-tool-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
