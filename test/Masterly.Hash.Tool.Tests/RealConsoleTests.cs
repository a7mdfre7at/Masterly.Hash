using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;

namespace Masterly.Hash.Tool.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class RealConsoleCollection
{
    public const string Name = "Real process console";
}

/// <summary>
/// The real-process wiring: <c>Program.Main</c>, <see cref="ToolEnvironment.CreateDefault"/>, <see cref="SystemConsole"/>
/// and the default Pwned Passwords client. These touch the process console, so they run alone; none of them reads a
/// key or makes a network request.
/// </summary>
[Collection(RealConsoleCollection.Name)]
public class RealConsoleTests
{
    [Fact]
    public async Task Main_PrintsTheVersionToTheProcessConsole()
    {
        MethodInfo main = typeof(ToolApp).Assembly.EntryPoint!;
        TextWriter original = Console.Out;
        var captured = new StringWriter();
        object? result;
        try
        {
            Console.SetOut(captured);
            result = main.Invoke(null, new object[] { new[] { "--version" } });
            if (result is Task<int> task)
                result = await task;
        }
        finally
        {
            Console.SetOut(original);
        }

        Assert.Equal(ExitCodes.Success, result);
        Assert.Equal(ToolApp.Version + Environment.NewLine, captured.ToString());
    }

    [Fact]
    public void CreateDefault_UsesTheSystemConsole()
    {
        ToolEnvironment environment = ToolEnvironment.CreateDefault();

        var console = Assert.IsType<SystemConsole>(environment.Console);
        Assert.Same(Console.Out, console.Out);
        Assert.Same(Console.Error, console.Error);
        Assert.Equal(Console.IsInputRedirected, console.IsInputRedirected);
        Assert.Equal(ToolEnvironment.MeasureOnce, environment.MeasureMilliseconds);
    }

    [Fact]
    public void SystemConsole_In_IsCreatedOnce()
    {
        var console = new SystemConsole();

        TextReader first = console.In;

        Assert.NotNull(first);
        Assert.Same(first, console.In);
    }

    [Fact]
    public void SystemConsole_ReadSecret_NullPrompt_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new SystemConsole().ReadSecret(null!));
    }

    [Fact]
    public void SystemConsole_ReadSecret_WithRedirectedInput_ReturnsNullWithoutPrompting()
    {
        if (!Console.IsInputRedirected)
            return; // An interactive test host would block on Console.ReadKey.

        TextWriter original = Console.Error;
        var captured = new StringWriter();
        string? secret;
        try
        {
            Console.SetError(captured);
            secret = new SystemConsole().ReadSecret("Password: ");
        }
        finally
        {
            Console.SetError(original);
        }

        Assert.Null(secret);
        Assert.Equal(string.Empty, captured.ToString());
    }

    [Fact]
    public void DefaultBreachChecker_IsDisposableAndHonoursCancellationBeforeAnyRequest()
    {
        IBreachedPasswordChecker checker = new ToolEnvironment(new SystemConsole()).BreachCheckerFactory();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Cancelled before the request is built, so nothing is sent.
        Assert.ThrowsAny<OperationCanceledException>(() => { _ = checker.CheckAsync("pw", cts.Token); });

        var disposable = Assert.IsAssignableFrom<IDisposable>(checker);
        disposable.Dispose();
    }
}
