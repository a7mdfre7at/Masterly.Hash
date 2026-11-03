using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Tests;

/// <summary>The interactive password prompt's key handling, driven with scripted key presses.</summary>
public class SecretKeyLoopTests
{
    private static ConsoleKeyInfo Char(char c) => new ConsoleKeyInfo(c, ConsoleKey.A, shift: false, alt: false, control: false);
    private static ConsoleKeyInfo Key(ConsoleKey key, char c = '\0', bool control = false) =>
        new ConsoleKeyInfo(c, key, shift: false, alt: false, control: control);
    private static readonly ConsoleKeyInfo Enter = Key(ConsoleKey.Enter, '\r');
    private static readonly ConsoleKeyInfo Backspace = Key(ConsoleKey.Backspace, '\b');

    private static IEnumerable<ConsoleKeyInfo> Type(string text) => text.Select(Char);

    private static (string? Result, string Error, int KeysRead) Run(IEnumerable<ConsoleKeyInfo> keys)
    {
        using IEnumerator<ConsoleKeyInfo> e = keys.GetEnumerator();
        int read = 0;
        var error = new StringWriter();
        string? result = SystemConsole.ReadSecret("Password: ", () =>
        {
            Assert.True(e.MoveNext(), "The loop read past the scripted keys.");
            read++;
            return e.Current;
        }, error);
        return (result, error.ToString(), read);
    }

    [Fact]
    public void Enter_returns_the_typed_text_and_ends_the_prompt_line()
    {
        var (result, error, _) = Run(Type("hunter2").Append(Enter));

        Assert.Equal("hunter2", result);
        Assert.Equal("Password: " + Environment.NewLine, error); // Never echoed.
    }

    [Fact]
    public void Enter_immediately_returns_empty()
    {
        Assert.Equal(string.Empty, Run(new[] { Enter }).Result);
    }

    [Fact]
    public void Escape_cancels()
    {
        var (result, error, read) = Run(Type("abc").Append(Key(ConsoleKey.Escape, '\u001b')).Append(Char('x')));

        Assert.Null(result);
        Assert.Equal(4, read); // Stops at Escape.
        Assert.EndsWith(Environment.NewLine, error);
    }

    [Fact]
    public void Backspace_deletes_the_last_character_and_is_harmless_on_empty_input()
    {
        var keys = new[] { Backspace }.Concat(Type("abcd")).Append(Backspace).Append(Backspace).Concat(Type("Z")).Append(Enter);

        Assert.Equal("abZ", Run(keys).Result);
    }

    [Fact]
    public void Backspace_deletes_a_whole_surrogate_pair()
    {
        // An emoji arrives as two key events (high then low surrogate); one Backspace must remove both,
        // or a lone surrogate is left that the hasher rejects.
        string emoji = "\U0001F600";
        var keys = Type("a" + emoji).Append(Backspace).Concat(Type("b")).Append(Enter);

        Assert.Equal("ab", Run(keys).Result);
    }

    [Fact]
    public void Backspace_after_a_lone_low_surrogate_deletes_one_unit()
    {
        var keys = Type("a").Append(Char('\uDC00')).Append(Backspace).Append(Enter);

        Assert.Equal("a", Run(keys).Result);
    }

    [Fact]
    public void Ctrl_U_clears_the_line()
    {
        var keys = Type("wrong").Append(Key(ConsoleKey.U, '\u0015', control: true)).Concat(Type("right")).Append(Enter);

        Assert.Equal("right", Run(keys).Result);
    }

    [Fact]
    public void Plain_u_is_typed_not_treated_as_clear()
    {
        var keys = Type("ab").Append(Key(ConsoleKey.U, 'u')).Append(Enter);

        Assert.Equal("abu", Run(keys).Result);
    }

    [Theory]
    [InlineData(ConsoleKey.Tab, '\t')]
    [InlineData(ConsoleKey.LeftArrow, '\0')]
    [InlineData(ConsoleKey.F1, '\0')]
    [InlineData(ConsoleKey.A, '\u0001')] // Ctrl+A
    public void Control_and_non_character_keys_are_ignored(ConsoleKey key, char c)
    {
        var keys = Type("ab").Append(Key(key, c)).Concat(Type("c")).Append(Enter);

        Assert.Equal("abc", Run(keys).Result);
    }

    [Fact]
    public void Exactly_the_maximum_length_is_accepted()
    {
        string max = new string('x', PasswordInput.MaxPasswordChars);

        Assert.Equal(max, Run(Type(max).Append(Enter)).Result);
    }

    [Fact]
    public void One_character_over_the_maximum_throws()
    {
        string tooLong = new string('x', PasswordInput.MaxPasswordChars + 1);
        var error = new StringWriter();
        using IEnumerator<ConsoleKeyInfo> e = Type(tooLong).Append(Enter).GetEnumerator();

        var ex = Assert.Throws<ToolException>(() => SystemConsole.ReadSecret("p: ", () => { e.MoveNext(); return e.Current; }, error));

        Assert.Equal(PasswordInput.TooLongMessage, ex.Message);
        Assert.Equal("p: " + Environment.NewLine, error.ToString());
    }

    [Fact]
    public void Deleting_below_the_maximum_allows_typing_again()
    {
        string max = new string('x', PasswordInput.MaxPasswordChars);
        var keys = Type(max).Append(Backspace).Concat(Type("y")).Append(Enter);

        Assert.Equal(max.Substring(1) + "y", Run(keys).Result);
    }
}
