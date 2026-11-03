using System;
using System.Text;

namespace Masterly.Hash.PropertyTests.Support;

/// <summary>Applies <see cref="MutationOp"/>s to hash strings deterministically.</summary>
internal static class Mutator
{
    private static readonly string[] DuplicateParams = { ",p=test", ",p=test2", ",k=key1", ",k=key2", ",w=v1", ",wp=AA", ",x=1", ",", ",p=" };
    private static readonly string[] Suffixes = { "$", "=", "==", "$AAAA", " ", "\n", "\0", "\r\n" };
    private static readonly string[] Prefixes = { " ", "﻿", "\t", "$" };
    private static readonly string[] PrefixSwaps = { "$MH$", "$mh$$", "mh$", "$mh2$", "$Mh$", "$$mh$" };

    public static string Apply(string value, MutationOp[] ops)
    {
        string current = value;
        foreach (MutationOp op in ops)
            current = Apply(current, op);
        return current;
    }

    public static string Apply(string s, MutationOp op)
    {
        int insertAt = op.Position % (s.Length + 1);
        int at = s.Length == 0 ? 0 : op.Position % s.Length;
        switch (op.Kind)
        {
            case 0: // replace one char
                return s.Length == 0 ? op.Char.ToString() : s.Remove(at, 1).Insert(at, op.Char.ToString());
            case 1: // delete one char
                return s.Length == 0 ? s : s.Remove(at, 1);
            case 2: // insert one char (biased towards the structural ones)
            {
                char c = (op.Variant % 3) switch { 0 => '$', 1 => ',', _ => op.Variant % 2 == 0 ? '=' : op.Char };
                return s.Insert(insertAt, c.ToString());
            }
            case 3: // toggle case
            {
                if (s.Length == 0)
                    return s;
                char c = s[at];
                char toggled = char.IsUpper(c) ? char.ToLowerInvariant(c) : char.IsLower(c) ? char.ToUpperInvariant(c) : op.Char;
                return s.Remove(at, 1).Insert(at, toggled.ToString());
            }
            case 4: // truncate
                return s.Substring(0, insertAt);
            case 5: // duplicate / add a parameter at the end of the parameter section
            {
                int end = NthIndexOf(s, '$', 3);
                string param = DuplicateParams[op.Variant % DuplicateParams.Length];
                return end < 0 ? s + param : s.Insert(end, param);
            }
            case 6: // rewrite a parameter value
                return RewriteParam(s, op.Variant);
            case 7: // swap salt and tag
            {
                string[] parts = s.Split('$');
                if (parts.Length < 5)
                    return s + "$";
                (parts[3], parts[4]) = (parts[4], parts[3]);
                return string.Join("$", parts);
            }
            case 8: // append junk
                return s + Suffixes[op.Variant % Suffixes.Length];
            case 9: // prepend junk
                return Prefixes[op.Variant % Prefixes.Length] + s;
            case 10: // mangle the format prefix
                return s.StartsWith("$mh$", StringComparison.Ordinal)
                    ? PrefixSwaps[op.Variant % PrefixSwaps.Length] + s.Substring(4)
                    : "$mh$" + s;
            default: // pad a base64 field (non-canonical)
            {
                string[] parts = s.Split('$');
                int index = parts.Length - 1 - (op.Variant % 2);
                if (index < 0)
                    return s + "=";
                parts[index] += op.Variant % 4 < 2 ? "=" : "==";
                return string.Join("$", parts);
            }
        }
    }

    private static string RewriteParam(string s, int variant)
    {
        switch (variant % 8)
        {
            case 0: return s.Replace("p=test$", "p=test2$").Replace("p=test,", "p=test2,");
            case 1: return s.Replace("p=test2", "p=test");
            case 2: return s.Replace("k=key1", "k=key2");
            case 3: return s.Replace(",k=key1", "").Replace(",k=key2", "");               // drop the pepper
            case 4: return Unwrap(s);                                                        // drop the wrap
            case 5: return s.Replace("w=v1", "w=md5");
            case 6: return s.Contains(",k=", StringComparison.Ordinal) ? s : InsertParam(s, ",k=key1");
            default: return InsertParam(s, ",w=v1");
        }
    }

    private static string Unwrap(string s)
    {
        int w = s.IndexOf(",w=", StringComparison.Ordinal);
        if (w < 0)
            return s;
        int end = s.IndexOf('$', w);
        return end < 0 ? s.Substring(0, w) : s.Remove(w, end - w);
    }

    private static string InsertParam(string s, string param)
    {
        int end = NthIndexOf(s, '$', 3);
        return end < 0 ? s + param : s.Insert(end, param);
    }

    private static int NthIndexOf(string s, char c, int n)
    {
        int index = -1;
        for (int i = 0; i < n; i++)
        {
            index = s.IndexOf(c, index + 1);
            if (index < 0)
                return -1;
        }
        return index;
    }
}
