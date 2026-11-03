using System;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Masterly.Hash
{
    /// <summary>
    /// A string that refuses to leak: <see cref="ToString"/>, the debugger and JSON serialization all show <c>***</c>.
    /// Use it for password fields in request models so they cannot end up in logs by accident.
    /// Call <see cref="Reveal"/> only where the value is actually needed.
    /// </summary>
    /// <remarks>
    /// JSON deserialization reads the real value; serialization always writes <c>"***"</c>, so a
    /// <see cref="SensitiveString"/> never round-trips through JSON.
    /// </remarks>
    [DebuggerDisplay("***")]
    [JsonConverter(typeof(SensitiveStringJsonConverter))]
    public sealed class SensitiveString
    {
        /// <summary>The text shown instead of the value.</summary>
        public const string Redacted = "***";

        private readonly string _value;

        /// <summary>Wraps a value.</summary>
        public SensitiveString(string value)
        {
            _value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>Length of the value in UTF-16 code units.</summary>
        public int Length => _value.Length;

        /// <summary>True if the value is empty.</summary>
        public bool IsEmpty => _value.Length == 0;

        /// <summary>Returns the real value. Every call site is a place the secret can leak; keep them few.</summary>
        public string Reveal() => _value;

        /// <summary>Always <c>***</c>.</summary>
        public override string ToString() => Redacted;

        /// <summary>Wraps a string.</summary>
        public static explicit operator SensitiveString(string value) => new SensitiveString(value);

        /// <summary>Enables ASP.NET Core minimal API binding from route, query or form values.</summary>
        public static bool TryParse(string? value, out SensitiveString? result)
        {
            result = value == null ? null : new SensitiveString(value);
            return result != null;
        }
    }

    /// <summary>Reads the real value; writes <c>"***"</c>.</summary>
    public sealed class SensitiveStringJsonConverter : JsonConverter<SensitiveString>
    {
        /// <inheritdoc />
        public override SensitiveString? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Null)
                return null;
            if (reader.TokenType != JsonTokenType.String)
                throw new JsonException("Expected a string.");
            return new SensitiveString(reader.GetString()!);
        }

        /// <inheritdoc />
        public override void Write(Utf8JsonWriter writer, SensitiveString value, JsonSerializerOptions options) =>
            writer.WriteStringValue(SensitiveString.Redacted);
    }
}
