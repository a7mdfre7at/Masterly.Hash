using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.AspNetCore
{
    /// <summary>
    /// Minimal API endpoint filter that answers <c>400 Bad Request</c> when a <see cref="SensitiveString"/> argument, or a
    /// public <see cref="SensitiveString"/> property of an argument (one level deep, e.g. <c>LoginRequest.Password</c>),
    /// exceeds <see cref="PasswordHasherOptions.MaxPasswordBytes"/>. The endpoint, and therefore the hasher, never runs.
    /// Add it with <c>.WithPasswordLengthLimit()</c>.
    /// </summary>
    /// <remarks>
    /// The length is measured exactly as the hasher measures it: UTF-8 bytes after NFKC normalization. A value longer
    /// than 8 times the limit (in UTF-16 code units) is rejected from its length alone, before NFKC can expand it, so
    /// the check itself cannot be used to exhaust memory. Only getters of
    /// <see cref="SensitiveString"/>-typed properties are invoked. The response states the limit but never echoes the value.
    /// </remarks>
    public sealed class PasswordLengthEndpointFilter : IEndpointFilter
    {
        private static readonly ConcurrentDictionary<Type, PropertyInfo[]> SensitiveProperties = new ConcurrentDictionary<Type, PropertyInfo[]>();

        /// <summary>Creates the filter with the limit configured for the registered hasher.</summary>
        [ActivatorUtilitiesConstructor]
        public PasswordLengthEndpointFilter(IOptions<PasswordHasherOptions> options)
            : this((options ?? throw new ArgumentNullException(nameof(options))).Value.MaxPasswordBytes)
        {
        }

        /// <summary>Creates the filter with an explicit limit in UTF-8 bytes (at least 1).</summary>
        public PasswordLengthEndpointFilter(int maxPasswordBytes)
        {
            if (maxPasswordBytes < 1)
                throw new ArgumentOutOfRangeException(nameof(maxPasswordBytes), maxPasswordBytes, "The limit must be positive.");
            MaxPasswordBytes = maxPasswordBytes;
        }

        /// <summary>Longest accepted password, in UTF-8 bytes after NFKC normalization.</summary>
        public int MaxPasswordBytes { get; }

        /// <inheritdoc />
        public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            if (next == null) throw new ArgumentNullException(nameof(next));

            IList<object?> arguments = context.Arguments;
            for (int i = 0; i < arguments.Count; i++)
            {
                if (ContainsTooLong(arguments[i]))
                    return new ValueTask<object?>(Reject());
            }
            return next(context);
        }

        /// <summary>True if <paramref name="password"/> is longer than <see cref="MaxPasswordBytes"/>.</summary>
        public bool IsTooLong(SensitiveString password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return IsTooLong(password.Reveal());
        }

        private bool ContainsTooLong(object? argument)
        {
            if (argument == null || argument is string)
                return false;
            if (argument is SensitiveString direct)
                return IsTooLong(direct.Reveal());

            foreach (PropertyInfo property in SensitiveProperties.GetOrAdd(argument.GetType(), FindSensitiveProperties))
            {
                if (property.GetValue(argument) is SensitiveString value && IsTooLong(value.Reveal()))
                    return true;
            }
            return false;
        }

        private bool IsTooLong(string value) => PasswordLength.IsTooLongToHash(value, MaxPasswordBytes);

        private object Reject() => TypedResults.Problem(
            statusCode: StatusCodes.Status400BadRequest,
            title: "Password too long",
            detail: "The password exceeds the maximum length of " + MaxPasswordBytes.ToString(CultureInfo.InvariantCulture) + " bytes.");

        private static PropertyInfo[] FindSensitiveProperties(Type type)
        {
            if (type.IsPrimitive || type.IsEnum)
                return Array.Empty<PropertyInfo>();

            var found = new List<PropertyInfo>();
            foreach (PropertyInfo property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                if (property.PropertyType == typeof(SensitiveString) && property.GetMethod != null &&
                    property.GetMethod.IsPublic && property.GetIndexParameters().Length == 0)
                {
                    found.Add(property);
                }
            }
            return found.ToArray();
        }
    }
}
