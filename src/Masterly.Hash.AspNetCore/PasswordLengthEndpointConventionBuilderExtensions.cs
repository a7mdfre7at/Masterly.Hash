using System;
using Masterly.Hash.AspNetCore;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>Adds <see cref="PasswordLengthEndpointFilter"/> to minimal API endpoints.</summary>
    public static class PasswordLengthEndpointConventionBuilderExtensions
    {
        /// <summary>
        /// Rejects requests with <c>400 Bad Request</c> before the handler runs when a <see cref="Masterly.Hash.SensitiveString"/>
        /// argument (or a <see cref="Masterly.Hash.SensitiveString"/> property of an argument) exceeds
        /// <see cref="Masterly.Hash.PasswordHasherOptions.MaxPasswordBytes"/>. Works on single endpoints and route groups.
        /// Requires <c>AddMasterlyHash</c> (or <c>AddMasterlyPasswordHasher</c>), which registers the options.
        /// </summary>
        /// <example>
        /// <code>
        /// app.MapPost("/login", (LoginRequest request, IPasswordHasher hasher) => ...)
        ///    .WithPasswordLengthLimit();
        /// </code>
        /// </example>
        /// <returns>The same builder, for chaining.</returns>
        public static TBuilder WithPasswordLengthLimit<TBuilder>(this TBuilder builder)
            where TBuilder : IEndpointConventionBuilder
        {
            if (builder == null) throw new ArgumentNullException(nameof(builder));
            return builder.AddEndpointFilter<TBuilder, PasswordLengthEndpointFilter>();
        }
    }
}
