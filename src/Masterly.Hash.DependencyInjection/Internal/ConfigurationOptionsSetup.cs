using System;
using System.Collections.Generic;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection.Internal
{
    /// <summary>Maps a validated <see cref="MasterlyHashConfiguration"/> onto <see cref="PasswordHasherOptions"/>.</summary>
    internal sealed class ConfigurationOptionsSetup : IConfigureOptions<PasswordHasherOptions>
    {
        private readonly IOptions<MasterlyHashConfiguration> _configuration;

        public ConfigurationOptionsSetup(IOptions<MasterlyHashConfiguration> configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public void Configure(PasswordHasherOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            // Reading Value runs MasterlyHashConfigurationValidator; invalid configuration throws OptionsValidationException here.
            MasterlyHashConfiguration config = _configuration.Value;

            if (!string.IsNullOrWhiteSpace(config.DefaultProfile))
                options.DefaultProfile = Ids.BuiltInProfiles[config.DefaultProfile!.Trim()];
            if (config.MaxConcurrency.HasValue)
                options.MaxConcurrency = config.MaxConcurrency.Value;
            if (config.ConcurrencyTimeout.HasValue)
                options.ConcurrencyTimeout = config.ConcurrencyTimeout.Value;
            if (config.MaxPasswordBytes.HasValue)
                options.MaxPasswordBytes = config.MaxPasswordBytes.Value;
            if (config.ComputeRehashOnVerify.HasValue)
                options.ComputeRehashOnVerify = config.ComputeRehashOnVerify.Value;

            if (config.Pepper != null && !config.Pepper.IsEmpty)
                options.Pepper = CreatePepper(config.Pepper);
        }

        private static HmacPepper CreatePepper(MasterlyHashPepperConfiguration pepper)
        {
            var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            try
            {
                foreach (KeyValuePair<string, string> pair in pepper.Keys)
                {
                    if (PepperKeyDecoder.TryDecode(pair.Value, out byte[] key) != PepperKeyDecodeResult.Ok)
                        throw new InvalidOperationException($"MasterlyHash:Pepper:Keys:{pair.Key} is not a valid pepper key.");
                    keys[pair.Key] = key;
                }

                // HmacPepper copies the keys, so the decoded buffers can be wiped afterwards.
                return new HmacPepper(pepper.CurrentKeyId!.Trim(), keys);
            }
            finally
            {
                foreach (byte[] key in keys.Values)
                    HashPrimitives.Zero(key);
            }
        }
    }
}
