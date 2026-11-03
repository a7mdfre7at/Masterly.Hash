using System;
using System.Collections.Generic;
using Masterly.Hash.DependencyInjection.Internal;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection
{
    /// <summary>
    /// Validates a bound <see cref="MasterlyHashConfiguration"/>: known profile id, numeric ranges, and a well-formed
    /// pepper key ring. Messages name keys by id only; key bytes and key text are never included.
    /// </summary>
    public sealed class MasterlyHashConfigurationValidator : IValidateOptions<MasterlyHashConfiguration>
    {
        /// <inheritdoc />
        public ValidateOptionsResult Validate(string? name, MasterlyHashConfiguration options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            var failures = new List<string>();

            // Blank counts as absent (as for the nullable numeric settings), so a setting can be cleared with an empty variable.
            if (!string.IsNullOrWhiteSpace(options.DefaultProfile) && !Ids.BuiltInProfiles.ContainsKey(options.DefaultProfile!.Trim()))
            {
                // Echo the value only if it looks like a profile id, so a secret pasted into the wrong field is never logged.
                string trimmed = options.DefaultProfile.Trim();
                string shown = Ids.IsValidProfileOrFormatId(trimmed) ? $" '{trimmed}'" : string.Empty;
                failures.Add($"MasterlyHash:DefaultProfile{shown} is not a known profile. Known profiles: {Ids.BuiltInProfileList}.");
            }

            if (options.MaxConcurrency < 0)
                failures.Add("MasterlyHash:MaxConcurrency cannot be negative.");
            if (options.MaxPasswordBytes.HasValue && (options.MaxPasswordBytes < 64 || options.MaxPasswordBytes > 1024 * 1024))
                failures.Add("MasterlyHash:MaxPasswordBytes must be between 64 and 1048576.");
            if (options.ConcurrencyTimeout.HasValue && !Ids.IsValidConcurrencyTimeout(options.ConcurrencyTimeout.Value))
                failures.Add("MasterlyHash:ConcurrencyTimeout " + Ids.ConcurrencyTimeoutRule + ".");

            if (options.Pepper != null && !options.Pepper.IsEmpty)
                ValidatePepper(options.Pepper, failures);

            return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
        }

        private static void ValidatePepper(MasterlyHashPepperConfiguration pepper, List<string> failures)
        {
            string? current = pepper.CurrentKeyId?.Trim();
            if (string.IsNullOrEmpty(current))
                failures.Add("MasterlyHash:Pepper:CurrentKeyId is required when pepper keys are configured.");
            else if (!Ids.IsValidKeyId(current))
                failures.Add("MasterlyHash:Pepper:CurrentKeyId must match ^[A-Za-z0-9-]{1,32}$.");

            Dictionary<string, string> keys = pepper.Keys ?? new Dictionary<string, string>();
            if (keys.Count == 0)
            {
                failures.Add("MasterlyHash:Pepper:Keys must contain at least one key.");
                return;
            }

            foreach (KeyValuePair<string, string> pair in keys)
            {
                if (!Ids.IsValidKeyId(pair.Key))
                {
                    failures.Add("A MasterlyHash:Pepper:Keys entry has an id that does not match ^[A-Za-z0-9-]{1,32}$.");
                    continue;
                }

                switch (PepperKeyDecoder.TryDecode(pair.Value, out byte[] key))
                {
                    case PepperKeyDecodeResult.NotBase64:
                        failures.Add($"MasterlyHash:Pepper:Keys:{pair.Key} is not valid base64.");
                        continue;
                    case PepperKeyDecodeResult.TooLong:
                        failures.Add($"MasterlyHash:Pepper:Keys:{pair.Key} must decode to at most {PepperKeyDecoder.MaxKeyLength} bytes.");
                        continue;
                }

                int length = key.Length;
                HashPrimitives.Zero(key);
                if (length < HmacPepper.MinKeyLength)
                    failures.Add($"MasterlyHash:Pepper:Keys:{pair.Key} must decode to at least {HmacPepper.MinKeyLength} bytes.");
            }

            if (current != null && Ids.IsValidKeyId(current) && !keys.ContainsKey(current))
                failures.Add($"MasterlyHash:Pepper:CurrentKeyId '{current}' is not in MasterlyHash:Pepper:Keys.");
        }
    }
}
