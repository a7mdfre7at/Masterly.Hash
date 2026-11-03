using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Testing
{
    /// <summary>
    /// Framework-agnostic assertions about stored password hashes. Each method returns normally on success and throws
    /// <see cref="MasterlyHashAssertionException"/> on failure. Failure messages describe the problem (format, profile id,
    /// pepper key id) but never include the password or the stored value, which may itself be a leaked plaintext.
    /// </summary>
    public static class MasterlyHashAssert
    {
        /// <summary>Passwords shorter than this are only checked for equality, not containment, to avoid chance matches inside random base64.</summary>
        private const int MinContainmentLength = 6;

        /// <summary>Bounds the core enforces on every profile's salt and tag length.</summary>
        private const int MinSaltOrTagBytes = 16, MaxSaltOrTagBytes = 64;

        /// <summary>Used only to parse hash strings; never hashes. Knows the built-in profiles and <c>test-fast</c>.</summary>
        private static readonly Lazy<PasswordHasher> Parser = new Lazy<PasswordHasher>(() =>
        {
            var options = new PasswordHasherOptions { MaxConcurrency = 0, AllowWeakProfiles = true };
            options.AdditionalProfiles.Add(FastPasswordHasher.Profile);
            return new PasswordHasher(options);
        });

        /// <summary>
        /// Asserts that <paramref name="value"/> is a well-formed Masterly hash string (<c>$mh$p=...$salt$tag</c>) whose salt
        /// and tag have the lengths its profile requires (for a built-in or <c>test-fast</c> profile), or lengths any profile
        /// could have (16 to 64 bytes) for other profile ids. Truncated or otherwise damaged hashes fail.
        /// </summary>
        /// <param name="value">The stored value.</param>
        /// <exception cref="MasterlyHashAssertionException">It is not.</exception>
        public static void IsMasterlyHash(string? value) => Parse(value);

        /// <summary>Asserts that <paramref name="value"/> is a Masterly hash made with the profile <paramref name="profileId"/>.</summary>
        /// <param name="value">The stored value.</param>
        /// <param name="profileId">Expected profile id, e.g. <c>2026a</c> or <c>test-fast</c>.</param>
        /// <exception cref="MasterlyHashAssertionException">It is not.</exception>
        public static void UsesProfile(string? value, string profileId)
        {
            if (profileId == null) throw new ArgumentNullException(nameof(profileId));
            HashInfo info = Parse(value);
            if (!string.Equals(info.ProfileId, profileId, StringComparison.Ordinal))
                throw Fail($"Expected a hash with profile '{profileId}', but it uses profile '{info.ProfileId}'.");
        }

        /// <summary>Asserts that <paramref name="value"/> is a Masterly hash made with <paramref name="profile"/>.</summary>
        /// <param name="value">The stored value.</param>
        /// <param name="profile">Expected profile.</param>
        /// <exception cref="MasterlyHashAssertionException">It is not.</exception>
        public static void UsesProfile(string? value, HashProfile profile)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            UsesProfile(value, profile.Id);
        }

        /// <summary>Asserts that <paramref name="value"/> is a Masterly hash peppered with the key <paramref name="keyId"/>.</summary>
        /// <param name="value">The stored value.</param>
        /// <param name="keyId">Expected pepper key id.</param>
        /// <exception cref="MasterlyHashAssertionException">It is not.</exception>
        public static void IsPeppered(string? value, string keyId)
        {
            if (keyId == null) throw new ArgumentNullException(nameof(keyId));
            HashInfo info = Parse(value);
            if (info.PepperKeyId == null)
                throw Fail($"Expected a hash peppered with key '{keyId}', but it is not peppered.");
            if (!string.Equals(info.PepperKeyId, keyId, StringComparison.Ordinal))
                throw Fail($"Expected a hash peppered with key '{keyId}', but it uses key '{info.PepperKeyId}'.");
        }

        /// <summary>Asserts that <paramref name="value"/> is a Masterly hash peppered with any key.</summary>
        /// <param name="value">The stored value.</param>
        /// <exception cref="MasterlyHashAssertionException">It is not.</exception>
        public static void IsPeppered(string? value)
        {
            if (Parse(value).PepperKeyId == null)
                throw Fail("Expected a peppered hash, but it is not peppered.");
        }

        /// <summary>Asserts that <paramref name="value"/> is a Masterly hash without a pepper.</summary>
        /// <param name="value">The stored value.</param>
        /// <exception cref="MasterlyHashAssertionException">It is peppered or not a Masterly hash.</exception>
        public static void IsNotPeppered(string? value)
        {
            HashInfo info = Parse(value);
            if (info.PepperKeyId != null)
                throw Fail($"Expected an unpeppered hash, but it is peppered with key '{info.PepperKeyId}'.");
        }

        /// <summary>Asserts that <paramref name="hasher"/> recognizes <paramref name="storedHash"/> and would replace it on the next successful login.</summary>
        /// <param name="hasher">The hasher as configured by the application. A <see cref="RecordingPasswordHasher"/> is unwrapped first, so the assertion's own call is not recorded.</param>
        /// <param name="storedHash">The stored value.</param>
        /// <exception cref="MasterlyHashAssertionException">It would not be rehashed.</exception>
        public static void NeedsRehash(IPasswordHasher hasher, string? storedHash)
        {
            HashInfo info = InspectWith(hasher, storedHash);
            if (!info.IsRecognized)
                throw Fail($"Expected a hash that needs rehashing, but the hasher does not recognize it ({Describe(info)}).");
            if (!info.NeedsRehash)
                throw Fail($"Expected a hash that needs rehashing, but it is current ({Describe(info)}).");
        }

        /// <summary>Asserts that <paramref name="hasher"/> recognizes <paramref name="storedHash"/> and considers it current.</summary>
        /// <param name="hasher">The hasher as configured by the application. A <see cref="RecordingPasswordHasher"/> is unwrapped first, so the assertion's own call is not recorded.</param>
        /// <param name="storedHash">The stored value.</param>
        /// <exception cref="MasterlyHashAssertionException">It is unrecognized or would be rehashed.</exception>
        public static void DoesNotNeedRehash(IPasswordHasher hasher, string? storedHash)
        {
            HashInfo info = InspectWith(hasher, storedHash);
            if (!info.IsRecognized)
                throw Fail($"Expected a current hash, but the hasher does not recognize it ({Describe(info)}).");
            if (info.NeedsRehash)
                throw Fail($"Expected a current hash, but it would be rehashed ({info.RehashReason}; {Describe(info)}).");
        }

        /// <summary>Asserts that <paramref name="password"/> verifies against <paramref name="storedHash"/> with <paramref name="hasher"/>.</summary>
        /// <param name="hasher">The hasher. A <see cref="RecordingPasswordHasher"/> is unwrapped first, so the assertion's own call (and any rehash it produces) is not recorded.</param>
        /// <param name="password">The password.</param>
        /// <param name="storedHash">The stored hash.</param>
        /// <returns>The verification result, for further checks.</returns>
        /// <exception cref="MasterlyHashAssertionException">It does not verify.</exception>
        public static PasswordVerificationResult Verifies(IPasswordHasher hasher, string password, string? storedHash)
        {
            if (hasher == null) throw new ArgumentNullException(nameof(hasher));
            if (password == null) throw new ArgumentNullException(nameof(password));
            PasswordVerificationResult result = Unwrap(hasher).Verify(password, storedHash!);
            if (!result.IsMatch)
                throw Fail($"Expected the password to verify, but verification failed ({result.FailureReason}).");
            return result;
        }

        /// <summary>Asserts that <paramref name="password"/> does not verify against <paramref name="storedHash"/> with <paramref name="hasher"/>.</summary>
        /// <param name="hasher">The hasher. A <see cref="RecordingPasswordHasher"/> is unwrapped first, so the assertion's own call is not recorded.</param>
        /// <param name="password">The password.</param>
        /// <param name="storedHash">The stored hash.</param>
        /// <returns>The verification result, for further checks.</returns>
        /// <exception cref="MasterlyHashAssertionException">It verifies.</exception>
        public static PasswordVerificationResult DoesNotVerify(IPasswordHasher hasher, string password, string? storedHash)
        {
            if (hasher == null) throw new ArgumentNullException(nameof(hasher));
            if (password == null) throw new ArgumentNullException(nameof(password));
            PasswordVerificationResult result = Unwrap(hasher).Verify(password, storedHash!);
            if (result.IsMatch)
                throw Fail($"Expected the password not to verify, but it did ({result.Status}).");
            return result;
        }

        /// <summary>
        /// Asserts that <paramref name="stored"/> is neither <paramref name="password"/> nor a trivially reversible form of
        /// it: the plaintext or its NFKC-normalized form (any case, or embedded), its bytes as base64 or hex, or an unsalted
        /// MD5, SHA-1, SHA-256, SHA-384 or SHA-512 digest of its bytes in hex or base64. The byte forms tried are UTF-8,
        /// UTF-16LE (<see cref="Encoding.Unicode"/>) and UTF-8 of the NFKC-normalized password. For a well-formed Masterly
        /// hash only the salt, tag and wrap parameter are searched, so a password that equals a profile or pepper key id is
        /// not reported. This is a leak check, not a strength check: a salted fast hash passes; use
        /// <see cref="IsMasterlyHash"/> to require a proper password hash.
        /// </summary>
        /// <param name="stored">The value the application persisted.</param>
        /// <param name="password">The password that was submitted.</param>
        /// <exception cref="MasterlyHashAssertionException">The stored value exposes the password.</exception>
        public static void IsNotPlaintext(string? stored, string password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (password.Length == 0) throw new ArgumentException("Password cannot be empty.", nameof(password));
            if (stored == null)
                return;

            string normalized = Normalize(password);
            if (string.Equals(stored, password, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(stored, normalized, StringComparison.OrdinalIgnoreCase))
                throw Fail("The stored value is the password in plaintext.");

            List<string> haystacks = SearchableSegments(stored);
            if ((password.Length >= MinContainmentLength && ContainsAny(haystacks, password)) ||
                (normalized.Length >= MinContainmentLength && ContainsAny(haystacks, normalized)))
                throw Fail("The stored value contains the password in plaintext.");

            var forms = new List<byte[]>(3);
            try
            {
                AddDistinct(forms, Encoding.UTF8.GetBytes(password));
                AddDistinct(forms, Encoding.Unicode.GetBytes(password));
                if (HashPrimitives.IsWellFormedPassword(password))
                    AddDistinct(forms, HashPrimitives.EncodePassword(password));

                foreach (byte[] form in forms)
                {
                    if (ContainsEncoding(haystacks, form))
                        throw Fail("The stored value contains the password, merely base64- or hex-encoded.");
                }

                foreach (KeyValuePair<string, Func<HashAlgorithm>> digest in UnsaltedDigests())
                {
                    foreach (byte[] form in forms)
                    {
                        byte[]? hash = TryDigest(digest.Value, form);
                        if (hash == null)
                            break; // Algorithm unavailable on this platform.
                        bool found = ContainsEncoding(haystacks, hash);
                        HashPrimitives.Zero(hash);
                        if (found)
                            throw Fail($"The stored value contains an unsalted {digest.Key} digest of the password, which is reversible by lookup.");
                    }
                }
            }
            finally
            {
                foreach (byte[] form in forms)
                    HashPrimitives.Zero(form);
            }
        }

        /// <summary>
        /// Asserts that the code under test called <see cref="IPasswordHasher.VerifyOrDummy"/> (or its async form) without a
        /// stored hash, i.e. for an unknown user, and never called <see cref="IPasswordHasher.Verify"/> (or its async form)
        /// without one, which returns immediately and reveals that the account does not exist.
        /// </summary>
        /// <param name="recorder">The recorder wrapping the hasher given to the code under test.</param>
        /// <exception cref="MasterlyHashAssertionException">No such call was recorded, or an unknown user was verified with <c>Verify</c>.</exception>
        public static void UsedVerifyOrDummyForUnknownUser(RecordingPasswordHasher recorder)
        {
            if (recorder == null) throw new ArgumentNullException(nameof(recorder));
            bool usedDummy = false;
            foreach (PasswordHasherCall call in recorder.Calls)
            {
                if (!string.IsNullOrEmpty(call.StoredHash))
                    continue;
                if (call.Operation == PasswordHasherOperation.Verify)
                    throw Fail("An unknown user was verified with Verify(password, null), which returns immediately and reveals that the account does not exist. Use VerifyOrDummy.");
                if (call.Operation != PasswordHasherOperation.VerifyOrDummy)
                    continue;
                if (call.StoredHash != null)
                    throw Fail("VerifyOrDummy was given an empty stored hash, which returns immediately without the dummy work. Pass null for an unknown user.");
                usedDummy = true;
            }
            if (!usedDummy)
                throw Fail("Expected a VerifyOrDummy call without a stored hash (unknown user), but none was recorded.");
        }

        /// <summary>
        /// Asserts that the code under test persisted the rehash produced on login: the most recent
        /// <see cref="PasswordVerificationResult.Rehash"/> the recorder saw equals <paramref name="persistedHash"/>.
        /// </summary>
        /// <param name="recorder">The recorder wrapping the hasher given to the code under test.</param>
        /// <param name="persistedHash">The hash now stored for the user (read back from the fake repository).</param>
        /// <exception cref="MasterlyHashAssertionException">No rehash was issued, or a different value was stored.</exception>
        public static void PersistedRehash(RecordingPasswordHasher recorder, string? persistedHash)
        {
            if (recorder == null) throw new ArgumentNullException(nameof(recorder));
            IReadOnlyList<string> rehashes = recorder.RehashesIssued;
            if (rehashes.Count == 0)
                throw Fail("Expected a rehash to be persisted, but no verification returned a rehash.");
            if (!string.Equals(rehashes[rehashes.Count - 1], persistedHash, StringComparison.Ordinal))
                throw Fail("A verification returned a rehash, but the persisted hash is not that rehash. Store PasswordVerificationResult.Rehash after a successful login.");
        }

        private static HashInfo Parse(string? value)
        {
            if (value == null)
                throw Fail("Expected a Masterly hash, but the value is null.");
            if (!value.StartsWith("$mh$", StringComparison.Ordinal))
                throw Fail($"Expected a Masterly hash, but the value (length {value.Length}) does not start with '$mh$'.");
            HashInfo info = Parser.Value.Inspect(value);
            if (info.ProfileId == null)
                throw Fail($"Expected a Masterly hash, but the value (length {value.Length}) is malformed.");

            // Inspect accepts any non-empty base64 salt and tag; a hasher rejects wrong lengths as MalformedHash.
            string[] parts = value.Split('$');
            if (parts.Length != 5 || !HashPrimitives.TryFromB64(parts[3], out byte[] salt) || !HashPrimitives.TryFromB64(parts[4], out byte[] tag))
                throw Fail($"Expected a Masterly hash, but the value (length {value.Length}) is malformed.");
            if (info.Profile != null)
            {
                if (salt.Length != info.Profile.SaltLength || tag.Length != info.Profile.TagLength)
                    throw Fail($"Expected a Masterly hash, but the salt ({salt.Length} bytes) or tag ({tag.Length} bytes) does not match profile '{info.ProfileId}' ({info.Profile.SaltLength} and {info.Profile.TagLength} bytes); the value may be truncated.");
            }
            else if (!InBounds(salt.Length) || !InBounds(tag.Length))
            {
                throw Fail($"Expected a Masterly hash, but the salt ({salt.Length} bytes) or tag ({tag.Length} bytes) is outside {MinSaltOrTagBytes}..{MaxSaltOrTagBytes} bytes; the value may be truncated.");
            }
            return info;
        }

        private static bool InBounds(int length) => length >= MinSaltOrTagBytes && length <= MaxSaltOrTagBytes;

        private static HashInfo InspectWith(IPasswordHasher hasher, string? storedHash)
        {
            if (hasher == null) throw new ArgumentNullException(nameof(hasher));
            if (storedHash == null)
                throw Fail("Expected a stored hash, but the value is null.");
            return Unwrap(hasher).Inspect(storedHash);
        }

        /// <summary>Bypasses recorders so an assertion's own calls do not pollute the history it may later inspect.</summary>
        private static IPasswordHasher Unwrap(IPasswordHasher hasher)
        {
            while (hasher is RecordingPasswordHasher recorder)
                hasher = recorder.Inner;
            return hasher;
        }

        /// <summary>The password NFKC-normalized as the hasher sees it; the original if it cannot be normalized.</summary>
        private static string Normalize(string password)
        {
            try
            {
                return password.Normalize(NormalizationForm.FormKC);
            }
            catch (ArgumentException)
            {
                return password; // Invalid UTF-16.
            }
        }

        /// <summary>
        /// The parts of <paramref name="stored"/> worth searching for a leak. For a well-formed Masterly hash these are the
        /// salt, tag and wrap parameter; the profile, pepper key and format ids come from configuration, not the password.
        /// </summary>
        private static List<string> SearchableSegments(string stored)
        {
            var segments = new List<string>(3);
            if (stored.StartsWith("$mh$", StringComparison.Ordinal) && Parser.Value.Inspect(stored).ProfileId != null)
            {
                string[] parts = stored.Split('$');
                if (parts.Length == 5)
                {
                    foreach (string pair in parts[2].Split(','))
                    {
                        if (pair.StartsWith("wp=", StringComparison.Ordinal))
                            segments.Add(pair.Substring(3));
                    }
                    segments.Add(parts[3]);
                    segments.Add(parts[4]);
                    return segments;
                }
            }
            segments.Add(stored);
            return segments;
        }

        private static void AddDistinct(List<byte[]> forms, byte[] candidate)
        {
            foreach (byte[] existing in forms)
            {
                if (existing.Length == candidate.Length && HashPrimitives.FixedTimeEquals(existing, candidate))
                {
                    HashPrimitives.Zero(candidate);
                    return;
                }
            }
            forms.Add(candidate);
        }

        private static bool ContainsAny(List<string> haystacks, string needle)
        {
            foreach (string haystack in haystacks)
            {
                if (Contains(haystack, needle))
                    return true;
            }
            return false;
        }

        private static bool ContainsEncoding(List<string> haystacks, byte[] bytes)
        {
            foreach (string haystack in haystacks)
            {
                if (ContainsEncoding(haystack, bytes))
                    return true;
            }
            return false;
        }

        private static string Describe(HashInfo info)
        {
            var sb = new StringBuilder("format '").Append(info.Format).Append('\'');
            if (info.ProfileId != null)
                sb.Append(", profile '").Append(info.ProfileId).Append('\'');
            if (info.PepperKeyId != null)
                sb.Append(", pepper key '").Append(info.PepperKeyId).Append('\'');
            if (info.WrappedFormat != null)
                sb.Append(", wraps '").Append(info.WrappedFormat).Append('\'');
            return sb.ToString();
        }

        private static bool ContainsEncoding(string stored, byte[] bytes)
        {
            string base64 = Convert.ToBase64String(bytes);
            string base64NoPad = base64.TrimEnd('=');
            string base64Url = base64NoPad.Replace('+', '-').Replace('/', '_');
            string hex = BitConverter.ToString(bytes).Replace("-", string.Empty);
            return (base64NoPad.Length >= MinContainmentLength && (stored.IndexOf(base64NoPad, StringComparison.Ordinal) >= 0 || stored.IndexOf(base64Url, StringComparison.Ordinal) >= 0))
                || (hex.Length >= MinContainmentLength && Contains(stored, hex));
        }

        private static bool Contains(string haystack, string needle) =>
            haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;

        private static IEnumerable<KeyValuePair<string, Func<HashAlgorithm>>> UnsaltedDigests()
        {
#pragma warning disable CA5350, CA5351 // Weak algorithms are what we are looking for.
            yield return new KeyValuePair<string, Func<HashAlgorithm>>("MD5", () => MD5.Create());
            yield return new KeyValuePair<string, Func<HashAlgorithm>>("SHA-1", () => SHA1.Create());
#pragma warning restore CA5350, CA5351
            yield return new KeyValuePair<string, Func<HashAlgorithm>>("SHA-256", () => SHA256.Create());
            yield return new KeyValuePair<string, Func<HashAlgorithm>>("SHA-384", () => SHA384.Create());
            yield return new KeyValuePair<string, Func<HashAlgorithm>>("SHA-512", () => SHA512.Create());
        }

        private static byte[]? TryDigest(Func<HashAlgorithm> factory, byte[] data)
        {
            try
            {
                using (HashAlgorithm algorithm = factory())
                    return algorithm.ComputeHash(data);
            }
            catch (Exception ex) when (ex is CryptographicException || ex is PlatformNotSupportedException || ex is InvalidOperationException)
            {
                // Algorithm unavailable on this platform (e.g. MD5 under a strict FIPS policy): skip it.
                return null;
            }
        }

        private static MasterlyHashAssertionException Fail(string message) => new MasterlyHashAssertionException(message);
    }
}
