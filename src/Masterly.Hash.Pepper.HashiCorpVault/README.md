# Masterly.Hash.Pepper.HashiCorpVault

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

A [Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash) pepper backed by the HashiCorp Vault **Transit** secrets engine.
Before hashing, the hasher sends the password-derived input to Vault's `hmac` endpoint. Vault returns HMAC-SHA256 under a Transit
key that **never leaves Vault**.

## Install

```
dotnet add package Masterly.Hash.Pepper.HashiCorpVault
```

## Vault setup

```sh
vault secrets enable transit
vault write -f transit/keys/password-pepper type=hmac   # or aes256-gcm96; any key type that supports HMAC

# Least-privilege policy for the application token
vault policy write app-pepper - <<'EOF'
path "transit/hmac/password-pepper/sha2-256" { capabilities = ["update"] }
EOF
```

## Quickstart

```csharp
using Masterly.Hash;
using Masterly.Hash.Pepper.HashiCorpVault;

var pepper = new HashiCorpVaultPepper(httpClient, new HashiCorpVaultPepperOptions
{
    VaultAddress = new Uri("https://vault.example.com:8200"),
    KeyName = "password-pepper",
    Token = Environment.GetEnvironmentVariable("VAULT_TOKEN"), // or TokenProvider = ct => ...
    CurrentKeyVersion = 1,
    // MountPath = "transit", Namespace = "admin/team-a", Timeout = TimeSpan.FromSeconds(10)
});

var hasher = new PasswordHasher(new PasswordHasherOptions { Pepper = pepper });

string stored = await hasher.HashAsync(password);                 // $mh$p=2026a,k=v1$...
PasswordVerificationResult r = await hasher.VerifyAsync(password, stored);
```

Use the **async** hasher methods. The synchronous `Apply` blocks a thread-pool thread while it waits for Vault.

## Key rotation

Pepper key ids map to Transit key versions (`v1`, `v2`, ...).

1. `vault write -f transit/keys/password-pepper/rotate` creates version N+1.
2. Deploy with `CurrentKeyVersion = N+1`. During a rolling deploy, first set `MaxKeyVersion = N+1` on the old
   instances so they can verify hashes written by the new ones.
3. Hashes made with older versions keep verifying and return `RehashReason.OutdatedPepperKey` with a fresh hash.
4. Once every hash has been upgraded, raise `MinKeyVersion`, then raise the Transit key's `min_decryption_version`.

`IsKnownKey` only checks the configured `[MinKeyVersion, MaxKeyVersion]` range. It never calls Vault.

## Trust model

- **The key** stays inside Vault. A database leak does not expose it, and neither does an application memory dump.
- **The input**: the NFKC-normalized UTF-8 password bytes are sent to Vault in every request. Vault, and anything that can read
  that TLS traffic, sees the password. Use https (http is rejected unless `AllowInsecureHttp` is set). Do not enable Vault audit
  devices that log request bodies in clear text. Vault's default audit logging HMACs request fields.
- **Availability**: if Vault is unreachable, slow (`Timeout`), refuses the request, or returns a malformed answer, hash and verify
  throw `PepperUnavailableException`. The same holds for any other failure in the injected `HttpClient` pipeline, such as
  resilience-handler timeouts or open circuits, custom `DelegatingHandler` errors, or a disposed client (original exception
  as `InnerException`). The hasher does not turn this into a failed login. Map it to HTTP 503.
- **No secrets in errors**: exception messages never contain the token, the input or the HMAC. Request and response buffers are
  zeroed after use. No password-derived string is created: the JSON is built and parsed as UTF-8 bytes.
- The response must name the requested key version (`vault:vN:`) and hold exactly 32 bytes. Response bodies over 64 KiB are rejected.
