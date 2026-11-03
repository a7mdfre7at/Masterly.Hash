# Masterly.Hash.Pepper.AwsKms

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

A [Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash) pepper computed by **AWS KMS `GenerateMac`**
(`HMAC_SHA_256`) on an HMAC KMS key. The pepper key **never leaves KMS**.

## Install

```
dotnet add package Masterly.Hash.Pepper.AwsKms
```

## AWS setup

```sh
aws kms create-key --key-spec HMAC_256 --key-usage GENERATE_VERIFY_MAC --description "password pepper 2026-01"
```

Least-privilege IAM policy for the application:

```json
{ "Effect": "Allow", "Action": "kms:GenerateMac",
  "Resource": "arn:aws:kms:us-east-1:111122223333:key/<key-id>",
  "Condition": { "StringEquals": { "kms:MacAlgorithm": "HMAC_SHA_256" } } }
```

## Quickstart

```csharp
using Amazon.KeyManagementService;
using Masterly.Hash;
using Masterly.Hash.Pepper.AwsKms;

var options = new AwsKmsPepperOptions { CurrentKeyId = "2026-01" };
options.Keys["2026-01"] = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-...";

var pepper = new AwsKmsPepper(new AmazonKeyManagementServiceClient(), options);
var hasher = new PasswordHasher(new PasswordHasherOptions { Pepper = pepper });

string stored = await hasher.HashAsync(password);                 // $mh$p=2026a,k=2026-01$...
PasswordVerificationResult r = await hasher.VerifyAsync(password, stored);
```

Use the **async** hasher methods. The synchronous `Apply` blocks a thread-pool thread while it waits for KMS.

## Key rotation

HMAC KMS keys do not support automatic rotation. To rotate:

1. Create a new HMAC key and add it under a **new** pepper key id: `options.Keys["2027-01"] = "<new arn>"`.
2. Set `CurrentKeyId = "2027-01"`. Hashes under `2026-01` keep verifying and return `RehashReason.OutdatedPepperKey`
   along with a fresh hash.
3. Once every hash has been upgraded, remove the old id. Hashes that still use it fail with `UnknownPepperKey`. Then disable
   the old KMS key.

Never point an existing pepper key id at a different KMS key, and prefer key ARNs to aliases. If an alias is repointed,
every hash stored under that id stops verifying.

## Trust model

- **The key** stays inside KMS (FIPS 140-validated HSMs). A database leak or an application memory dump does not expose it.
- **The input**: each `GenerateMac` request sends the NFKC-normalized UTF-8 password bytes to KMS over TLS. KMS does
  not log message contents to CloudTrail, but AWS does process the password.
- **Limits**: KMS accepts messages of up to 4096 bytes, so keep `PasswordHasherOptions.MaxPasswordBytes` at 4096 or less (the default is 1024).
  KMS request quotas apply to every hash and verify, so size them for your peak login rate.
- **Availability**: hash and verify throw `PepperUnavailableException` when KMS errors, throttles, denies access, hits a disabled key, has a network
  failure, exceeds `Timeout` or the SDK client's own `ClientConfig.Timeout`, returns a malformed response, or the SDK
  fails in any other way (e.g. a disposed client). The hasher does not turn this into a failed login.
  Map it to HTTP 503.
- **No secrets in errors**: exception messages carry only the KMS error code and HTTP status, never the input. The returned
  MAC buffer is zeroed after copying.
- `IsKnownKey` checks the configured key map only. It never calls KMS.
