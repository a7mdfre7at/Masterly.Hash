using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Masterly.Hash.Pepper.AwsKms;

namespace Masterly.Hash.Pepper.AwsKms.Tests;

public sealed record KmsCall(string KeyId, string MacAlgorithm, byte[] Message, List<string>? GrantTokens);

/// <summary>
/// In-memory imitation of KMS <c>GenerateMac</c>. <see cref="IAmazonKeyManagementService"/> has dozens of members,
/// so the client is a <see cref="DispatchProxy"/> that implements only <c>GenerateMacAsync</c> and <c>Dispose</c>.
/// </summary>
public sealed class FakeKms
{
    private readonly ConcurrentDictionary<string, byte[]> _keys = new(StringComparer.Ordinal);

    public FakeKms(params string[] kmsKeyIds)
    {
        foreach (string id in kmsKeyIds)
            _keys[id] = SHA256.HashData(Encoding.UTF8.GetBytes("kms-hmac-key-" + id));
        Client = DispatchProxy.Create<IAmazonKeyManagementService, KmsProxy>();
        ((KmsProxy)(object)Client).Fake = this;
    }

    public IAmazonKeyManagementService Client { get; }

    public ConcurrentQueue<KmsCall> Calls { get; } = new();

    /// <summary>Buffers of every MAC stream handed back, to check the pepper zeroes them.</summary>
    public ConcurrentQueue<byte[]> ReturnedBuffers { get; } = new();

    public Func<GenerateMacRequest, CancellationToken, Task<GenerateMacResponse>>? Override { get; set; }

    public void SetKey(string kmsKeyId, byte[] key) => _keys[kmsKeyId] = key;

    public byte[] Expected(string kmsKeyId, byte[] message) => HMACSHA256.HashData(_keys[kmsKeyId], message);

    public Task<GenerateMacResponse> GenerateMacAsync(GenerateMacRequest request, CancellationToken ct)
    {
        Calls.Enqueue(new KmsCall(request.KeyId, request.MacAlgorithm?.Value ?? "", request.Message.ToArray(), request.GrantTokens));
        if (Override != null)
            return Override(request, ct);

        if (!_keys.TryGetValue(request.KeyId, out byte[]? key))
            throw new NotFoundException($"Key '{request.KeyId}' does not exist") { ErrorCode = "NotFoundException", StatusCode = System.Net.HttpStatusCode.BadRequest };
        if (request.MacAlgorithm != MacAlgorithmSpec.HMAC_SHA_256)
            throw new InvalidKeyUsageException("wrong algorithm") { ErrorCode = "InvalidKeyUsageException" };

        return Task.FromResult(Response(HMACSHA256.HashData(key, request.Message.ToArray()), MacAlgorithmSpec.HMAC_SHA_256, "arn:aws:kms:us-east-1:111122223333:key/" + request.KeyId));
    }

    public GenerateMacResponse Response(byte[] mac, MacAlgorithmSpec? algorithm, string? keyId = null)
    {
        var stream = new MemoryStream();
        stream.Write(mac, 0, mac.Length);
        stream.Position = 0;
        ReturnedBuffers.Enqueue(stream.GetBuffer());
        return new GenerateMacResponse { Mac = stream, MacAlgorithm = algorithm, KeyId = keyId };
    }

    public static AwsKmsPepperOptions Options(string current, params (string Id, string KmsKey)[] keys)
    {
        var o = new AwsKmsPepperOptions { CurrentKeyId = current };
        foreach (var (id, kmsKey) in keys)
            o.Keys[id] = kmsKey;
        return o;
    }

    public static PasswordHasher Hasher(IPasswordPepper pepper) =>
        new(new PasswordHasherOptions { DefaultProfile = HashProfile.Argon2id("test", 64, 1), AllowWeakProfiles = true, Pepper = pepper });
}

public class KmsProxy : DispatchProxy
{
    internal FakeKms Fake { get; set; } = null!;

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        switch (targetMethod!.Name)
        {
            case nameof(IAmazonKeyManagementService.GenerateMacAsync):
                return Fake.GenerateMacAsync((GenerateMacRequest)args![0]!, (CancellationToken)args[1]!);
            case nameof(IDisposable.Dispose):
                return null;
            default:
                throw new NotImplementedException(targetMethod.Name);
        }
    }
}
