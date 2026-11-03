using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Detection
{
    /// <summary>
    /// The honeychecker from Juels and Rivest: a separate, hardened system that knows only which sweetword index is
    /// real for each user. It must not share storage, credentials or an administrator with the password database,
    /// so that one breach does not reveal both halves.
    /// </summary>
    /// <remarks>
    /// Keep the interface this narrow on the wire as well: the honeychecker should accept only "set" and "is this
    /// index real?" and should raise its own alarm (independently of the caller) when a wrong index is checked.
    /// </remarks>
    public interface IHoneychecker
    {
        /// <summary>Records the real sweetword index for <paramref name="userId"/>, replacing any previous value.</summary>
        Task SetAsync(string userId, int index, CancellationToken cancellationToken = default);

        /// <summary>
        /// True if <paramref name="index"/> is the real sweetword for <paramref name="userId"/>. Unknown users must
        /// return false (fail closed).
        /// </summary>
        Task<bool> IsRealAsync(string userId, int index, CancellationToken cancellationToken = default);
    }
}
