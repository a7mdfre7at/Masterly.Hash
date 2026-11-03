using System.Threading.Tasks;

namespace Masterly.Hash.Tool
{
    internal static class Program
    {
        private static Task<int> Main(string[] args) => ToolApp.RunAsync(args, ToolEnvironment.CreateDefault());
    }
}
