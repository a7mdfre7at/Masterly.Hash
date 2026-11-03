using System;
using System.Collections.Generic;

namespace Masterly.Hash.Policy.Internal
{
    /// <summary>
    /// Key adjacency for a US QWERTY keyboard (slanted rows) and a numeric keypad (aligned grid), built the same
    /// way as zxcvbn's <c>build_keyboard_adjacency_graphs</c>: each key maps to its neighbours in a fixed
    /// direction order, with null where there is no key. Each neighbour is the key's unshifted and shifted characters.
    /// </summary>
    internal sealed class AdjacencyGraph
    {
        private const string QwertyLayout =
            "`~ 1! 2@ 3# 4$ 5% 6^ 7& 8* 9( 0) -_ =+\n" +
            "    qQ wW eE rR tT yY uU iI oO pP [{ ]} \\|\n" +
            "     aA sS dD fF gG hH jJ kK lL ;: '\"\n" +
            "      zZ xX cC vV bB nN mM ,< .> /?";

        private const string KeypadLayout =
            "  / * -\n" +
            "7 8 9 +\n" +
            "4 5 6\n" +
            "1 2 3\n" +
            "  0 .";

        public static readonly AdjacencyGraph Qwerty = new AdjacencyGraph("qwerty", QwertyLayout, slanted: true);
        public static readonly AdjacencyGraph Keypad = new AdjacencyGraph("keypad", KeypadLayout, slanted: false);

        private readonly Dictionary<char, string?[]> _adjacency = new Dictionary<char, string?[]>();

        private AdjacencyGraph(string name, string layout, bool slanted)
        {
            Name = name;
            var positions = new Dictionary<(int X, int Y), string>();
            string[] lines = layout.Split('\n');
            int tokenSize = -1;
            for (int y = 1; y <= lines.Length; y++)
            {
                string line = lines[y - 1];
                int slant = slanted ? y - 1 : 0;
                foreach (string token in line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (tokenSize < 0)
                        tokenSize = token.Length;
                    int xUnit = tokenSize + 1;
                    int x = (line.IndexOf(token, StringComparison.Ordinal) - slant) / xUnit;
                    positions[(x, y)] = token;
                }
            }

            foreach (KeyValuePair<(int X, int Y), string> entry in positions)
            {
                (int X, int Y)[] neighbours = slanted ? Slanted(entry.Key.X, entry.Key.Y) : Aligned(entry.Key.X, entry.Key.Y);
                var adjacent = new string?[neighbours.Length];
                for (int k = 0; k < neighbours.Length; k++)
                    adjacent[k] = positions.TryGetValue(neighbours[k], out string? key) ? key : null;
                foreach (char c in entry.Value)
                    _adjacency[c] = adjacent;
            }

            int degreeSum = 0;
            foreach (string?[] adjacent in _adjacency.Values)
            {
                foreach (string? key in adjacent)
                {
                    if (key != null)
                        degreeSum++;
                }
            }
            StartingPositions = _adjacency.Count;
            AverageDegree = (double)degreeSum / _adjacency.Count;
        }

        public string Name { get; }

        /// <summary>Number of characters on the layout (zxcvbn's <c>KEYBOARD_STARTING_POSITIONS</c>).</summary>
        public int StartingPositions { get; }

        /// <summary>Mean number of neighbours per character (zxcvbn's <c>KEYBOARD_AVERAGE_DEGREE</c>).</summary>
        public double AverageDegree { get; }

        public bool TryGetAdjacent(char c, out string?[] adjacent) => _adjacency.TryGetValue(c, out adjacent!);

        private static (int, int)[] Slanted(int x, int y) =>
            new[] { (x - 1, y), (x, y - 1), (x + 1, y - 1), (x + 1, y), (x, y + 1), (x - 1, y + 1) };

        private static (int, int)[] Aligned(int x, int y) =>
            new[] { (x - 1, y), (x - 1, y - 1), (x, y - 1), (x + 1, y - 1), (x + 1, y), (x + 1, y + 1), (x, y + 1), (x - 1, y + 1) };
    }
}
