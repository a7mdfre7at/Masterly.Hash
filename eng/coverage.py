#!/usr/bin/env python3
"""Merge Cobertura reports from every test project and enforce minimum coverage.

Usage:
    python eng/coverage.py TestResults [--min-line 98] [--min-branch 95] [--details PACKAGE]

A line counts as covered if any test project executed it,
and a branch as covered if any run took it. Paths are normalized, so the same source file
reported by different test projects is merged rather than counted twice.
"""
import argparse
import collections
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

TEST_ASSEMBLY = re.compile(r"(\.Tests|UnitTests|PropertyTests)$")


def load(root):
    lines = collections.defaultdict(dict)     # (package, file) -> line -> hits
    branches = collections.defaultdict(dict)  # (package, file) -> line -> (covered, total)
    reports = glob.glob(os.path.join(root, "**", "*.cobertura.xml"), recursive=True)
    for report in reports:
        tree = ET.parse(report)
        sources = [s.text or "" for s in tree.iter("source")]
        for package in tree.iter("package"):
            name = package.get("name")
            if TEST_ASSEMBLY.search(name):
                continue
            for cls in package.iter("class"):
                path = cls.get("filename")
                if not os.path.isabs(path):
                    path = next((os.path.join(s, path) for s in sources if os.path.exists(os.path.join(s, path))), path)
                key = (name, os.path.normcase(os.path.abspath(path)))
                for line in cls.iter("line"):
                    number, hits = int(line.get("number")), int(line.get("hits"))
                    lines[key][number] = max(lines[key].get(number, 0), hits)
                    match = re.search(r"\((\d+)/(\d+)\)", line.get("condition-coverage", ""))
                    if line.get("branch") == "True" and match:
                        covered, total = int(match.group(1)), int(match.group(2))
                        previous = branches[key].get(number, (0, total))
                        branches[key][number] = (max(previous[0], covered), total)
    return reports, lines, branches


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results")
    parser.add_argument("--min-line", type=float, default=0)
    parser.add_argument("--min-branch", type=float, default=0)
    parser.add_argument("--details", metavar="PACKAGE", help="list uncovered lines of one package")
    args = parser.parse_args()

    reports, lines, branches = load(args.results)
    if not reports:
        print(f"No *.cobertura.xml under {args.results}.", file=sys.stderr)
        return 2

    totals = collections.defaultdict(lambda: [0, 0, 0, 0])
    for key, hits in lines.items():
        t = totals[key[0]]
        t[0] += sum(1 for h in hits.values() if h > 0)
        t[1] += len(hits)
        t[2] += sum(c for c, _ in branches[key].values())
        t[3] += sum(n for _, n in branches[key].values())

    def pct(a, b):
        return 100.0 * a / b if b else 100.0

    print(f"| Package | Lines | Branches |\n|---|---:|---:|")
    for name in sorted(totals):
        c, n, bc, bn = totals[name]
        print(f"| {name} | {pct(c, n):.1f}% ({c}/{n}) | {pct(bc, bn):.1f}% ({bc}/{bn}) |")
    c, n, bc, bn = (sum(t[i] for t in totals.values()) for i in range(4))
    line_pct, branch_pct = pct(c, n), pct(bc, bn)
    print(f"| **Total** | **{line_pct:.1f}%** ({c}/{n}) | **{branch_pct:.1f}%** ({bc}/{bn}) |")

    if args.details:
        for (name, path), hits in sorted(lines.items()):
            if name != args.details:
                continue
            missing = sorted(k for k, h in hits.items() if h == 0)
            partial = sorted(k for k, (cv, tot) in branches[(name, path)].items() if cv < tot and k not in missing)
            if missing or partial:
                print(f"\n{path}\n  uncovered: {missing}\n  partial branches: {partial}")

    failed = False
    if line_pct < args.min_line:
        print(f"::error::Line coverage {line_pct:.1f}% is below the {args.min_line}% minimum.")
        failed = True
    if branch_pct < args.min_branch:
        print(f"::error::Branch coverage {branch_pct:.1f}% is below the {args.min_branch}% minimum.")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
