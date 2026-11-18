#!/usr/bin/env python3
"""Fast: direct module/release contracts. Slow: isolated system lifecycle regressions."""

import argparse
import unittest
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", choices=("fast", "slow", "all"), default="all")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    patterns = sorted(path.name for path in directory.glob("test_*.py"))
    if args.group == "fast":
        patterns.remove("test_deploy.py")
    elif args.group == "slow":
        patterns = ["test_deploy.py"]
    suite = unittest.TestSuite(
        unittest.defaultTestLoader.discover(str(directory), pattern=pattern) for pattern in patterns
    )
    if not suite.countTestCases():
        parser.error("No tests were selected")
    print(f"Running {args.group}: {suite.countTestCases()} tests", flush=True)
    return (
        0
        if unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite).wasSuccessful()
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
