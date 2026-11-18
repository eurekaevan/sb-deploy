#!/usr/bin/env python3
"""Generate the portable release; no third-party packages are required."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from sb_deploy.bundle import bundle_script


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/sing-box-deploy.sh")
    args = parser.parse_args()
    text = bundle_script((ROOT / "sing-box-deploy.sh").read_text(), ROOT / "lib/sb_deploy")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)
    args.output.chmod(0o700)
    print(args.output)


if __name__ == "__main__":
    main()
