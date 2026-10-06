"""Score one URL with the lexical feature extractor. No model file required.

This is the inspection tool. Run it on a URL and read which signals fired
before you trust a model score.
"""

from __future__ import annotations

import argparse
import json

from features import extract_features


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    args = parser.parse_args()
    print(json.dumps(extract_features(args.url), indent=2))


if __name__ == "__main__":
    main()
