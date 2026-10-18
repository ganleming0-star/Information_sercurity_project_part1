"""Count the three marking-scheme characters in the complete source file."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parents[1] / "py_http_server" / "middlewares" / "digest_auth_subverted.py"
    parser.add_argument("path", nargs="?", type=Path, default=default)
    args = parser.parse_args()
    try:
        source = args.path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        parser.error(str(error))
    counts = {char: source.count(char) for char in "(:,"}
    print(json.dumps({"file": str(args.path), "counts": counts, "total": sum(counts.values())},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
