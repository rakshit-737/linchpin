"""Fail when the committed preprint's text differs from a fresh build of paper/linchpin.tex.

    python scripts/compare_pdf_text.py committed.pdf fresh.pdf

Both PDFs go through ``pdftotext`` (Poppler). The comparison ignores layout: text is NFKC-normalised,
hyphens and line breaks are dropped, and the two multisets of words are compared, so different line
or page breaks between TeX distributions do not matter but any changed word or number does.
"""
from __future__ import annotations

import re
import subprocess
import sys
import unicodedata
from collections import Counter


def words(pdf: str) -> Counter:
    text = subprocess.run(["pdftotext", "-enc", "UTF-8", pdf, "-"], capture_output=True, text=True,
                          encoding="utf-8", check=True).stdout
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"-\s*\n\s*", "", text).replace("-", "")  # hyphenation and hyphens, wherever lines broke
    return Counter(re.findall(r"[^\W_]+", text))


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    a, b = words(argv[0]), words(argv[1])
    only_a, only_b = a - b, b - a
    if not only_a and not only_b:
        print(f"same text ({sum(a.values())} words)")
        return 0
    print(f"text differs: {sum(only_a.values())} word(s) only in {argv[0]}, {sum(only_b.values())} only in {argv[1]}")
    print("  only in committed:", " ".join(sorted(only_a.elements()))[:2000])
    print("  only in fresh:    ", " ".join(sorted(only_b.elements()))[:2000])
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
