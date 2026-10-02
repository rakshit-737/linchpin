"""Repository hygiene checks run in CI (python scripts/check_repo.py):

* no tracked file is larger than 1 MB (datasets and large artefacts stay out of git);
* every relative link in the Markdown files (README, docs/, ADRs, results) points to a file
  that exists, so a moved file cannot leave a broken link behind.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1 << 20
LINK = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def tracked() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [ROOT / p for p in out.decode().split("\0") if p]


def main() -> int:
    problems = []
    files = tracked()
    for p in files:
        if p.is_file() and p.stat().st_size > LIMIT:
            problems.append(f"{p.relative_to(ROOT)}: {p.stat().st_size / 1e6:.2f} MB > 1 MB")
    for md in (p for p in files if p.suffix == ".md"):
        text = md.read_text(encoding="utf-8")
        text = re.sub(r"```.*?```", "", text, flags=re.S)  # ignore code blocks
        for target in LINK.findall(text):
            if re.match(r"^[a-z]+:", target) or target.startswith("#"):
                continue  # external link or same-page anchor
            path = unquote(target.split("#", 1)[0])
            if not path:
                continue
            base = ROOT if path.startswith("/") else md.parent
            resolved = (base / path.lstrip("/")).resolve()
            # MkDocs pages link to other pages as page.md or page/ (directory URLs)
            if not (resolved.exists() or resolved.with_suffix(".md").exists()
                    or (resolved / "index.md").exists()):
                problems.append(f"{md.relative_to(ROOT)}: broken link -> {target}")
    for p in problems:
        print(p, file=sys.stderr)
    print(f"checked {len(files)} tracked files: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
