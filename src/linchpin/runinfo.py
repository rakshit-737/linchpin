"""Which code produced a result file: git commit, a dirty flag and, in GitHub Actions, the run.

Every script under ``benchmarks/`` (and the GDS cross-check test) stores :func:`run_provenance`
in its JSON output, so a committed table can be traced to the commit it was computed from, or
to the CI run whose artefact it is.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

# Paths whose uncommitted changes would make a result differ from what the commit says.
CODE_PATHS = ("src/**", "benchmarks/*.py", "scripts/**", "scenarios/**", "lab/**", "pyproject.toml")


def _git(args: list[str], cwd: Path) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip()


def run_provenance(repo: str | Path | None = None) -> dict:
    """Commit (and whether code under it had uncommitted changes) plus the CI run, if any.

    Args:
        repo: A directory inside the git checkout (default: this package's checkout).

    Returns:
        ``{"git_commit", "git_dirty_code"}`` (both None outside a git checkout) and, when
        ``GITHUB_RUN_ID`` is set, ``github_run_id``, ``github_sha``, ``github_workflow``,
        ``github_job`` and ``github_run_url``.
    """
    cwd = Path(repo) if repo else Path(__file__).resolve().parent
    sha = _git(["rev-parse", "HEAD"], cwd)
    top = [f":(top,glob){p}" for p in CODE_PATHS]  # pathspecs relative to the checkout root, not to cwd
    status = _git(["status", "--porcelain", "--untracked-files=no", "--", *top], cwd) if sha else None
    out: dict = {"git_commit": sha, "git_dirty_code": None if status is None else bool(status)}
    run_id = os.environ.get("GITHUB_RUN_ID")
    if run_id:
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        repo_name = os.environ.get("GITHUB_REPOSITORY", "")
        out.update({"github_run_id": run_id, "github_sha": os.environ.get("GITHUB_SHA"),
                    "github_workflow": os.environ.get("GITHUB_WORKFLOW"), "github_job": os.environ.get("GITHUB_JOB"),
                    "github_run_url": f"{server}/{repo_name}/actions/runs/{run_id}" if repo_name else None})
    return out
