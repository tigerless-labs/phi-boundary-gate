#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path


VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
INIT_VERSION_RE = re.compile(r'^__version__ = "([^"]+)"$', re.M)
README_BADGE_RE = re.compile(r"badge/release-v(\d+\.\d+\.\d+)-")
INSTALL_TAG_RE = re.compile(r"phi-context-boundary-report(?:\[ner\])? @ .*?@v(\d+\.\d+\.\d+)")
CHANGELOG_TOP_RE = re.compile(r"^## (\d+\.\d+\.\d+) - ", re.M)

VERSION_FILES = (
    "pyproject.toml",
    "src/phi_boundary_report/__init__.py",
    "README.md",
    "docs/install.md",
    "CHANGELOG.md",
)
SHIPPED_SURFACE_PREFIXES = (
    "src/",
    "samples/",
    "docs/",
    "reports/trace-corpus-coverage.json",
    "tools/",
    "README.md",
    "CHANGELOG.md",
    "pyproject.toml",
)


class VersionProblem(Exception):
    pass


def read_text(repo_root: Path, relative_path: str) -> str:
    path = repo_root / relative_path
    if not path.is_file():
        raise VersionProblem(f"{relative_path} is missing")
    return path.read_text(encoding="utf-8")


def read_pyproject_version(repo_root: Path) -> str:
    raw = tomllib.loads(read_text(repo_root, "pyproject.toml"))
    version = str(raw["project"]["version"])
    assert_semver(version, "pyproject.toml")
    return version


def read_init_version(repo_root: Path) -> str:
    match = INIT_VERSION_RE.search(read_text(repo_root, "src/phi_boundary_report/__init__.py"))
    if not match:
        raise VersionProblem("src/phi_boundary_report/__init__.py has no __version__ assignment")
    version = match.group(1)
    assert_semver(version, "__init__.__version__")
    return version


def read_readme_badge_version(repo_root: Path) -> str:
    match = README_BADGE_RE.search(read_text(repo_root, "README.md"))
    if not match:
        raise VersionProblem("README.md has no release-vX.Y.Z badge")
    return match.group(1)


def read_install_versions(repo_root: Path) -> list[str]:
    versions = INSTALL_TAG_RE.findall(read_text(repo_root, "docs/install.md"))
    if not versions:
        raise VersionProblem("docs/install.md has no Git tag install example")
    return versions


def read_changelog_top_version(repo_root: Path) -> str:
    match = CHANGELOG_TOP_RE.search(read_text(repo_root, "CHANGELOG.md"))
    if not match:
        raise VersionProblem("CHANGELOG.md has no top release entry")
    return match.group(1)


def assert_semver(version: str, source: str) -> None:
    if not VERSION_RE.match(version):
        raise VersionProblem(f"{source} version {version!r} is not MAJOR.MINOR.PATCH")


def collect_version_copies(repo_root: Path) -> dict[str, str]:
    copies = {
        "pyproject.toml": read_pyproject_version(repo_root),
        "__init__.__version__": read_init_version(repo_root),
        "README.md badge": read_readme_badge_version(repo_root),
        "CHANGELOG.md top entry": read_changelog_top_version(repo_root),
    }
    install_versions = read_install_versions(repo_root)
    for index, version in enumerate(install_versions, start=1):
        copies[f"docs/install.md tag #{index}"] = version
    return copies


def assert_copies_agree(copies: dict[str, str]) -> str:
    distinct = set(copies.values())
    if len(distinct) > 1:
        lines = [f"  {source}: {version}" for source, version in copies.items()]
        raise VersionProblem("version copies disagree:\n" + "\n".join(lines))
    return distinct.pop()


def git_output(repo_root: Path, *args: str) -> str | None:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def base_pyproject_version(repo_root: Path, base_ref: str) -> str | None:
    blob = git_output(repo_root, "show", f"{base_ref}:pyproject.toml")
    if blob is None:
        return None
    try:
        return str(tomllib.loads(blob)["project"]["version"])
    except (KeyError, tomllib.TOMLDecodeError):
        return None


def changed_files(repo_root: Path, base_ref: str) -> list[str] | None:
    committed = git_output(repo_root, "diff", "--name-only", f"{base_ref}...HEAD")
    if committed is None:
        return None
    uncommitted = git_output(repo_root, "status", "--porcelain", "--untracked-files=all") or ""
    names = set(filter(None, committed.splitlines()))
    for line in uncommitted.splitlines():
        if len(line) < 4:
            continue
        name = line[3:].strip().split(" -> ")[-1]
        if name:
            names.add(name)
    return sorted(names)


def shipped_surface_changes(paths: list[str]) -> list[str]:
    return [
        path
        for path in paths
        if path in VERSION_FILES or path.startswith(SHIPPED_SURFACE_PREFIXES)
    ]


def version_tuple(version: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in version.split("."))


def assert_bumped_for_surface_change(repo_root: Path, base_ref: str, current: str) -> None:
    previous = base_pyproject_version(repo_root, base_ref)
    paths = changed_files(repo_root, base_ref)
    if previous is None or paths is None:
        print(f"bump check skipped: base ref {base_ref!r} is not available")
        return

    touched = shipped_surface_changes(paths)
    if not touched:
        print(f"bump check passed: no shipped surface changed against {base_ref}")
        return
    if current == previous:
        listing = "\n".join(f"  {path}" for path in touched)
        raise VersionProblem(
            f"shipped surface changed but version stayed {current}; changed files:\n{listing}"
        )
    if version_tuple(current) < version_tuple(previous):
        raise VersionProblem(f"version moved backward: {previous} -> {current}")
    print(f"bump check passed: {previous} -> {current} for {len(touched)} shipped file(s)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check package release version consistency.")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--base-ref", default="origin/main")
    parser.add_argument("--skip-bump-check", action="store_true")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    try:
        copies = collect_version_copies(repo_root)
        current = assert_copies_agree(copies)
        print(f"version copies agree: {current}")
        if not args.skip_bump_check:
            assert_bumped_for_surface_change(repo_root, args.base_ref, current)
    except VersionProblem as exc:
        print(f"release version check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
