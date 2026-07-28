from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / ".github/scripts"))

import check_release_version as guard  # noqa: E402


def write_release_files(repo: Path, version: str) -> None:
    (repo / "src/phi_boundary_report").mkdir(parents=True)
    (repo / "docs").mkdir()
    (repo / "pyproject.toml").write_text(
        f'[project]\nname = "phi-context-boundary-report"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    (repo / "src/phi_boundary_report/__init__.py").write_text(
        f'__version__ = "{version}"\n',
        encoding="utf-8",
    )
    (repo / "README.md").write_text(
        f'<img src="https://img.shields.io/badge/release-v{version}-brightgreen.svg" />\n',
        encoding="utf-8",
    )
    (repo / "docs/install.md").write_text(
        f'phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v{version}\n',
        encoding="utf-8",
    )
    (repo / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## {version} - 2026-07-28\n\n- Test release.\n",
        encoding="utf-8",
    )


class ReleaseVersionGuardTest(unittest.TestCase):
    def test_collects_matching_version_copies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            write_release_files(repo, "0.3.1")

            copies = guard.collect_version_copies(repo)

            self.assertEqual(set(copies.values()), {"0.3.1"})
            self.assertEqual(guard.assert_copies_agree(copies), "0.3.1")

    def test_rejects_disagreeing_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            write_release_files(repo, "0.3.1")
            (repo / "README.md").write_text(
                '<img src="https://img.shields.io/badge/release-v0.3.0-brightgreen.svg" />\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(guard.VersionProblem, "version copies disagree"):
                guard.assert_copies_agree(guard.collect_version_copies(repo))

    def test_requires_install_tag_examples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            write_release_files(repo, "0.3.1")
            (repo / "docs/install.md").write_text("No install example.\n", encoding="utf-8")

            with self.assertRaisesRegex(guard.VersionProblem, "no Git tag install example"):
                guard.collect_version_copies(repo)


if __name__ == "__main__":
    unittest.main()
