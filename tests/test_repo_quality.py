from __future__ import annotations

import re
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phi_boundary_gate import PhiBoundaryGate, __version__, build_report, load_trace, redacted_trace_events  # noqa: E402
from phi_boundary_gate.detectors import RULES, detect_candidates  # noqa: E402
from phi_boundary_gate.policy import load_policy  # noqa: E402


README = ROOT / "README.md"
INSTALL_DOC = ROOT / "docs/install.md"
CHANGELOG = ROOT / "CHANGELOG.md"
SAMPLE_POLICY = ROOT / "samples/policies/default.yml"


class RepoQualityTest(unittest.TestCase):
    def test_project_version_copies_are_in_sync(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        readme = README.read_text(encoding="utf-8")
        install = INSTALL_DOC.read_text(encoding="utf-8")
        changelog = CHANGELOG.read_text(encoding="utf-8")

        self.assertEqual(metadata["project"]["version"], __version__)
        self.assertIn(f"release-v{__version__}", readme)
        self.assertIn(f"@v{__version__}", install)
        self.assertRegex(changelog, rf"(?m)^## {re.escape(__version__)} - ")

    def test_readme_keeps_badges_on_one_source_line(self) -> None:
        text = README.read_text(encoding="utf-8")
        badge_lines = [line for line in text.splitlines() if "img.shields.io/badge" in line]

        self.assertEqual(len(badge_lines), 1)
        self.assertGreaterEqual(badge_lines[0].count("img.shields.io/badge"), 5)

    def test_readme_carries_install_update_and_safety_sections(self) -> None:
        text = README.read_text(encoding="utf-8")

        self.assertIn("### Install from another project", text)
        self.assertIn("## Development", text)
        self.assertIn("## Limits", text)
        self.assertIn("--enable-presidio", text)
        self.assertIn("does not claim HIPAA compliance", text)

    def test_sample_policy_covers_regex_detector_categories(self) -> None:
        policy = load_policy(SAMPLE_POLICY)
        detector_categories = {rule.category for rule in RULES}

        self.assertFalse(detector_categories - set(policy.categories))

    def test_expanded_sample_exercises_many_policy_categories(self) -> None:
        content = (ROOT / "samples/traces/expanded_phi_variants.jsonl").read_text(encoding="utf-8")
        categories = {candidate.category for candidate in detect_candidates(content)}

        self.assertGreaterEqual(len(categories), 12)
        self.assertIn("ssn", categories)
        self.assertIn("url", categories)
        self.assertIn("ip_address", categories)

    def test_presidio_failure_message_points_to_optional_extra(self) -> None:
        with self.assertRaisesRegex(ValueError, r"pip install -e '\.\[ner\]'"):
            detect_candidates("No PHI here.", enable_presidio=True)

    def test_public_sdk_api_exports_are_available(self) -> None:
        self.assertEqual(PhiBoundaryGate.__name__, "PhiBoundaryGate")
        self.assertEqual(build_report.__name__, "build_report")
        self.assertEqual(load_trace.__name__, "load_trace")
        self.assertEqual(redacted_trace_events.__name__, "redacted_trace_events")

    def test_package_includes_typed_marker_and_project_templates(self) -> None:
        package_root = ROOT / "src/phi_boundary_gate"

        self.assertTrue((package_root / "py.typed").is_file())
        self.assertTrue((package_root / "templates/phi-policy.yml").is_file())
        self.assertTrue((package_root / "templates/phi-compliance-policy.yml").is_file())


if __name__ == "__main__":
    unittest.main()
