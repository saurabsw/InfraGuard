"""Integration tests validating all synthetic fixtures against expected findings manifest."""

from __future__ import annotations

import json
from pathlib import Path

from app.core.constants import ConfigFormat, EvaluationStatus, Provider
from app.engine.evaluator import RuleEvaluator
from app.normalization.normalizer import ResourceNormalizer
from app.parsers.registry import get_parser
from app.scoring.scorer import RiskScorer


class TestFixtureManifest:
    def test_all_fixtures_match_manifest(self):
        root = Path(__file__).parent.parent.parent
        manifest_path = root / "fixtures" / "expected_findings.json"
        assert manifest_path.exists(), "Manifest file not found"

        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)["fixtures"]

        normalizer = ResourceNormalizer()
        evaluator = RuleEvaluator()
        scorer = RiskScorer()

        for rel_path, expected in manifest.items():
            fixture_file = root / "fixtures" / rel_path
            assert fixture_file.exists(), f"Fixture file not found: {rel_path}"

            prov = Provider(expected["provider"])
            fmt = ConfigFormat(expected["format"])

            with open(fixture_file, "rb") as ff:
                content = ff.read()

            parser = get_parser(prov, fmt)
            parse_result = parser.parse(content, fixture_file.name, prov.value)

            if "expected_parse_success" in expected:
                assert parse_result.success is expected["expected_parse_success"]
                continue

            assert parse_result.success is True, (
                f"Failed parsing {rel_path}: {parse_result.diagnostics}"
            )

            normalized = normalizer.normalize(parse_result.resources, prov, fmt)
            findings = evaluator.evaluate_resources(normalized)
            summary = scorer.calculate_score(findings)

            if "expected_fails" in expected:
                actual_fails = {f.rule_id for f in findings if f.status == EvaluationStatus.FAIL}
                expected_fails = set(expected["expected_fails"])
                assert expected_fails.issubset(actual_fails), (
                    f"Fixture {rel_path} missing expected fails: {expected_fails - actual_fails}"
                )

            if "expected_score_band" in expected:
                assert summary.risk_band.value == expected["expected_score_band"], (
                    f"Fixture {rel_path} expected band {expected['expected_score_band']}, got {summary.risk_band.value}"
                )

            if "expected_not_evaluated" in expected:
                actual_not_eval = {
                    f.rule_id for f in findings if f.status == EvaluationStatus.NOT_EVALUATED
                }
                for rule_id in expected["expected_not_evaluated"]:
                    assert rule_id in actual_not_eval, (
                        f"Fixture {rel_path} expected NOT_EVALUATED for {rule_id}"
                    )
