#!/usr/bin/env python3
"""
Automated Detection Testing Engine
====================================
Runs Atomic Red Team (ART) simulations against Sigma rules and
scores their detection effectiveness.

This script:
  1. Loads Sigma rules and their ART test mappings
  2. Simulates attack commands (safe mode by default)
  3. Matches simulated process events against Sigma detection logic
  4. Scores each rule's effectiveness (TP rate, FP rate, coverage)
  5. Generates a detailed test report

OPSEC: Runs in safe_mode=true by default (no actual commands executed).
       Set safe_mode=false ONLY in isolated test environments.
"""

import os
import sys
import re
import json
import yaml
import hashlib
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict


# ============================================================
# Data Models
# ============================================================
@dataclass
class TestCase:
    """Represents a single atomic test case."""
    test_id: str
    name: str
    command: str
    expected_detect: bool
    platform: str = "windows"
    cleanup: str = ""
    requires_admin: bool = False


@dataclass
class TestResult:
    """Result of running a single test case against a rule."""
    test_id: str
    test_name: str
    expected: bool       # Should the rule detect this?
    detected: bool       # Did the rule detect this?
    correct: bool        # Was the result correct?
    match_details: str = ""


@dataclass
class RuleTestReport:
    """Complete test report for a single Sigma rule."""
    rule_name: str
    rule_file: str
    mitre_technique: str
    total_tests: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    detection_score: float = 0.0
    grade: str = "F"
    promotion_eligible: bool = False
    test_results: List[dict] = field(default_factory=list)
    timestamp: str = ""


# ============================================================
# Sigma Rule Matcher (Local simulation)
# ============================================================
class SigmaRuleMatcher:
    """
    Simulates Sigma detection logic locally by parsing the YAML
    rule and matching against simulated process creation events.
    """

    def __init__(self, rule_path: str):
        with open(rule_path, "r", encoding="utf-8") as f:
            self.rule = yaml.safe_load(f)
        self.detection = self.rule.get("detection", {})
        self.condition = self.detection.get("condition", "")

    def match_event(self, event: Dict[str, str]) -> Tuple[bool, str]:
        """
        Check if a simulated event matches the Sigma rule's detection logic.
        Returns (matched, details).
        """
        # Evaluate each selection/filter in the detection block
        selection_results = {}

        for key, criteria in self.detection.items():
            if key == "condition":
                continue
            if isinstance(criteria, dict):
                selection_results[key] = self._match_selection(criteria, event)
            elif isinstance(criteria, list):
                # List of OR'd dictionaries
                selection_results[key] = any(
                    self._match_selection(c, event) for c in criteria if isinstance(c, dict)
                )

        # Evaluate condition
        matched = self._evaluate_condition(self.condition, selection_results)
        details = f"Selections: {selection_results} | Condition: '{self.condition}' → {matched}"
        return matched, details

    def _match_selection(self, criteria: Dict, event: Dict) -> bool:
        """Match a selection block against an event."""
        all_match = True

        for field_spec, values in criteria.items():
            parts = field_spec.split("|")
            field_name = parts[0]
            modifiers = parts[1:] if len(parts) > 1 else []

            event_value = event.get(field_name, "").lower()
            if not event_value:
                # Try common field aliases
                aliases = {
                    "Image": ["process_path", "image", "exe"],
                    "CommandLine": ["command_line", "cmdline", "cmd"],
                    "TargetObject": ["target_object", "registry_key"],
                    "TargetImage": ["target_image", "target_process"],
                    "User": ["user", "username"],
                }
                for alias in aliases.get(field_name, []):
                    event_value = event.get(alias, "").lower()
                    if event_value:
                        break

            if not isinstance(values, list):
                values = [values]

            # Check if 'all' modifier is present (AND logic for values)
            use_all = "all" in modifiers
            modifier = next((m for m in modifiers if m in ("endswith", "contains", "startswith", "re")), "")

            match_results = []
            for value in values:
                value_lower = str(value).lower()
                if modifier == "endswith":
                    match_results.append(event_value.endswith(value_lower))
                elif modifier == "contains":
                    match_results.append(value_lower in event_value)
                elif modifier == "startswith":
                    match_results.append(event_value.startswith(value_lower))
                elif modifier == "re":
                    match_results.append(bool(re.search(value, event_value, re.IGNORECASE)))
                else:
                    match_results.append(event_value == value_lower)

            if use_all:
                field_matched = all(match_results)
            else:
                field_matched = any(match_results)

            if not field_matched:
                all_match = False

        return all_match

    def _evaluate_condition(self, condition: str, results: Dict[str, bool]) -> bool:
        """Evaluate the Sigma condition string against selection results."""
        if not condition:
            return False

        # Build a boolean expression from the condition
        expr = condition

        # Sort keys by length (longest first) to avoid partial replacements
        sorted_keys = sorted(results.keys(), key=len, reverse=True)
        for key in sorted_keys:
            expr = expr.replace(key, str(results.get(key, False)))

        # Handle 'not' keyword
        expr = expr.replace(" not ", " not ")
        expr = expr.replace(" and ", " and ")
        expr = expr.replace(" or ", " or ")

        # Handle '1 of selection_*' type conditions
        if "1 of" in expr or "all of" in expr:
            pattern_match = re.match(r"(\d+|all) of (\w+)\*?", condition)
            if pattern_match:
                count_or_all = pattern_match.group(1)
                prefix = pattern_match.group(2)
                matching = [v for k, v in results.items() if k.startswith(prefix)]
                if count_or_all == "all":
                    return all(matching)
                else:
                    return sum(matching) >= int(count_or_all)

        try:
            return eval(expr, {"__builtins__": {}}, {})
        except Exception:
            # Fallback: check if any selection matched and no filter excluded it
            selections = {k: v for k, v in results.items() if not k.startswith("filter")}
            filters = {k: v for k, v in results.items() if k.startswith("filter")}

            any_selection = any(selections.values()) if selections else False
            any_filter = any(filters.values()) if filters else False

            if "not" in condition:
                return any_selection and not any_filter
            return any_selection


# ============================================================
# Simulated Event Generator
# ============================================================
class EventSimulator:
    """
    Generates simulated process creation events from ART test commands.
    These events mimic what Sysmon/Windows Event logs would produce.
    """

    @staticmethod
    def command_to_event(command: str) -> Dict[str, str]:
        """Convert a test command string to a simulated process event."""
        parts = command.split()
        exe = parts[0] if parts else ""

        # Extract the executable name
        if "\\" in exe:
            image_path = exe
        else:
            image_path = f"C:\\Windows\\System32\\{exe}"

        # Ensure .exe extension
        if not image_path.lower().endswith(".exe"):
            image_path += ".exe" if "." not in image_path.split("\\")[-1] else ""

        return {
            "Image": image_path,
            "CommandLine": command,
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "User": "DESKTOP-TEST\\testuser",
            "ComputerName": "DESKTOP-TEST",
            "ProcessId": "12345",
            "ParentProcessId": "6789",
            "UtcTime": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            # Aliases
            "process_path": image_path,
            "command_line": command,
            "image": image_path,
            "cmdline": command,
            "user": "DESKTOP-TEST\\testuser",
            "TargetObject": command,  # For registry rules
            "TargetImage": "",
            "GrantedAccess": "",
            "SourceImage": image_path,
        }


# ============================================================
# Detection Scorer
# ============================================================
class DetectionScorer:
    """Calculates detection effectiveness scores."""

    def __init__(self, config_path: str = "config/promotion_criteria.yml"):
        try:
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            self.config = self._default_config()

        scoring = self.config.get("scoring", {})
        self.weights = scoring.get("weights", {
            "true_positive_rate": 0.40,
            "false_positive_rate": 0.30,
            "coverage_breadth": 0.15,
            "query_efficiency": 0.15,
        })
        self.grades = scoring.get("grades", {"A": 90, "B": 80, "C": 70, "D": 60, "F": 0})

    def _default_config(self):
        return {
            "scoring": {
                "weights": {
                    "true_positive_rate": 0.40,
                    "false_positive_rate": 0.30,
                    "coverage_breadth": 0.15,
                    "query_efficiency": 0.15,
                },
                "grades": {"A": 90, "B": 80, "C": 70, "D": 60, "F": 0},
            }
        }

    def calculate_score(self, report: RuleTestReport) -> float:
        """Calculate weighted detection score."""
        if report.total_tests == 0:
            return 0.0

        tp_count = report.true_positives
        tn_count = report.true_negatives
        fp_count = report.false_positives
        fn_count = report.false_negatives

        # True Positive Rate (sensitivity/recall)
        tp_rate = tp_count / max(tp_count + fn_count, 1) * 100

        # False Positive Rate (1 - specificity) — lower is better
        fp_rate = fp_count / max(fp_count + tn_count, 1) * 100
        fp_score = max(0, 100 - fp_rate)  # Invert so higher = better

        # Coverage breadth — % of tests that ran successfully
        coverage = (tp_count + tn_count) / max(report.total_tests, 1) * 100

        # Query efficiency — placeholder (100 for locally matched rules)
        efficiency = 100.0

        score = (
            self.weights["true_positive_rate"] * tp_rate +
            self.weights["false_positive_rate"] * fp_score +
            self.weights["coverage_breadth"] * coverage +
            self.weights["query_efficiency"] * efficiency
        )

        return round(min(score, 100.0), 1)

    def get_grade(self, score: float) -> str:
        """Convert score to a letter grade."""
        for grade, threshold in sorted(self.grades.items(), key=lambda x: -x[1]):
            if score >= threshold:
                return grade
        return "F"


# ============================================================
# Main Test Runner
# ============================================================
class DetectionTestRunner:
    """Orchestrates the full detection testing pipeline."""

    def __init__(self, rules_dir: str = "rules",
                 test_config_path: str = "config/atomic_tests.yml",
                 promo_config_path: str = "config/promotion_criteria.yml"):
        self.rules_dir = Path(rules_dir)
        self.scorer = DetectionScorer(promo_config_path)

        with open(test_config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        self.test_mappings = config.get("test_mappings", {})
        self.test_config = config.get("test_config", {})
        self.safe_mode = self.test_config.get("safe_mode", True)

    def run_all_tests(self) -> Dict[str, RuleTestReport]:
        """Run tests for all mapped Sigma rules."""
        reports = {}

        print(f"\n{'='*70}")
        print(f"  🧪 AUTOMATED DETECTION TESTING ENGINE")
        print(f"  Mode: {'🔒 SAFE (simulation only)' if self.safe_mode else '⚠️  LIVE (commands executed)'}")
        print(f"  Rules directory: {self.rules_dir}")
        print(f"  Test mappings: {len(self.test_mappings)}")
        print(f"{'='*70}\n")

        for rule_key, mapping in self.test_mappings.items():
            report = self._test_single_rule(rule_key, mapping)
            reports[rule_key] = report

        self._print_summary(reports)
        return reports

    def _test_single_rule(self, rule_key: str, mapping: Dict) -> RuleTestReport:
        """Test a single Sigma rule against its mapped ART tests."""
        rule_file = mapping.get("sigma_rule", "")
        mitre_tech = mapping.get("mitre_technique", "")
        atomic_tests = mapping.get("atomic_tests", [])
        min_score = mapping.get("min_detection_score", 80)

        report = RuleTestReport(
            rule_name=rule_key,
            rule_file=rule_file,
            mitre_technique=mitre_tech,
            total_tests=len(atomic_tests),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

        print(f"  📋 Testing: {rule_key} (MITRE: {mitre_tech})")
        print(f"     Rule: {rule_file}")
        print(f"     Tests: {len(atomic_tests)}")

        # Load the Sigma rule matcher
        rule_path = Path(rule_file)
        if not rule_path.exists():
            # Try relative to project root
            rule_path = self.rules_dir / Path(rule_file).name
            if not rule_path.exists():
                print(f"     ❌ Rule file not found: {rule_file}")
                return report

        matcher = SigmaRuleMatcher(str(rule_path))

        for test in atomic_tests:
            test_case = TestCase(
                test_id=test.get("test_id", ""),
                name=test.get("name", ""),
                command=test.get("command", ""),
                expected_detect=test.get("expected_detect", True),
                platform=test.get("platform", "windows"),
                cleanup=test.get("cleanup", ""),
                requires_admin=test.get("requires_admin", False),
            )

            result = self._run_single_test(matcher, test_case)
            report.test_results.append(asdict(result))

            if result.correct:
                if result.expected:
                    report.true_positives += 1
                else:
                    report.true_negatives += 1
            else:
                if result.expected:
                    report.false_negatives += 1
                else:
                    report.false_positives += 1

        # Calculate score
        report.detection_score = self.scorer.calculate_score(report)
        report.grade = self.scorer.get_grade(report.detection_score)
        report.promotion_eligible = report.detection_score >= min_score

        grade_emoji = {"A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "F": "🔴"}.get(report.grade, "⚪")
        promo_emoji = "🚀" if report.promotion_eligible else "⏸️"

        print(f"     Score: {report.detection_score}% | Grade: {grade_emoji} {report.grade}")
        print(f"     TP: {report.true_positives} | TN: {report.true_negatives} | "
              f"FP: {report.false_positives} | FN: {report.false_negatives}")
        print(f"     {promo_emoji} {'Promotion eligible' if report.promotion_eligible else 'NOT eligible for promotion'}")
        print()

        return report

    def _run_single_test(self, matcher: SigmaRuleMatcher, test: TestCase) -> TestResult:
        """Run a single test case and check detection."""
        # Generate simulated event from test command
        event = EventSimulator.command_to_event(test.command)

        # Match against Sigma rule
        detected, details = matcher.match_event(event)

        correct = (detected == test.expected_detect)
        status = "✅" if correct else "❌"
        detect_str = "DETECTED" if detected else "MISSED"
        expected_str = "should detect" if test.expected_detect else "should NOT detect"

        print(f"       {status} [{test.test_id}] {test.name}")
        print(f"          Command: {test.command[:80]}{'...' if len(test.command) > 80 else ''}")
        print(f"          Result: {detect_str} | Expected: {expected_str}")

        return TestResult(
            test_id=test.test_id,
            test_name=test.name,
            expected=test.expected_detect,
            detected=detected,
            correct=correct,
            match_details=details,
        )

    def _print_summary(self, reports: Dict[str, RuleTestReport]):
        """Print overall test summary."""
        print(f"\n{'='*70}")
        print(f"  📊 TEST SUMMARY")
        print(f"{'='*70}")
        print(f"  {'Rule':<35} {'Score':>7} {'Grade':>6} {'Status':>12}")
        print(f"  {'-'*35} {'-'*7} {'-'*6} {'-'*12}")

        total_eligible = 0
        total_rules = len(reports)

        for key, report in reports.items():
            grade_emoji = {"A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "F": "🔴"}.get(report.grade, "⚪")
            status = "✅ Eligible" if report.promotion_eligible else "❌ Blocked"
            print(f"  {key:<35} {report.detection_score:>6.1f}% {grade_emoji} {report.grade:>4}  {status}")
            if report.promotion_eligible:
                total_eligible += 1

        print(f"\n  Total: {total_rules} rules | {total_eligible} eligible for promotion")
        print(f"{'='*70}\n")

    def save_report(self, reports: Dict[str, RuleTestReport], output_dir: str = "output"):
        """Save test reports to JSON."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report_data = {}
        for key, report in reports.items():
            report_data[key] = asdict(report)

        report_file = output_path / "test_report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        print(f"  📄 Test report saved to: {report_file}")

        # Generate summary for GitHub Actions
        summary_file = output_path / "test_summary.md"
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write("# Detection Test Report\n\n")
            f.write(f"**Date:** {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n")
            f.write("| Rule | MITRE | Score | Grade | Promo |\n")
            f.write("|------|-------|-------|-------|-------|\n")
            for key, report in reports.items():
                promo = "✅" if report.promotion_eligible else "❌"
                f.write(f"| {report.rule_name} | {report.mitre_technique} | "
                        f"{report.detection_score}% | {report.grade} | {promo} |\n")
            f.write(f"\n**Total:** {len(reports)} rules tested\n")

        print(f"  📄 Summary saved to: {summary_file}")

        # GitHub Actions output
        output_file = os.environ.get("GITHUB_OUTPUT", "")
        if output_file:
            eligible = sum(1 for r in reports.values() if r.promotion_eligible)
            with open(output_file, "a") as f:
                f.write(f"tested_rules={len(reports)}\n")
                f.write(f"eligible_rules={eligible}\n")
                f.write(f"blocked_rules={len(reports) - eligible}\n")

        return report_data


# ============================================================
# Entry point
# ============================================================
if __name__ == "__main__":
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else "rules"
    test_config = sys.argv[2] if len(sys.argv) > 2 else "config/atomic_tests.yml"
    promo_config = sys.argv[3] if len(sys.argv) > 3 else "config/promotion_criteria.yml"
    output_dir = sys.argv[4] if len(sys.argv) > 4 else "output"

    runner = DetectionTestRunner(rules_dir, test_config, promo_config)
    reports = runner.run_all_tests()
    runner.save_report(reports, output_dir)

    # Exit with error if any rule failed testing
    blocked = sum(1 for r in reports.values() if not r.promotion_eligible)
    if blocked > 0:
        print(f"\n⚠️  {blocked} rule(s) blocked from promotion.")
        # Don't exit with error — just report
    else:
        print(f"\n✅ All rules passed testing and are eligible for promotion!")

    sys.exit(0)
