#!/usr/bin/env python3
"""
Sigma Rule Validator
====================
Validates all Sigma rules for syntax, required fields, and quality checks.
Ensures rules meet minimum standards before conversion and deployment.
"""

import os
import sys
import yaml
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple


REQUIRED_FIELDS = ["title", "id", "status", "description", "author", "date", "logsource", "detection", "level"]
VALID_LEVELS = ["informational", "low", "medium", "high", "critical"]
VALID_STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"]

# Minimum severity to deploy — skip informational-only rules
MIN_DEPLOY_LEVEL = os.environ.get("MIN_DEPLOY_LEVEL", "low")


class RuleValidationError:
    """Represents a validation error for a Sigma rule."""

    def __init__(self, file: str, field: str, message: str, severity: str = "error"):
        self.file = file
        self.field = field
        self.message = message
        self.severity = severity  # error, warning

    def __str__(self):
        return f"[{self.severity.upper()}] {self.file}: {self.field} — {self.message}"


def load_rule(file_path: str) -> Tuple[Dict[str, Any] | None, str | None]:
    """Load and parse a YAML Sigma rule file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        if not isinstance(rule, dict):
            return None, "File does not contain a valid YAML dictionary"
        return rule, None
    except yaml.YAMLError as e:
        return None, f"YAML parsing error: {e}"
    except Exception as e:
        return None, f"File read error: {e}"


def validate_required_fields(rule: Dict, file_name: str) -> List[RuleValidationError]:
    """Check that all required fields are present."""
    errors = []
    for field in REQUIRED_FIELDS:
        if field not in rule or rule[field] is None:
            errors.append(RuleValidationError(file_name, field, f"Required field '{field}' is missing"))
    return errors


def validate_level(rule: Dict, file_name: str) -> List[RuleValidationError]:
    """Check that the level is valid."""
    errors = []
    level = rule.get("level", "")
    if level and level not in VALID_LEVELS:
        errors.append(RuleValidationError(
            file_name, "level",
            f"Invalid level '{level}'. Must be one of: {', '.join(VALID_LEVELS)}"
        ))
    return errors


def validate_status(rule: Dict, file_name: str) -> List[RuleValidationError]:
    """Check that the status is valid."""
    errors = []
    status = rule.get("status", "")
    if status and status not in VALID_STATUSES:
        errors.append(RuleValidationError(
            file_name, "status",
            f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}"
        ))
    return errors


def validate_detection(rule: Dict, file_name: str) -> List[RuleValidationError]:
    """Check that detection block has a condition."""
    errors = []
    detection = rule.get("detection", {})
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append(RuleValidationError(
                file_name, "detection.condition",
                "Detection block must contain a 'condition' field"
            ))
        # Check for at least one selection
        selections = [k for k in detection.keys() if k != "condition" and not k.startswith("filter")]
        if not selections:
            errors.append(RuleValidationError(
                file_name, "detection",
                "Detection block must contain at least one selection"
            ))
    else:
        errors.append(RuleValidationError(file_name, "detection", "Detection must be a dictionary"))
    return errors


def validate_logsource(rule: Dict, file_name: str) -> List[RuleValidationError]:
    """Check that logsource has required sub-fields."""
    errors = []
    logsource = rule.get("logsource", {})
    if isinstance(logsource, dict):
        if "category" not in logsource and "product" not in logsource and "service" not in logsource:
            errors.append(RuleValidationError(
                file_name, "logsource",
                "Logsource must contain at least one of: category, product, service"
            ))
    else:
        errors.append(RuleValidationError(file_name, "logsource", "Logsource must be a dictionary"))
    return errors


def validate_mitre_tags(rule: Dict, file_name: str) -> List[RuleValidationError]:
    """Warn if MITRE ATT&CK tags are missing (not an error, but recommended)."""
    warnings = []
    tags = rule.get("tags", [])
    if not tags:
        warnings.append(RuleValidationError(
            file_name, "tags",
            "No MITRE ATT&CK tags found. Consider adding tags for better categorization.",
            severity="warning"
        ))
    else:
        has_attack_tag = any(str(t).startswith("attack.") for t in tags)
        if not has_attack_tag:
            warnings.append(RuleValidationError(
                file_name, "tags",
                "No 'attack.*' tags found. Consider adding MITRE ATT&CK technique tags.",
                severity="warning"
            ))
    return warnings


def check_deploy_eligibility(rule: Dict, file_name: str) -> bool:
    """Check if a rule meets minimum level for deployment."""
    level = rule.get("level", "informational")
    level_order = {l: i for i, l in enumerate(VALID_LEVELS)}
    min_idx = level_order.get(MIN_DEPLOY_LEVEL, 1)
    rule_idx = level_order.get(level, 0)
    return rule_idx >= min_idx


def validate_rule(file_path: str) -> Tuple[List[RuleValidationError], bool]:
    """Run all validations on a single rule file."""
    file_name = os.path.basename(file_path)
    all_issues = []

    rule, parse_error = load_rule(file_path)
    if parse_error:
        all_issues.append(RuleValidationError(file_name, "yaml", parse_error))
        return all_issues, False

    all_issues.extend(validate_required_fields(rule, file_name))
    all_issues.extend(validate_level(rule, file_name))
    all_issues.extend(validate_status(rule, file_name))
    all_issues.extend(validate_detection(rule, file_name))
    all_issues.extend(validate_logsource(rule, file_name))
    all_issues.extend(validate_mitre_tags(rule, file_name))

    has_errors = any(i.severity == "error" for i in all_issues)
    deployable = not has_errors and check_deploy_eligibility(rule, file_name)

    return all_issues, deployable


def validate_all_rules(rules_dir: str) -> Tuple[int, int, int]:
    """Validate all Sigma rules in the directory."""
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        print(f"❌ Rules directory not found: {rules_dir}")
        sys.exit(1)

    rule_files = list(rules_path.glob("*.yml")) + list(rules_path.glob("*.yaml"))

    if not rule_files:
        print("⚠️  No Sigma rule files found.")
        return 0, 0, 0

    total_errors = 0
    total_warnings = 0
    deployable_count = 0
    results = []

    print(f"\n{'='*60}")
    print(f"  SIGMA RULE VALIDATION REPORT")
    print(f"  Rules directory: {rules_dir}")
    print(f"  Rules found: {len(rule_files)}")
    print(f"  Minimum deploy level: {MIN_DEPLOY_LEVEL}")
    print(f"{'='*60}\n")

    for rule_file in sorted(rule_files):
        issues, deployable = validate_rule(str(rule_file))
        errors = [i for i in issues if i.severity == "error"]
        warnings = [i for i in issues if i.severity == "warning"]

        total_errors += len(errors)
        total_warnings += len(warnings)

        status = "✅ PASS" if not errors else "❌ FAIL"
        deploy_status = "🚀 Deployable" if deployable else "⏸️  Skipped"

        print(f"  {status} | {deploy_status} | {rule_file.name}")

        for issue in issues:
            prefix = "    ❌" if issue.severity == "error" else "    ⚠️"
            print(f"{prefix} {issue.field}: {issue.message}")

        if deployable:
            deployable_count += 1
            results.append(str(rule_file))

    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"  Total rules: {len(rule_files)}")
    print(f"  Errors: {total_errors}")
    print(f"  Warnings: {total_warnings}")
    print(f"  Deployable: {deployable_count}/{len(rule_files)}")
    print(f"{'='*60}\n")

    # Write deployable rules list for downstream steps
    output_file = os.environ.get("GITHUB_OUTPUT", "")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"deployable_count={deployable_count}\n")
            f.write(f"total_rules={len(rule_files)}\n")
            f.write(f"validation_errors={total_errors}\n")

    # Also write list of deployable rules to a temp file
    deploy_list_path = Path(rules_dir).parent / "deployable_rules.json"
    with open(deploy_list_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  📄 Deployable rules list saved to: {deploy_list_path}")

    return len(rule_files), total_errors, deployable_count


if __name__ == "__main__":
    rules_directory = sys.argv[1] if len(sys.argv) > 1 else "rules"
    total, errors, deployable = validate_all_rules(rules_directory)

    if errors > 0:
        print("\n❌ Validation failed! Fix the errors above before deploying.")
        sys.exit(1)
    else:
        print("\n✅ All rules passed validation!")
        sys.exit(0)
