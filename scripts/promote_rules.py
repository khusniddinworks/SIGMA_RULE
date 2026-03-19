#!/usr/bin/env python3
"""
Rule Promotion Engine
=====================
Manages the lifecycle of Sigma rules across environments:
  draft → dev → staging → production

Rules are promoted automatically when they meet the criteria
defined in config/promotion_criteria.yml.

Process:
  1. Reads test results from the testing engine
  2. Checks current rule stage (from metadata)
  3. Evaluates promotion criteria for the next stage
  4. Promotes eligible rules and generates promotion report
"""

import os
import sys
import json
import yaml
import shutil
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


# ============================================================
# Rule Lifecycle Manager
# ============================================================
STAGES = ["draft", "dev", "staging", "production"]


@dataclass
class RuleState:
    """Tracks a rule's current lifecycle state."""
    rule_name: str
    current_stage: str
    detection_score: float
    grade: str
    test_runs: int
    false_positive_rate: float
    promoted_at: str = ""
    promoted_from: str = ""
    promoted_to: str = ""
    blocked_reason: str = ""


class PromotionEngine:
    """Manages rule promotion across environments."""

    def __init__(self, config_path: str = "config/promotion_criteria.yml",
                 state_path: str = "config/rule_states.json"):
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        self.state_path = Path(state_path)
        self.states = self._load_states()
        self.criteria = self.config.get("promotion_stages", {})

    def _load_states(self) -> Dict[str, Dict]:
        """Load current rule states from JSON."""
        if self.state_path.exists():
            with open(self.state_path, "r") as f:
                return json.load(f)
        return {}

    def _save_states(self):
        """Save rule states to JSON."""
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_path, "w") as f:
            json.dump(self.states, f, indent=2)

    def get_rule_stage(self, rule_name: str) -> str:
        """Get the current stage of a rule."""
        return self.states.get(rule_name, {}).get("stage", "draft")

    def get_next_stage(self, current_stage: str) -> Optional[str]:
        """Get the next promotion stage."""
        try:
            idx = STAGES.index(current_stage)
            if idx + 1 < len(STAGES):
                return STAGES[idx + 1]
        except ValueError:
            pass
        return None

    def evaluate_promotion(self, rule_name: str, test_report: Dict) -> RuleState:
        """Evaluate if a rule is eligible for promotion."""
        current_stage = self.get_rule_stage(rule_name)
        next_stage = self.get_next_stage(current_stage)

        score = test_report.get("detection_score", 0.0)
        grade = test_report.get("grade", "F")
        tp = test_report.get("true_positives", 0)
        fp = test_report.get("false_positives", 0)
        tn = test_report.get("true_negatives", 0)
        fn = test_report.get("false_negatives", 0)
        total = test_report.get("total_tests", 0)

        fp_rate = (fp / max(fp + tn, 1)) * 100
        test_runs = self.states.get(rule_name, {}).get("test_runs", 0) + 1

        state = RuleState(
            rule_name=rule_name,
            current_stage=current_stage,
            detection_score=score,
            grade=grade,
            test_runs=test_runs,
            false_positive_rate=round(fp_rate, 1),
        )

        if not next_stage:
            state.blocked_reason = "Already in production"
            return state

        # Get criteria for this promotion transition
        transition_key = f"{current_stage}_to_{next_stage}"
        criteria = self.criteria.get(transition_key, {})
        requirements = criteria.get("requirements", [])

        # Evaluate each requirement
        blocked = False
        reasons = []

        for req in requirements:
            if isinstance(req, dict):
                for key, threshold in req.items():
                    if key == "validation_pass" and not threshold:
                        continue
                    elif key == "detection_score_min" and score < threshold:
                        reasons.append(f"Score {score}% < {threshold}% required")
                        blocked = True
                    elif key == "false_positive_rate_max" and fp_rate > threshold:
                        reasons.append(f"FP rate {fp_rate}% > {threshold}% max")
                        blocked = True
                    elif key == "test_runs_min" and test_runs < threshold:
                        reasons.append(f"Test runs {test_runs} < {threshold} required")
                        blocked = True
                    elif key == "atomic_test_mapped" and threshold:
                        has_tests = total > 0
                        if not has_tests:
                            reasons.append("No atomic tests mapped")
                            blocked = True
                    elif key == "mitre_tags_present" and threshold:
                        mitre = test_report.get("mitre_technique", "")
                        if not mitre:
                            reasons.append("No MITRE technique mapped")
                            blocked = True

        if blocked:
            state.blocked_reason = "; ".join(reasons)
        else:
            state.promoted_from = current_stage
            state.promoted_to = next_stage
            state.promoted_at = datetime.datetime.utcnow().isoformat()
            state.current_stage = next_stage

            # Update stored state
            self.states[rule_name] = {
                "stage": next_stage,
                "score": score,
                "grade": grade,
                "test_runs": test_runs,
                "fp_rate": fp_rate,
                "promoted_at": state.promoted_at,
                "history": self.states.get(rule_name, {}).get("history", []) + [
                    {
                        "from": current_stage,
                        "to": next_stage,
                        "score": score,
                        "timestamp": state.promoted_at,
                    }
                ],
            }

        return state

    def process_all_reports(self, test_reports: Dict) -> List[RuleState]:
        """Process test reports and promote eligible rules."""
        results = []

        print(f"\n{'='*70}")
        print(f"  🎯 RULE PROMOTION ENGINE")
        print(f"  Stages: {' → '.join(STAGES)}")
        print(f"{'='*70}\n")

        for rule_name, report in test_reports.items():
            state = self.evaluate_promotion(rule_name, report)
            results.append(state)

            if state.promoted_to:
                print(f"  🚀 {rule_name}: {state.promoted_from} → {state.promoted_to}")
                print(f"     Score: {state.detection_score}% | Grade: {state.grade}")
            elif state.blocked_reason:
                print(f"  ⏸️  {rule_name}: Staying in '{state.current_stage}'")
                print(f"     Reason: {state.blocked_reason}")
            else:
                print(f"  ✅ {rule_name}: Already in production")

        # Save updated states
        self._save_states()

        # Print summary
        promoted_count = sum(1 for r in results if r.promoted_to)
        blocked_count = sum(1 for r in results if r.blocked_reason)

        print(f"\n{'='*70}")
        print(f"  PROMOTION SUMMARY")
        print(f"  Promoted: {promoted_count} | Blocked: {blocked_count} | "
              f"Total: {len(results)}")
        print(f"{'='*70}\n")

        return results

    def generate_promotion_report(self, results: List[RuleState], output_dir: str = "output"):
        """Generate the promotion report."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report_data = [asdict(r) for r in results]
        report_file = output_path / "promotion_report.json"
        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"  📄 Promotion report: {report_file}")

        # GitHub Actions output
        output_file = os.environ.get("GITHUB_OUTPUT", "")
        if output_file:
            promoted = sum(1 for r in results if r.promoted_to)
            prod_rules = sum(1 for r in results if r.current_stage == "production")
            with open(output_file, "a") as f:
                f.write(f"promoted_count={promoted}\n")
                f.write(f"production_rules={prod_rules}\n")

        return report_data

    def copy_rules_to_environment(self, results: List[RuleState], base_dir: str = "."):
        """
        Copy promoted rules to environment-specific directories.
        Structure:
          environments/dev/rules/
          environments/staging/rules/
          environments/production/rules/
        """
        base = Path(base_dir)

        for result in results:
            if not result.promoted_to:
                continue

            # Source rule file
            rule_file = Path(f"rules/{result.rule_name}.yml")
            if not rule_file.exists():
                # Try to find by filename match
                candidates = list(Path("rules").glob(f"*{result.rule_name}*"))
                if candidates:
                    rule_file = candidates[0]
                else:
                    continue

            # Target environment directory
            env_dir = base / "environments" / result.promoted_to / "rules"
            env_dir.mkdir(parents=True, exist_ok=True)

            target = env_dir / rule_file.name
            shutil.copy2(rule_file, target)
            print(f"  📁 Copied {rule_file.name} → environments/{result.promoted_to}/rules/")


# ============================================================
# Entry point
# ============================================================
if __name__ == "__main__":
    test_report_path = sys.argv[1] if len(sys.argv) > 1 else "output/test_report.json"
    promo_config = sys.argv[2] if len(sys.argv) > 2 else "config/promotion_criteria.yml"
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "output"

    # Load test reports
    if not Path(test_report_path).exists():
        print(f"❌ Test report not found: {test_report_path}")
        print("Run test_rules.py first to generate test reports.")
        sys.exit(1)

    with open(test_report_path, "r") as f:
        test_reports = json.load(f)

    engine = PromotionEngine(promo_config)
    results = engine.process_all_reports(test_reports)
    engine.generate_promotion_report(results, output_dir)
    engine.copy_rules_to_environment(results)

    print("\n✅ Promotion engine complete!")
