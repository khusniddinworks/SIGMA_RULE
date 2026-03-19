#!/usr/bin/env python3
"""
Sigma Rule Converter — Multi-SIEM
==================================
Converts Sigma rules to multiple SIEM-native query formats:
  - Splunk SPL
  - Elasticsearch Query DSL / Lucene
  - Microsoft Sentinel KQL (future)

Uses pySigma backends for accurate conversion.
"""

import os
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from sigma.rule import SigmaRule
    from sigma.backends.splunk import SplunkBackend
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline
    from sigma.pipelines.elasticsearch import ecs_windows_pipeline
    SIGMA_AVAILABLE = True
except ImportError:
    SIGMA_AVAILABLE = False
    print("⚠️  pySigma libraries not fully installed. Using fallback converter.")


def load_siem_config(config_path: str = "config/siem_config.yml") -> Dict:
    """Load the SIEM configuration file."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        print(f"⚠️  Config file not found: {config_path}, using defaults.")
        return {"siem_platforms": {}}


def load_sigma_rule(file_path: str) -> Optional[Dict]:
    """Load a Sigma rule from YAML file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"  ❌ Error loading {file_path}: {e}")
        return None


def convert_to_splunk(rule_path: str, rule_data: Dict) -> Optional[Dict]:
    """Convert Sigma rule to Splunk SPL format."""
    if not SIGMA_AVAILABLE:
        return fallback_splunk_convert(rule_data)

    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            rule_content = f.read()

        sigma_rule = SigmaRule.from_yaml(rule_content)
        pipeline = splunk_windows_pipeline()
        backend = SplunkBackend(pipeline)
        queries = backend.convert_rule(sigma_rule)

        level = rule_data.get("level", "medium")
        title = rule_data.get("title", "Unnamed Rule")

        return {
            "name": f"Sigma - {title}",
            "search": queries[0] if queries else "",
            "description": rule_data.get("description", ""),
            "severity": level,
            "disabled": False,
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.suppress": "1",
            "alert.suppress.period": "1h",
            "alert.suppress.fields": "ComputerName,User",
            "cron_schedule": "*/15 * * * *",
            "dispatch.earliest_time": "-15m",
            "dispatch.latest_time": "now",
            "actions": "notable",
            "action.notable.param.rule_title": title,
            "action.notable.param.severity": level,
            "action.notable.param.nes_fields": "ComputerName,User,CommandLine",
        }
    except Exception as e:
        print(f"  ⚠️  pySigma Splunk conversion failed: {e}")
        return fallback_splunk_convert(rule_data)


def fallback_splunk_convert(rule_data: Dict) -> Dict:
    """Fallback Splunk conversion when pySigma is not available."""
    detection = rule_data.get("detection", {})
    condition = detection.get("condition", "")
    spl_parts = []

    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            for field, match in value.items():
                field_name = field.split("|")[0]
                modifier = field.split("|")[1] if "|" in field else ""
                if isinstance(match, list):
                    if modifier == "endswith":
                        or_parts = [f'{field_name}="*{m}"' for m in match]
                    elif modifier == "contains":
                        or_parts = [f'{field_name}="*{m}*"' for m in match]
                    else:
                        or_parts = [f'{field_name}="{m}"' for m in match]
                    spl_parts.append(f"({' OR '.join(or_parts)})")
                else:
                    if modifier == "endswith":
                        spl_parts.append(f'{field_name}="*{match}"')
                    elif modifier == "contains":
                        spl_parts.append(f'{field_name}="*{match}*"')
                    else:
                        spl_parts.append(f'{field_name}="{match}"')

    search = " AND ".join(spl_parts) if spl_parts else "*"
    title = rule_data.get("title", "Unnamed")

    return {
        "name": f"Sigma - {title}",
        "search": search,
        "description": rule_data.get("description", ""),
        "severity": rule_data.get("level", "medium"),
    }


def convert_to_elasticsearch(rule_path: str, rule_data: Dict) -> Optional[Dict]:
    """Convert Sigma rule to Elasticsearch detection rule format."""
    if not SIGMA_AVAILABLE:
        return fallback_elastic_convert(rule_data)

    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            rule_content = f.read()

        sigma_rule = SigmaRule.from_yaml(rule_content)
        pipeline = ecs_windows_pipeline()
        backend = LuceneBackend(pipeline)
        queries = backend.convert_rule(sigma_rule)

        level = rule_data.get("level", "medium")
        risk_map = {"critical": 99, "high": 73, "medium": 47, "low": 21, "informational": 5}
        tags = rule_data.get("tags", [])
        mitre_tags = [t for t in tags if str(t).startswith("attack.t")]

        return {
            "name": f"Sigma - {rule_data.get('title', 'Unnamed')}",
            "description": rule_data.get("description", ""),
            "risk_score": risk_map.get(level, 47),
            "severity": level,
            "type": "query",
            "query": queries[0] if queries else "*",
            "language": "lucene",
            "index": ["winlogbeat-*", "logs-endpoint.events.*"],
            "enabled": True,
            "interval": "5m",
            "from": "now-6m",
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "technique": [{"id": t.replace("attack.", "").upper()} for t in mitre_tags],
                }
            ] if mitre_tags else [],
            "throttle": "1h",
            "max_signals": 100,
            "tags": tags,
            "author": [rule_data.get("author", "CyberBrother")],
            "false_positives": rule_data.get("falsepositives", []),
        }
    except Exception as e:
        print(f"  ⚠️  pySigma Elasticsearch conversion failed: {e}")
        return fallback_elastic_convert(rule_data)


def fallback_elastic_convert(rule_data: Dict) -> Dict:
    """Fallback Elasticsearch conversion."""
    detection = rule_data.get("detection", {})
    query_parts = []

    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            for field, match in value.items():
                field_name = field.split("|")[0]
                modifier = field.split("|")[1] if "|" in field else ""
                if isinstance(match, list):
                    if modifier == "endswith":
                        parts = [f'{field_name}:*{m}' for m in match]
                    elif modifier == "contains":
                        parts = [f'{field_name}:*{m}*' for m in match]
                    else:
                        parts = [f'{field_name}:"{m}"' for m in match]
                    query_parts.append(f"({' OR '.join(parts)})")
                else:
                    if modifier == "endswith":
                        query_parts.append(f"{field_name}:*{match}")
                    elif modifier == "contains":
                        query_parts.append(f"{field_name}:*{match}*")
                    else:
                        query_parts.append(f'{field_name}:"{match}"')

    query = " AND ".join(query_parts) if query_parts else "*"
    level = rule_data.get("level", "medium")
    risk_map = {"critical": 99, "high": 73, "medium": 47, "low": 21, "informational": 5}

    return {
        "name": f"Sigma - {rule_data.get('title', 'Unnamed')}",
        "description": rule_data.get("description", ""),
        "risk_score": risk_map.get(level, 47),
        "severity": level,
        "type": "query",
        "query": query,
        "language": "lucene",
        "index": ["winlogbeat-*", "logs-endpoint.events.*"],
        "enabled": True,
    }


def convert_all_rules(rules_dir: str, output_dir: str, config_path: str = "config/siem_config.yml"):
    """Convert all deployable Sigma rules to all enabled SIEM formats."""
    config = load_siem_config(config_path)
    platforms = config.get("siem_platforms", {})

    # Load deployable rules list
    deploy_list_path = Path(rules_dir).parent / "deployable_rules.json"
    if deploy_list_path.exists():
        with open(deploy_list_path, "r") as f:
            rule_files = json.load(f)
    else:
        # If no validation was run, convert all rules
        rules_path = Path(rules_dir)
        rule_files = [str(p) for p in rules_path.glob("*.yml")]

    if not rule_files:
        print("⚠️  No rules to convert.")
        return

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    results = {"splunk": [], "elasticsearch": []}

    print(f"\n{'='*60}")
    print(f"  SIGMA RULE CONVERSION")
    print(f"  Rules to convert: {len(rule_files)}")
    print(f"  Output directory: {output_dir}")
    print(f"{'='*60}\n")

    for rule_file in rule_files:
        rule_data = load_sigma_rule(rule_file)
        if not rule_data:
            continue

        rule_name = Path(rule_file).stem
        print(f"  📝 Converting: {Path(rule_file).name}")

        # Convert to Splunk
        if platforms.get("splunk", {}).get("enabled", True):
            splunk_result = convert_to_splunk(rule_file, rule_data)
            if splunk_result:
                results["splunk"].append(splunk_result)
                splunk_out = output_path / "splunk" / f"{rule_name}.json"
                splunk_out.parent.mkdir(parents=True, exist_ok=True)
                with open(splunk_out, "w") as f:
                    json.dump(splunk_result, f, indent=2)
                print(f"    ✅ Splunk SPL → {splunk_out.name}")

        # Convert to Elasticsearch
        if platforms.get("elasticsearch", {}).get("enabled", True):
            elastic_result = convert_to_elasticsearch(rule_file, rule_data)
            if elastic_result:
                results["elasticsearch"].append(elastic_result)
                elastic_out = output_path / "elasticsearch" / f"{rule_name}.json"
                elastic_out.parent.mkdir(parents=True, exist_ok=True)
                with open(elastic_out, "w") as f:
                    json.dump(elastic_result, f, indent=2)
                print(f"    ✅ Elasticsearch → {elastic_out.name}")

    # Write combined output files
    for platform, rules in results.items():
        if rules:
            combined_path = output_path / f"{platform}_all_rules.json"
            with open(combined_path, "w") as f:
                json.dump(rules, f, indent=2)
            print(f"\n  📦 Combined {platform} rules: {combined_path} ({len(rules)} rules)")

    print(f"\n{'='*60}")
    print(f"  CONVERSION COMPLETE")
    for platform, rules in results.items():
        print(f"  {platform}: {len(rules)} rules converted")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    rules_directory = sys.argv[1] if len(sys.argv) > 1 else "rules"
    output_directory = sys.argv[2] if len(sys.argv) > 2 else "output"
    config_file = sys.argv[3] if len(sys.argv) > 3 else "config/siem_config.yml"

    convert_all_rules(rules_directory, output_directory, config_file)
