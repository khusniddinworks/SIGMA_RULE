#!/usr/bin/env python3
"""
SIEM Deployment Engine
======================
Deploys converted Sigma rules to target SIEM platforms via their REST APIs.
All credentials are read from environment variables (GitHub Secrets).

OPSEC: No credentials are hardcoded. All auth is token/API-key based.
"""

import os
import sys
import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
import yaml

# ============================================================
# Logging setup
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("siem-deployer")


# ============================================================
# Credential Manager — reads only from environment variables
# ============================================================
class SecureCredentialManager:
    """
    Manages SIEM credentials securely.
    All values come from environment variables (GitHub Secrets).
    NEVER logs or prints credential values.
    """

    CREDENTIAL_MAP = {
        "splunk": {
            "url": "SPLUNK_URL",
            "token": "SPLUNK_API_TOKEN",
            "username": "SPLUNK_USERNAME",  # For basic auth fallback
            "password": "SPLUNK_PASSWORD",  # For basic auth fallback
        },
        "elasticsearch": {
            "url": "ELASTIC_URL",
            "api_key": "ELASTIC_API_KEY",
            "username": "ELASTIC_USERNAME",  # For basic auth fallback
            "password": "ELASTIC_PASSWORD",  # For basic auth fallback
        },
    }

    @classmethod
    def get_credential(cls, platform: str, key: str) -> Optional[str]:
        """Get a credential from environment variables."""
        env_var = cls.CREDENTIAL_MAP.get(platform, {}).get(key, "")
        value = os.environ.get(env_var, "")
        if not value:
            logger.warning(f"Credential '{key}' for '{platform}' not found in env var '{env_var}'")
            return None
        # OPSEC: Never log credential values
        logger.debug(f"Credential '{key}' for '{platform}' loaded from '{env_var}'")
        return value

    @classmethod
    def validate_credentials(cls, platform: str, auth_type: str) -> bool:
        """Check if required credentials are available."""
        if auth_type == "token":
            return cls.get_credential(platform, "token") is not None and \
                   cls.get_credential(platform, "url") is not None
        elif auth_type == "api_key":
            return cls.get_credential(platform, "api_key") is not None and \
                   cls.get_credential(platform, "url") is not None
        elif auth_type == "basic":
            return cls.get_credential(platform, "username") is not None and \
                   cls.get_credential(platform, "password") is not None and \
                   cls.get_credential(platform, "url") is not None
        return False


# ============================================================
# Splunk Deployer
# ============================================================
class SplunkDeployer:
    """Deploy Sigma rules to Splunk via REST API."""

    def __init__(self):
        self.base_url = SecureCredentialManager.get_credential("splunk", "url")
        self.token = SecureCredentialManager.get_credential("splunk", "token")
        self.session = requests.Session()
        self.session.verify = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() == "true"

        if self.token:
            self.session.headers.update({
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            })
        else:
            # Fallback to basic auth
            username = SecureCredentialManager.get_credential("splunk", "username")
            password = SecureCredentialManager.get_credential("splunk", "password")
            if username and password:
                self.session.auth = (username, password)

    def check_connection(self) -> bool:
        """Test the connection to Splunk."""
        if not self.base_url:
            logger.error("Splunk URL not configured")
            return False
        try:
            resp = self.session.get(
                f"{self.base_url}/services/server/info",
                params={"output_mode": "json"},
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info("✅ Splunk connection successful")
                return True
            else:
                logger.error(f"❌ Splunk connection failed: HTTP {resp.status_code}")
                return False
        except requests.RequestException as e:
            logger.error(f"❌ Splunk connection error: {e}")
            return False

    def deploy_rule(self, rule: Dict) -> Tuple[bool, str]:
        """Deploy a single saved search to Splunk."""
        name = rule.get("name", "Unnamed")
        endpoint = f"{self.base_url}/servicesNS/admin/search/saved/searches"

        payload = {
            "name": name,
            "search": rule.get("search", ""),
            "description": rule.get("description", ""),
            "is_scheduled": "1",
            "cron_schedule": rule.get("cron_schedule", "*/15 * * * *"),
            "dispatch.earliest_time": rule.get("dispatch.earliest_time", "-15m"),
            "dispatch.latest_time": rule.get("dispatch.latest_time", "now"),
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.suppress": "1",
            "alert.suppress.period": rule.get("alert.suppress.period", "1h"),
            "disabled": "0",
            "output_mode": "json",
        }

        try:
            # Try to create first
            resp = self.session.post(endpoint, data=payload, timeout=30)
            if resp.status_code == 201:
                logger.info(f"  ✅ Created: {name}")
                return True, "created"
            elif resp.status_code == 409:
                # Already exists — update
                update_url = f"{endpoint}/{requests.utils.quote(name, safe='')}"
                resp = self.session.post(update_url, data=payload, timeout=30)
                if resp.status_code == 200:
                    logger.info(f"  🔄 Updated: {name}")
                    return True, "updated"
                else:
                    logger.error(f"  ❌ Update failed for {name}: HTTP {resp.status_code}")
                    return False, f"update_failed_{resp.status_code}"
            else:
                logger.error(f"  ❌ Deploy failed for {name}: HTTP {resp.status_code}")
                return False, f"deploy_failed_{resp.status_code}"
        except requests.RequestException as e:
            logger.error(f"  ❌ Network error deploying {name}: {e}")
            return False, f"network_error"

    def deploy_all(self, rules_dir: str) -> Dict:
        """Deploy all converted Splunk rules."""
        splunk_dir = Path(rules_dir) / "splunk"
        if not splunk_dir.exists():
            logger.warning("No Splunk rules directory found")
            return {"deployed": 0, "failed": 0, "skipped": 0}

        results = {"deployed": 0, "failed": 0, "skipped": 0, "details": []}
        rule_files = list(splunk_dir.glob("*.json"))

        logger.info(f"\n  🔷 Deploying {len(rule_files)} rules to Splunk...")

        if not self.check_connection():
            logger.error("  Skipping Splunk deployment — connection failed")
            results["skipped"] = len(rule_files)
            return results

        for rule_file in rule_files:
            with open(rule_file, "r") as f:
                rule = json.load(f)

            success, status = self.deploy_rule(rule)
            results["details"].append({
                "rule": rule.get("name", "Unknown"),
                "status": status,
                "success": success,
            })

            if success:
                results["deployed"] += 1
            else:
                results["failed"] += 1

            # Rate limiting
            time.sleep(0.5)

        return results


# ============================================================
# Elasticsearch Deployer
# ============================================================
class ElasticsearchDeployer:
    """Deploy Sigma rules to Elasticsearch/Kibana Security via API."""

    def __init__(self):
        self.base_url = SecureCredentialManager.get_credential("elasticsearch", "url")
        self.api_key = SecureCredentialManager.get_credential("elasticsearch", "api_key")
        self.session = requests.Session()
        self.session.verify = os.environ.get("ELASTIC_VERIFY_SSL", "true").lower() == "true"

        if self.api_key:
            self.session.headers.update({
                "Authorization": f"ApiKey {self.api_key}",
                "Content-Type": "application/json",
                "kbn-xsrf": "true",
            })
        else:
            username = SecureCredentialManager.get_credential("elasticsearch", "username")
            password = SecureCredentialManager.get_credential("elasticsearch", "password")
            if username and password:
                self.session.auth = (username, password)
                self.session.headers.update({
                    "Content-Type": "application/json",
                    "kbn-xsrf": "true",
                })

    def check_connection(self) -> bool:
        """Test the connection to Elasticsearch."""
        if not self.base_url:
            logger.error("Elasticsearch URL not configured")
            return False
        try:
            resp = self.session.get(f"{self.base_url}/api/status", timeout=10)
            if resp.status_code == 200:
                logger.info("✅ Elasticsearch/Kibana connection successful")
                return True
            else:
                logger.error(f"❌ Elasticsearch connection failed: HTTP {resp.status_code}")
                return False
        except requests.RequestException as e:
            logger.error(f"❌ Elasticsearch connection error: {e}")
            return False

    def generate_rule_id(self, rule_name: str) -> str:
        """Generate a deterministic UUID-like ID from rule name for idempotent deploys."""
        return hashlib.md5(rule_name.encode()).hexdigest()[:8] + "-" + \
               hashlib.sha256(rule_name.encode()).hexdigest()[:4] + "-" + \
               hashlib.sha256(rule_name.encode()).hexdigest()[4:8] + "-" + \
               hashlib.sha256(rule_name.encode()).hexdigest()[8:12] + "-" + \
               hashlib.sha256(rule_name.encode()).hexdigest()[12:24]

    def deploy_rule(self, rule: Dict) -> Tuple[bool, str]:
        """Deploy a single detection rule to Elasticsearch Security."""
        name = rule.get("name", "Unnamed")
        rule_id = self.generate_rule_id(name)
        endpoint = f"{self.base_url}/api/detection_engine/rules"

        payload = {
            "rule_id": rule_id,
            "name": name,
            "description": rule.get("description", ""),
            "risk_score": rule.get("risk_score", 47),
            "severity": rule.get("severity", "medium"),
            "type": "query",
            "query": rule.get("query", "*"),
            "language": rule.get("language", "lucene"),
            "index": rule.get("index", ["winlogbeat-*"]),
            "enabled": rule.get("enabled", True),
            "interval": rule.get("interval", "5m"),
            "from": rule.get("from", "now-6m"),
            "tags": rule.get("tags", []),
            "author": rule.get("author", ["CyberBrother"]),
            "false_positives": rule.get("false_positives", []),
            "throttle": rule.get("throttle", "1h"),
            "max_signals": rule.get("max_signals", 100),
        }

        if rule.get("threat"):
            payload["threat"] = rule["threat"]

        try:
            # Try PUT (create or update)
            resp = self.session.put(
                f"{endpoint}?rule_id={rule_id}",
                json=payload,
                timeout=30,
            )

            if resp.status_code in (200, 201):
                logger.info(f"  ✅ Deployed: {name}")
                return True, "deployed"
            elif resp.status_code == 409:
                # Update existing
                resp = self.session.patch(
                    f"{endpoint}",
                    json=payload,
                    timeout=30,
                )
                if resp.status_code == 200:
                    logger.info(f"  🔄 Updated: {name}")
                    return True, "updated"
                else:
                    logger.error(f"  ❌ Update failed: HTTP {resp.status_code}")
                    return False, f"update_failed_{resp.status_code}"
            else:
                logger.error(f"  ❌ Deploy failed for {name}: HTTP {resp.status_code}")
                return False, f"deploy_failed_{resp.status_code}"
        except requests.RequestException as e:
            logger.error(f"  ❌ Network error deploying {name}: {e}")
            return False, "network_error"

    def deploy_all(self, rules_dir: str) -> Dict:
        """Deploy all converted Elasticsearch rules."""
        elastic_dir = Path(rules_dir) / "elasticsearch"
        if not elastic_dir.exists():
            logger.warning("No Elasticsearch rules directory found")
            return {"deployed": 0, "failed": 0, "skipped": 0}

        results = {"deployed": 0, "failed": 0, "skipped": 0, "details": []}
        rule_files = list(elastic_dir.glob("*.json"))

        logger.info(f"\n  🟡 Deploying {len(rule_files)} rules to Elasticsearch...")

        if not self.check_connection():
            logger.error("  Skipping Elasticsearch deployment — connection failed")
            results["skipped"] = len(rule_files)
            return results

        for rule_file in rule_files:
            with open(rule_file, "r") as f:
                rule = json.load(f)

            success, status = self.deploy_rule(rule)
            results["details"].append({
                "rule": rule.get("name", "Unknown"),
                "status": status,
                "success": success,
            })

            if success:
                results["deployed"] += 1
            else:
                results["failed"] += 1

            time.sleep(0.3)

        return results


# ============================================================
# Main Deployment Orchestrator
# ============================================================
def deploy_to_all_platforms(output_dir: str, config_path: str = "config/siem_config.yml"):
    """Orchestrate deployment to all SIEM platforms."""
    config = {}
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning("Config file not found, using defaults")

    platforms = config.get("siem_platforms", {})
    all_results = {}

    print(f"\n{'='*60}")
    print(f"  MULTI-SIEM DEPLOYMENT ENGINE")
    print(f"  Output directory: {output_dir}")
    print(f"{'='*60}")

    # Deploy to Splunk
    if platforms.get("splunk", {}).get("enabled", True):
        if SecureCredentialManager.validate_credentials("splunk", "token"):
            deployer = SplunkDeployer()
            all_results["splunk"] = deployer.deploy_all(output_dir)
        else:
            logger.warning("⏭️  Splunk: Credentials not configured — skipping")
            all_results["splunk"] = {"deployed": 0, "failed": 0, "skipped": 0, "reason": "no_credentials"}
    else:
        logger.info("⏭️  Splunk: Disabled in config")

    # Deploy to Elasticsearch
    if platforms.get("elasticsearch", {}).get("enabled", True):
        if SecureCredentialManager.validate_credentials("elasticsearch", "api_key"):
            deployer = ElasticsearchDeployer()
            all_results["elasticsearch"] = deployer.deploy_all(output_dir)
        else:
            logger.warning("⏭️  Elasticsearch: Credentials not configured — skipping")
            all_results["elasticsearch"] = {"deployed": 0, "failed": 0, "skipped": 0, "reason": "no_credentials"}
    else:
        logger.info("⏭️  Elasticsearch: Disabled in config")

    # Print summary
    print(f"\n{'='*60}")
    print(f"  DEPLOYMENT SUMMARY")
    print(f"{'='*60}")
    for platform, result in all_results.items():
        deployed = result.get("deployed", 0)
        failed = result.get("failed", 0)
        skipped = result.get("skipped", 0)
        reason = result.get("reason", "")
        status = "✅" if failed == 0 and deployed > 0 else "⚠️" if reason else "❌"
        print(f"  {status} {platform}: {deployed} deployed, {failed} failed, {skipped} skipped")
        if reason:
            print(f"     Reason: {reason}")
    print(f"{'='*60}\n")

    # Write deployment report
    report_path = Path(output_dir) / "deployment_report.json"
    with open(report_path, "w") as f:
        json.dump(all_results, f, indent=2)
    logger.info(f"📄 Deployment report saved to: {report_path}")

    # Set GitHub Actions output
    output_file = os.environ.get("GITHUB_OUTPUT", "")
    if output_file:
        total_deployed = sum(r.get("deployed", 0) for r in all_results.values())
        total_failed = sum(r.get("failed", 0) for r in all_results.values())
        with open(output_file, "a") as f:
            f.write(f"total_deployed={total_deployed}\n")
            f.write(f"total_failed={total_failed}\n")

    # Exit with error if any failed
    total_failed = sum(r.get("failed", 0) for r in all_results.values())
    if total_failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    output_directory = sys.argv[1] if len(sys.argv) > 1 else "output"
    config_file = sys.argv[2] if len(sys.argv) > 2 else "config/siem_config.yml"
    deploy_to_all_platforms(output_directory, config_file)
