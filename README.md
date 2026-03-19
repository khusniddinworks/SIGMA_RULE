# 🛡️ SIGMA RULE — Multi-SIEM Detection Orchestrator

> **End-to-End Detection Development Pipeline** bilan Sigma qoidalarini yozing, test qiling, va avtomatik deploy qiling.

---

## 📋 Project Overview

Bu loyiha Sigma detection qoidalarini:
1. **Yozish** — YAML formatda Sigma qoidalarini yaratish
2. **Validatsiya** — Avtomatik sintaksis va sifat tekshiruvi
3. **Test qilish** — Atomic Red Team simulyatsiyasi bilan aniqlash kuchini tekshirish
4. **Baholash** — Detection score hisoblash (TP/FP/TN/FN)
5. **Promote** — Threshold asosida `draft → dev → staging → production`
6. **Konvertatsiya** — Splunk SPL va Elasticsearch formatlariga aylantirish
7. **Deploy** — SIEM platformalariga API orqali avtomatik yuborish

---

## 📁 Project Structure

```
sigma/
├── .github/
│   └── workflows/
│       ├── sigma-deploy.yml           # Multi-SIEM deploy workflow
│       └── detection-pipeline.yml     # Full E2E pipeline
├── config/
│   ├── siem_config.yml                # SIEM platform settings
│   ├── atomic_tests.yml               # ART test mappings
│   └── promotion_criteria.yml         # Promotion thresholds
├── rules/                             # Sigma detection rules
│   ├── susp_cmd_whoami.yml
│   ├── susp_powershell_execution.yml
│   ├── susp_net_user_enum.yml
│   ├── susp_registry_persistence.yml
│   ├── susp_remote_file_download.yml
│   ├── susp_lsass_access.yml
│   ├── susp_scheduled_task_creation.yml
│   └── susp_defender_disabled.yml
├── scripts/
│   ├── validate_rules.py              # Rule validator
│   ├── convert_rules.py               # Multi-SIEM converter
│   ├── test_rules.py                  # ART-based tester
│   ├── promote_rules.py              # Promotion engine
│   └── deploy_siem.py                 # SIEM deployer
├── environments/                      # Auto-generated
│   ├── dev/rules/
│   ├── staging/rules/
│   └── production/rules/
├── output/                            # Auto-generated
│   ├── splunk/
│   ├── elasticsearch/
│   ├── test_report.json
│   └── promotion_report.json
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Validate Rules

```bash
python scripts/validate_rules.py rules/
```

### 3. Run Detection Tests

```bash
python scripts/test_rules.py rules/ config/atomic_tests.yml config/promotion_criteria.yml output/
```

### 4. Promote Rules

```bash
python scripts/promote_rules.py output/test_report.json config/promotion_criteria.yml output/
```

### 5. Convert to SIEM Formats

```bash
python scripts/convert_rules.py rules/ output/ config/siem_config.yml
```

### 6. Deploy to SIEMs

```bash
# Set credentials first (never hardcode!)
export SPLUNK_URL="https://splunk.example.com:8089"
export SPLUNK_API_TOKEN="your-token-here"
export ELASTIC_URL="https://kibana.example.com:5601"
export ELASTIC_API_KEY="your-api-key-here"

python scripts/deploy_siem.py output/ config/siem_config.yml
```

---

## 🔬 Pipeline Architecture

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ VALIDATE │───▶│   TEST   │───▶│ PROMOTE  │───▶│ CONVERT  │───▶│  DEPLOY  │
│          │    │  (ART)   │    │          │    │          │    │          │
│ • Syntax │    │ • TP/FP  │    │ • Score  │    │ • Splunk │    │ • API    │
│ • Schema │    │ • TN/FN  │    │ • Grade  │    │ • Elastic│    │ • Token  │
│ • MITRE  │    │ • Score  │    │ • Stage  │    │ • KQL    │    │ • SSL    │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
```

### Rule Lifecycle

```
  draft ──▶ dev ──▶ staging ──▶ production
   │          │         │           │
   │ Auto     │ Score   │ Score     │ Human
   │ promote  │ ≥ 80%   │ ≥ 85%    │ approval
   │          │ FP <15% │ FP <10%  │ + soak 24h
```

---

## 🧪 Detection Testing (Atomic Red Team)

Har bir Sigma qoidasi Atomic Red Team testlari bilan sinovdan o'tkaziladi:

| Metric | Description |
|--------|-------------|
| **True Positive (TP)** | Hujumni to'g'ri aniqladi ✅ |
| **True Negative (TN)** | Normal faoliyatni to'g'ri o'tkazib yubordi ✅ |
| **False Positive (FP)** | Normal faoliyatni hujum deb aniqladi ❌ |
| **False Negative (FN)** | Hujumni aniqlamadi ❌ |

### Scoring Formula

```
Score = (0.40 × TP_Rate) + (0.30 × (100 - FP_Rate)) + (0.15 × Coverage) + (0.15 × Efficiency)
```

### Grades

| Grade | Score | Status |
|-------|-------|--------|
| 🟢 A | ≥ 90% | Production ready |
| 🔵 B | ≥ 80% | Staging ready |
| 🟡 C | ≥ 70% | Needs improvement |
| 🟠 D | ≥ 60% | Rework needed |
| 🔴 F | < 60% | Blocked |

---

## 🔒 OPSEC (Operational Security)

> **OPSEC** — operatsion xavfsizlik. Loyihaning o'zi xavfsiz bo'lishi kerak.

### ✅ Implemented

| Practice | Implementation |
|----------|---------------|
| No hardcoded secrets | All credentials via `GitHub Secrets` |
| Token-based auth | Bearer tokens for Splunk, API keys for Elastic |
| SSL verification | Enabled by default |
| Safe test mode | ART tests simulate, don't execute |
| Credential isolation | `SecureCredentialManager` class |
| No credential logging | Never prints tokens/passwords |
| Minimal permissions | Read-only repo, write artifacts only |
| Concurrency control | Prevents parallel deployments |

### 🔑 Required GitHub Secrets

```
SPLUNK_URL           — Splunk instance URL
SPLUNK_API_TOKEN     — Splunk Bearer token
ELASTIC_URL          — Kibana/Elasticsearch URL
ELASTIC_API_KEY      — Elasticsearch API key
SLACK_WEBHOOK_URL    — (Optional) Slack notifications
```

---

## 🎯 MITRE ATT&CK Coverage

| Technique | ID | Sigma Rule | Status |
|-----------|-----|-----------|--------|
| System Owner Discovery | T1033 | `susp_cmd_whoami` | ✅ |
| PowerShell Execution | T1059.001 | `susp_powershell_execution` | ✅ |
| Account Discovery | T1087.001 | `susp_net_user_enum` | ✅ |
| Registry Run Keys | T1547.001 | `susp_registry_persistence` | ✅ |
| Ingress Tool Transfer | T1105 | `susp_remote_file_download` | ✅ |
| LSASS Credential Dump | T1003.001 | `susp_lsass_access` | ✅ |
| Scheduled Task | T1053.005 | `susp_scheduled_task_creation` | ✅ |
| Disable Defender | T1562.001 | `susp_defender_disabled` | ✅ |

---

## 📝 Writing New Rules

1. Create a `.yml` file in `rules/` directory
2. Add ART test mapping in `config/atomic_tests.yml`
3. Push to `develop` branch → pipeline runs automatically
4. Rule goes through: validate → test → score → promote

### Example Rule Template

```yaml
title: Suspicious Activity Description
id: <generate-unique-uuid>
status: experimental
description: What this rule detects and why it matters.
author: CyberBrother
date: 2026-03-19
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\suspicious.exe'
        CommandLine|contains:
            - 'malicious_arg1'
            - 'malicious_arg2'
    filter_legit:
        User|contains: 'SYSTEM'
    condition: selection and not filter_legit
falsepositives:
    - Describe known false positive scenarios
level: high
tags:
    - attack.tactic_name
    - attack.tXXXX
```

---

## 👨‍💻 Author

**CyberBrother** — Kiberxavfsizlik bo'yicha detection engineering loyihasi.

---

*Built with ❤️ for the security community*
