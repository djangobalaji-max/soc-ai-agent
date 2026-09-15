# AI-Augmented SOC Triage Agent

An interactive AI agent that triages security alerts from Wazuh SIEM using LLM analysis.

## Features
- Real-time alert triage with Groq LLM
- Severity classification & true positive likelihood
- MITRE ATT&CK mapping
- SLA tracking (ACK & response times)
- Interactive chat interface
- Live metrics dashboard
- Human-in-the-loop action approval

## Tech
Python | FastAPI | WebSocket | Wazuh 4.3 | OpenSearch | Groq API | GCP

## Quick Start
```bash
source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

## Architecture
Wazuh → Filebeat → OpenSearch → AI Agent → Chat UI + Dashboard

## Why Human-in-the-Loop?
Speed without risk. Analysts approve actions instantly.
