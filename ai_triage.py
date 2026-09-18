import json
import os
from groq import Groq
from dotenv import load_dotenv
from wazuh_client import WazuhClient

load_dotenv()

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst AI agent. 
Your job is to triage security alerts from a Wazuh SIEM.

For each alert, you must provide:

1. **Alert Summary**: What happened in plain language
2. **Severity Assessment**: Critical / High / Medium / Low / Informational
3. **True Positive Likelihood**: Percentage estimate (0-100%) of whether this is a real threat
4. **MITRE ATT&CK Mapping**: Relevant technique IDs and names
5. **Triage Analysis**: 
   - What the alert indicates
   - Potential impact if this is a real attack
   - Related IOCs (Indicators of Compromise) if any
6. **Recommended Actions**: Specific steps to investigate or respond
7. **Auto-Action Suggestion**: Whether an automated response is appropriate
   - BLOCK_IP: Block the source IP via firewall
   - DISABLE_ACCOUNT: Disable the user account
   - ISOLATE_HOST: Isolate the affected host
   - NONE: No automated action needed
   - ESCALATE: Requires human analyst review

Always explain your reasoning. Be concise but thorough.
When asked follow-up questions about an alert, provide deeper analysis.
If asked to execute an action, confirm the action details and wait for human approval.
"""


class AITriageEngine:
    def __init__(self):
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.model = "qwen/qwen3.8-27b"
        self.conversation_history = []
        self.wazuh_client = WazuhClient()

    def reset_conversation(self):
        self.conversation_history = []

    def get_alert_evidence(self, alert_data):
        """Query Wazuh for contextual evidence about the alert"""
        try:
            context = self.wazuh_client.get_alert_context(alert_data)
            
            evidence = {
                "rule_frequency": context.get("rule_frequency"),
                "agent_pattern": context.get("agent_pattern"),
                "user_pattern": context.get("user_pattern"),
                "ip_history": context.get("ip_history"),
                "correlated": context.get("correlated")
            }
            return evidence
        except Exception as e:
            print(f"Warning: Could not gather evidence - {e}")
            return {}

    def format_evidence_for_prompt(self, evidence):
        """Convert evidence dict into readable prompt text"""
        if not evidence:
            return ""
        
        lines = ["\n## EVIDENCE FROM WAZUH INDEXER:"]
        
        if evidence.get("rule_frequency"):
            freq = evidence["rule_frequency"]
            lines.append(f"- Rule Frequency: {freq['total_in_24h']} times/24h - {freq['reason']}")
        
        if evidence.get("agent_pattern"):
            agent = evidence["agent_pattern"]
            lines.append(f"- Agent Pattern: {agent['verdict']} - {agent.get('reason', '')}")
        
        if evidence.get("ip_history"):
            ip = evidence["ip_history"]
            lines.append(f"- IP History: {ip['total_alerts']} total alerts - {ip['verdict']}")
        
        if evidence.get("correlated"):
            corr = evidence["correlated"]
            lines.append(f"- Correlated Alerts: {corr['correlated_alerts']} in {corr['time_window']} - {corr['verdict']}")
        
        return "\n".join(lines)

    def triage_alert(self, alert_data):
        """Analyze a single alert with contextual evidence"""
        evidence = self.get_alert_evidence(alert_data)
        evidence_text = self.format_evidence_for_prompt(evidence)
        
        alert_json = json.dumps(alert_data, indent=2, default=str)
        prompt = f"""Triage the following Wazuh security alert:

````json
{alert_json}
````

{evidence_text}

Based on the alert and evidence from SIEM, provide complete triage analysis."""

        self.conversation_history = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        response = self.client.chat.completions.create(
            model=self.model,
            messages=self.conversation_history,
            max_tokens=2000,
            temperature=0.3
        )

        assistant_msg = response.choices[0].message.content
        self.conversation_history.append(
            {"role": "assistant", "content": assistant_msg}
        )
        return assistant_msg

    def chat(self, user_message, alert_context=None):
        """Continue conversation about an alert"""
        if not self.conversation_history:
            self.conversation_history = [
                {"role": "system", "content": SYSTEM_PROMPT}
            ]
            if alert_context:
                context_json = json.dumps(alert_context, indent=2, default=str)
                self.conversation_history.append({
                    "role": "user",
                    "content": f"Here is the alert context:\n```json\n{context_json}\n```"
                })

        self.conversation_history.append(
            {"role": "user", "content": user_message}
        )

        response = self.client.chat.completions.create(
            model=self.model,
            messages=self.conversation_history,
            max_tokens=2000,
            temperature=0.3
        )

        assistant_msg = response.choices[0].message.content
        self.conversation_history.append(
            {"role": "assistant", "content": assistant_msg}
        )
        return assistant_msg

    def batch_triage(self, alerts):
        """Quick classification for multiple alerts"""
        summaries = []
        for alert in alerts:
            alert_json = json.dumps(alert, indent=2, default=str)
            prompt = f"""Classify this alert in ONE line:
SEVERITY | RULE_ID | SHORT_DESC | ACTION

Alert:
````json
{alert_json}
```"""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a SOC analyst. Classify alerts in one line."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.1
            )
            summaries.append(response.choices[0].message.content.strip())
        return summaries
