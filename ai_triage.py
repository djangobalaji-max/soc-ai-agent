import json
import os
from groq import Groq
from dotenv import load_dotenv

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

    def reset_conversation(self):
        self.conversation_history = []

    def triage_alert(self, alert_data):
        """Analyze a single alert and return triage results"""
        alert_json = json.dumps(alert_data, indent=2, default=str)
        prompt = f"""Triage the following Wazuh security alert:

```json
{alert_json}
```

Provide your complete triage analysis."""

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
        """Continue conversation about an alert or general SOC questions"""
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
        """Quick severity classification for multiple alerts"""
        summaries = []
        for alert in alerts:
            alert_json = json.dumps(alert, indent=2, default=str)
            prompt = f"""Classify this alert in ONE line with format:
SEVERITY | RULE_ID | SHORT_DESCRIPTION | ACTION_NEEDED

Alert:
```json
{alert_json}
```"""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a SOC analyst. Classify alerts concisely in one line."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.1
            )
            summaries.append(response.choices[0].message.content.strip())
        return summaries
