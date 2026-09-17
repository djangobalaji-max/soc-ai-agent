import httpx
import json
import os
from dotenv import load_dotenv

load_dotenv()

class WazuhClient:
    def __init__(self):
        self.base_url = os.getenv("WAZUH_API_URL")
        self.username = os.getenv("WAZUH_API_USER")
        self.password = os.getenv("WAZUH_API_PASS")
        self.indexer_url = os.getenv("INDEXER_URL")
        self.indexer_user = os.getenv("INDEXER_USER")
        self.indexer_pass = os.getenv("INDEXER_PASS")
        self.token = None

    def authenticate(self):
        r = httpx.get(
            f"{self.base_url}/security/user/authenticate?raw=true",
            auth=(self.username, self.password),
            verify=False,
            timeout=30
        )
        if r.status_code == 200:
            self.token = r.text
            return True
        return False

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def _request(self, method, endpoint, **kwargs):
        if not self.token:
            self.authenticate()
        r = httpx.request(
            method,
            f"{self.base_url}{endpoint}",
            headers=self._headers(),
            verify=False,
            timeout=30,
            **kwargs
        )
        if r.status_code == 401:
            self.authenticate()
            r = httpx.request(
                method,
                f"{self.base_url}{endpoint}",
                headers=self._headers(),
                verify=False,
                timeout=30,
                **kwargs
            )
        return r.json()

    def get_alerts(self, limit=20):
        """Fetch recent alerts from the Wazuh indexer (OpenSearch)"""
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"match_all": {}}
        }
        r = httpx.post(
            f"{self.indexer_url}/wazuh-alerts-*/_search",
            auth=(self.indexer_user, self.indexer_pass),
            json=query,
            verify=False,
            timeout=30
        )
        data = r.json()
        if "hits" in data and "hits" in data["hits"]:
            alerts = [hit["_source"] for hit in data["hits"]["hits"]]
            return {
                "data": {
                    "affected_items": alerts,
                    "total_affected_items": data["hits"]["total"]["value"]
                }
            }
        return {"data": {"affected_items": [], "total_affected_items": 0}}

    def get_alerts_by_level(self, min_level=10, limit=20):
        """Fetch high-severity alerts"""
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "range": {"rule.level": {"gte": min_level}}
            }
        }
        r = httpx.post(
            f"{self.indexer_url}/wazuh-alerts-*/_search",
            auth=(self.indexer_user, self.indexer_pass),
            json=query,
            verify=False,
            timeout=30
        )
        data = r.json()
        if "hits" in data and "hits" in data["hits"]:
            alerts = [hit["_source"] for hit in data["hits"]["hits"]]
            return {
                "data": {
                    "affected_items": alerts,
                    "total_affected_items": data["hits"]["total"]["value"]
                }
            }
        return {"data": {"affected_items": [], "total_affected_items": 0}}

    def get_agents(self):
        """List all registered agents"""
        result = self._request("GET", "/agents?select=id,name,status,ip,os.name")
        return result

    def get_agent_summary(self):
        """Get agent status summary"""
        result = self._request("GET", "/agents/summary/status")
        return result

    def get_rules(self, rule_id=None):
        """Get rule details"""
        if rule_id:
            result = self._request("GET", f"/rules?rule_ids={rule_id}")
        else:
            result = self._request("GET", "/rules?limit=10&sort=-level")
        return result

    def get_active_response(self, agent_id, command, parameters=None):
        """Execute active response on an agent"""
        body = {
            "command": command,
            "arguments": parameters or []
        }
        result = self._request(
            "PUT",
            f"/active-response/{agent_id}",
            json=body
        )
        return result

    def get_manager_stats(self):
        """Get manager statistics"""
        result = self._request("GET", "/manager/stats")
        return result

    def get_manager_info(self):
        """Get manager info"""
        result = self._request("GET", "/manager/info")
        return result

    # ============ FALSE POSITIVE DETECTION QUERIES ============

    def get_rule_frequency(self, rule_id, time_range="24h", limit=100):
        """Query: How often does a rule fire? (Establishes baseline)"""
        query = {
            "size": limit,
            "query": {
                "bool": {
                    "must": [
                        {"match": {"rule.id": str(rule_id)}},
                        {"range": {"timestamp": {"gte": f"now-{time_range}"}}}
                    ]
                }
            }
        }
        r = httpx.post(
            f"{self.indexer_url}/wazuh-alerts-*/_search",
            auth=(self.indexer_user, self.indexer_pass),
            json=query,
            verify=False,
            timeout=30
        )
        data = r.json()
        total = data["hits"]["total"]["value"]
        return {
            "rule_id": rule_id,
            "total_in_24h": total,
            "verdict": "LIKELY_FALSE_POSITIVE" if total >= 1 else "INVESTIGATE",
            "reason": f"Rule fires {total} times/day - expected behavior" if total >= 1 else "Rare event"
        }

    def get_rule_by_agent(self, rule_id, agent_id, limit=50):
        """Query: Does rule fire on specific agent?"""
        query = {
            "size": limit,
            "query": {
                "bool": {
                    "must": [
                        {"match": {"rule.id": str(rule_id)}},
                        {"match": {"agent.id": str(agent_id)}}
                    ]
                }
            }
        }
        r = httpx.post(
            f"{self.indexer_url}/wazuh-alerts-*/_search",
            auth=(self.indexer_user, self.indexer_pass),
            json=query,
            verify=False,
            timeout=30
        )
        data = r.json()
        count = data["hits"]["total"]["value"]
        is_system = agent_id == "000"
        return {
            "rule_id": rule_id,
            "agent_id": agent_id,
            "count": count,
            "is_system_agent": is_system,
            "verdict": "EXPECTED" if (is_system and count >= 5) else "SUSPICIOUS"
        }

    def get_alert_context(self, alert_dict):
        """Comprehensive context for an alert"""
        rule_id = alert_dict.get("rule", {}).get("id")
        agent_id = alert_dict.get("agent", {}).get("id")
        
        context = {
            "rule_frequency": self.get_rule_frequency(rule_id) if rule_id else None,
            "agent_pattern": self.get_rule_by_agent(rule_id, agent_id) if rule_id and agent_id else None
        }
        return context
