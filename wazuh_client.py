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
