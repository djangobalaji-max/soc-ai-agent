from datetime import datetime, timedelta
from collections import defaultdict

class MetricsTracker:
    def __init__(self):
        self.triages = []
        self.approvals = []
        self.start_time = datetime.now()
    
    def record_triage(self, rule_id, severity, triage_time_ms, alert_data):
        self.triages.append({
            "timestamp": datetime.now().isoformat(),
            "rule_id": rule_id,
            "severity": severity,
            "triage_time_ms": triage_time_ms,
            "agent": alert_data.get("agent", {}).get("name", "unknown"),
        })
    
    def record_approval(self, action, severity, agent_id):
        self.approvals.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "severity": severity,
            "agent_id": agent_id,
        })
    
    def get_summary(self):
        if not self.triages:
            return {"total_triaged": 0, "avg_triage_time_ms": 0, "severity_breakdown": {}, "uptime_hours": 0, "total_approvals": 0}
        
        uptime = datetime.now() - self.start_time
        uptime_hours = uptime.total_seconds() / 3600
        
        severity_counts = defaultdict(int)
        for triage in self.triages:
            severity_counts[triage["severity"]] += 1
        
        avg_triage_time = sum(t["triage_time_ms"] for t in self.triages) / len(self.triages)
        
        return {
            "total_triaged": len(self.triages),
            "avg_triage_time_ms": int(avg_triage_time),
            "severity_breakdown": dict(severity_counts),
            "uptime_hours": round(uptime_hours, 2),
            "total_approvals": len(self.approvals),
            "last_triage": self.triages[-1]["timestamp"] if self.triages else None,
            "alerts_per_hour": len(self.triages) / max(uptime_hours, 0.1),
        }
    
    def get_timeline(self, hours=24):
        cutoff = datetime.now() - timedelta(hours=hours)
        recent = [t for t in self.triages if datetime.fromisoformat(t["timestamp"]) > cutoff]
        return recent
    
    def get_severity_trend(self):
        breakdown = defaultdict(int)
        for triage in self.triages:
            breakdown[triage["severity"]] += 1
        
        return [
            {"name": sev, "value": breakdown.get(sev, 0)}
            for sev in ["Critical", "High", "Medium", "Low", "Info"]
            if breakdown.get(sev, 0) > 0
        ]
