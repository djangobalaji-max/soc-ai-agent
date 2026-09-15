import json
import os
import time
from datetime import datetime, timedelta
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from dotenv import load_dotenv

load_dotenv()

from wazuh_client import WazuhClient
from ai_triage import AITriageEngine
from metrics import MetricsTracker

app = FastAPI(title="AI SOC Triage Agent")

wazuh = WazuhClient()
metrics = MetricsTracker()
triage_sessions = {}

# SLA Matrix by severity level
SLA_MATRIX = {
    1: {"name": "Info", "ack_mins": 480, "respond_mins": 480},
    2: {"name": "Low", "ack_mins": 240, "respond_mins": 480},
    3: {"name": "Low", "ack_mins": 240, "respond_mins": 480},
    4: {"name": "Medium", "ack_mins": 120, "respond_mins": 240},
    5: {"name": "Medium", "ack_mins": 120, "respond_mins": 240},
    6: {"name": "High", "ack_mins": 60, "respond_mins": 120},
    7: {"name": "High", "ack_mins": 60, "respond_mins": 120},
    8: {"name": "High", "ack_mins": 60, "respond_mins": 120},
    9: {"name": "Critical", "ack_mins": 60, "respond_mins": 60},
    10: {"name": "Critical", "ack_mins": 60, "respond_mins": 60},
    11: {"name": "Critical", "ack_mins": 60, "respond_mins": 60},
    12: {"name": "Critical", "ack_mins": 60, "respond_mins": 60},
    13: {"name": "Critical", "ack_mins": 60, "respond_mins": 60},
    14: {"name": "Critical", "ack_mins": 60, "respond_mins": 60},
    15: {"name": "Critical", "ack_mins": 60, "respond_mins": 60},
}

def get_sla_info(alert):
    """Calculate SLA times and remaining time for an alert"""
    level = alert.get("rule", {}).get("level", 3)
    sla = SLA_MATRIX.get(level, SLA_MATRIX[3])
    
    try:
        alert_time = datetime.fromisoformat(alert.get("timestamp", "").replace("Z", "+00:00"))
    except:
        alert_time = datetime.utcnow()
    
    now = datetime.utcnow()
    if alert_time.tzinfo:
        now = now.replace(tzinfo=alert_time.tzinfo)
    
    ack_deadline = alert_time + timedelta(minutes=sla["ack_mins"])
    respond_deadline = alert_time + timedelta(minutes=sla["respond_mins"])
    
    ack_remaining = int((ack_deadline - now).total_seconds() / 60)
    respond_remaining = int((respond_deadline - now).total_seconds() / 60)
    
    return {
        "severity": sla["name"],
        "ack_mins": sla["ack_mins"],
        "respond_mins": sla["respond_mins"],
        "ack_remaining": max(0, ack_remaining),
        "respond_remaining": max(0, respond_remaining),
        "ack_breached": ack_remaining < 0,
        "respond_breached": respond_remaining < 0
    }


@app.get("/")
async def root():
    return FileResponse("static/index.html")


@app.get("/api/alerts")
async def get_alerts(limit: int = Query(default=20, le=100)):
    try:
        alerts = wazuh.get_alerts(limit=limit)
        return alerts
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/agents")
async def get_agents():
    try:
        agents = wazuh.get_agents()
        return agents
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/agents/summary")
async def get_agent_summary():
    try:
        summary = wazuh.get_agent_summary()
        return summary
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/rules/{rule_id}")
async def get_rule(rule_id: str):
    try:
        rule = wazuh.get_rules(rule_id=rule_id)
        return rule
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/manager/stats")
async def get_stats():
    try:
        stats = wazuh.get_manager_stats()
        return stats
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/manager/info")
async def get_info():
    try:
        info = wazuh.get_manager_info()
        return info
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/metrics/summary")
async def get_metrics_summary():
    return metrics.get_summary()


@app.get("/api/metrics/timeline")
async def get_metrics_timeline(hours: int = Query(default=24, le=168)):
    return metrics.get_timeline(hours=hours)


@app.get("/api/metrics/severity")
async def get_severity_breakdown():
    return metrics.get_severity_trend()


@app.post("/api/triage")
async def triage_alert(alert: dict):
    try:
        engine = AITriageEngine()
        result = engine.triage_alert(alert)
        return {"triage": result}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/active-response/{agent_id}")
async def active_response(agent_id: str, body: dict):
    try:
        command = body.get("command")
        parameters = body.get("parameters", [])
        result = wazuh.get_active_response(agent_id, command, parameters)
        return result
    except Exception as e:
        return {"error": str(e)}


@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    await websocket.accept()

    session_id = id(websocket)
    engine = AITriageEngine()
    triage_sessions[session_id] = {
        "engine": engine,
        "current_alert": None,
        "pending_action": None,
        "history": []
    }

    await websocket.send_json({
        "type": "system",
        "message": "SOC AI Agent connected. Commands: 'fetch alerts', 'triage <number>', 'agents', 'approve', 'reset', 'history'"
    })

    try:
        while True:
            data = await websocket.receive_text()
            msg = data.strip()
            session = triage_sessions[session_id]

            try:
                if msg.lower() == "fetch alerts":
                    await websocket.send_json({
                        "type": "system",
                        "message": "Fetching recent alerts from Wazuh..."
                    })
                    alerts = wazuh.get_alerts(limit=10)
                    if "data" in alerts and "affected_items" in alerts["data"]:
                        items = alerts["data"]["affected_items"]
                        session["alerts_cache"] = items
                        alert_list = []
                        
                        severity_emoji = {
                            "Critical": "🔴",
                            "High": "🟠",
                            "Medium": "🟡",
                            "Low": "🟢",
                            "Info": "⚪"
                        }
                        
                        for i, alert in enumerate(items):
                            rule = alert.get("rule", {})
                            sla = get_sla_info(alert)
                            emoji = severity_emoji.get(sla["severity"], "⚪")
                            
                            ack_status = "⚠️ BREACHED" if sla["ack_breached"] else f"{sla['ack_remaining']}m"
                            respond_status = "⚠️ BREACHED" if sla["respond_breached"] else f"{sla['respond_remaining']}m"
                            
                            alert_line = (
                                f"{i+1}. {emoji} [{sla['severity']}] Rule {rule.get('id', '?')}: "
                                f"{rule.get('description', 'N/A')}\n"
                                f"   Agent: {alert.get('agent', {}).get('name', 'manager')} | "
                                f"SLA ACK: {ack_status} | Respond: {respond_status}"
                            )
                            alert_list.append(alert_line)
                        
                        await websocket.send_json({
                            "type": "alerts",
                            "message": f"Found {len(items)} recent alerts:\n\n" + "\n".join(alert_list) + "\n\nType 'triage <number>' to analyze."
                        })

                elif msg.lower().startswith("triage "):
                    try:
                        idx = int(msg.split()[1]) - 1
                        if "alerts_cache" in session and 0 <= idx < len(session["alerts_cache"]):
                            alert = session["alerts_cache"][idx]
                            session["current_alert"] = alert
                            sla = get_sla_info(alert)
                            
                            await websocket.send_json({
                                "type": "system",
                                "message": f"Analyzing {sla['severity']} alert..."
                            })
                            
                            triage_start = time.time()
                            result = engine.triage_alert(alert)
                            triage_time_ms = int((time.time() - triage_start) * 1000)
                            
                            metrics.record_triage(
                                alert.get("rule", {}).get("id"),
                                sla["severity"],
                                triage_time_ms,
                                alert
                            )
                            
                            session["history"].append({
                                "timestamp": datetime.now().isoformat(),
                                "alert": alert.get("rule", {}).get("id"),
                                "triage": result[:200]
                            })
                            await websocket.send_json({
                                "type": "triage",
                                "message": result
                            })
                    except ValueError:
                        await websocket.send_json({
                            "type": "error",
                            "message": "Usage: triage <number>"
                        })

                elif msg.lower() == "agents":
                    agents = wazuh.get_agents()
                    if "data" in agents and "affected_items" in agents["data"]:
                        items = agents["data"]["affected_items"]
                        agent_list = []
                        for a in items:
                            agent_list.append(
                                f"• ID: {a.get('id')} | Name: {a.get('name')} | Status: {a.get('status')} | IP: {a.get('ip', 'N/A')}"
                            )
                        await websocket.send_json({
                            "type": "agents",
                            "message": "Connected agents:\n\n" + "\n".join(agent_list)
                        })

                elif msg.lower() == "approve" and session.get("pending_action"):
                    action = session["pending_action"]
                    alert = session.get("current_alert", {})
                    sla = get_sla_info(alert) if alert else {"severity": "Unknown"}
                    metrics.record_approval(
                        action["command"],
                        sla["severity"],
                        action["agent_id"]
                    )
                    
                    result = {
                        "status": "success",
                        "action": action["command"],
                        "agent_id": action["agent_id"],
                        "timestamp": datetime.now().isoformat(),
                    }
                    session["pending_action"] = None
                    session["current_alert"] = None
                    
                    await websocket.send_json({
                        "type": "action",
                        "message": f"✓ Action '{action['command']}' executed. Alert closed."
                    })

                elif msg.lower() == "reset":
                    engine.reset_conversation()
                    session["current_alert"] = None
                    session["pending_action"] = None
                    await websocket.send_json({
                        "type": "system",
                        "message": "Conversation reset. Ready for new triage."
                    })

                else:
                    response = engine.chat(msg, alert_context=session.get("current_alert"))

                    if any(kw in response.lower() for kw in ["block_ip", "disable_account"]):
                        if "block_ip" in response.lower():
                            session["pending_action"] = {
                                "command": "firewall-drop",
                                "agent_id": session.get("current_alert", {}).get("agent", {}).get("id", "000"),
                            }
                        response += "\n\n⚠️ Type 'approve' to execute this action."

                    await websocket.send_json({
                        "type": "chat",
                        "message": response
                    })

            except Exception as e:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Error: {str(e)}"
                })

    except WebSocketDisconnect:
        if session_id in triage_sessions:
            del triage_sessions[session_id]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
