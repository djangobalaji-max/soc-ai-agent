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
        for i, alert in enumerate(items):
            rule = alert.get("rule", {})
            sla = get_sla_info(alert)
            
            # Color coding
            severity_emoji = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
                "Info": "⚪"
            }
            emoji = severity_emoji.get(sla["severity"], "⚪")
            
            # SLA status
            ack_status = "⚠️ BREACHED" if sla["ack_breached"] else f"{sla['ack_remaining']}m"
            respond_status = "⚠️ BREACHED" if sla["respond_breached"] else f"{sla['respond_remaining']}m"
            
            alert_line = (
                f"{i+1}. {emoji} [{sla['severity']}] Rule {rule.get('id', '?')}: "
                f"{rule.get('description', 'N/A')}\n"
                f"   Agent: {alert.get('agent', {}).get('name', 'manager')} | "
                f"ACK: {ack_status} | Respond: {respond_status}"
            )
            alert_list.append(alert_line)
        
        await websocket.send_json({
            "type": "alerts",
            "message": f"Found {len(items)} recent alerts (sorted by timestamp):\n\n" + "\n".join(alert_list) + "\n\nType 'triage <number>' to analyze an alert."
        })
    else:
        await websocket.send_json({
            "type": "error",
            "message": f"API response: {json.dumps(alerts, indent=2)}"
        })
