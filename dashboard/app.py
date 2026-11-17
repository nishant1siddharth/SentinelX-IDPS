import subprocess
import json
from pathlib import Path
from flask import Flask, render_template, jsonify

app = Flask(__name__)

EVE_LOG = Path("/var/log/suricata/eve.json")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({
        "project": "SentinelX",
        "status": "running",
        "version": "1.0"
    })


@app.route("/api/alerts")
def get_alerts():
    alerts = []

    if not EVE_LOG.exists():
        return jsonify({
            "total": 0,
            "alerts": [],
            "error": "Suricata EVE log not found"
        }), 503

    try:
        with EVE_LOG.open("r", encoding="utf-8") as eve:
            for line in eve:
                try:
                    event = json.loads(line)

                    if event.get("event_type") != "alert":
                        continue

                    alert = event.get("alert", {})

                    alerts.append({
                        "timestamp": event.get("timestamp"),
                        "severity": alert.get("severity"),
                        "source_ip": event.get("src_ip"),
                        "destination_ip": event.get("dest_ip"),
                        "protocol": event.get("proto"),
                        "signature": alert.get("signature"),
                        "signature_id": alert.get("signature_id"),
                        "action": alert.get("action"),
                        "interface": event.get("in_iface")
                    })

                except json.JSONDecodeError:
                    continue

        alerts.reverse()

        return jsonify({
            "total": len(alerts),
            "displayed": min(len(alerts), 100),
            "alerts": alerts[:100]
        })

    except OSError:
        app.logger.exception("Unable to read Suricata EVE log")

        return jsonify({
            "error": "Unable to read Suricata logs"
        }), 500


@app.route("/api/blocked-ips")
def get_blocked_ips():
    try:
        result = subprocess.run(
            [
                "sudo",
                "-n",
                "/usr/local/bin/sentinelx-read-blocklist"
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )

        data = json.loads(result.stdout)

        blocked_ips = []

        for item in data.get("nftables", []):
            set_data = item.get("set")

            if not set_data:
                continue

            if set_data.get("name") == "blocked_ips":
                blocked_ips = set_data.get("elem", [])
                break

        return jsonify({
            "total": len(blocked_ips),
            "blocked_ips": blocked_ips
        })

    except (subprocess.SubprocessError, json.JSONDecodeError) as error:
        app.logger.error("Blocklist error: %s", error)

        return jsonify({
            "error": "Unable to retrieve blocked IP addresses"
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
