

import json
import subprocess
import time
import os
from collections import OrderedDict

EVE_LOG = "/var/log/suricata/eve.json"
RESPONSE_LOG = "/var/log/sentinelx-response.log"

# Only approved lab attacker
ALLOWED_ATTACKER = "192.168.56.10"

# Only TCP SYN scan detection rule
TRIGGER_SIDS = {1000002}

# Bounded cache for duplicate event protection
MAX_PROCESSED_EVENTS = 10000
processed_events = OrderedDict()


def log_response(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(RESPONSE_LOG, "a") as log:
        log.write(f"[{timestamp}] {message}\n")
    print(message, flush=True)


def event_fingerprint(event):
    alert = event.get("alert", {})
    return (
        event.get("timestamp"),
        alert.get("gid"),
        alert.get("signature_id"),
        event.get("src_ip"),
        event.get("src_port"),
        event.get("dest_ip"),
        event.get("dest_port"),
        event.get("proto")
    )


def is_duplicate(event):
    fingerprint = event_fingerprint(event)

    if fingerprint in processed_events:
        return True

    processed_events[fingerprint] = time.monotonic()

    if len(processed_events) > MAX_PROCESSED_EVENTS:
        processed_events.popitem(last=False)

    return False


def block_attacker(ip, sid, destination_ip):
    if ip != ALLOWED_ATTACKER:
        log_response(f"BLOCK DENIED: unauthorized source IP {ip}")
        return

    result = subprocess.run(
        [
            "nft", "add", "element", "inet", "sentinelx",
            "blocked_ips", "{", ip, "}"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode == 0 or "File exists" in result.stderr:

        verification = subprocess.run(
            [
                "nft", "get", "element", "inet", "sentinelx",
                "blocked_ips", "{", ip, "}"
            ],
            capture_output=True,
            text=True
        )

        if verification.returncode == 0:
            log_response(
                f"BLOCK VERIFIED source={ip} "
                f"destination={destination_ip} SID={sid}"
            )
        else:
            log_response(
                f"BLOCK VERIFICATION FAILED source={ip} SID={sid}: "
                f"{verification.stderr.strip()}"
            )

    else:
        log_response(
            f"FIREWALL ERROR source={ip} SID={sid}: "
            f"{result.stderr.strip()}"
        )

def monitor_alerts():
    log_response("SentinelX automated response started")

    eve = None
    current_inode = None
    last_file_size = 0

    while True:

        try:
            if not os.path.exists(EVE_LOG):
                time.sleep(1)
                continue

            file_stat = os.stat(EVE_LOG)
            new_inode = file_stat.st_ino
            new_size = file_stat.st_size

            copytruncate_detected = (
                eve is not None
                and new_inode == current_inode
                and new_size < last_file_size
            )

            if (
                eve is None
                or new_inode != current_inode
                or copytruncate_detected
            ):

                if eve is not None:
                    eve.close()
                    log_response("EVE log rotation detected")

                eve = open(EVE_LOG, "r")

                if copytruncate_detected:
                    eve.seek(0)
                    log_response("EVE copytruncate rotation detected")
                else:
                    eve.seek(0, os.SEEK_END)

                current_inode = new_inode
                last_file_size = new_size

                log_response("Monitoring EVE log: " + EVE_LOG)
            last_file_size = new_size
            line = eve.readline()

            if not line:
                time.sleep(0.2)
                continue

            try:
                event = json.loads(line)

                if event.get("event_type") != "alert":
                    continue

                alert = event.get("alert", {})
                sid = alert.get("signature_id")
                source_ip = event.get("src_ip")
                destination_ip = event.get("dest_ip")

                if sid not in TRIGGER_SIDS:
                    continue

                if is_duplicate(event):
                    continue

                log_response(
                    f"DETECTED SID={sid} source={source_ip} "
                    f"destination={destination_ip}"
                )

                block_attacker(source_ip, sid, destination_ip)

            except json.JSONDecodeError:
                log_response("WARNING: Ignored malformed EVE JSON event")

        except OSError as error:
            log_response(f"EVE LOG ERROR: {error}")
            if eve is not None:
                eve.close()
                eve = None
                current_inode = None
            time.sleep(1)

if __name__ == "__main__":
    monitor_alerts()
