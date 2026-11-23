
import json
from collections import Counter

log_file = "/var/log/suricata/eve.json"

alert_counts = Counter()
alert_details = {}
invalid_lines = 0

with open(log_file, "r") as file:
    for line in file:
        if not line.strip():
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue

        if event.get("event_type") == "alert":
            alert = event.get("alert", {})
            sid = alert.get("signature_id")

            alert_counts[sid] += 1

            alert_details[sid] = {
                "name": alert.get("signature"),
                "source": event.get("src_ip"),
                "destination": event.get("dest_ip")
            }

print("===== SURICATA THREAT HUNTING SUMMARY =====")

for sid, count in sorted(alert_counts.items()):
    details = alert_details[sid]

    print("\nRule ID:", sid)
    print("Detection:", details["name"])
    print("Alert count:", count)
    print("Source IP:", details["source"])
    print("Destination IP:", details["destination"])

print("\n===== FINAL SUMMARY =====")
print("Total alert events:", sum(alert_counts.values()))
print("Different alert rules:", len(alert_counts))
print("Invalid JSON lines skipped:", invalid_lines)
