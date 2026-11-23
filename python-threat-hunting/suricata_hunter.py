import json

# Step 1: Open Suricata's EVE JSON log
log_file = "/var/log/suricata/eve.json"

print("===== SURICATA ALERT HUNTING =====")

alert_count = 0

# Step 2: Read the log line by line
with open(log_file, "r") as file:

    for line in file:

        try:
            event = json.loads(line)

            # Step 3: Identify alert events
            if event.get("event_type") == "alert":

                alert_count += 1

                alert = event.get("alert", {})

                print("\n[IDS ALERT]")
                print("Timestamp:", event.get("timestamp"))
                print("Rule ID:", alert.get("signature_id"))
                print("Detection:", alert.get("signature"))
                print("Source IP:", event.get("src_ip"))
                print("Destination IP:", event.get("dest_ip"))

                # Step 4: Display HTTP information if available
                if "http" in event:
                    http = event["http"]
                    print("HTTP Method:", http.get("http_method"))
                    print("User-Agent:", http.get("http_user_agent"))

        except json.JSONDecodeError:
            continue

# Step 5: Display final results
print("\n===== INVESTIGATION SUMMARY =====")
print("Total IDS alerts found:", alert_count)
