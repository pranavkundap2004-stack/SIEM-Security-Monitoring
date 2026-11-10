import json
from pathlib import Path

from elasticsearch import Elasticsearch


# ---------------------------------------------------------
# Elasticsearch connection
# ---------------------------------------------------------

es = Elasticsearch("http://localhost:9200")


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
KNOWN_IP_FILE = BASE_DIR / "known_ips.json"


# ---------------------------------------------------------
# Load known IPs
# ---------------------------------------------------------

def load_known_ips():

    with KNOWN_IP_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return set(data["known_ips"])


# ---------------------------------------------------------
# Query source IP activity
# ---------------------------------------------------------

def get_source_ips():

    response = es.search(
        index="security-events-*",
        query={
            "exists": {
                "field": "source_ip"
            }
        },
        size=1000
    )

    return response["hits"]["hits"]


# ---------------------------------------------------------
# Detect unknown IPs
# ---------------------------------------------------------

def detect_unknown_ips(events, known_ips):

    ip_activity = {}

    for event in events:

        source_ip = event["_source"].get("source_ip")

        if not source_ip:
            continue

        if source_ip not in ip_activity:

            ip_activity[source_ip] = {
                "total_events": 0,
                "failed_logins": 0,
                "successful_logins": 0
            }

        ip_activity[source_ip]["total_events"] += 1

        event_type = event["_source"].get("event_type")

        if event_type == "login_failed":
            ip_activity[source_ip]["failed_logins"] += 1

        elif event_type == "login_success":
            ip_activity[source_ip]["successful_logins"] += 1

    results = []

    for source_ip, stats in ip_activity.items():

        if source_ip not in known_ips:

            results.append({
                "source_ip": source_ip,
                "total_events": stats["total_events"],
                "failed_logins": stats["failed_logins"],
                "successful_logins": stats["successful_logins"],
                "status": "SUSPICIOUS",
                "reason": "Source IP is not present in known IP baseline"
            })

    return results


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("SIEM UNKNOWN IP DETECTOR")
    print("=" * 60)

    print("\nLoading known IP baseline...")

    known_ips = load_known_ips()

    print(f"Known IPs: {len(known_ips)}")

    print("\nQuerying Elasticsearch...")

    events = get_source_ips()

    print(f"Events analyzed: {len(events)}")

    alerts = detect_unknown_ips(events, known_ips)

    print("\n" + "=" * 60)
    print("UNKNOWN IP ANALYSIS")
    print("=" * 60)

    if not alerts:

        print("\nNo unknown source IPs detected.")

    else:

        for alert in alerts:

            print("\n🚨 UNKNOWN IP DETECTED")
            print(f"Source IP        : {alert['source_ip']}")
            print(f"Total Events     : {alert['total_events']}")
            print(f"Failed Logins    : {alert['failed_logins']}")
            print(f"Successful Logins: {alert['successful_logins']}")
            print(f"Status           : {alert['status']}")
            print(f"Reason           : {alert['reason']}")

            print("-" * 60)

    print(f"\nUnknown IPs detected: {len(alerts)}")