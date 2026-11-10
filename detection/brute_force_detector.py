from collections import defaultdict, deque
from datetime import datetime

from elasticsearch import Elasticsearch


# ---------------------------------------------------------
# Elasticsearch connection
# ---------------------------------------------------------

es = Elasticsearch("http://localhost:9200")


# ---------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------

FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60


# ---------------------------------------------------------
# Query failed login events
# ---------------------------------------------------------

def get_failed_logins():

    response = es.search(
        index="security-events-*",
        query={
            "term": {
                "event_type.keyword": "login_failed"
            }
        },
        sort=[
            {
                "@timestamp": {
                    "order": "asc"
                }
            }
        ],
        size=1000
    )

    return response["hits"]["hits"]


# ---------------------------------------------------------
# Brute-force detection
# ---------------------------------------------------------

def detect_brute_force(events):

    failed_attempts = defaultdict(deque)
    alerts = []

    # Track whether an IP has already triggered
    # an alert during its current attack window.
    alerted_ips = set()

    for event in events:

        source_ip = event["_source"].get("source_ip")
        timestamp = event["_source"].get("@timestamp")

        if not source_ip or not timestamp:
            continue

        event_time = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        attempts = failed_attempts[source_ip]

        # Add current failed-login timestamp
        attempts.append(event_time)

        # Remove attempts older than the detection window
        while attempts and (
            event_time - attempts[0]
        ).total_seconds() > TIME_WINDOW_SECONDS:

            attempts.popleft()

        # -------------------------------------------------
        # Trigger only ONCE when threshold is reached
        # -------------------------------------------------

        if (
            len(attempts) >= FAILED_LOGIN_THRESHOLD
            and source_ip not in alerted_ips
        ):

            alert = {
                "alert_type": "brute_force",
                "severity": "high",
                "source_ip": source_ip,
                "failed_attempts": len(attempts),
                "time_window_seconds": TIME_WINDOW_SECONDS,
                "status": "alert",
                "message": (
                    f"Possible brute-force attack detected "
                    f"from {source_ip}"
                )
            }

            alerts.append(alert)

            # Prevent duplicate alerts for the same
            # IP during this detection run.
            alerted_ips.add(source_ip)

    return alerts


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("BRUTE FORCE DETECTION ENGINE")
    print("=" * 60)

    print("\nQuerying Elasticsearch for failed login events...\n")

    events = get_failed_logins()

    print(f"Failed login events found: {len(events)}")

    alerts = detect_brute_force(events)

    print(f"Alerts generated: {len(alerts)}")

    print("\n" + "-" * 60)

    if not alerts:

        print("No brute-force activity detected.")

    else:

        for alert in alerts:

            print("🚨 BRUTE FORCE ALERT")
            print(f"Source IP       : {alert['source_ip']}")
            print(f"Failed Attempts : {alert['failed_attempts']}")
            print(
                f"Time Window     : "
                f"{alert['time_window_seconds']} seconds"
            )
            print(f"Severity        : {alert['severity'].upper()}")
            print(f"Status          : {alert['status'].upper()}")
            print(f"Message         : {alert['message']}")
            print("-" * 60)