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

MIN_UNIQUE_IPS = 2
TIME_WINDOW_SECONDS = 60


# ---------------------------------------------------------
# Get successful login events
# ---------------------------------------------------------

def get_successful_login_events():

    response = es.search(
        index="security-events-*",
        query={
            "term": {
                "event_type.keyword": "login_success"
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
# Detect multiple IPs for same user
# ---------------------------------------------------------

def detect_multiple_ips_same_user(events):

    user_activity = defaultdict(deque)

    alerts = []
    alerted_users = set()

    for event in events:

        source = event["_source"]

        source_ip = source.get("source_ip")
        username = source.get("username")
        timestamp = source.get("@timestamp")

        if not source_ip or not username or not timestamp:
            continue

        try:
            event_time = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
        except ValueError:
            continue

        # -------------------------------------------------
        # Store successful login for this user
        # -------------------------------------------------

        attempts = user_activity[username]

        attempts.append(
            {
                "timestamp": event_time,
                "source_ip": source_ip
            }
        )

        # -------------------------------------------------
        # Remove events outside the time window
        # -------------------------------------------------

        while attempts and (
            event_time - attempts[0]["timestamp"]
        ).total_seconds() > TIME_WINDOW_SECONDS:

            attempts.popleft()

        # -------------------------------------------------
        # Find unique source IPs
        # -------------------------------------------------

        unique_ips = {
            attempt["source_ip"]
            for attempt in attempts
        }

        # -------------------------------------------------
        # Multiple IP detection condition
        # -------------------------------------------------

        if (
            len(unique_ips) >= MIN_UNIQUE_IPS
            and username not in alerted_users
        ):

            alert = {
                "alert_type": "multiple_ips_same_user",
                "severity": "high",
                "username": username,
                "source_ips": sorted(unique_ips),
                "unique_ip_count": len(unique_ips),
                "successful_logins": len(attempts),
                "time_window_seconds": TIME_WINDOW_SECONDS,
                "status": "alert",
                "message": (
                    f"User '{username}' successfully logged in "
                    f"from {len(unique_ips)} different IP addresses "
                    f"within {TIME_WINDOW_SECONDS} seconds"
                )
            }

            alerts.append(alert)
            alerted_users.add(username)

    return alerts


# ---------------------------------------------------------
# Display alerts
# ---------------------------------------------------------

def display_alerts(alerts):

    print("\n" + "=" * 70)
    print("MULTIPLE IPs -> SAME USER DETECTION")
    print("=" * 70)

    if not alerts:

        print("\nNo multiple-IP same-user activity detected.")
        return

    for alert in alerts:

        print("\n🚨 MULTIPLE IP -> SAME USER ALERT")

        print(f"Username         : {alert['username']}")
        print(
            f"Source IPs       : "
            f"{', '.join(alert['source_ips'])}"
        )
        print(
            f"Unique IPs       : "
            f"{alert['unique_ip_count']}"
        )
        print(
            f"Successful Logins: "
            f"{alert['successful_logins']}"
        )
        print(
            f"Time Window      : "
            f"{alert['time_window_seconds']} seconds"
        )
        print(f"Severity         : {alert['severity'].upper()}")
        print(f"Status           : {alert['status'].upper()}")
        print(f"Message          : {alert['message']}")

        print("-" * 70)

    print(f"\nTotal alerts: {len(alerts)}")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 70)
    print("SIEM MULTIPLE IP -> SAME USER DETECTOR")
    print("=" * 70)

    print("\nQuerying Elasticsearch...\n")

    events = get_successful_login_events()

    print(
        f"Successful login events found: "
        f"{len(events)}"
    )

    alerts = detect_multiple_ips_same_user(events)

    display_alerts(alerts)