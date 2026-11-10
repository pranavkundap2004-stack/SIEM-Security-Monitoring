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

MIN_UNIQUE_USERS = 3
TIME_WINDOW_SECONDS = 60


# ---------------------------------------------------------
# Get failed login events
# ---------------------------------------------------------

def get_failed_login_events():

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
# Detect password spraying
# ---------------------------------------------------------

def detect_password_spraying(events):

    ip_activity = defaultdict(deque)
    alerts = []
    alerted_ips = set()

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
        # Store failed login for this source IP
        # -------------------------------------------------

        attempts = ip_activity[source_ip]

        attempts.append(
            {
                "timestamp": event_time,
                "username": username
            }
        )

        # -------------------------------------------------
        # Remove attempts outside the time window
        # -------------------------------------------------

        while attempts and (
            event_time - attempts[0]["timestamp"]
        ).total_seconds() > TIME_WINDOW_SECONDS:

            attempts.popleft()

        # -------------------------------------------------
        # Count unique targeted usernames
        # -------------------------------------------------

        unique_users = {
            attempt["username"]
            for attempt in attempts
        }

        # -------------------------------------------------
        # Password spraying condition
        # -------------------------------------------------

        if (
            len(unique_users) >= MIN_UNIQUE_USERS
            and source_ip not in alerted_ips
        ):

            alert = {
                "alert_type": "password_spraying",
                "severity": "high",
                "source_ip": source_ip,
                "targeted_users": sorted(unique_users),
                "unique_user_count": len(unique_users),
                "failed_attempts": len(attempts),
                "time_window_seconds": TIME_WINDOW_SECONDS,
                "status": "alert",
                "message": (
                    f"Possible password spraying attack detected "
                    f"from {source_ip} targeting "
                    f"{len(unique_users)} usernames"
                )
            }

            alerts.append(alert)
            alerted_ips.add(source_ip)

    return alerts


# ---------------------------------------------------------
# Display alerts
# ---------------------------------------------------------

def display_alerts(alerts):

    print("\n" + "=" * 70)
    print("PASSWORD SPRAYING DETECTION")
    print("=" * 70)

    if not alerts:

        print("\nNo password spraying activity detected.")
        return

    for alert in alerts:

        print("\n🚨 PASSWORD SPRAYING ALERT")

        print(f"Source IP       : {alert['source_ip']}")
        print(
            f"Targeted Users  : "
            f"{', '.join(alert['targeted_users'])}"
        )
        print(
            f"Unique Users    : "
            f"{alert['unique_user_count']}"
        )
        print(
            f"Failed Attempts : "
            f"{alert['failed_attempts']}"
        )
        print(
            f"Time Window     : "
            f"{alert['time_window_seconds']} seconds"
        )
        print(f"Severity        : {alert['severity'].upper()}")
        print(f"Status          : {alert['status'].upper()}")
        print(f"Message         : {alert['message']}")

        print("-" * 70)

    print(f"\nTotal alerts: {len(alerts)}")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 70)
    print("SIEM PASSWORD SPRAYING DETECTOR")
    print("=" * 70)

    print("\nQuerying Elasticsearch...\n")

    events = get_failed_login_events()

    print(f"Failed login events found: {len(events)}")

    alerts = detect_password_spraying(events)

    display_alerts(alerts)