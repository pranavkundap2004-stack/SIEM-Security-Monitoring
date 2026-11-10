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

FAILED_LOGIN_THRESHOLD = 3
TIME_WINDOW_SECONDS = 60


# ---------------------------------------------------------
# Get login events
# ---------------------------------------------------------

def get_login_events():

    response = es.search(
        index="security-events-*",
        query={
            "terms": {
                "event_type.keyword": [
                    "login_failed",
                    "login_success"
                ]
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
# Detect failure -> success pattern
# ---------------------------------------------------------

def detect_failure_success(events):

    failed_attempts = defaultdict(deque)
    alerts = []
    alerted_sessions = set()

    for event in events:

        source = event["_source"]

        source_ip = source.get("source_ip")
        username = source.get("username")
        event_type = source.get("event_type")
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
        # Track failed logins
        # -------------------------------------------------

        if event_type == "login_failed":

            key = (source_ip, username)

            attempts = failed_attempts[key]

            attempts.append(event_time)

            # Remove failures older than the detection window
            while attempts and (
                event_time - attempts[0]
            ).total_seconds() > TIME_WINDOW_SECONDS:

                attempts.popleft()

        # -------------------------------------------------
        # Check successful login after failures
        # -------------------------------------------------

        elif event_type == "login_success":

            key = (source_ip, username)

            attempts = failed_attempts.get(key)

            if not attempts:
                continue

            # Remove old failed attempts
            while attempts and (
                event_time - attempts[0]
            ).total_seconds() > TIME_WINDOW_SECONDS:

                attempts.popleft()

            if len(attempts) >= FAILED_LOGIN_THRESHOLD:

                session_key = (
                    source_ip,
                    username,
                    event_time
                )

                if session_key in alerted_sessions:
                    continue

                alert = {
                    "alert_type": "failure_success_correlation",
                    "severity": "high",
                    "source_ip": source_ip,
                    "username": username,
                    "failed_attempts": len(attempts),
                    "time_window_seconds": TIME_WINDOW_SECONDS,
                    "success_timestamp": timestamp,
                    "status": "alert",
                    "message": (
                        f"Multiple failed login attempts followed "
                        f"by a successful login for user '{username}' "
                        f"from {source_ip}"
                    )
                }

                alerts.append(alert)
                alerted_sessions.add(session_key)

    return alerts


# ---------------------------------------------------------
# Display alerts
# ---------------------------------------------------------

def display_alerts(alerts):

    print("\n" + "=" * 70)
    print("FAILURE -> SUCCESS CORRELATION")
    print("=" * 70)

    if not alerts:

        print("\nNo failure -> success correlation detected.")
        return

    for alert in alerts:

        print("\n🚨 FAILURE -> SUCCESS ALERT")

        print(f"Source IP       : {alert['source_ip']}")
        print(f"Username        : {alert['username']}")
        print(f"Failed Attempts : {alert['failed_attempts']}")
        print(
            f"Time Window     : "
            f"{alert['time_window_seconds']} seconds"
        )
        print(
            f"Success Time    : "
            f"{alert['success_timestamp']}"
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
    print("SIEM FAILURE -> SUCCESS DETECTOR")
    print("=" * 70)

    print("\nQuerying Elasticsearch...\n")

    events = get_login_events()

    print(f"Login events found: {len(events)}")

    alerts = detect_failure_success(events)

    display_alerts(alerts)