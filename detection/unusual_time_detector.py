from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch


# ---------------------------------------------------------
# Elasticsearch connection
# ---------------------------------------------------------

es = Elasticsearch("http://localhost:9200")


# ---------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------

# Normal login activity window in IST
NORMAL_START_HOUR = 6
NORMAL_END_HOUR = 23

IST = timezone(timedelta(hours=5, minutes=30))


# ---------------------------------------------------------
# Query login events
# ---------------------------------------------------------

def get_login_events():

    response = es.search(
        index="security-events-*",
        query={
            "terms": {
                "event_type.keyword": [
                    "login_success",
                    "login_failed"
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
# Unusual login-time detection
# ---------------------------------------------------------

def detect_unusual_times(events):

    suspicious_events = []

    for event in events:

        source = event["_source"]

        timestamp = source.get("@timestamp")
        source_ip = source.get("source_ip")
        username = source.get("username")
        event_type = source.get("event_type")

        if not timestamp:
            continue

        try:
            event_time = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            # Convert UTC timestamp to IST
            event_time_ist = event_time.astimezone(IST)

        except ValueError:
            continue

        hour = event_time_ist.hour

        # -------------------------------------------------
        # Check whether login occurred outside normal hours
        # -------------------------------------------------

        if hour < NORMAL_START_HOUR or hour >= NORMAL_END_HOUR:

            suspicious_events.append({
                "timestamp": event_time_ist.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "source_ip": source_ip,
                "username": username,
                "event_type": event_type,
                "status": "SUSPICIOUS",
                "reason": "Login occurred outside normal activity hours"
            })

    return suspicious_events


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("SIEM UNUSUAL LOGIN-TIME DETECTOR")
    print("=" * 60)

    print("\nNormal login window: 06:00 - 23:00 IST")

    print("\nQuerying Elasticsearch...\n")

    events = get_login_events()

    print(f"Login events analyzed: {len(events)}")

    suspicious_events = detect_unusual_times(events)

    print("\n" + "=" * 60)
    print("UNUSUAL LOGIN-TIME ANALYSIS")
    print("=" * 60)

    if not suspicious_events:

        print("\nNo unusual login times detected.")

    else:

        for event in suspicious_events:

            print("\n⚠ UNUSUAL LOGIN DETECTED")
            print(f"Timestamp : {event['timestamp']} IST")
            print(f"Source IP : {event['source_ip']}")
            print(f"Username  : {event['username']}")
            print(f"Event     : {event['event_type']}")
            print(f"Status    : {event['status']}")
            print(f"Reason    : {event['reason']}")
            print("-" * 60)

    print(
        f"\nSuspicious login events: "
        f"{len(suspicious_events)}"
    )