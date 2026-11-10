from collections import defaultdict

from elasticsearch import Elasticsearch


# ---------------------------------------------------------
# Elasticsearch connection
# ---------------------------------------------------------

es = Elasticsearch("http://localhost:9200")


# ---------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------

FAILED_LOGIN_THRESHOLD = 5


# ---------------------------------------------------------
# Get security events
# ---------------------------------------------------------

def get_security_events():

    response = es.search(
        index="security-events-*",
        query={
            "match_all": {}
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
# Analyze IP activity
# ---------------------------------------------------------

def analyze_ip_activity(events):

    ip_activity = defaultdict(
        lambda: {
            "total_events": 0,
            "failed_logins": 0,
            "successful_logins": 0
        }
    )

    # ---------------------------------------------
    # Count activity for every source IP
    # ---------------------------------------------

    for event in events:

        source = event["_source"]

        source_ip = source.get("source_ip")
        event_type = source.get("event_type")

        if not source_ip:
            continue

        ip_activity[source_ip]["total_events"] += 1

        if event_type == "login_failed":
            ip_activity[source_ip]["failed_logins"] += 1

        elif event_type == "login_success":
            ip_activity[source_ip]["successful_logins"] += 1

    # ---------------------------------------------
    # Determine status
    # ---------------------------------------------

    results = []

    for source_ip, stats in ip_activity.items():

        if stats["failed_logins"] >= FAILED_LOGIN_THRESHOLD:
            status = "ALERT"
        else:
            status = "NORMAL"

        results.append(
            {
                "source_ip": source_ip,
                "total_events": stats["total_events"],
                "failed_logins": stats["failed_logins"],
                "successful_logins": stats["successful_logins"],
                "status": status
            }
        )

    # ---------------------------------------------
    # Sort by total activity
    # ---------------------------------------------

    results.sort(
        key=lambda item: item["total_events"],
        reverse=True
    )

    return results


# ---------------------------------------------------------
# Display results
# ---------------------------------------------------------

def display_results(results):

    print("\n" + "=" * 85)
    print("SOURCE IP ACTIVITY ANALYSIS")
    print("=" * 85)

    print(
        f"{'SOURCE IP':<18}"
        f"{'TOTAL':<10}"
        f"{'FAILED':<10}"
        f"{'SUCCESS':<12}"
        f"{'STATUS':<10}"
    )

    print("-" * 85)

    for item in results:

        print(
            f"{item['source_ip']:<18}"
            f"{item['total_events']:<10}"
            f"{item['failed_logins']:<10}"
            f"{item['successful_logins']:<12}"
            f"{item['status']:<10}"
        )

    print("-" * 85)

    alert_count = sum(
        1 for item in results
        if item["status"] == "ALERT"
    )

    normal_count = sum(
        1 for item in results
        if item["status"] == "NORMAL"
    )

    print(f"\nTotal source IPs : {len(results)}")
    print(f"Alert IPs        : {alert_count}")
    print(f"Normal IPs       : {normal_count}")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("SIEM SOURCE IP ANALYZER")
    print("=" * 60)

    print("\nQuerying Elasticsearch...\n")

    events = get_security_events()

    print(f"Events analyzed: {len(events)}")

    results = analyze_ip_activity(events)

    display_results(results)