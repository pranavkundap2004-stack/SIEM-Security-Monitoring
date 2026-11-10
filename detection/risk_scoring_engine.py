from collections import defaultdict


# ---------------------------------------------------------
# Risk score configuration
# ---------------------------------------------------------

RISK_SCORES = {
    "brute_force": 40,
    "failure_success_correlation": 40,
    "password_spraying": 30,
    "multiple_ips_same_user": 30,
    "unknown_ip": 20,
    "unusual_login_time": 20
}


# ---------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------

def get_severity(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    return "LOW"


# ---------------------------------------------------------
# Create entity key
# ---------------------------------------------------------

def get_entity_key(alert):

    source_ip = alert.get("source_ip")
    username = alert.get("username")

    # -----------------------------------------------------
    # Source IP is the primary security entity
    # -----------------------------------------------------
    #
    # This allows multiple detections associated with the
    # same source IP to contribute to one combined risk score.
    #
    # Example:
    #
    # 192.168.1.25
    #     brute_force              -> +40
    #     failure_success           -> +40
    #
    # Combined:
    #     192.168.1.25              -> 80 CRITICAL
    #
    # -----------------------------------------------------

    if source_ip:
        return source_ip

    # -----------------------------------------------------
    # Username-only detections
    # -----------------------------------------------------

    if username:
        return username

    return "unknown"


# ---------------------------------------------------------
# Calculate risk scores
# ---------------------------------------------------------

def calculate_risk_scores(all_alerts):

    entity_alerts = defaultdict(list)

    # -----------------------------------------------------
    # Group alerts by primary security entity
    # -----------------------------------------------------

    for alert in all_alerts:

        alert_type = alert.get("alert_type")

        if alert_type not in RISK_SCORES:
            continue

        entity_key = get_entity_key(alert)

        entity_alerts[entity_key].append(alert)

    results = []

    # -----------------------------------------------------
    # Calculate score for every entity
    # -----------------------------------------------------

    for entity_key, alerts in entity_alerts.items():

        score = 0
        detected_types = set()

        for alert in alerts:

            alert_type = alert.get("alert_type")

            # -------------------------------------------------
            # Count each detection type only once
            # -------------------------------------------------
            #
            # Multiple alerts of the same detection type
            # should not inflate the risk score repeatedly.
            #
            # Example:
            #
            # 6 brute-force alerts for one entity
            # still contribute only +40.
            #
            # -------------------------------------------------

            if alert_type in detected_types:
                continue

            score += RISK_SCORES[alert_type]
            detected_types.add(alert_type)

        severity = get_severity(score)

        # -----------------------------------------------------
        # Extract identifying information
        # -----------------------------------------------------

        source_ips = sorted({
            alert.get("source_ip")
            for alert in alerts
            if alert.get("source_ip")
        })

        usernames = sorted({
            alert.get("username")
            for alert in alerts
            if alert.get("username")
        })

        results.append(
            {
                "entity": entity_key,
                "source_ips": source_ips,
                "usernames": usernames,
                "risk_score": score,
                "severity": severity,
                "detections": sorted(detected_types),
                "detection_count": len(detected_types)
            }
        )

    # ---------------------------------------------------------
    # Sort highest risk first
    # ---------------------------------------------------------

    results.sort(
        key=lambda item: item["risk_score"],
        reverse=True
    )

    return results


# ---------------------------------------------------------
# Display risk results
# ---------------------------------------------------------

def display_risk_results(results):

    print("\n" + "=" * 80)
    print("SIEM RISK SCORING ENGINE")
    print("=" * 80)

    if not results:

        print("\nNo alerts available for risk scoring.")
        return

    for result in results:

        print("\n🚨 RISK ASSESSMENT")

        print(
            f"Entity          : "
            f"{result['entity']}"
        )

        print(
            f"Risk Score      : "
            f"{result['risk_score']}"
        )

        print(
            f"Severity        : "
            f"{result['severity']}"
        )

        if result["source_ips"]:

            print(
                f"Source IPs      : "
                f"{', '.join(result['source_ips'])}"
            )

        if result["usernames"]:

            print(
                f"Usernames       : "
                f"{', '.join(result['usernames'])}"
            )

        print(
            f"Detections      : "
            f"{', '.join(result['detections'])}"
        )

        print(
            f"Detection Count : "
            f"{result['detection_count']}"
        )

        print("-" * 80)

    print(
        f"\nEntities scored: "
        f"{len(results)}"
    )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 80)
    print("SIEM RISK SCORING ENGINE")
    print("=" * 80)

    print(
        "\nThis module expects alerts from "
        "the detection engines."
    )

    print(
        "Run the individual detectors "
        "during the integration phase."
    )