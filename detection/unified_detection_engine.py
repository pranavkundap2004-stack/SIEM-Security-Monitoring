from detection.brute_force_detector import (
    get_failed_logins,
    detect_brute_force
)

from detection.unknown_ip_detector import (
    load_known_ips,
    get_source_ips,
    detect_unknown_ips
)

from detection.unusual_time_detector import (
    get_login_events,
    detect_unusual_times
)

from detection.failure_success_detector import (
    get_login_events as get_failure_success_events,
    detect_failure_success
)

from detection.password_spraying_detector import (
    get_failed_login_events,
    detect_password_spraying
)

from detection.multiple_ip_same_user_detector import (
    get_successful_login_events,
    detect_multiple_ips_same_user
)

from detection.ip_activity_analyzer import (
    get_security_events,
    analyze_ip_activity
)

from detection.risk_scoring_engine import (
    calculate_risk_scores,
    display_risk_results
)

from detection.alert_storage import (
    store_alerts,
    verify_alert_index
)


# ---------------------------------------------------------
# Unified Detection Engine
# ---------------------------------------------------------

def run_detection_engine():

    print("=" * 80)
    print("SIEM UNIFIED DETECTION ENGINE")
    print("=" * 80)

    all_alerts = []

    # =====================================================
    # 1. BRUTE FORCE
    # =====================================================

    print("\n[1/7] Running brute-force detection...")

    failed_events = get_failed_logins()

    brute_force_alerts = detect_brute_force(
        failed_events
    )

    all_alerts.extend(brute_force_alerts)

    print(
        f"Brute-force alerts: "
        f"{len(brute_force_alerts)}"
    )

    # =====================================================
    # 2. UNKNOWN IP
    # =====================================================

    print("\n[2/7] Running unknown-IP detection...")

    known_ips = load_known_ips()

    source_ip_events = get_source_ips()

    unknown_ip_results = detect_unknown_ips(
        source_ip_events,
        known_ips
    )

    # -----------------------------------------------------
    # Normalize unknown-IP results into unified format
    # -----------------------------------------------------

    unknown_ip_alerts = []

    for event in unknown_ip_results:

        alert = {
            "alert_type": "unknown_ip",
            "severity": "medium",
            "source_ip": event.get("source_ip"),
            "failed_logins": event.get(
                "failed_logins",
                0
            ),
            "successful_logins": event.get(
                "successful_logins",
                0
            ),
            "status": event.get(
                "status",
                "SUSPICIOUS"
            ),
            "reason": event.get(
                "reason"
            ),
            "message": (
                f"Activity detected from unknown "
                f"source IP {event.get('source_ip')}"
            )
        }

        unknown_ip_alerts.append(alert)

    all_alerts.extend(unknown_ip_alerts)

    print(
        f"Unknown-IP alerts: "
        f"{len(unknown_ip_alerts)}"
    )

    # =====================================================
    # 3. UNUSUAL LOGIN TIME
    # =====================================================

    print(
        "\n[3/7] Running "
        "unusual-login-time detection..."
    )

    login_events = get_login_events()

    unusual_time_events = detect_unusual_times(
        login_events
    )

    # -----------------------------------------------------
    # Normalize unusual-time events into alert format
    # -----------------------------------------------------

    unusual_time_alerts = []

    for event in unusual_time_events:

        alert = {
            "alert_type": "unusual_login_time",
            "severity": "medium",
            "source_ip": event.get(
                "source_ip"
            ),
            "username": event.get(
                "username"
            ),
            "timestamp": event.get(
                "timestamp"
            ),
            "event_type": event.get(
                "event_type"
            ),
            "status": event.get(
                "status",
                "SUSPICIOUS"
            ),
            "reason": event.get(
                "reason"
            ),
            "message": (
                "Login activity detected outside "
                "normal activity hours"
            )
        }

        unusual_time_alerts.append(alert)

    all_alerts.extend(unusual_time_alerts)

    print(
        f"Unusual-time alerts: "
        f"{len(unusual_time_alerts)}"
    )

    # =====================================================
    # 4. FAILURE -> SUCCESS
    # =====================================================

    print(
        "\n[4/7] Running "
        "failure -> success correlation..."
    )

    failure_success_events = get_failure_success_events()

    failure_success_alerts = detect_failure_success(
        failure_success_events
    )

    all_alerts.extend(failure_success_alerts)

    print(
        f"Failure -> success alerts: "
        f"{len(failure_success_alerts)}"
    )

    # =====================================================
    # 5. PASSWORD SPRAYING
    # =====================================================

    print(
        "\n[5/7] Running "
        "password-spraying detection..."
    )

    password_spraying_events = get_failed_login_events()

    password_spraying_alerts = detect_password_spraying(
        password_spraying_events
    )

    all_alerts.extend(password_spraying_alerts)

    print(
        f"Password-spraying alerts: "
        f"{len(password_spraying_alerts)}"
    )

    # =====================================================
    # 6. MULTIPLE IP -> SAME USER
    # =====================================================

    print(
        "\n[6/7] Running "
        "multiple-IP same-user detection..."
    )

    successful_login_events = get_successful_login_events()

    multiple_ip_alerts = detect_multiple_ips_same_user(
        successful_login_events
    )

    all_alerts.extend(multiple_ip_alerts)

    print(
        f"Multiple-IP same-user alerts: "
        f"{len(multiple_ip_alerts)}"
    )

    # =====================================================
    # 7. IP ACTIVITY ANALYSIS
    # =====================================================

    print(
        "\n[7/7] Running "
        "IP activity analysis..."
    )

    security_events = get_security_events()

    ip_activity_results = analyze_ip_activity(
        security_events
    )

    print(
        f"Source IPs analyzed: "
        f"{len(ip_activity_results)}"
    )

    # =====================================================
    # SUMMARY BEFORE RISK SCORING
    # =====================================================

    print("\n" + "=" * 80)
    print("DETECTION SUMMARY")
    print("=" * 80)

    print(
        f"\nTotal detection alerts: "
        f"{len(all_alerts)}"
    )

    # -----------------------------------------------------
    # Count alert types
    # -----------------------------------------------------

    alert_type_counts = {}

    for alert in all_alerts:

        alert_type = alert.get(
            "alert_type",
            "unknown"
        )

        alert_type_counts[alert_type] = (
            alert_type_counts.get(
                alert_type,
                0
            ) + 1
        )

    print("\nAlert distribution:")

    for alert_type, count in sorted(
        alert_type_counts.items()
    ):

        print(
            f"  {alert_type:<35} : {count}"
        )

    # =====================================================
    # RISK SCORING
    # =====================================================

    print("\n" + "=" * 80)
    print("RISK SCORING")
    print("=" * 80)

    risk_results = calculate_risk_scores(
        all_alerts
    )

    display_risk_results(
        risk_results
    )

    # =====================================================
    # ALERT STORAGE
    # =====================================================

    print("\n" + "=" * 80)
    print("ALERT STORAGE")
    print("=" * 80)

    storage_result = store_alerts(
        all_alerts,
        risk_results
    )

    alert_index = storage_result.get(
        "index"
    )

    stored_alert_count = verify_alert_index(
        alert_index
    )

    # =====================================================
    # FINAL RESULT
    # =====================================================

    print("\n" + "=" * 80)
    print("UNIFIED DETECTION COMPLETE")
    print("=" * 80)

    print(
        f"\nTotal alerts generated : "
        f"{len(all_alerts)}"
    )

    print(
        f"Risk entities scored   : "
        f"{len(risk_results)}"
    )

    print(
        f"IP activity records    : "
        f"{len(ip_activity_results)}"
    )

    print(
        f"Alerts stored          : "
        f"{storage_result.get('stored', 0)}"
    )

    print(
        f"Storage failures       : "
        f"{storage_result.get('failed', 0)}"
    )

    print(
        f"Alerts in Elasticsearch: "
        f"{stored_alert_count}"
    )

    return {
        "alerts": all_alerts,
        "risk_results": risk_results,
        "ip_activity": ip_activity_results,
        "storage": storage_result,
        "stored_alert_count": stored_alert_count
    }


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    run_detection_engine()