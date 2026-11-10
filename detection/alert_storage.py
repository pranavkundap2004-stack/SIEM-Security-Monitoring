import hashlib
import json
from datetime import datetime, timezone

from elasticsearch import Elasticsearch


# ---------------------------------------------------------
# Elasticsearch connection
# ---------------------------------------------------------

es = Elasticsearch("http://localhost:9200")


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

ALERT_INDEX_PREFIX = "siem-alerts"


# ---------------------------------------------------------
# Generate alert index name
# ---------------------------------------------------------

def get_alert_index():

    current_date = datetime.now(
        timezone.utc
    ).strftime("%Y.%m.%d")

    return f"{ALERT_INDEX_PREFIX}-{current_date}"


# ---------------------------------------------------------
# Generate deterministic alert ID
# ---------------------------------------------------------

def generate_alert_id(alert):

    # -----------------------------------------------------
    # Use alert content to create a stable unique ID.
    #
    # storage-specific fields are excluded because they
    # change every time the engine is executed.
    # -----------------------------------------------------

    identity_data = {
        key: value
        for key, value in alert.items()
        if key not in {
            "stored_at",
            "storage_status",
            "risk_score",
            "risk_severity",
            "risk_entity",
            "risk_detections"
        }
    }

    canonical_data = json.dumps(
        identity_data,
        sort_keys=True,
        default=str
    )

    return hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------
# Create alert document
# ---------------------------------------------------------

def prepare_alert_document(
    alert,
    risk_result=None
):

    document = dict(alert)

    # -----------------------------------------------------
    # Add storage timestamp
    # -----------------------------------------------------

    document["stored_at"] = datetime.now(
        timezone.utc
    ).isoformat()

    # -----------------------------------------------------
    # Add risk information
    # -----------------------------------------------------

    if risk_result:

        document["risk_score"] = risk_result.get(
            "risk_score",
            0
        )

        document["risk_severity"] = risk_result.get(
            "severity",
            "LOW"
        )

        document["risk_entity"] = risk_result.get(
            "entity"
        )

        document["risk_detections"] = risk_result.get(
            "detections",
            []
        )

    else:

        document["risk_score"] = 0
        document["risk_severity"] = "LOW"
        document["risk_entity"] = None
        document["risk_detections"] = []

    # -----------------------------------------------------
    # Storage metadata
    # -----------------------------------------------------

    document["storage_status"] = "stored"

    return document


# ---------------------------------------------------------
# Find risk result for alert
# ---------------------------------------------------------

def find_risk_result(
    alert,
    risk_results
):

    source_ip = alert.get("source_ip")
    username = alert.get("username")

    # -----------------------------------------------------
    # Prefer exact IP + username entity
    # -----------------------------------------------------

    if source_ip and username:

        combined_entity = (
            f"{source_ip}:{username}"
        )

        for result in risk_results:

            if result.get("entity") == combined_entity:
                return result

    # -----------------------------------------------------
    # Source IP entity
    # -----------------------------------------------------

    if source_ip:

        for result in risk_results:

            if result.get("entity") == source_ip:
                return result

    # -----------------------------------------------------
    # Username-only entity
    # -----------------------------------------------------

    if username:

        for result in risk_results:

            if result.get("entity") == username:
                return result

    return None


# ---------------------------------------------------------
# Store alerts in Elasticsearch
# ---------------------------------------------------------

def store_alerts(
    alerts,
    risk_results
):

    if not alerts:

        print(
            "\nNo alerts available "
            "for Elasticsearch storage."
        )

        return {
            "index": get_alert_index(),
            "stored": 0,
            "updated": 0,
            "failed": 0
        }

    index_name = get_alert_index()

    print("\n" + "=" * 80)
    print("SIEM ALERT STORAGE")
    print("=" * 80)

    print(
        f"\nTarget index: {index_name}"
    )

    stored_count = 0
    updated_count = 0
    failed_count = 0

    # -----------------------------------------------------
    # Store every alert
    # -----------------------------------------------------

    for alert in alerts:

        risk_result = find_risk_result(
            alert,
            risk_results
        )

        document = prepare_alert_document(
            alert,
            risk_result
        )

        # -------------------------------------------------
        # Generate stable document ID
        # -------------------------------------------------

        alert_id = generate_alert_id(alert)

        try:

            response = es.index(
                index=index_name,
                id=alert_id,
                document=document
            )

            result = response.get("result")

            if result == "created":

                stored_count += 1

            elif result == "updated":

                updated_count += 1

        except Exception as error:

            failed_count += 1

            print(
                "\nERROR storing alert:"
            )

            print(error)

    # -----------------------------------------------------
    # Storage summary
    # -----------------------------------------------------

    print(
        f"\nAlerts processed : {len(alerts)}"
    )

    print(
        f"New alerts stored: {stored_count}"
    )

    print(
        f"Existing alerts updated: {updated_count}"
    )

    print(
        f"Alerts failed    : {failed_count}"
    )

    print(
        f"Alert index      : {index_name}"
    )

    return {
        "index": index_name,
        "stored": stored_count,
        "updated": updated_count,
        "failed": failed_count
    }


# ---------------------------------------------------------
# Verify alert index
# ---------------------------------------------------------

def verify_alert_index(index_name):

    try:

        response = es.count(
            index=index_name
        )

        count = response.get(
            "count",
            0
        )

        print(
            f"\nAlerts currently stored "
            f"in {index_name}: {count}"
        )

        return count

    except Exception as error:

        print(
            "\nUnable to verify alert index:"
        )

        print(error)

        return 0


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 80)
    print("SIEM ALERT STORAGE MODULE")
    print("=" * 80)

    print(
        "\nThis module stores alerts generated "
        "by the unified detection engine."
    )

    print(
        "\nRun the unified detection engine "
        "to generate and store alerts."
    )