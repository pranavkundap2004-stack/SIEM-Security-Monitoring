import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path


LOG_FILE = Path(__file__).parent / "logs" / "security_events.jsonl"

USERS = [
    "admin",
    "analyst",
    "john",
    "alice",
    "service_account"
]

SOURCE_IPS = [
    "192.168.1.10",
    "192.168.1.25",
    "10.0.0.15",
    "10.0.0.42",
    "172.16.0.20"
]


def create_event(event_type, username, source_ip, severity, message):
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "severity": severity,
        "message": message
    }


def write_event(event):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    print(
        f"[{event['severity'].upper()}] "
        f"{event['event_type']} | "
        f"user={event['username']} | "
        f"ip={event['source_ip']}"
    )


def generate_normal_events(count=10):
    for _ in range(count):
        username = random.choice(USERS)
        source_ip = random.choice(SOURCE_IPS)

        if random.random() < 0.7:
            event = create_event(
                "login_success",
                username,
                source_ip,
                "low",
                "Successful user login"
            )
        else:
            event = create_event(
                "login_failed",
                username,
                source_ip,
                "medium",
                "Failed login attempt"
            )

        write_event(event)
        time.sleep(1)


def generate_bruteforce_sequence():
    suspicious_ip = "10.10.10.50"
    target_user = "admin"

    print("\nGenerating brute-force test sequence...\n")

    for attempt in range(6):
        event = create_event(
            "login_failed",
            target_user,
            suspicious_ip,
            "high",
            f"Repeated failed login attempt #{attempt + 1}"
        )

        write_event(event)
        time.sleep(2)


def main():
    print("=" * 60)
    print("SIEM SECURITY EVENT GENERATOR")
    print("=" * 60)

    print(f"\nLog file: {LOG_FILE}")

    print("\nGenerating normal security events...\n")
    generate_normal_events()

    generate_bruteforce_sequence()

    print("\nEvent generation completed.")
    print(f"Events written to: {LOG_FILE}")


if __name__ == "__main__":
    main()