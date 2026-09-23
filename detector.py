from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os

TEST_FOLDER = "test_files"

TIME_WINDOW = 10

activity = []


def calculate_risk():
    global activity

    score = 0

    # Keep only recent activity
    if not activity:
        return 0

    # 1. Number of changes
    changes = len(activity)

    if changes >= 3:
        score += 20

    if changes >= 5:
        score += 20

    if changes >= 8:
        score += 20

    # 2. Different files affected
    unique_files = set(item["path"] for item in activity)

    if len(unique_files) >= 3:
        score += 15

    if len(unique_files) >= 5:
        score += 15

    # 3. Suspicious extensions
    suspicious_extensions = [
        ".locked",
        ".encrypted",
        ".enc"
    ]

    suspicious_count = 0

    for item in activity:
        path = item["path"].lower()

        if any(path.endswith(ext) for ext in suspicious_extensions):
            suspicious_count += 1

    if suspicious_count >= 1:
        score += 20

    if suspicious_count >= 3:
        score += 20

    # 4. Mass rename detection
    rename_count = sum(
        1 for item in activity
        if item["type"] == "File renamed"
    )

    if rename_count >= 2:
        score += 15

    if rename_count >= 4:
        score += 20

    return min(score, 100)


class RansomwareDetector(FileSystemEventHandler):

    def record_activity(self, event_type, path):

        global activity

        now = time.time()

        # Keep activities from the last 10 seconds
        activity = [
            item for item in activity
            if now - item["time"] <= TIME_WINDOW
        ]

        activity.append({
            "time": now,
            "type": event_type,
            "path": path
        })

        risk = calculate_risk()

        print(f"⚠️ {event_type}: {path}")
        print(f"📊 Risk Score: {risk}/100")

        if risk >= 80:
            print("\n🔴 CRITICAL RISK!")
            print("🚨 POSSIBLE RANSOMWARE ACTIVITY")
            print("🛡️ PROTECTION SHOULD BE ACTIVATED!\n")

        elif risk >= 60:
            print("\n🟠 HIGH RISK!")
            print("⚠️ Suspicious file activity detected.\n")

        elif risk >= 30:
            print("\n🟡 MEDIUM RISK!")
            print("⚠️ Multiple file changes detected.\n")


    def on_modified(self, event):

        if not event.is_directory:
            self.record_activity(
                "File modified",
                event.src_path
            )


    def on_created(self, event):

        if not event.is_directory:
            self.record_activity(
                "File created",
                event.src_path
            )


    def on_deleted(self, event):

        if not event.is_directory:
            self.record_activity(
                "File deleted",
                event.src_path
            )


    def on_moved(self, event):

        if not event.is_directory:
            self.record_activity(
                "File renamed",
                event.dest_path
            )


event_handler = RansomwareDetector()

observer = Observer()

observer.schedule(
    event_handler,
    TEST_FOLDER,
    recursive=True
)

observer.start()

print("===================================")
print("🛡️ RANSOMWARE GUARD")
print("===================================")
print("👀 Monitoring:", TEST_FOLDER)
print("📊 Risk detection enabled")
print("Press CTRL+C to stop.\n")


try:

    while True:
        time.sleep(1)

except KeyboardInterrupt:

    observer.stop()

observer.join()