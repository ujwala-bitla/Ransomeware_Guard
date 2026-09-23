import os
import time

TEST_FOLDER = "test_files"

print("=" * 45)
print("🧪 RANSOMWARE BEHAVIOR SIMULATOR")
print("=" * 45)

files = [
    "document.txt",
    "notes.txt",
    "project.txt",
    "resume.txt",
    "photo.jpg"
]

print("\n⚠️ Starting SAFE simulation...")
print("Only files inside test_files will be affected.\n")

for filename in files:
    old_path = os.path.join(TEST_FOLDER, filename)

    if os.path.exists(old_path):
        name, ext = os.path.splitext(filename)
        new_path = os.path.join(TEST_FOLDER, name + ".locked")

        os.rename(old_path, new_path)

        print(f"🔒 Simulated encryption: {filename} → {name}.locked")
        time.sleep(0.5)

print("\n🚨 Simulation completed!")
print("Check Ransomware Guard for the detected activity.")