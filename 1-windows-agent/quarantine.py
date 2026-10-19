#!/usr/bin/python3
import os
import sys
import json
import datetime
import shutil
import hashlib

LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
QUARANTINE_DIR = "C:\\Quarantine"
SCAN_DIRS = ["C:\\Users\\YOURUSER\\Downloads"]  # adapt to the monitored user/folder

OS_SUCCESS = 0
OS_INVALID = -1

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name + ": " + msg + "\n")

def calculate_sha256(filepath):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha256.update(block)
        return sha256.hexdigest().lower()
    except Exception:
        return None

def find_file_by_hash(target_hash, scan_dirs):
    for scan_dir in scan_dirs:
        if not os.path.exists(scan_dir):
            continue
        for root, dirs, files in os.walk(scan_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                file_hash = calculate_sha256(filepath)
                if file_hash and file_hash == target_hash.lower():
                    return filepath
    return None

def main(argv):
    write_debug_file(argv[0], "Started")

    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'JSON decode failed')
        sys.exit(OS_INVALID)

    command = data.get("command")
    if command != "add":
        write_debug_file(argv[0], f"Not an add command: {command}")
        sys.exit(OS_SUCCESS)

    try:
        alert = data["parameters"]["alert"]
        syscheck = alert.get("syscheck", {})

        # Try path first, then hash
        file_path = syscheck.get("path")
        sha256 = syscheck.get("sha256_after") or syscheck.get("sha256")

        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)

        target = None

        if file_path and os.path.exists(file_path):
            target = file_path
            write_debug_file(argv[0], f"Using direct path: {target}")
        elif sha256:
            write_debug_file(argv[0], f"Searching by SHA256: {sha256}")
            target = find_file_by_hash(sha256, SCAN_DIRS)
            if target:
                write_debug_file(argv[0], f"Found file by hash: {target}")
            else:
                write_debug_file(argv[0], f"No file matched SHA256: {sha256}")

        if target and os.path.exists(target):
            filename = os.path.basename(target)
            destination = os.path.join(QUARANTINE_DIR, filename)
            counter = 1
            while os.path.exists(destination):
                destination = os.path.join(QUARANTINE_DIR, f"{filename}.{counter}")
                counter += 1
            shutil.move(target, destination)
            write_debug_file(argv[0], f"QUARANTINED: {target} -> {destination}")
        else:
            write_debug_file(argv[0], "No target file found to quarantine")

    except KeyError as e:
        write_debug_file(argv[0], f"Missing key: {e}")
    except Exception as e:
        write_debug_file(argv[0], f"Error: {str(e)}")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)
