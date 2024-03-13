#!/usr/bin/env python3

import time
import json
import os
import sys
import tempfile
from datetime import datetime

def main():
    # Check if '-reason' is in the command line arguments
    report_reason = '-reason' in sys.argv

    # Read JSON string from the standard input
    try:
        json_from_input = sys.stdin.read()
    except KeyboardInterrupt:
        sys.exit(1)

    # Parse JSON string
    try:
        json_data = json.loads(json_from_input)
    except json.JSONDecodeError as e:
        return False, f"Error decoding JSON: {e}"

    # Get the system's temporary directory
    temp_dir = tempfile.gettempdir()

    # Create or append to the log file
    log_file_path = os.path.join(temp_dir, "RaPluginLog.txt")
    with open(log_file_path, 'a') as file:
        # Write the current time to the file
        file.write(f"-------------------------{datetime.now()}\n")

        # Write the input to the file
        json.dump(json_data, file, indent=2)

    # Print '1' to the screen
    print("1", end='')

    # If '-reason' is in the command line arguments, print the reason JSON
    if report_reason:
        print("\n\n{\"reason\":\"I trust you\"}")

if __name__ == "__main__":
    main()

