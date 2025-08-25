#!/usr/bin/env python3
import os
import sys
from src.detection import detect_project_languages

def main():
    """
    Main entry point for the Autonomous Security Remediator.
    """
    print("Autonomous Security Remediator initialized.")

    if len(sys.argv) > 1:
        target_directory = sys.argv[1]
    else:
        # For demonstration, we'll use the current directory.
        # The 'auto_trivy_fix' directory has examples we can detect.
        target_directory = './auto_trivy_fix/example'

    if not os.path.isdir(target_directory):
        print(f"Error: Directory not found at '{target_directory}'")
        sys.exit(1)

    print(f"Scanning project in: {target_directory}")

    languages = detect_project_languages(target_directory)

    if not languages:
        print("Could not detect a supported project type in the directory.")
    else:
        print(f"Detected project languages: {', '.join(languages)}")

if __name__ == "__main__":
    main()
