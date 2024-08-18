import os
import requests
import sys

# Replace these variables with your DefectDojo configuration
DOJO_URL = "http://20.42.57.168:8080/api/v2"
API_KEY = "6fc6300d17a08a9040f5b429bf74292e2cd1a288"
ENGAGEMENT_ID = 2  # Replace with your engagement ID

HEADERS = {
    'Authorization': f'Token {API_KEY}',
    'Accept': 'application/json'
}

def upload_report(file_path, scan_type):
    """
    Uploads the given report to DefectDojo.

    :param file_path: Path to the report file.
    :param scan_type: Type of the scan (e.g., Gitleaks, Nodejsscan, Semgrep).
    """
    try:
        files = {'file': open(file_path, 'rb')}
        data = {
            'engagement': ENGAGEMENT_ID,
            'scan_type': scan_type,
            'active': True,
            'verified': False
        }

        response = requests.post(
            f"{DOJO_URL}/import-scan/",
            headers=HEADERS,
            files=files,
            data=data
        )

        if response.status_code == 201:
            print(f"Successfully uploaded {file_path} as {scan_type}.")
        else:
            print(f"Failed to upload {file_path}: {response.status_code}, {response.text}")
    
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Map the report file to its scan type in DefectDojo
    reports = {
        "gitleaks.json": "Gitleaks Scan",
        "nodejsscan.sarif": "Gitleaks Scan",
        "semgrep.json": "Semgrep JSON Report",
        "retirejsscan.json": "Retire.js Scan"
    }

    for report_file, scan_type in reports.items():
        if os.path.exists(report_file):
            upload_report(report_file, scan_type)
        else:
            print(f"Report file {report_file} does not exist.")
