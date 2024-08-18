import requests
import sys
import json
import os

# Get file name from command line arguments
file_name = sys.argv[1]

# Determine scan type based on file name
scan_type = ''
if file_name == 'gitleaks.json':
    scan_type = 'Gitleaks Scan'
elif file_name == 'nodejsscan.sarif':
    scan_type = 'SARIF'
elif file_name == 'semgrep.json':
    scan_type = 'Semgrep JSON Report'
elif file_name == 'retirejsscan.json':
    scan_type = 'Retire.js Scan'
# ... other conditions

# Define headers and URL for DefectDojo API
headers = {
    'Authorization': 'Token 6fc6300d17a08a9040f5b429bf74292e2cd1a288'
}
url = 'http://20.42.57.168:8080/api/v2'

# Define the engagement ID and data for the request
engagement_id = 3
data = {
    'active': True,
    'verified': True,
    'scan_type': scan_type,
    'minimum_severity': 'Low',
    'engagement': engagement_id
}

# File to track previously uploaded fingerprints
fingerprints_file = 'uploaded_fingerprints.json'

# Load previously uploaded fingerprints if the file exists
if os.path.exists(fingerprints_file):
    with open(fingerprints_file, 'r') as f:
        uploaded_fingerprints = set(json.load(f))
else:
    uploaded_fingerprints = set()

# Read new scan results
with open(file_name, 'r') as file:
    new_findings = json.load(file)

# Prepare new findings for upload
new_findings_to_upload = []

for finding in new_findings:
    # Use the 'Fingerprint' field for uniqueness
    fingerprint = finding.get('Fingerprint')
    if fingerprint:
        if fingerprint not in uploaded_fingerprints:
            new_findings_to_upload.append(finding)
        uploaded_fingerprints.add(fingerprint)

if not new_findings_to_upload:
    print('No new findings to upload.')
else:
    files = {
        'file': ('scan_results.json', json.dumps(new_findings_to_upload), 'application/json')
    }
    response = requests.post(url, headers=headers, data=data, files=files)
    if response.status_code == 201:
        print('Scan results imported successfully')
        
        # Update the fingerprints file with new fingerprints
        with open(fingerprints_file, 'w') as f:
            json.dump(list(uploaded_fingerprints), f)
    else:
        print(f'Failed to import scan results: {response.content}')
