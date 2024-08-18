import requests
import sys
import json

# Configuration
DOJO_URL = 'http://20.42.57.168:8080/api/v2'  # DefectDojo URL
API_KEY = '6fc6300d17a08a9040f5b429bf74292e2cd1a288'  # API Key
ENGAGEMENT_ID = 2  # Engagement ID

file_name = sys.argv[1]
scan_type = ''
if file_name == 'gitleaks.json':
    scan_type = 'Gitleaks Scan'
elif file_name == 'njsscan.sarif':
    scan_type = 'SARIF'
elif file_name == 'semgrep.json':
    scan_type = 'Semgrep JSON Report'
elif file_name == 'retire.json':
    scan_type = 'Retire.js Scan'

headers = {
    'Authorization': f'Token {API_KEY}',
    'Content-Type': 'application/json'
}

# Function to get existing findings
def get_existing_findings():
    url = f'{DOJO_URL}/findings/'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()  # Assuming the API returns JSON data
    else:
        print(f'Failed to get existing findings: {response.content}')
        return []

# Function to filter new findings
def filter_new_findings(existing_findings, new_findings):
    existing_ids = {finding['id'] for finding in existing_findings}
    filtered_findings = [finding for finding in new_findings if finding['id'] not in existing_ids]
    return filtered_findings

# Read new findings from the file
with open(file_name, 'r') as file:
    new_findings = json.load(file)

# Get existing findings
existing_findings = get_existing_findings()

# Filter new findings
filtered_findings = filter_new_findings(existing_findings, new_findings)

# Import filtered findings
if filtered_findings:
    url = f'{DOJO_URL}/import-scan/'
    data = {
        'active': True,
        'verified': True,
        'scan_type': scan_type,
        'minimum_severity': 'Low',
        'engagement': ENGAGEMENT_ID
    }
    files = {
        'file': open(file_name, 'rb')
    }
    response = requests.post(url, headers=headers, data=data, files=files)
    if response.status_code == 201:
        print('Scan results imported successfully')
    else:
        print(f'Failed to import scan results: {response.content}')
else:
    print('No new findings to import')
