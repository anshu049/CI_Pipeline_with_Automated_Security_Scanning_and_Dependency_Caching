import requests
import sys

file_name = sys.argv[1]
scan_type = ''

if file_name == 'gitleaks.json':
    scan_type = 'Gitleaks Scan'
elif file_name == 'nodejsscan.sarif':
    scan_type = 'SARIF'
elif file_name == 'semgrep.json':
    scan_type = 'Semgrep JSON Report'
elif file_name == 'retirejsscan.json':
    scan_type = 'Retire.js Scan'
elif file_name == 'trivy.json':
    scan_type = 'Trivy Scan'


headers = {
    'Authorization': 'Token 6fc6300d17a08a9040f5b429bf74292e2cd1a288'
}

url = 'http://20.42.57.168:8080/api/v2'

data = {
    'active': True,
    'verified': True,
    'scan_type': scan_type,
    'minimum_severity': 'Low',
    'engagement': 3
}

files = {
    'file': open(file_name, 'rb')
}

response = requests.post(url, headers=headers, data=data, files=files)

if response.status_code == 201:
    print('Scan results imported successfully')
else:
    print(f'Failed to import scan results: {response.content}')
