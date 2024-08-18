import os
import requests
import uuid
import logging
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Configuration
DOJO_URL = 'http://20.42.57.168:8080/api/v2'  # Replace with your DefectDojo URL
API_KEY = '6fc6300d17a08a9040f5b429bf74292e2cd1a288'  # Replace with your API key
ENGAGEMENT_ID = 2  # Replace with your engagement ID

HEADERS = {
    'Authorization': f'Token {API_KEY}',
    'Accept': 'application/json'
}

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_unique_scan_id():
    """
    Generates a unique scan ID to avoid duplicate findings.
    """
    return str(uuid.uuid4())

def setup_retries(session):
    """
    Configures retries for the requests session.
    """
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

def find_existing_scan_id(session, scan_type):
    """
    Finds an existing scan ID for the given scan type and engagement ID.
    """
    url = f"{DOJO_URL}/engagements/{ENGAGEMENT_ID}/scans/"
    response = session.get(url, headers=HEADERS)
    if response.status_code == 200:
        scans = response.json().get('results', [])
        for scan in scans:
            if scan['scan_type']['name'] == scan_type:
                return scan['id']
    else:
        logger.error(f"Failed to fetch existing scans: {response.status_code}, {response.text}")
    return None

def delete_scan(session, scan_id):
    """
    Deletes a scan by ID.
    """
    url = f"{DOJO_URL}/scans/{scan_id}/"
    response = session.delete(url, headers=HEADERS)
    if response.status_code == 204:
        logger.info(f"Successfully deleted scan ID {scan_id}.")
    else:
        logger.error(f"Failed to delete scan ID {scan_id}: {response.status_code}, {response.text}")

def upload_report(file_path, scan_type):
    """
    Uploads the given report to DefectDojo.

    :param file_path: Path to the report file.
    :param scan_type: Type of the scan (e.g., Gitleaks, Nodejsscan, Semgrep).
    """
    if not os.path.isfile(file_path):
        logger.error(f"Report file {file_path} does not exist.")
        return

    try:
        session = requests.Session()
        setup_retries(session)
        
        existing_scan_id = find_existing_scan_id(session, scan_type)
        if existing_scan_id:
            logger.info(f"Found existing scan with ID {existing_scan_id}. Deleting it.")
            delete_scan(session, existing_scan_id)

        with open(file_path, 'rb') as file:
            files = {'file': file}
            data = {
                'engagement': ENGAGEMENT_ID,
                'scan_type': scan_type,
                'active': True,
                'verified': False,
                'scan_id': generate_unique_scan_id()  # Add a unique scan ID
            }

            response = session.post(
                f"{DOJO_URL}/import-scan/",
                headers=HEADERS,
                files=files,
                data=data
            )

            if response.status_code == 201:
                logger.info(f"Successfully uploaded {file_path} as {scan_type}.")
            else:
                logger.error(f"Failed to upload {file_path}: {response.status_code}, {response.text}")
    
    except requests.RequestException as e:
        logger.error(f"An error occurred: {e}")

if __name__ == "__main__":
    # Map the report file to its scan type in DefectDojo
    reports = {
        "gitleaks.json": "Gitleaks Scan",
        "nodejsscan.sarif": "Node.js Scan",
        "semgrep.json": "Semgrep JSON Report",
        "retirejsscan.json": "Retire.js Scan"
    }

    for report_file, scan_type in reports.items():
        upload_report(report_file, scan_type)
