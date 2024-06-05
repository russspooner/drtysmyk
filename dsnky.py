import requests
import json
from datetime import datetime
from collections import defaultdict
from urllib.parse import urljoin
from dateutil.parser import parse
from tqdm import tqdm


# Function to read configuration file
def read_config(file_path):
    config = {}
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            key, value = line.strip().split('=')
            config[key] = value
    return config


# Read configuration
config = read_config('dsnyk.conf')
SNYK_API_TOKEN = config.get("AUTH_TOKEN").strip()
ORG_IDS = [org_id.strip() for org_id in config.get("ORGS").split(',')]

# Snyk API base URL
SNYK_API_URL = "https://api.snyk.io/rest"

# API version
API_VERSION = "2024-05-23"

# Set up headers for authentication
headers = {
    "Authorization": f"token {SNYK_API_TOKEN}",
    "Content-Type": "application/json"
}


def get_org_name(org_id):
    """Fetches the organization name for a given organization ID."""
    url = f"{SNYK_API_URL}/orgs/{org_id}?version={API_VERSION}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()["data"]["attributes"]["name"]
    else:
        print(f"Error fetching organization name for org {org_id}: {response.status_code} {response.text}")
        return None


def get_vulnerabilities(org_id):
    """Fetches the list of vulnerabilities for a given organization, handling pagination."""
    vulnerabilities = []
    url = f"{SNYK_API_URL}/orgs/{org_id}/issues?version={API_VERSION}&limit=100"

    while url:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities.extend(data.get("data", []))
            next_url = data["links"].get("next", None)  # Get the next page URL if it exists
            if next_url:
                url = urljoin(SNYK_API_URL, next_url)  # Combine base URL with relative URL
            else:
                url = None
        else:
            print(f"Error fetching vulnerabilities for organization {org_id}: {response.status_code} {response.text}")
            return None

    return vulnerabilities


def process_vulnerabilities(vulnerabilities):
    """Processes the list of vulnerabilities to extract statistics."""
    current_month = datetime.now().month
    stats = {
        "open": defaultdict(lambda: defaultdict(int)),
        "new": defaultdict(lambda: defaultdict(int)),
        "closed": defaultdict(lambda: defaultdict(int)),
        "mttr": defaultdict(list),  # Changed to a single list per severity
    }

    for vuln in vulnerabilities:
        try:
            created_at = vuln["attributes"].get("created_at")
            if created_at:
                created_at = parse(created_at)
            else:
                continue

            effective_severity_level = vuln["attributes"]["effective_severity_level"]
            status = vuln["attributes"].get("status")
            resolution = vuln["attributes"].get("resolution")

            if status == "resolved" and resolution and "resolved_at" in resolution:
                resolved_at = parse(resolution["resolved_at"])
                month_closed = resolved_at.month
                stats["closed"][month_closed][effective_severity_level] += 1
                stats["mttr"][effective_severity_level].append((resolved_at - created_at).days)
            else:
                month_open = created_at.month
                stats["open"][month_open][effective_severity_level] += 1
        except KeyError as e:
            continue

    # Calculate overall MTTR for each severity
    overall_mttr = {}
    for severity in ["critical", "high", "medium", "low"]:
        if stats["mttr"][severity]:
            overall_mttr[severity] = sum(stats["mttr"][severity]) / len(stats["mttr"][severity])
        else:
            overall_mttr[severity] = 0

    return stats, overall_mttr


def generate_html_table(org_name, stats, overall_mttr):
    """Generates an HTML table for the given statistics."""
    table_html = f"<h2>Statistics for {org_name}</h2>"
    table_html += "<table border='1'>"
    table_html += "<tr><th>Severity</th><th>Overall MTTR (days)</th></tr>"
    severity_colors = {
        "critical": "#ff4d4d",
        "high": "#ff751a",
        "medium": "#ffff99",
        "low": "#99ff99"
    }
    for severity in ["critical", "high", "medium", "low"]:
        table_html += f"<tr><td style='background-color:{severity_colors[severity]}'>{severity.capitalize()}</td>"
        table_html += f"<td>{overall_mttr[severity]:.2f}</td></tr>"
    table_html += "</table><br>"

    table_html += "<table border='1'><tr><th>Month</th><th>Severity</th><th>Open</th><th>New</th><th>Closed</th></tr>"
    current_month = datetime.now().month

    for month in range(1, current_month + 1):
        for severity in ["critical", "high", "medium", "low"]:
            table_html += f"<tr><td>{datetime(2024, month, 1).strftime('%B')}</td>"
            table_html += f"<td style='background-color:{severity_colors[severity]}'>{severity.capitalize()}</td>"
            table_html += f"<td>{stats['open'][month][severity]}</td>"
            table_html += f"<td>{stats['new'][month][severity]}</td>"
            table_html += f"<td>{stats['closed'][month][severity]}</td></tr>"

    table_html += "</table>"
    return table_html


def main():
    html_report = "<html><head><title>Snyk Vulnerability Report</title></head><body>"

    for org_id in tqdm(ORG_IDS, desc="Processing organizations"):
        org_name = get_org_name(org_id)
        if not org_name:
            continue

        vulnerabilities = get_vulnerabilities(org_id)
        if not vulnerabilities:
            continue

        stats, overall_mttr = process_vulnerabilities(vulnerabilities)
        html_report += generate_html_table(org_name, stats, overall_mttr)

    html_report += "</body></html>"

    with open("snyk_report.html", "w") as file:
        file.write(html_report)
    print("Report generated: snyk_report.html")


if __name__ == "__main__":
    main()
