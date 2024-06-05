import requests
import json
from datetime import datetime
from collections import defaultdict


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
SNYK_API_TOKEN = config.get("AUTH_TOKEN")
ORG_IDS = config.get("ORGS").split(',')

# Snyk API base URL
SNYK_API_URL = "https://snyk.io/api/v1"

# Set up headers for authentication
headers = {
    "Authorization": f"token {SNYK_API_TOKEN}",
    "Content-Type": "application/json"
}


def get_org_name(org_id):
    """Fetches the organization name for a given organization ID."""
    url = f"{SNYK_API_URL}/org/{org_id}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()["name"]
    else:
        print(f"Error fetching organization name for org {org_id}:", response.status_code, response.text)
        return None


def get_projects(org_id):
    """Fetches the list of projects for a given organization."""
    url = f"{SNYK_API_URL}/org/{org_id}/projects"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()["projects"]
    else:
        print(f"Error fetching projects for org {org_id}:", response.status_code, response.text)
        return None


def get_vulnerabilities(org_id, project_id):
    """Fetches the list of vulnerabilities for a given project."""
    url = f"{SNYK_API_URL}/org/{org_id}/project/{project_id}/issues"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()["issues"]
    else:
        print(f"Error fetching vulnerabilities for project {project_id}:", response.status_code, response.text)
        return None


def process_vulnerabilities(vulnerabilities):
    """Processes the list of vulnerabilities to extract statistics."""
    current_month = datetime.now().month
    stats = {
        "open": defaultdict(lambda: defaultdict(int)),
        "new": defaultdict(lambda: defaultdict(int)),
        "closed": defaultdict(lambda: defaultdict(int)),
        "mttr": defaultdict(lambda: defaultdict(list)),
    }

    for vuln in vulnerabilities:
        created = datetime.strptime(vuln["created"], "%Y-%m-%dT%H:%M:%S.%fZ")
        severity = vuln["issueData"]["severity"]
        if vuln.get("fixedIn"):
            closed = datetime.strptime(vuln["fixedIn"], "%Y-%m-%dT%H:%M:%S.%fZ")
            month_closed = closed.month
            stats["closed"][month_closed][severity] += 1
            stats["mttr"][month_closed][severity].append((closed - created).days)
        else:
            month_open = created.month
            stats["open"][month_open][severity] += 1

    for month in range(1, current_month + 1):
        for severity in ["critical", "high", "medium", "low"]:
            if stats["mttr"][month][severity]:
                stats["mttr"][month][severity] = sum(stats["mttr"][month][severity]) / len(
                    stats["mttr"][month][severity])
            else:
                stats["mttr"][month][severity] = 0

    return stats


def generate_html_table(org_name, stats):
    """Generates an HTML table for the given statistics."""
    table_html = f"<h2>Statistics for {org_name}</h2>"
    table_html += "<table border='1'><tr><th>Month</th><th>Severity</th><th>Open</th><th>New</th><th>Closed</th><th>MTTR</th></tr>"
    current_month = datetime.now().month
    severity_colors = {
        "critical": "#ff4d4d",
        "high": "#ff751a",
        "medium": "#ffff99",
        "low": "#99ff99"
    }

    for month in range(1, current_month + 1):
        for severity in ["critical", "high", "medium", "low"]:
            table_html += f"<tr><td>{datetime(2024, month, 1).strftime('%B')}</td>"
            table_html += f"<td style='background-color:{severity_colors[severity]}'>{severity.capitalize()}</td>"
            table_html += f"<td>{stats['open'][month][severity]}</td>"
            table_html += f"<td>{stats['new'][month][severity]}</td>"
            table_html += f"<td>{stats['closed'][month][severity]}</td>"
            table_html += f"<td>{stats['mttr'][month][severity]:.2f} days</td></tr>"

    table_html += "</table>"
    return table_html


def main():
    html_report = "<html><head><title>Snyk Vulnerability Report</title></head><body>"

    for org_id in ORG_IDS:
        org_name = get_org_name(org_id)
        if not org_name:
            continue
        print(f"Fetching data for organization: {org_name}")

        projects = get_projects(org_id)
        if not projects:
            continue

        all_vulnerabilities = []
        for project in projects:
            vulnerabilities = get_vulnerabilities(org_id, project["id"])
            if not vulnerabilities:
                continue
            all_vulnerabilities.extend(vulnerabilities)

        stats = process_vulnerabilities(all_vulnerabilities)
        html_report += generate_html_table(org_name, stats)

    html_report += "</body></html>"

    with open("snyk_report.html", "w") as file:
        file.write(html_report)
    print("Report generated: snyk_report.html")


if __name__ == "__main__":
    main()

