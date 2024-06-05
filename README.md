  Snyk Vulnerability Report Script

Snyk Vulnerability Report Script
================================

This script generates a detailed HTML report on vulnerabilities from Snyk, including statistics on open, new, and closed vulnerabilities, as well as the Mean Time to Resolve (MTTR) for each severity level across the entire period. The script handles multiple organizations as specified in a configuration file.

Table of Contents
-----------------

*   [Dependencies](#dependencies)
*   [Configuration File](#configuration-file)
*   [Usage](#usage)
*   [Explanation](#explanation)
    *   [Vulnerability Statistics](#vulnerability-statistics)
    *   [Mean Time to Resolve (MTTR)](#mean-time-to-resolve-mttr)
*   [License](#license)

Dependencies
------------

This script requires the following Python libraries:

*   requests
*   dateutil
*   tqdm

You can install these dependencies using pip:

    pip install requests python-dateutil tqdm

Configuration File
------------------

The script uses a configuration file named `dsnyk.conf` with the following format:

    AUTH_TOKEN=your_snyk_auth_token
    ORGS=org_id_1, org_id_2, org_id_3, ...
    

*   `AUTH_TOKEN`: Your Snyk API authentication token.
*   `ORGS`: A comma-separated list of organization IDs for which you want to generate the report.

Usage
-----

1.  Ensure you have your configuration file (`dsnyk.conf`) correctly set up.
2.  Run the script:

    python snyk_report.py

The script will generate an HTML report named `snyk_report.html` in the current directory.

Explanation
-----------

### Vulnerability Statistics

The script fetches vulnerability data from Snyk for each specified organization and processes the data to generate statistics on the number of open, new, and closed vulnerabilities per month for each severity level (critical, high, medium, low).

### Mean Time to Resolve (MTTR)

The Mean Time to Resolve (MTTR) is calculated for each severity level across the entire period. The MTTR represents the average number of days taken to resolve vulnerabilities.

#### How MTTR is Calculated

1.  **Collect Time Intervals**: For each resolved vulnerability, the script calculates the time interval (in days) between the `created_at` and `resolved_at` timestamps.
2.  **Aggregate Time Intervals**: These intervals are aggregated in a list for each severity level.
3.  **Compute Average**: The MTTR is computed as the average of the aggregated intervals for each severity level. The formula used is:
    
    > MTTR = Total Time to Resolve All Vulnerabilities / Number of Resolved Vulnerabilities
    

The script outputs the overall MTTR for each severity level in the HTML report.

License
-------

This script is licensed under the GNU General Public License v3.0.

> Snyk Vulnerability Report Script  
> (c) 2024 Russ Spooner