import argparse
import requests
import logging
from bs4 import BeautifulSoup
import sys
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyze Content Security Policy (CSP) headers for potential weaknesses.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.")
    parser.add_argument("-o", "--output", help="Output file to save the results.")

    return parser

def fetch_csp_header(url):
    """
    Fetches the Content Security Policy (CSP) header from a given URL.

    Args:
        url (str): The URL to fetch the CSP header from.

    Returns:
        str: The CSP header value, or None if not found.  Returns None if an error occurs.
    """
    try:
        response = requests.get(url, allow_redirects=True)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        csp_header = response.headers.get('Content-Security-Policy') or response.headers.get('content-security-policy')
        if csp_header:
            logging.debug(f"CSP Header found: {csp_header}")
            return csp_header
        else:
            logging.warning(f"No CSP header found for {url}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def analyze_csp(csp_header):
    """
    Analyzes a CSP header for potential weaknesses.

    Args:
        csp_header (str): The CSP header value.

    Returns:
        list: A list of findings (strings) indicating potential weaknesses.
    """
    findings = []

    if not csp_header:
        findings.append("No CSP header found.")
        return findings
    
    # Split the CSP header into directives
    directives = csp_header.split(';')

    # Check for 'unsafe-inline' and 'unsafe-eval'
    if "unsafe-inline" in csp_header.lower():
        findings.append("Warning: 'unsafe-inline' is used, which can allow inline script execution.")
    if "unsafe-eval" in csp_header.lower():
        findings.append("Warning: 'unsafe-eval' is used, which can allow execution of strings as code.")
    if "data:" in csp_header.lower():
        findings.append("Warning: 'data:' is used as a source, which is generally insecure and allows data injection attacks.")

    # Check for overly permissive wildcards
    for directive in directives:
        directive = directive.strip()
        if directive.startswith("script-src") or directive.startswith("default-src"):
            if "*" in directive:
                findings.append(f"Warning: Wildcard (*) is used in '{directive}', which can be overly permissive.")
            elif "'none'" not in directive and  not directive.endswith("'self'"):

                #check if the script src is from un trusted origin
                source_list = directive.split()
                for source in source_list:
                    source = source.strip()
                    if source.startswith("http://") and not source.startswith("http://localhost") and not source.startswith("http://127.0.0.1"):
                            findings.append(f"Warning:  '{source}' is used and script src is from un-trusted origin http")


        if directive.startswith("object-src"):
            if "*" in directive:
                findings.append(f"Warning: Wildcard (*) is used in '{directive}', which can be overly permissive.")

    #Check for base-uri usage.
    if "base-uri" in csp_header.lower():
       findings.append("Warning: base-uri is used which can be misconfigured.")

    #check for report-uri.
    if "report-uri" in csp_header.lower():
        findings.append("Info: report-uri is used, which can help in monitoring and enforcing CSP. Review endpoint security.")

    return findings


def main():
    """
    The main function of the vscan-csp-analyzer tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.url:
        print("Error: URL is required.")
        parser.print_help()
        sys.exit(1)

    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    logging.info(f"Analyzing CSP for URL: {args.url}")

    csp_header = fetch_csp_header(args.url)

    if csp_header:
        findings = analyze_csp(csp_header)

        if findings:
            print("CSP Analysis Findings:")
            for finding in findings:
                print(f"- {finding}")

            output_string = "\n".join(findings)

            if args.output:
                try:
                    with open(args.output, "w") as f:
                        f.write(output_string)
                    logging.info(f"Results saved to {args.output}")
                except IOError as e:
                    logging.error(f"Error writing to file {args.output}: {e}")

        else:
            print("No CSP weaknesses found.")
    else:
        print("Could not retrieve CSP header.")


if __name__ == "__main__":
    main()