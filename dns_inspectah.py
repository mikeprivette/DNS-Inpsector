#!/usr/bin/env python3

import dns.resolver
from dns import rdatatype
import ssl
import socket
import requests
import configparser
import argparse
import pyfiglet
import time

ALL_RECORD_TYPES = [rdatatype.to_text(t) for t in rdatatype.RdataType]

# Delay between DNS queries to mimic human-like behavior
QUERY_DELAY = 0.5

# Timeout for HTTP requests made by the vulnerability scanner
REQUEST_TIMEOUT = 5  # seconds

class Domain:
    """
    Represents a domain and includes methods to perform various checks.
    """
    def __init__(self, name, query_delay=QUERY_DELAY):
        self.name = name
        self.query_delay = query_delay

    def get_dns_records(self, record_type):
        """
        Retrieve DNS records of a specified type for the domain.
        Args:
            record_type (str): The type of DNS record to retrieve.
        Returns:
            list: A list of DNS records.
        """
        try:
            time.sleep(self.query_delay)
            answers = dns.resolver.resolve(self.name, record_type)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            return []
        except Exception as e:
            print(f"Error retrieving {record_type} records for {self.name}: {e}")
            return []

    def check_wildcard_records(self, record_types):
        """
        Check for wildcard DNS records for the domain across the provided
        record types.

        Args:
            record_types (list): DNS record types to query for wildcard entries.

        Returns:
            bool: True if any wildcard records are found, False otherwise.
        """
        try:
            for rtype in record_types:
                try:
                    time.sleep(self.query_delay)
                    answers = dns.resolver.resolve('*.' + self.name, rtype)
                    if answers:
                        return True
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                    continue
            return False
        except Exception as e:
            print(f"Error checking wildcard records for {self.name}: {e}")
            return False

    def query_subdomains(self, subdomains, record_type='A'):
        """Query DNS records for a list of subdomains.

        Args:
            subdomains (list): Subdomain prefixes to query.
            record_type (str): DNS record type to retrieve. Defaults to ``'A'``.

        Returns:
            dict: Mapping of fully qualified domain names to lists of records.
        """
        results = {}
        for sub in subdomains:
            fqdn = f"{sub}.{self.name}"
            host_domain = Domain(fqdn, query_delay=self.query_delay)
            records = host_domain.get_dns_records(record_type)
            if records:
                results[fqdn] = records
        return results

class Inspector:
    """
    Coordinates the inspection process for a given domain.
    """
    def __init__(self, domain, config):
        self.domain = Domain(domain, query_delay=QUERY_DELAY)
        self.config = config  # Configuration settings

    def inspect(self):
        """
        Perform the inspection process for the domain.
        """
        print(f"\n[*] Inspecting domain: {self.domain.name}\n")

        # Check for wildcard DNS records across all configured types
        print("[*] Checking for wildcard DNS records...")
        if self.domain.check_wildcard_records(self.config['dns_record_types']):
            print("    [!] Wildcard DNS records found.\n")
        else:
            print("    [ ] No wildcard DNS records found.\n")

        if self.config.get('subdomains'):
            print("[*] Checking common subdomains...")
            hosts = self.domain.query_subdomains(self.config['subdomains'])
            if hosts:
                for host, recs in hosts.items():
                    print(f"  {host}: {', '.join(recs)}")
                print()
            else:
                print("    [ ] No hosts found in subdomain list.\n")

        print("[*] Gathering DNS records...\n")
        for record_type in self.config['dns_record_types']:
            records = self.domain.get_dns_records(record_type)
            if records:
                print(f"{record_type} records:")
                for record in records:
                    print(f"  - {record}")
                print()

class SSLValidator:
    """
    Handles the validation of SSL/TLS certificates for a domain.
    """
    def __init__(self, domain):
        self.domain = domain

    def validate_certificate(self):
        """
        Validates the SSL/TLS certificate of the domain.
        Returns:
            bool: True if the certificate is valid, False otherwise.
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    ssock.getpeercert()
            print(f"[+] Valid SSL certificate for {self.domain}\n")
            return True
        except Exception as e:
            print(f"[-] Error validating SSL certificate for {self.domain}: {e}\n")
            return False

class VulnerabilityScanner:
    """
    Scans for common web vulnerabilities in the domain's web services.
    """
    def __init__(self, domain):
        self.domain = domain

    def scan_for_vulnerabilities(self):
        """
        Scans the domain for common web vulnerabilities.
        """
        # Example: Basic check for a sample vulnerability (to be expanded)
        try:
            response = requests.get(f'http://{self.domain}', timeout=REQUEST_TIMEOUT)
            if 'vulnerable keyword' in response.text:
                print(f"[!] Potential vulnerability found in {self.domain}\n")
            else:
                print(f"[+] No obvious vulnerabilities found in {self.domain}\n")
        except Exception as e:
            print(f"[-] Error scanning {self.domain} for vulnerabilities: {e}\n")
            
class ConfigManager:
    """
    Manages the application's configuration settings.
    """
    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

    def get_setting(self, section, setting, fallback=None):
        """
        Retrieves a specific setting from the configuration.

        Args:
            section (str): The section in the configuration file.
            setting (str): The setting key to retrieve.
            fallback: The default value to return if the setting is not found.

        Returns:
            The value of the setting, or the fallback value if not found. If the
            retrieved value is a comma separated string it will be returned as a
            list of stripped items.
        """
        value = self.config.get(section, setting, fallback=fallback)

        if setting == 'types' and (value is None or value == '' or value == fallback):
            return ALL_RECORD_TYPES

        if isinstance(value, str):
            if ',' in value:
                return [v.strip() for v in value.split(',')]
            if value.upper() == 'ALL':
                return ALL_RECORD_TYPES
        return value

def main():
    parser = argparse.ArgumentParser(description='DNS Inspection Tool')
    parser.add_argument('domain', help='The domain to inspect')
    parser.add_argument('--config', help='Path to configuration file', default='config.ini')
    args = parser.parse_args()

    # Initialize configuration manager
    config_manager = ConfigManager(args.config)

    # Retrieve configuration settings
    dns_record_types = config_manager.get_setting(
        'DNSRecords', 'types', fallback=ALL_RECORD_TYPES
    )
    subdomain_list = config_manager.get_setting('Subdomains', 'list', fallback=[])

    # Initialize Inspector with domain and configuration
    inspector = Inspector(
        args.domain,
        {'dns_record_types': dns_record_types, 'subdomains': subdomain_list},
    )

    # Perform the inspection
    inspector.inspect()

    # Initialize and use SSLValidator and VulnerabilityScanner if needed
    ssl_validator = SSLValidator(args.domain)
    ssl_validator.validate_certificate()

    vulnerability_scanner = VulnerabilityScanner(args.domain)
    vulnerability_scanner.scan_for_vulnerabilities()

def print_banner(text):
    banner = pyfiglet.figlet_format(text)
    print(banner)

if __name__ == '__main__':
    print_banner("DNS INSPECTAH")
    main()

