#!/usr/bin/env python3

import dns.resolver
import ssl
import socket
import requests
import configparser
import sys
import argparse
import pyfiglet

class Domain:
    """
    Represents a domain and includes methods to perform various checks.
    """
    def __init__(self, name):
        self.name = name

    def get_dns_records(self, record_type):
        """
        Retrieve DNS records of a specified type for the domain.
        Args:
            record_type (str): The type of DNS record to retrieve.
        Returns:
            list: A list of DNS records.
        """
        try:
            return [str(rdata) for rdata in dns.resolver.resolve(self.name, record_type)]
        except Exception as e:
            print(f"Error retrieving {record_type} records for {self.name}: {e}")
            return []

    def check_wildcard_records(self):
        """
        Check for wildcard DNS records for the domain.
        Returns:
            bool: True if wildcard records are found, False otherwise.
        """
        try:
            answers = dns.resolver.resolve('*.' + self.name, 'A')
            return bool(answers)
        except Exception as e:
            print(f"Error checking wildcard records for {self.name}: {e}")
            return False

class DNSRecord:
    """
    Represents a DNS record, handling different types of records.
    """
    def __init__(self, record_type, value):
        self.record_type = record_type
        self.value = value

    def __str__(self):
        return f"{self.record_type} record: {self.value}"

    # Add more methods here for specific processing of different DNS record types if needed

class Inspector:
    """
    Coordinates the inspection process for a given domain.
    """
    def __init__(self, domain, config):
        self.domain = Domain(domain)
        self.config = config  # Configuration settings

    def inspect(self):
        """
        Perform the inspection process for the domain.
        """
        print(f"Starting inspection for domain: {self.domain.name}")

        # Check for wildcard DNS records
        if self.domain.check_wildcard_records():
            print("Wildcard DNS records found.")
        else:
            print("No wildcard DNS records found.")

        # Iterate through desired DNS record types from config and check each
        for record_type in self.config['dns_record_types']:
            records = self.domain.get_dns_records(record_type)
            for record in records:
                dns_record = DNSRecord(record_type, record)
                print(dns_record)

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
                    cert = ssock.getpeercert()
            # Additional certificate validation logic goes here
            return True
        except Exception as e:
            print(f"Error validating SSL certificate for {self.domain}: {e}")
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
            response = requests.get(f'http://{self.domain}')
            if 'vulnerable keyword' in response.text:
                print(f"Potential vulnerability found in {self.domain}")
            else:
                print(f"No obvious vulnerabilities found in {self.domain}")
        except Exception as e:
            print(f"Error scanning {self.domain} for vulnerabilities: {e}")
            
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
        if isinstance(value, str) and ',' in value:
            return [v.strip() for v in value.split(',')]
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
        'DNSRecords', 'types', fallback=['A', 'MX', 'TXT']
    )

    # Initialize Inspector with domain and configuration
    inspector = Inspector(args.domain, {'dns_record_types': dns_record_types})

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