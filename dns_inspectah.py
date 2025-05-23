#!/usr/bin/env python3

import dns.resolver
from dns import rdatatype
import dns.query
import dns.zone
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

class Domain:
    """Represents a domain and includes methods to perform various checks."""

    def __init__(self, name, query_delay=QUERY_DELAY):
        self.name = name
        self.query_delay = query_delay
        self.metaquery_denied = []

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
            msg = str(e).lower()
            if 'metaqueries' in msg:
                self.metaquery_denied.append(record_type)
                return []
            print(f"Error retrieving {record_type} records for {self.name}: {e}")
            return []

    def enumerate_subdomains(self, subdomain_list):
        """Return discovered subdomains from a provided candidate list."""
        found = []
        for sub in subdomain_list:
            fqdn = f"{sub}.{self.name}"
            try:
                time.sleep(self.query_delay)
                dns.resolver.resolve(fqdn, 'A')
                found.append(fqdn)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                continue
            except Exception:
                continue
        return found

    def check_dnssec(self):
        """Determine if DNSSEC records exist for the domain."""
        try:
            time.sleep(self.query_delay)
            dns.resolver.resolve(self.name, 'DNSKEY')
            return True
        except Exception:
            return False

    def attempt_zone_transfer(self):
        """Attempt a zone transfer from each authoritative nameserver."""
        try:
            ns_records = [r.to_text() for r in dns.resolver.resolve(self.name, 'NS')]
        except Exception:
            return False
        for ns in ns_records:
            try:
                time.sleep(self.query_delay)
                dns.query.xfr(ns, self.name, timeout=2)
                return True
            except Exception:
                continue
        return False

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

        print("[*] Gathering DNS records...\n")
        for record_type in self.config['dns_record_types']:
            records = self.domain.get_dns_records(record_type)
            if records:
                print(f"{record_type} records:")
                for record in records:
                    print(f"  - {record}")
                print()

        if self.domain.metaquery_denied:
            types = ', '.join(self.domain.metaquery_denied)
            print("[*] Note: DNS metaqueries (special requests like zone transfers) were not allowed for: " + types + "\n")

        # Email-specific DNS checks
        if 'MX' in self.config['dns_record_types'] or 'TXT' in self.config['dns_record_types']:
            print("[*] Email DNS records")
            mx = self.domain.get_dns_records('MX')
            if mx:
                print("  MX records:")
                for r in mx:
                    print(f"    - {r}")
            spf_records = [t for t in self.domain.get_dns_records('TXT') if 'v=spf1' in t.lower()]
            if spf_records:
                print("  SPF:")
                for r in spf_records:
                    print(f"    - {r}")
            dmarc = self.domain.get_dns_records('_dmarc.' + self.domain.name)
            if dmarc:
                print("  DMARC:")
                for r in dmarc:
                    print(f"    - {r}")
            print()

        # DNSSEC
        print("[*] DNSSEC:")
        if self.domain.check_dnssec():
            print("    [!] DNSSEC records found.\n")
        else:
            print("    [ ] DNSSEC not configured.\n")

        # Zone transfer attempt
        print("[*] Attempting zone transfer:")
        if self.domain.attempt_zone_transfer():
            print("    [!] Zone transfer successful!\n")
        else:
            print("    [ ] Zone transfer not permitted.\n")

        # Subdomain enumeration
        if 'subdomains' in self.config:
            found = self.domain.enumerate_subdomains(self.config['subdomains'])
            if found:
                print("[*] Discovered subdomains:")
                for sub in found:
                    print(f"  - {sub}")
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
                    cert = ssock.getpeercert()
            issuer = dict(x[0] for x in cert.get('issuer', []))
            not_before = cert.get('notBefore')
            not_after = cert.get('notAfter')
            print(f"[+] Valid SSL certificate for {self.domain}")
            if issuer:
                print(f"    Issuer: {issuer.get('organizationName', 'Unknown')}")
            if not_before and not_after:
                print(f"    Valid from {not_before} to {not_after}\n")
            else:
                print()
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
        Perform a simple HTTP request and look for signs of common misconfigurations.
        """
        try:
            response = requests.get(f'http://{self.domain}', timeout=3)
            if (any(keyword in response.text.lower() for keyword in ['index of /', 'directory listing'])
                    or 'server version' in response.headers.get('Server', '').lower()):
                print(f"[!] Potential misconfiguration detected on {self.domain}\n")
            else:
                print(f"[+] No obvious vulnerabilities (basic checks) found on {self.domain}\n")
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
    subdomain_list = config_manager.get_setting('Subdomains', 'list', fallback='')

    config = {
        'dns_record_types': dns_record_types,
    }
    if subdomain_list:
        config['subdomains'] = subdomain_list

    # Initialize Inspector with domain and configuration
    inspector = Inspector(args.domain, config)

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