#!/usr/bin/env python3

import dns.resolver
import dns.query
import dns.zone
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

class Domain:
    """
    Represents a domain and includes methods to perform various checks.
    """
    def __init__(self, name, query_delay=QUERY_DELAY):
        self.name = name
        self.query_delay = query_delay
        self.metaquery_denied = []  # track record types that disallow metaqueries

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
            if 'DNS metaqueries are not allowed' in str(e):
                self.metaquery_denied.append(record_type)
                return []
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

    def has_dnssec(self):
        """Check if DNSSEC is enabled for the domain."""
        try:
            time.sleep(self.query_delay)
            dns.resolver.resolve(self.name, 'DNSKEY')
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            return False
        except Exception:
            return False

    def attempt_zone_transfer(self):
        """Attempt a zone transfer from each authoritative nameserver."""
        transferred_from = []
        try:
            ns_records = dns.resolver.resolve(self.name, 'NS')
            for ns in ns_records:
                ns_name = str(ns)
                try:
                    time.sleep(self.query_delay)
                    xfr = dns.query.xfr(ns_name, self.name, lifetime=5)
                    if dns.zone.from_xfr(xfr):
                        transferred_from.append(ns_name)
                except Exception:
                    continue
        except Exception:
            pass
        return transferred_from

    def enumerate_subdomains(self, subdomains):
        """Enumerate subdomains based on a provided list."""
        found = []
        for sub in subdomains:
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

    def get_email_dns(self, dkim_selectors=None):
        """Retrieve SPF, DMARC and DKIM records."""
        email_records = {"SPF": [], "DMARC": [], "DKIM": {}}
        try:
            time.sleep(self.query_delay)
            txt_records = dns.resolver.resolve(self.name, 'TXT')
            for rdata in txt_records:
                text = rdata.to_text().strip('"')
                if text.lower().startswith('v=spf1'):
                    email_records['SPF'].append(text)
        except Exception:
            pass

        try:
            time.sleep(self.query_delay)
            dmarc_answers = dns.resolver.resolve(f'_dmarc.{self.name}', 'TXT')
            for rdata in dmarc_answers:
                email_records['DMARC'].append(rdata.to_text().strip('"'))
        except Exception:
            pass

        if dkim_selectors:
            for selector in dkim_selectors:
                domain_part = f"{selector}._domainkey.{self.name}"
                try:
                    time.sleep(self.query_delay)
                    answers = dns.resolver.resolve(domain_part, 'TXT')
                    for rdata in answers:
                        text = rdata.to_text().strip('"')
                        if 'v=DKIM1' in text:
                            email_records['DKIM'][selector] = text
                except Exception:
                    continue
        return email_records

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
        self.subdomains = config.get('subdomains', [])
        self.dkim_selectors = config.get('dkim_selectors', [])

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
            denied = ', '.join(sorted(set(self.domain.metaquery_denied)))
            print(
                "[!] Metaqueries (special DNS metadata requests) were denied for: "
                f"{denied}\n"
            )

        print("[*] Checking DNSSEC status...")
        if self.domain.has_dnssec():
            print("    [!] DNSSEC enabled.\n")
        else:
            print("    [ ] DNSSEC not enabled.\n")

        print("[*] Attempting zone transfer...")
        zones = self.domain.attempt_zone_transfer()
        if zones:
            print("    [!] Zone transfer succeeded from: " + ", ".join(zones) + "\n")
        else:
            print("    [ ] Zone transfer not permitted.\n")

        if self.subdomains:
            print("[*] Enumerating subdomains...")
            found = self.domain.enumerate_subdomains(self.subdomains)
            if found:
                for sub in found:
                    print(f"  - {sub}")
            else:
                print("    [ ] No subdomains discovered.")
            print()

        print("[*] Gathering email-related DNS records...")
        email_records = self.domain.get_email_dns(self.dkim_selectors)
        if any([email_records['SPF'], email_records['DMARC'], email_records['DKIM']]):
            if email_records['SPF']:
                print("  SPF:")
                for spf in email_records['SPF']:
                    print(f"    - {spf}")
            if email_records['DMARC']:
                print("  DMARC:")
                for dm in email_records['DMARC']:
                    print(f"    - {dm}")
            if email_records['DKIM']:
                print("  DKIM:")
                for sel, val in email_records['DKIM'].items():
                    print(f"    {sel}: {val}")
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
            issuer = dict(x[0] for x in cert.get('issuer', ()))
            not_before = cert.get('notBefore')
            not_after = cert.get('notAfter')
            print(f"[+] Valid SSL certificate for {self.domain}")
            if issuer:
                print(f"    Issuer: {issuer.get('commonName', 'Unknown')}")
            if not_before and not_after:
                print(f"    Valid: {not_before} to {not_after}\n")
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
        """Perform very basic vulnerability checks for demonstration."""
        try:
            response = requests.get(f'http://{self.domain}', timeout=5)
            if 'vulnerable keyword' in response.text:
                print(f"[!] Potential vulnerability found in {self.domain}\n")
            else:
                print(
                    f"[+] No common web vulnerabilities detected in {self.domain}\n"
                )
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
    dkim_selectors = config_manager.get_setting('Email', 'dkim_selectors', fallback=[])

    # Initialize Inspector with domain and configuration
    inspector = Inspector(
        args.domain,
        {
            'dns_record_types': dns_record_types,
            'subdomains': subdomain_list,
            'dkim_selectors': dkim_selectors,
        },
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
