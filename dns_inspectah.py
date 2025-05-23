#!/usr/bin/env python3

import dns.resolver
from dns import rdatatype
import dns.query
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

# Short descriptions explaining the security relevance of common DNS records
RECORD_DESCRIPTIONS = {
    'A': 'IPv4 addresses that reveal server locations',
    'AAAA': 'IPv6 addresses of hosts',
    'MX': 'Mail exchange servers used for email delivery',
    'NS': 'Authoritative name servers',
    'TXT': 'Miscellaneous text including SPF or verification tokens',
    'SOA': 'Start of authority information including admin email',
}

class Domain:
    """
    Represents a domain and includes methods to perform various checks.
    """
    def __init__(self, name, query_delay=QUERY_DELAY):
        self.name = name
        self.query_delay = query_delay
        self.metaquery_types = []

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
            msg = str(e)
            if 'metaqueries' in msg.lower():
                self.metaquery_types.append(record_type)
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

    def get_subdomain_records(self, subdomains):
        """Attempt to resolve a list of subdomains for this domain."""
        results = {}
        for sub in subdomains:
            fqdn = f"{sub}.{self.name}"
            try:
                time.sleep(self.query_delay)
                answers = dns.resolver.resolve(fqdn, 'A')
                results[fqdn] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                continue
            except Exception:
                continue
        return results

    def check_dnssec(self):
        """Return True if DNSSEC appears to be enabled for this domain."""
        try:
            time.sleep(self.query_delay)
            dns.resolver.resolve(self.name, 'DNSKEY')
            return True
        except Exception:
            return False

    def attempt_zone_transfer(self):
        """Attempt a DNS zone transfer from the domain's name servers."""
        try:
            nameservers = self.get_dns_records('NS')
            for ns in nameservers:
                host = ns.rstrip('.')
                try:
                    time.sleep(self.query_delay)
                    axfr = dns.query.xfr(host, self.name, timeout=5)
                    if any(axfr):
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    def get_email_records(self, selectors):
        """Retrieve SPF, DKIM, and DMARC records."""
        spf = []
        dmarc = []
        dkim = {}

        txt_records = self.get_dns_records('TXT')
        for rec in txt_records:
            cleaned = rec.strip('"')
            if cleaned.lower().startswith('v=spf1'):
                spf.append(cleaned)

        try:
            time.sleep(self.query_delay)
            answers = dns.resolver.resolve(f"_dmarc.{self.name}", 'TXT')
            dmarc = [str(rdata).strip('"') for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            pass
        except Exception as e:
            msg = str(e)
            if 'metaqueries' in msg.lower():
                self.metaquery_types.append('DMARC')
            else:
                print(f"Error retrieving DMARC record for {self.name}: {e}")

        for sel in selectors:
            try:
                time.sleep(self.query_delay)
                answers = dns.resolver.resolve(f"{sel}._domainkey.{self.name}", 'TXT')
                dkim[sel] = [str(rdata).strip('"') for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                continue
            except Exception as e:
                msg = str(e)
                if 'metaqueries' in msg.lower():
                    self.metaquery_types.append(f'DKIM {sel}')
                else:
                    print(f"Error retrieving DKIM selector {sel} for {self.name}: {e}")

        return spf, dkim, dmarc

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
                desc = RECORD_DESCRIPTIONS.get(record_type, "")
                header = f"{record_type} records"
                if desc:
                    header += f" ({desc})"
                print(header + ":")
                for record in records:
                    print(f"  - {record}")
                print()

        if self.domain.metaquery_types:
            types_list = ', '.join(sorted(set(self.domain.metaquery_types)))
            print("Metaqueries are special DNS operations (like zone transfers or key negotiation) that this resolver refused."
                  f" The following types could not be queried: {types_list}\n")

        # Email-related records
        print("[*] Email DNS checks...")
        selectors = self.config.get('dkim_selectors', [])
        spf, dkim, dmarc = self.domain.get_email_records(selectors)
        if spf:
            print("SPF:")
            for rec in spf:
                print(f"  - {rec}")
        if dkim:
            print("DKIM:")
            for sel, records in dkim.items():
                for rec in records:
                    print(f"  - {sel}: {rec}")
        if dmarc:
            print("DMARC:")
            for rec in dmarc:
                print(f"  - {rec}")
        print()

        # DNSSEC
        print("[*] DNSSEC check...")
        if self.domain.check_dnssec():
            print("    [+] DNSSEC appears to be enabled.\n")
        else:
            print("    [-] DNSSEC not detected.\n")

        # Zone transfer attempt
        print("[*] Attempting zone transfer...")
        if self.domain.attempt_zone_transfer():
            print("    [!] Zone transfer succeeded!\n")
        else:
            print("    [ ] Zone transfer refused.\n")

        # Subdomain enumeration
        if 'subdomains' in self.config:
            subs = self.config['subdomains']
        else:
            subs = []
        if subs:
            print("[*] Enumerating common subdomains...")
            sub_results = self.domain.get_subdomain_records(subs)
            for fqdn, addrs in sub_results.items():
                print(f"  {fqdn}: {', '.join(addrs)}")
            if not sub_results:
                print("  No listed subdomains were found.")
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
            issued_by = issuer.get('commonName', 'Unknown issuer')
            expires = cert.get('notAfter', 'unknown')
            print(f"[+] Valid SSL certificate for {self.domain}")
            print(f"    Issuer: {issued_by}")
            print(f"    Expires: {expires}\n")
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
        try:
            response = requests.get(f'http://{self.domain}', timeout=5)
            issues = []
            if 'X-Frame-Options' not in response.headers:
                issues.append('Missing X-Frame-Options header')
            if 'Content-Security-Policy' not in response.headers:
                issues.append('Missing Content-Security-Policy header')

            if issues:
                print(f"[!] Potential web security issues on {self.domain}:")
                for issue in issues:
                    print(f"    - {issue}")
                print()
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
        if value == '':
            return []

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

    start_time = time.time()

    # Initialize configuration manager
    config_manager = ConfigManager(args.config)

    # Retrieve configuration settings
    dns_record_types = config_manager.get_setting(
        'DNSRecords', 'types', fallback=ALL_RECORD_TYPES
    )
    subdomain_list = config_manager.get_setting('Subdomains', 'list', fallback='')
    dkim_selectors = config_manager.get_setting('Email', 'dkim_selectors', fallback='default')

    # Initialize Inspector with domain and configuration
    inspector = Inspector(args.domain, {
        'dns_record_types': dns_record_types,
        'subdomains': subdomain_list,
        'dkim_selectors': dkim_selectors,
    })

    # Perform the inspection
    inspector.inspect()

    # Initialize and use SSLValidator and VulnerabilityScanner if needed
    ssl_validator = SSLValidator(args.domain)
    ssl_validator.validate_certificate()

    vulnerability_scanner = VulnerabilityScanner(args.domain)
    vulnerability_scanner.scan_for_vulnerabilities()

    end_time = time.time()
    print(f"Execution time: {end_time - start_time:.2f}s")

def print_banner(text):
    banner = pyfiglet.figlet_format(text)
    print(banner)

if __name__ == '__main__':
    print_banner("DNS INSPECTAH")
    main()
