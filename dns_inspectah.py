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
import datetime
from pathlib import Path

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
            tuple: (records, meta_error)
                records (list): A list of DNS records (empty if none).
                meta_error (bool): True if a DNS metaquery error occurred.
        """
        try:
            time.sleep(self.query_delay)
            answers = dns.resolver.resolve(self.name, record_type)
            return [str(rdata) for rdata in answers], False
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            return [], False
        except Exception as e:
            if "DNS metaqueries" in str(e):
                return [], True
            print(f"Error retrieving {record_type} records for {self.name}: {e}")
            return [], False

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
                    answers = dns.resolver.resolve("*." + self.name, rtype)
                    if answers:
                        return True
                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers,
                    dns.resolver.LifetimeTimeout,
                ):
                    continue
            return False
        except Exception as e:
            print(f"Error checking wildcard records for {self.name}: {e}")
            return False

    def enumerate_subdomains(self, subdomains):
        """
        Attempt to resolve a list of subdomains for the domain.

        Args:
            subdomains (list): Subdomain prefixes to check.

        Returns:
            list: Fully qualified subdomains that resolve successfully.
        """
        discovered = []
        for sub in subdomains:
            fqdn = f"{sub}.{self.name}"
            try:
                time.sleep(self.query_delay)
                dns.resolver.resolve(fqdn, "A")
                discovered.append(fqdn)
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.resolver.LifetimeTimeout,
            ):
                continue
        return discovered

    def get_txt_record(self, name):
        """Retrieve TXT records for an arbitrary name."""
        try:
            time.sleep(self.query_delay)
            answers = dns.resolver.resolve(name, "TXT")
            records = []
            for rdata in answers:
                # Join multi-part TXT strings and remove surrounding quotes
                if hasattr(rdata, "strings"):
                    joined = "".join(
                        part.decode("utf-8") if isinstance(part, bytes) else str(part)
                        for part in rdata.strings
                    )
                else:
                    joined = str(rdata)
                records.append(joined.strip('"'))
            return records, False
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            return [], False
        except Exception as e:
            if "DNS metaqueries" in str(e):
                return [], True
            print(f"Error retrieving TXT record for {name}: {e}")
            return [], False

    def check_dmarc(self):
        """Check DMARC policy and return details."""
        domain = f"_dmarc.{self.name}"
        records, _ = self.get_txt_record(domain)
        result = {
            "records": records,
            "present": False,
            "policy": None,
            "rua": None,
            "ruf": None,
        }
        for rec in records:
            if "v=DMARC1" in rec:
                result["present"] = True
                tags = dict(
                    part.strip().split("=", 1) for part in rec.split(";") if "=" in part
                )
                result["policy"] = tags.get("p")
                result["rua"] = tags.get("rua")
                result["ruf"] = tags.get("ruf")
                break
        return result

    def check_spf(self):
        """Retrieve SPF records and highlight soft or neutral policies."""
        records, _ = self.get_txt_record(self.name)
        spf_records = [r for r in records if r.lower().startswith("v=spf1")]
        soft = any(r.strip().lower().endswith("~all") for r in spf_records)
        neutral = any(r.strip().lower().endswith("?all") for r in spf_records)
        return {
            "records": spf_records,
            "soft": soft,
            "neutral": neutral,
        }

    def check_dkim(self, selectors):
        """Check DKIM TXT records for the provided selectors."""
        results = {}
        for sel in selectors:
            name = f"{sel}._domainkey.{self.name}"
            records, _ = self.get_txt_record(name)
            found = None
            for rec in records:
                if "v=DKIM1" in rec:
                    found = rec
                    break
            results[sel] = found
        return results


class Inspector:
    """
    Coordinates the inspection process for a given domain.
    """

    def __init__(self, domain, config):
        self.domain = Domain(domain, query_delay=config.get("query_delay", QUERY_DELAY))
        self.config = config  # Configuration settings

    def inspect(self):
        """
        Perform the inspection process for the domain.
        """
        print(f"\n[*] Inspecting domain: {self.domain.name}\n")

        # Check for wildcard DNS records across all configured types
        print("[*] Checking for wildcard DNS records...")
        if self.domain.check_wildcard_records(self.config["dns_record_types"]):
            print("    [!] Wildcard DNS records found.\n")
        else:
            print("    [ ] No wildcard DNS records found.\n")

        subdomain_count = 0
        if self.config.get("subdomains"):
            print("[*] Enumerating subdomains...")
            found_subs = self.domain.enumerate_subdomains(self.config["subdomains"])
            subdomain_count = len(found_subs)
            if found_subs:
                print("    Discovered subdomains:")
                for sub in found_subs:
                    print(f"    - {sub}")
                print()
            else:
                print("    No subdomains found.\n")

        print("[*] Gathering DNS records...\n")
        meta_errors = []
        record_counts = {}
        for record_type in self.config["dns_record_types"]:
            records, meta_error = self.domain.get_dns_records(record_type)
            if meta_error:
                meta_errors.append(record_type)
                continue
            record_counts[record_type] = len(records)
            if records:
                print(f"{record_type} records:")
                for record in records:
                    print(f"  - {record}")
                print()
            else:
                continue
        if meta_errors:
            print(
                "DNS metaqueries are not allowed for: " + ", ".join(meta_errors) + "\n"
            )

        if record_counts or subdomain_count:
            print("[*] Summary:")
            for rtype, count in record_counts.items():
                print(f"  {rtype}: {count} record(s)")
            if self.config.get("subdomains"):
                print(f"  Subdomains found: {subdomain_count}\n")

        print("[*] Checking email authentication records...")
        dmarc = self.domain.check_dmarc()
        if not dmarc["present"]:
            print("  [!] No DMARC record found.")
        else:
            print(f"  DMARC policy: {dmarc['policy']}")
            if dmarc["policy"] == "none":
                print("  [!] DMARC policy set to none")
            if dmarc["rua"]:
                print(f"  RUA: {dmarc['rua']}")
            if dmarc["ruf"]:
                print(f"  RUF: {dmarc['ruf']}")

        spf = self.domain.check_spf()
        if not spf["records"]:
            print("  [!] No SPF record found.")
        else:
            for rec in spf["records"]:
                print(f"  SPF: {rec}")
            if spf["soft"]:
                print("  [!] SPF ends with ~all")
            if spf["neutral"]:
                print("  [!] SPF ends with ?all")

        dkim_selectors = self.config.get("dkim_selectors", [])
        if dkim_selectors:
            dkim_results = self.domain.check_dkim(dkim_selectors)
            for sel, rec in dkim_results.items():
                if rec:
                    print(f"  DKIM selector '{sel}' found")
                else:
                    print(f"  [!] DKIM selector '{sel}' missing")
        print()


class SSLValidator:
    """
    Handles the validation of SSL/TLS certificates for a domain.
    """

    def __init__(self, domain):
        self.domain = domain

    def validate_certificate(self):
        """Validate and display certificate issuer and expiry."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (self.domain, 443), timeout=REQUEST_TIMEOUT
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()

            issuer_parts = []
            for part in cert.get("issuer", []):
                for name, value in part:
                    issuer_parts.append(f"{name}={value}")
            issuer = ", ".join(issuer_parts) if issuer_parts else "Unknown"

            not_after = cert.get("notAfter")
            expires = "Unknown"
            if not_after:
                try:
                    exp_dt = datetime.datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    )
                    expires = exp_dt.strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    expires = not_after

            print(f"[+] Valid SSL certificate for {self.domain}")
            print(f"    Issuer: {issuer}")
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
        # Example: Basic check for a sample vulnerability (to be expanded)
        try:
            response = requests.get(f"http://{self.domain}", timeout=REQUEST_TIMEOUT)
            if "vulnerable keyword" in response.text:
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

    def get_subdomains(self, fallback=None):
        """Return a list of subdomains from config and optional wordlist."""
        subs = self.get_setting("Subdomains", "list", fallback=fallback or [])
        wordlist = self.config.get("Subdomains", "wordlist_file", fallback=None)
        if wordlist:
            try:
                path = Path(wordlist)
                if path.is_file():
                    with path.open("r", encoding="utf-8") as fh:
                        file_subs = [
                            ln.strip()
                            for ln in fh
                            if ln.strip() and not ln.startswith("#")
                        ]
                    subs = list(dict.fromkeys(subs + file_subs))
            except Exception as e:
                print(f"Error reading subdomain wordlist {wordlist}: {e}")
        return subs

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
            list of stripped items. When requesting the ``selectors`` option or
            when the provided fallback is a list, a single value will also be
            wrapped in a list.
        """
        value = self.config.get(section, setting, fallback=fallback)

        if setting == "types" and (value is None or value == "" or value == fallback):
            return ALL_RECORD_TYPES

        if isinstance(value, str):
            if setting == "query_delay":
                try:
                    return float(value)
                except ValueError:
                    return fallback
            if "," in value:
                return [v.strip() for v in value.split(",")]
            if value.upper() == "ALL":
                return ALL_RECORD_TYPES
            if setting == "selectors" or isinstance(fallback, list):
                return [value.strip()]

        if isinstance(value, list):
            return value
        return value


def main():
    parser = argparse.ArgumentParser(description="DNS Inspection Tool")
    parser.add_argument("domain", help="The domain to inspect")
    parser.add_argument(
        "--config", help="Path to configuration file", default="config.ini"
    )
    args = parser.parse_args()

    # Initialize configuration manager
    config_manager = ConfigManager(args.config)

    # Retrieve configuration settings
    dns_record_types = config_manager.get_setting(
        "DNSRecords", "types", fallback=ALL_RECORD_TYPES
    )
    subdomains = config_manager.get_subdomains(fallback=[])
    query_delay = config_manager.get_setting(
        "Settings", "query_delay", fallback=QUERY_DELAY
    )
    dkim_selectors = config_manager.get_setting("DKIM", "selectors", fallback=[])

    # Initialize Inspector with domain and configuration
    inspector = Inspector(
        args.domain,
        {
            "dns_record_types": dns_record_types,
            "subdomains": subdomains,
            "query_delay": query_delay,
            "dkim_selectors": dkim_selectors,
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


if __name__ == "__main__":
    print_banner("DNS INSPECTAH")
    main()
