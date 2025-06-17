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
import datetime
import json
import threading
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TaskID

console = Console()

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
        """Store the domain `name` and DNS `query_delay`."""
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

    def enumerate_subdomains(self, subdomains, max_workers=10, recursive=True):
        """
        Attempt to resolve a list of subdomains for the domain with threading and recursion.

        Args:
            subdomains (list): Subdomain prefixes to check.
            max_workers (int): Maximum number of concurrent threads.
            recursive (bool): Whether to perform recursive subdomain discovery.

        Returns:
            list: Fully qualified subdomains that resolve successfully.
        """
        discovered = set()
        lock = threading.Lock()
        
        def check_subdomain(sub):
            fqdn = f"{sub}.{self.name}"
            try:
                time.sleep(self.query_delay)
                dns.resolver.resolve(fqdn, "A")
                with lock:
                    discovered.add(fqdn)
                    if recursive:
                        # Generate common permutations for recursive discovery
                        permutations = self._generate_permutations(sub)
                        return fqdn, permutations
                return fqdn, []
            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.resolver.LifetimeTimeout,
            ):
                return None, []
        
        # Initial subdomain enumeration
        with Progress() as progress:
            task = progress.add_task("[cyan]Enumerating subdomains...", total=len(subdomains))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_subdomain = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
                recursive_subs = set()
                
                for future in as_completed(future_to_subdomain):
                    result, perms = future.result()
                    if result and recursive:
                        recursive_subs.update(perms)
                    progress.advance(task)
        
        # Recursive enumeration on discovered subdomains
        if recursive and recursive_subs:
            console.print(f"[*] Found {len(discovered)} subdomains, checking {len(recursive_subs)} permutations...")
            with Progress() as progress:
                task = progress.add_task("[cyan]Recursive enumeration...", total=len(recursive_subs))
                
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_subdomain = {executor.submit(check_subdomain, sub): sub for sub in recursive_subs}
                    
                    for future in as_completed(future_to_subdomain):
                        future.result()
                        progress.advance(task)
        
        return list(discovered)

    def attempt_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR) from domain nameservers."""
        subdomains = []
        ns_records, _ = self.get_dns_records("NS")
        for ns in ns_records:
            try:
                time.sleep(self.query_delay)
                xfr = dns.query.xfr(ns, self.name, lifetime=5)
                zone = dns.zone.from_xfr(xfr)
                for name in zone.nodes.keys():
                    if str(name) == "@":
                        sub = self.name
                    else:
                        sub = f"{name}.{self.name}"
                    subdomains.append(sub.rstrip("."))
            except Exception as e:
                print(f"    [-] AXFR failed for {ns}: {e}")
        return list(dict.fromkeys(subdomains))
    
    def _generate_permutations(self, subdomain):
        """
        Generate common subdomain permutations for recursive discovery.
        
        Args:
            subdomain (str): Base subdomain to generate permutations for.
            
        Returns:
            list: List of subdomain permutations.
        """
        common_prefixes = ['dev', 'test', 'staging', 'prod', 'admin', 'api', 'cdn', 'www']
        common_suffixes = ['1', '2', '01', '02', 'new', 'old', 'backup', 'temp']
        separators = ['-', '_', '']
        
        permutations = set()
        
        # Add prefixes
        for prefix in common_prefixes:
            for sep in separators:
                if sep:
                    permutations.add(f"{prefix}{sep}{subdomain}")
                else:
                    permutations.add(f"{prefix}{subdomain}")
        
        # Add suffixes  
        for suffix in common_suffixes:
            for sep in separators:
                if sep:
                    permutations.add(f"{subdomain}{sep}{suffix}")
                else:
                    permutations.add(f"{subdomain}{suffix}")
        
        # Add common combinations
        if len(subdomain.split('-')) == 1 and len(subdomain.split('_')) == 1:
            # Single word subdomains - try with common separators
            for word in ['app', 'web', 'mail', 'ftp', 'admin']:
                for sep in ['-', '_']:
                    permutations.add(f"{subdomain}{sep}{word}")
                    permutations.add(f"{word}{sep}{subdomain}")
        
        return list(permutations)[:50]  # Limit to prevent explosion

    def enumerate_ct_subdomains(self):
        """Retrieve subdomains from multiple certificate transparency logs."""
        discovered = set()
        
        # Multiple CT log sources for better coverage
        sources = [
            f"https://crt.sh/?q=%25.{self.name}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.name}&include_subdomains=true&expand=dns_names"
        ]
        
        for url in sources:
            try:
                console.print(f"[*] Querying CT logs: {url.split('//')[1].split('/')[0]}...")
                resp = requests.get(url, timeout=REQUEST_TIMEOUT)
                if resp.status_code == 200:
                    if 'crt.sh' in url:
                        # Handle crt.sh format
                        for entry in resp.json():
                            value = entry.get("name_value", "")
                            for sub in value.split("\n"):
                                sub = sub.strip().lower()
                                # Clean up wildcard entries and validate
                                if sub.startswith('*.'):
                                    sub = sub[2:]
                                if (sub.endswith(self.name) and sub != self.name and 
                                    not any(c in sub for c in ['*', ' ', '\t'])):
                                    discovered.add(sub)
                    
                    elif 'certspotter' in url:
                        # Handle certspotter format
                        for entry in resp.json():
                            dns_names = entry.get("dns_names", [])
                            for name in dns_names:
                                name = name.strip().lower()
                                if name.startswith('*.'):
                                    name = name[2:]
                                if (name.endswith(self.name) and name != self.name and
                                    not any(c in name for c in ['*', ' ', '\t'])):
                                    discovered.add(name)
                        
            except Exception as exc:
                console.print(f"[yellow]Warning: CT log query failed for {url.split('//')[1].split('/')[0]}: {exc}[/yellow]")
                continue
        
        return list(discovered)
    
    def enumerate_dns_dumpster(self):
        """Retrieve subdomains from DNSDumpster API."""
        try:
            session = requests.Session()
            url = 'https://dnsdumpster.com/'
            
            # Get CSRF token
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return []
            
            # Extract CSRF token from response
            csrf_token = None
            for line in resp.text.split('\n'):
                if 'csrfmiddlewaretoken' in line:
                    csrf_token = line.split('value="')[1].split('"')[0]
                    break
            
            if not csrf_token:
                return []
            
            # Submit domain search
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.name
            }
            
            headers = {
                'Referer': url,
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            }
            
            resp = session.post(url, data=data, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if resp.status_code == 200:
                # Parse HTML response to extract domains
                discovered = set()
                lines = resp.text.split('\n')
                for line in lines:
                    if self.name in line and ('http://' in line or 'https://' in line):
                        # Extract subdomain from HTML
                        for part in line.split():
                            if self.name in part and ('http' in part or part.endswith(self.name)):
                                clean_domain = part.replace('http://', '').replace('https://', '')
                                clean_domain = clean_domain.split('/')[0]
                                if clean_domain.endswith(self.name) and clean_domain != self.name:
                                    discovered.add(clean_domain)
                
                return list(discovered)
            
        except Exception as exc:
            console.print(f"[yellow]Warning: DNSDumpster query failed: {exc}[/yellow]")
        
        return []
    
    def enumerate_alternate_dns(self, subdomains, dns_servers=None):
        """
        Enumerate subdomains using alternative DNS servers for better coverage.
        
        Args:
            subdomains (list): Subdomain prefixes to check.
            dns_servers (list): List of DNS servers to use.
            
        Returns:
            list: Additional subdomains found using alternate DNS servers.
        """
        if not dns_servers:
            dns_servers = [
                '8.8.8.8',      # Google
                '1.1.1.1',      # Cloudflare
                '208.67.222.222', # OpenDNS
                '9.9.9.9',      # Quad9
            ]
        
        discovered = set()
        
        for dns_server in dns_servers:
            try:
                # Create custom resolver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 3
                resolver.lifetime = 5
                
                console.print(f"[*] Checking subdomains via DNS server {dns_server}...")
                
                for sub in subdomains[:100]:  # Limit to prevent abuse
                    fqdn = f"{sub}.{self.name}"
                    try:
                        time.sleep(self.query_delay / 2)  # Faster for alternate servers
                        resolver.resolve(fqdn, "A")
                        discovered.add(fqdn)
                    except (
                        dns.resolver.NoAnswer,
                        dns.resolver.NXDOMAIN,
                        dns.resolver.NoNameservers,
                        dns.resolver.LifetimeTimeout,
                    ):
                        continue
                    except Exception:
                        break  # DNS server might be rate limiting
                        
            except Exception as exc:
                console.print(f"[yellow]Warning: DNS server {dns_server} failed: {exc}[/yellow]")
                continue
        
        return list(discovered)

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
        """Create a Domain for `domain` and retain `config` settings."""
        self.domain = Domain(domain, query_delay=config.get("query_delay", QUERY_DELAY))
        self.config = config  # Configuration settings

    def inspect(self):
        """
        Perform the inspection process for the domain.
        """
        console.print(f"\n[bold]* Inspecting domain: {self.domain.name}[/bold]\n")
        results = {"domain": self.domain.name}

        # Check for wildcard DNS records across all configured types
        console.print("[*] Checking for wildcard DNS records...")
        wildcard = self.domain.check_wildcard_records(self.config["dns_record_types"])
        results["wildcard"] = wildcard
        if wildcard:
            console.print("    [bold red][!] Wildcard DNS records found.[/bold red]\n")
        else:
            console.print("    [green][ ] No wildcard DNS records found.[/green]\n")

        subdomains = []
        if self.config.get("subdomains"):
            console.print("[*] Enumerating subdomains...")
            found_subs = self.domain.enumerate_subdomains(
                self.config["subdomains"], 
                max_workers=self.config.get("max_workers", 10),
                recursive=self.config.get("recursive", True)
            )
            subdomains.extend(found_subs)
            
            # Try alternate DNS servers for additional coverage
            if self.config.get("alternate_dns", False):
                console.print("[*] Checking subdomains via alternate DNS servers...")
                alt_subs = self.domain.enumerate_alternate_dns(self.config["subdomains"])
                subdomains.extend(alt_subs)
                
        if self.config.get("ct_logs"):
            console.print(
                "[*] Pulling subdomains from certificate transparency logs..."
            )
            ct_subs = self.domain.enumerate_ct_subdomains()
            subdomains.extend(ct_subs)
            
        if self.config.get("dns_dumpster", False):
            console.print("[*] Querying DNSDumpster for additional subdomains...")
            dd_subs = self.domain.enumerate_dns_dumpster()
            subdomains.extend(dd_subs)
            
        if self.config.get("zone_transfer"):
            console.print("[*] Attempting zone transfer...")
            axfr_subs = self.domain.attempt_zone_transfer()
            subdomains.extend(axfr_subs)
            if not axfr_subs:
                console.print("    Zone transfer failed or no records found.\n")

        subdomain_count = len(set(subdomains))
        results["subdomains"] = sorted(set(subdomains))
        if subdomains:
            table = Table(title="Discovered subdomains")
            table.add_column("Subdomain", style="cyan")
            for sub in sorted(set(subdomains)):
                table.add_row(sub)
            console.print(table)
        elif self.config.get("subdomains") or self.config.get("zone_transfer"):
            console.print("    No subdomains found.\n")

        console.print("[*] Gathering DNS records...\n")
        meta_errors = []
        record_counts = {}
        dns_records = {}
        record_table = Table(title="DNS Records")
        record_table.add_column("Type", style="green")
        record_table.add_column("Value", style="magenta")
        for record_type in self.config["dns_record_types"]:
            records, meta_error = self.domain.get_dns_records(record_type)
            if meta_error:
                meta_errors.append(record_type)
                continue
            record_counts[record_type] = len(records)
            dns_records[record_type] = records
            for record in records:
                record_table.add_row(record_type, record)
        if record_table.row_count:
            console.print(record_table)
        if meta_errors:
            console.print(
                f"[yellow]DNS metaqueries are not allowed for: {', '.join(meta_errors)}[/yellow]\n"
            )

        results["dns_records"] = dns_records
        results["meta_errors"] = meta_errors
        if record_counts or subdomain_count:
            summary = Table(title="Summary")
            summary.add_column("Record Type", style="green")
            summary.add_column("Count", style="magenta")
            for rtype, count in record_counts.items():
                summary.add_row(rtype, str(count))
            if self.config.get("subdomains") or self.config.get("zone_transfer"):
                summary.add_row("Subdomains found", str(subdomain_count))
            console.print(summary)

        console.print("[*] Checking email authentication records...")
        dmarc = self.domain.check_dmarc()
        results["dmarc"] = dmarc
        if not dmarc["present"]:
            console.print("  [bold red]! No DMARC record found.[/bold red]")
        else:
            console.print(f"  DMARC policy: {dmarc['policy']}")
            if dmarc["policy"] == "none":
                console.print("  [bold yellow]! DMARC policy set to none[/bold yellow]")
            if dmarc["rua"]:
                console.print(f"  RUA: {dmarc['rua']}")
            if dmarc["ruf"]:
                console.print(f"  RUF: {dmarc['ruf']}")

        spf = self.domain.check_spf()
        results["spf"] = spf
        if not spf["records"]:
            console.print("  [bold red]! No SPF record found.[/bold red]")
        else:
            for rec in spf["records"]:
                console.print(f"  SPF: {rec}")
            if spf["soft"]:
                console.print("  [bold yellow]! SPF ends with ~all[/bold yellow]")
            if spf["neutral"]:
                console.print("  [bold yellow]! SPF ends with ?all[/bold yellow]")

        dkim_selectors = self.config.get("dkim_selectors", [])
        dkim_results = {}
        if dkim_selectors:
            dkim_results = self.domain.check_dkim(dkim_selectors)
            for sel, rec in dkim_results.items():
                if rec:
                    console.print(f"  DKIM selector '{sel}' found")
                else:
                    console.print(
                        f"  [bold red]! DKIM selector '{sel}' missing[/bold red]"
                    )
        results["dkim"] = dkim_results
        console.print()
        return results


class SSLValidator:
    """
    Handles the validation of SSL/TLS certificates for a domain.
    """

    def __init__(self, domain):
        """Save the domain to validate its SSL certificate."""
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

            console.print(f"[+] Valid SSL certificate for {self.domain}")
            cert_table = Table(show_header=False)
            cert_table.add_column("Field", style="cyan")
            cert_table.add_column("Value", style="magenta")
            cert_table.add_row("Issuer", issuer)
            cert_table.add_row("Expires", expires)
            console.print(cert_table)
            console.print()
            return {"valid": True, "issuer": issuer, "expires": expires}
        except Exception as e:
            console.print(
                f"[-] Error validating SSL certificate for {self.domain}: {e}\n",
                style="red",
            )
            return {"valid": False, "error": str(e)}


class VulnerabilityScanner:
    """
    Scans for common web vulnerabilities in the domain's web services.
    """

    def __init__(self, domain):
        """Store the domain to scan for vulnerabilities."""
        self.domain = domain

    def scan_for_vulnerabilities(self):
        """
        Scans the domain for common web vulnerabilities.
        """
        # Example: Basic check for a sample vulnerability (to be expanded)
        try:
            response = requests.get(f"http://{self.domain}", timeout=REQUEST_TIMEOUT)
            if "vulnerable keyword" in response.text:
                console.print(
                    f"[bold red][!] Potential vulnerability found in {self.domain}[/bold red]\n"
                )
                return {"vulnerable": True}
            else:
                console.print(
                    f"[green][+] No obvious vulnerabilities found in {self.domain}[/green]\n"
                )
                return {"vulnerable": False}
        except Exception as e:
            console.print(
                f"[-] Error scanning {self.domain} for vulnerabilities: {e}\n",
                style="red",
            )
            return {"error": str(e)}


class ConfigManager:
    """
    Manages the application's configuration settings.
    """

    def __init__(self, config_file):
        """Load configuration from the given `config_file`."""
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
            if isinstance(fallback, bool):
                return value.strip().lower() in ("true", "yes", "1")
            if setting == "query_delay":
                try:
                    return float(value)
                except ValueError:
                    return fallback
            if setting == "max_workers":
                try:
                    return int(value)
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
    parser.add_argument(
        "--output-json", help="Write results to the given JSON file", default=None
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
    zone_transfer = config_manager.get_setting(
        "ZoneTransfer", "enabled", fallback=False
    )
    ct_logs = config_manager.get_setting("Subdomains", "ct_logs", fallback=False)
    dns_dumpster = config_manager.get_setting("Subdomains", "dns_dumpster", fallback=False)
    alternate_dns = config_manager.get_setting("Subdomains", "alternate_dns", fallback=False)
    max_workers = config_manager.get_setting("Subdomains", "max_workers", fallback=10)
    recursive = config_manager.get_setting("Subdomains", "recursive", fallback=True)

    # Initialize Inspector with domain and configuration
    inspector = Inspector(
        args.domain,
        {
            "dns_record_types": dns_record_types,
            "subdomains": subdomains,
            "query_delay": query_delay,
            "dkim_selectors": dkim_selectors,
            "zone_transfer": zone_transfer,
            "ct_logs": ct_logs,
            "dns_dumpster": dns_dumpster,
            "alternate_dns": alternate_dns,
            "max_workers": max_workers,
            "recursive": recursive,
        },
    )

    # Perform the inspection
    results = inspector.inspect()

    # Initialize and use SSLValidator and VulnerabilityScanner if needed
    ssl_validator = SSLValidator(args.domain)
    results["ssl"] = ssl_validator.validate_certificate()

    vulnerability_scanner = VulnerabilityScanner(args.domain)
    results["vulnerabilities"] = vulnerability_scanner.scan_for_vulnerabilities()

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        console.print(f"[green]Results written to {args.output_json}[/green]")


def print_banner(text):
    banner = pyfiglet.figlet_format(text)
    console.print(f"[bold green]{banner}[/bold green]")


if __name__ == "__main__":
    print_banner("DNS INSPECTAH")
    main()
