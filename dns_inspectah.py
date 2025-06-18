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

    def discover_dkim_selectors(self, use_common_selectors=True, use_brute_force=False):
        """
        Discover DKIM selectors for the domain using multiple techniques.
        
        Args:
            use_common_selectors (bool): Check against common selector names
            use_brute_force (bool): Attempt brute force with common patterns
            
        Returns:
            dict: Dictionary of found selectors and their records
        """
        discovered_selectors = {}
        
        # Common DKIM selectors used by major email providers
        common_selectors = [
            "default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
            "dkim", "mail", "email", "mx", "key1", "key2", "sig1", "sig2",
            # Date-based selectors (Google style)
            "20240101", "20230101", "20220101", "20210101", "20200101",
            "20210112", "20161025", "20190801", "20120113", "20150602",
            # Provider-specific selectors
            "mailgun", "mandrill", "sendgrid", "amazonses", "protonmail", 
            "zoho", "outlook", "office365", "gsuite", "workspace",
            # Common patterns
            "v1", "v2", "prod", "production", "test", "dev"
        ]
        
        from rich.console import Console
        console = Console()
        
        if use_common_selectors:
            console.print("  [cyan]Checking common DKIM selectors...[/cyan]")
            common_results = self.check_dkim(common_selectors)
            for selector, record in common_results.items():
                if record:
                    discovered_selectors[selector] = record
        
        if use_brute_force:
            console.print("  [cyan]Brute forcing DKIM selectors...[/cyan]")
            
            # Generate date-based selectors (last 5 years)
            import datetime
            current_year = datetime.datetime.now().year
            date_selectors = []
            
            # Year-based
            for year in range(current_year - 5, current_year + 1):
                date_selectors.extend([str(year), f"{year}01", f"{year}0101"])
            
            # Month-based for current and last year
            for year in [current_year - 1, current_year]:
                for month in range(1, 13):
                    date_selectors.append(f"{year}{month:02d}")
                    date_selectors.append(f"{year}{month:02d}01")
            
            # Alphanumeric patterns
            alpha_selectors = []
            for i in range(1, 21):  # 1-20
                alpha_selectors.extend([str(i), f"s{i}", f"k{i}", f"key{i}", f"sel{i}"])
            
            # Single letters and combinations
            for char in "abcdefghijklmnopqrstuvwxyz":
                alpha_selectors.extend([char, f"{char}1", f"{char}2"])
            
            all_brute_selectors = date_selectors + alpha_selectors
            brute_results = self.check_dkim(all_brute_selectors)
            
            for selector, record in brute_results.items():
                if record and selector not in discovered_selectors:
                    discovered_selectors[selector] = record
        
        return discovered_selectors

    def enumerate_dkim_from_mx(self):
        """
        Attempt to discover DKIM selectors based on MX record patterns.
        Some organizations use predictable DKIM selector patterns based on their MX records.
        """
        discovered_selectors = {}
        
        try:
            # Get MX records to infer potential DKIM selector patterns
            mx_records, _ = self.get_dns_records("MX")
            if mx_records:
                mx_hosts = []
                for mx_record in mx_records:
                    # Extract hostname from MX record (format: "priority hostname")
                    parts = str(mx_record).split()
                    if len(parts) >= 2:
                        hostname = parts[1].rstrip('.')
                        mx_hosts.append(hostname)
                
                # Generate potential selectors based on MX patterns
                potential_selectors = []
                for mx_host in mx_hosts:
                    # Extract provider patterns
                    if "google" in mx_host.lower():
                        potential_selectors.extend(["google", "googleapis", "gapps"])
                    elif "outlook" in mx_host.lower() or "microsoft" in mx_host.lower():
                        potential_selectors.extend(["selector1", "selector2", "microsoft"])
                    elif "amazon" in mx_host.lower() or "ses" in mx_host.lower():
                        potential_selectors.extend(["amazonses", "ses"])
                    elif "mailgun" in mx_host.lower():
                        potential_selectors.extend(["mailgun", "mg"])
                    elif "sendgrid" in mx_host.lower():
                        potential_selectors.extend(["sendgrid", "sg"])
                
                if potential_selectors:
                    mx_results = self.check_dkim(potential_selectors)
                    for selector, record in mx_results.items():
                        if record:
                            discovered_selectors[selector] = record
        
        except Exception as e:
            from rich.console import Console
            console = Console()
            console.print(f"  [yellow]Warning: Could not analyze MX records for DKIM discovery: {e}[/yellow]")
        
        return discovered_selectors


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
        console.print(f"\n[bold]* Inspecting domain: {self.domain.name}[/bold]")
        
        # Display enabled components
        components = []
        if self.config.get("run_dns", True):
            components.append("DNS Discovery")
        if self.config.get("run_email", True):
            components.append("Email Security")
        if self.config.get("run_web", True):
            components.append("Web Security")
        
        if self.config.get("quick_mode", False):
            console.print(f"[cyan]Running quick scan: {', '.join(components)}[/cyan]\n")
        else:
            console.print(f"[cyan]Running components: {', '.join(components)}[/cyan]\n")
        
        results = {"domain": self.domain.name, "components": components}

        # DNS Discovery Section
        if self.config.get("run_dns", True):
            console.print("[bold blue]===== DNS DISCOVERY =====[/bold blue]")
            
            # Check for wildcard DNS records across all configured types
            if self.config["dns_record_types"]:
                console.print("[*] Checking for wildcard DNS records...")
                wildcard = self.domain.check_wildcard_records(self.config["dns_record_types"])
                results["wildcard"] = wildcard
                if wildcard:
                    console.print("    [bold red][!] Wildcard DNS records found.[/bold red]\n")
                else:
                    console.print("    [green][ ] No wildcard DNS records found.[/green]\n")
            else:
                results["wildcard"] = False

            # Subdomain enumeration
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

            # DNS record gathering
            if self.config["dns_record_types"]:
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
                
                # DNS Summary
                if record_counts or subdomain_count:
                    summary = Table(title="DNS Discovery Summary")
                    summary.add_column("Record Type", style="green")
                    summary.add_column("Count", style="magenta")
                    for rtype, count in record_counts.items():
                        summary.add_row(rtype, str(count))
                    if self.config.get("subdomains") or self.config.get("zone_transfer"):
                        summary.add_row("Subdomains found", str(subdomain_count))
                    console.print(summary)
            else:
                results["dns_records"] = {}
                results["meta_errors"] = []
                results["subdomains"] = []
        else:
            # DNS section skipped
            results["wildcard"] = False
            results["subdomains"] = []
            results["dns_records"] = {}
            results["meta_errors"] = []

        # Email Security Section
        if self.config.get("run_email", True):
            console.print("\n[bold green]===== EMAIL SECURITY =====[/bold green]")
            
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

            # DKIM Discovery and Validation
            console.print("[*] Discovering DKIM selectors...")
            
            # First check configured selectors
            dkim_selectors = self.config.get("dkim_selectors", [])
            configured_results = {}
            if dkim_selectors:
                console.print("  [cyan]Checking configured DKIM selectors...[/cyan]")
                configured_results = self.domain.check_dkim(dkim_selectors)
            
            # Discover additional selectors if enabled
            discovered_results = {}
            mx_results = {}
            
            if self.config.get("dkim_discovery", True):
                console.print("  [cyan]Attempting DKIM selector discovery...[/cyan]")
                discovered_results = self.domain.discover_dkim_selectors(
                    use_common_selectors=True, 
                    use_brute_force=self.config.get("dkim_brute_force", False)
                )
            
                # Try MX-based discovery if enabled
                if self.config.get("dkim_mx_analysis", True):
                    mx_results = self.domain.enumerate_dkim_from_mx()
            
            # Combine all results
            all_dkim_results = {}
            all_dkim_results.update(configured_results)
            all_dkim_results.update(discovered_results)
            all_dkim_results.update(mx_results)
            
            # Display results
            found_selectors = []
            missing_selectors = []
            
            for sel, rec in all_dkim_results.items():
                if rec:
                    found_selectors.append(sel)
                    console.print(f"  [green]✓ DKIM selector '{sel}' found[/green]")
                else:
                    missing_selectors.append(sel)
            
            # Show configured selectors that weren't found
            for sel in dkim_selectors:
                if sel not in all_dkim_results or not all_dkim_results[sel]:
                    console.print(f"  [bold red]✗ Configured DKIM selector '{sel}' missing[/bold red]")
            
            if found_selectors:
                console.print(f"  [bold green]Found {len(found_selectors)} DKIM selector(s): {', '.join(found_selectors)}[/bold green]")
            else:
                console.print("  [bold red]No DKIM selectors found[/bold red]")
            
            results["dkim"] = {
                "configured": configured_results,
                "discovered": discovered_results,
                "mx_based": mx_results,
                "all_found": {k: v for k, v in all_dkim_results.items() if v}
            }
        else:
            # Email security section skipped
            results["dmarc"] = {"present": False}
            results["spf"] = {"records": []}
            results["dkim"] = {"all_found": {}}

        # Web Security Section  
        if self.config.get("run_web", True):
            console.print("\n[bold magenta]===== WEB SECURITY =====[/bold magenta]")
            
            # SSL/TLS Certificate validation
            console.print("[*] Validating SSL certificate...")
            ssl_validator = SSLValidator(self.domain.name)
            ssl_results = ssl_validator.validate_certificate()
            results["ssl"] = ssl_results
            
            # Website vulnerability scanning
            if not self.config.get("quick_mode", False):
                console.print("[*] Performing security scan...")
                vuln_scanner = VulnerabilityScanner(self.domain.name)
                vuln_results = vuln_scanner.scan()
                results["vulnerabilities"] = vuln_results
            else:
                results["vulnerabilities"] = {}
        else:
            # Web security section skipped
            results["ssl"] = {}
            results["vulnerabilities"] = {}
        
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


class SecurityHeaderScanner:
    """
    Analyzes HTTP security headers for web security best practices.
    """

    def __init__(self, domain):
        """Initialize the security header scanner with the target domain."""
        self.domain = domain
        
        # Realistic browser headers to avoid detection
        self.request_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        
        self.security_headers = {
            'strict-transport-security': {
                'name': 'HSTS',
                'description': 'HTTP Strict Transport Security',
                'critical': True
            },
            'content-security-policy': {
                'name': 'CSP',
                'description': 'Content Security Policy',
                'critical': True
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'description': 'Clickjacking protection',
                'critical': True
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'description': 'MIME type sniffing protection',
                'critical': False
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection',
                'description': 'XSS filter protection',
                'critical': False
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'description': 'Referrer information control',
                'critical': False
            },
            'permissions-policy': {
                'name': 'Permissions-Policy',
                'description': 'Feature policy control',
                'critical': False
            }
        }

    def scan_security_headers(self):
        """
        Analyzes HTTP security headers for both HTTP and HTTPS endpoints.
        Returns detailed analysis of security header implementation.
        """
        results = {
            'headers_found': {},
            'missing_critical': [],
            'missing_recommended': [],
            'recommendations': [],
            'score': 0,
            'grade': 'F'
        }

        # Test both HTTP and HTTPS
        protocols = ['https', 'http']
        
        for protocol in protocols:
            url = f"{protocol}://{self.domain}"
            
            try:
                # Add randomized delay between protocols to avoid rate limiting
                if protocol == 'http':
                    import time
                    import random
                    time.sleep(random.uniform(1.5, 3.0))
                
                # Create session for better connection handling
                session = requests.Session()
                session.headers.update(self.request_headers)
                
                # Use HEAD request first for stealth, fallback to GET if needed
                try:
                    response = session.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                    # If HEAD doesn't return security headers, try GET
                    if not any(header in response.headers for header in ['strict-transport-security', 'content-security-policy', 'x-frame-options']):
                        response = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                except:
                    response = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                console.print(f"[bold cyan]Security Headers Analysis for {url}[/bold cyan]")
                
                # Create table for header analysis
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Header", style="cyan", no_wrap=True)
                table.add_column("Status", justify="center")
                table.add_column("Value", style="dim", max_width=50)
                table.add_column("Assessment", style="yellow")
                
                found_headers = 0
                total_critical = sum(1 for h in self.security_headers.values() if h['critical'])
                
                for header_key, header_info in self.security_headers.items():
                    if header_key in headers:
                        found_headers += 1
                        header_value = headers[header_key]
                        results['headers_found'][header_key] = header_value
                        
                        # Analyze header quality
                        assessment = self._analyze_header_value(header_key, header_value)
                        status_color = "green" if assessment['secure'] else "yellow"
                        
                        table.add_row(
                            header_info['name'],
                            f"[{status_color}]✓ Present[/{status_color}]",
                            header_value[:47] + "..." if len(header_value) > 50 else header_value,
                            assessment['message']
                        )
                        
                        if assessment['secure'] and header_info['critical']:
                            results['score'] += 20
                        elif assessment['secure']:
                            results['score'] += 10
                        else:
                            results['recommendations'].append(f"Improve {header_info['name']}: {assessment['message']}")
                            
                    else:
                        status = "critical" if header_info['critical'] else "recommended"
                        if header_info['critical']:
                            results['missing_critical'].append(header_info['name'])
                        else:
                            results['missing_recommended'].append(header_info['name'])
                            
                        table.add_row(
                            header_info['name'],
                            "[red]✗ Missing[/red]",
                            "Not set",
                            f"Missing {status} security header"
                        )
                        
                        results['recommendations'].append(
                            f"Implement {header_info['name']}: {header_info['description']}"
                        )
                
                console.print(table)
                
                # Calculate security grade
                results['grade'] = self._calculate_security_grade(results['score'])
                
                # Display summary
                console.print(f"\n[bold]Security Headers Summary[/bold]")
                console.print(f"Headers found: {found_headers}/{len(self.security_headers)}")
                console.print(f"Security score: {results['score']}/100")
                console.print(f"Security grade: [bold]{results['grade']}[/bold]")
                
                if results['missing_critical']:
                    console.print(f"[red]Missing critical headers: {', '.join(results['missing_critical'])}[/red]")
                
                if results['recommendations']:
                    console.print(f"\n[yellow]Recommendations:[/yellow]")
                    for rec in results['recommendations'][:3]:  # Show top 3 recommendations
                        console.print(f"  • {rec}")
                
                console.print()
                session.close()  # Clean up session
                break  # Use first successful response
                
            except requests.exceptions.SSLError:
                session.close()  # Clean up session
                if protocol == 'https':
                    console.print(f"[yellow]HTTPS not available for {self.domain}, trying HTTP...[/yellow]")
                    continue
                else:
                    console.print(f"[red]Connection failed for {url}[/red]")
            except Exception as e:
                session.close()  # Clean up session
                if protocol == 'https':
                    continue  # Try HTTP if HTTPS fails
                console.print(f"[red]Error analyzing security headers for {self.domain}: {e}[/red]")
                results['error'] = str(e)
                break
        
        return results

    def _analyze_header_value(self, header, value):
        """Analyze the quality and security of a specific header value."""
        analyses = {
            'strict-transport-security': self._analyze_hsts,
            'content-security-policy': self._analyze_csp,
            'x-frame-options': self._analyze_frame_options,
            'x-content-type-options': self._analyze_content_type_options,
            'x-xss-protection': self._analyze_xss_protection,
            'referrer-policy': self._analyze_referrer_policy,
        }
        
        analyzer = analyses.get(header, lambda v: {'secure': True, 'message': 'Present'})
        return analyzer(value)

    def _analyze_hsts(self, value):
        """Analyze HSTS header configuration."""
        value_lower = value.lower()
        if 'includesubdomains' in value_lower and 'preload' in value_lower:
            return {'secure': True, 'message': 'Excellent - includes subdomains and preload'}
        elif 'includesubdomains' in value_lower:
            return {'secure': True, 'message': 'Good - includes subdomains'}
        else:
            return {'secure': False, 'message': 'Basic - consider includeSubDomains'}

    def _analyze_csp(self, value):
        """Analyze Content Security Policy header."""
        if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
            return {'secure': False, 'message': 'Contains unsafe directives'}
        elif 'default-src' in value:
            return {'secure': True, 'message': 'Good policy structure'}
        else:
            return {'secure': False, 'message': 'Missing default-src directive'}

    def _analyze_frame_options(self, value):
        """Analyze X-Frame-Options header."""
        value_upper = value.upper()
        if value_upper in ['DENY', 'SAMEORIGIN']:
            return {'secure': True, 'message': f'Secure setting: {value_upper}'}
        else:
            return {'secure': False, 'message': 'Use DENY or SAMEORIGIN'}

    def _analyze_content_type_options(self, value):
        """Analyze X-Content-Type-Options header."""
        if value.lower() == 'nosniff':
            return {'secure': True, 'message': 'Correctly configured'}
        else:
            return {'secure': False, 'message': 'Should be "nosniff"'}

    def _analyze_xss_protection(self, value):
        """Analyze X-XSS-Protection header."""
        if value == '1; mode=block':
            return {'secure': True, 'message': 'Optimal configuration'}
        elif value == '1':
            return {'secure': True, 'message': 'Basic protection enabled'}
        else:
            return {'secure': False, 'message': 'Use "1; mode=block"'}

    def _analyze_referrer_policy(self, value):
        """Analyze Referrer-Policy header."""
        secure_policies = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']
        if value.lower() in secure_policies:
            return {'secure': True, 'message': f'Secure policy: {value}'}
        else:
            return {'secure': False, 'message': 'Consider stricter policy'}

    def _calculate_security_grade(self, score):
        """Calculate security grade based on score."""
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'


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
    
    # Component selection flags
    component_group = parser.add_argument_group("Component Selection", 
                                               "Choose which components to test (default: all)")
    component_group.add_argument(
        "--dns-only", action="store_true", 
        help="Only perform DNS record discovery and subdomain enumeration"
    )
    component_group.add_argument(
        "--email-only", action="store_true", 
        help="Only perform email security checks (SPF, DMARC, DKIM)"
    )
    component_group.add_argument(
        "--web-only", action="store_true", 
        help="Only perform website security checks (SSL, HTTP headers, vulnerabilities)"
    )
    component_group.add_argument(
        "--no-subdomains", action="store_true", 
        help="Skip subdomain enumeration (faster execution)"
    )
    
    # Quick test flags
    quick_group = parser.add_argument_group("Quick Tests", 
                                          "Fast testing options")
    quick_group.add_argument(
        "--quick", action="store_true", 
        help="Quick scan - basic checks only, no subdomain enumeration"
    )
    quick_group.add_argument(
        "--dkim-discovery", action="store_true", 
        help="Focus on comprehensive DKIM selector discovery"
    )
    args = parser.parse_args()
    
    # Validate component selection flags (only one can be selected)
    component_flags = [args.dns_only, args.email_only, args.web_only]
    if sum(component_flags) > 1:
        parser.error("Only one of --dns-only, --email-only, or --web-only can be specified")
    
    # Determine which components to run
    run_dns = True
    run_email = True 
    run_web = True
    
    if args.dns_only:
        run_email = False
        run_web = False
    elif args.email_only:
        run_dns = False
        run_web = False
    elif args.web_only:
        run_dns = False
        run_email = False
    elif args.quick:
        # Quick mode: basic DNS, email security, SSL check only
        pass  # All components run but with limited scope
    
    # Initialize configuration manager
    config_manager = ConfigManager(args.config)

    # Retrieve configuration settings based on selected components
    dns_record_types = config_manager.get_setting(
        "DNSRecords", "types", fallback=ALL_RECORD_TYPES
    ) if run_dns else []
    
    # Handle subdomain configuration
    subdomains = []
    if run_dns and not args.no_subdomains and not args.quick:
        subdomains = config_manager.get_subdomains(fallback=[])
    
    query_delay = config_manager.get_setting(
        "Settings", "query_delay", fallback=QUERY_DELAY
    )
    
    # Email security settings
    if run_email:
        dkim_selectors = config_manager.get_setting("DKIM", "selectors", fallback=[])
        dkim_discovery = config_manager.get_setting("DKIM", "discovery_enabled", fallback=True)
        dkim_brute_force = config_manager.get_setting("DKIM", "brute_force", fallback=False)
        dkim_mx_analysis = config_manager.get_setting("DKIM", "mx_analysis", fallback=True)
        
        # Enable comprehensive DKIM discovery if requested
        if args.dkim_discovery:
            dkim_discovery = True
            dkim_brute_force = True
            dkim_mx_analysis = True
    else:
        dkim_selectors = []
        dkim_discovery = False
        dkim_brute_force = False
        dkim_mx_analysis = False
    
    # DNS-specific settings
    if run_dns:
        zone_transfer = config_manager.get_setting("ZoneTransfer", "enabled", fallback=False)
        ct_logs = config_manager.get_setting("Subdomains", "ct_logs", fallback=False)
        dns_dumpster = config_manager.get_setting("Subdomains", "dns_dumpster", fallback=False)
        alternate_dns = config_manager.get_setting("Subdomains", "alternate_dns", fallback=False)
        max_workers = config_manager.get_setting("Subdomains", "max_workers", fallback=10)
        recursive = config_manager.get_setting("Subdomains", "recursive", fallback=True)
        
        # Quick mode adjustments
        if args.quick:
            ct_logs = False
            dns_dumpster = False
            alternate_dns = False
            recursive = False
            max_workers = 5
    else:
        zone_transfer = False
        ct_logs = False
        dns_dumpster = False
        alternate_dns = False
        max_workers = 10
        recursive = True

    # Initialize Inspector with domain and configuration
    inspector = Inspector(
        args.domain,
        {
            "dns_record_types": dns_record_types,
            "subdomains": subdomains,
            "query_delay": query_delay,
            "dkim_selectors": dkim_selectors,
            "dkim_discovery": dkim_discovery,
            "dkim_brute_force": dkim_brute_force,
            "dkim_mx_analysis": dkim_mx_analysis,
            "zone_transfer": zone_transfer,
            "ct_logs": ct_logs,
            "dns_dumpster": dns_dumpster,
            "alternate_dns": alternate_dns,
            "max_workers": max_workers,
            "recursive": recursive,
            # Component selection flags
            "run_dns": run_dns,
            "run_email": run_email,
            "run_web": run_web,
            "quick_mode": args.quick,
        },
    )

    # Perform the inspection
    results = inspector.inspect()

    # Initialize and use SSLValidator and SecurityHeaderScanner if needed
    ssl_validator = SSLValidator(args.domain)
    results["ssl"] = ssl_validator.validate_certificate()

    security_scanner = SecurityHeaderScanner(args.domain)
    results["security_headers"] = security_scanner.scan_security_headers()

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
