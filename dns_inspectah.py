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
        Discover DKIM selectors using advanced techniques including SPF analysis,
        certificate transparency, and intelligent pattern recognition.
        
        Args:
            use_common_selectors (bool): Check against common selector names
            use_brute_force (bool): Attempt intelligent brute force with patterns
            
        Returns:
            dict: Dictionary of found selectors and their records
        """
        discovered_selectors = {}
        
        from rich.console import Console
        console = Console()
        
        # 1. SPF Record Analysis - Extract domains from SPF includes
        console.print("  [cyan]Analyzing SPF records for DKIM clues...[/cyan]")
        spf_selectors = self._extract_dkim_from_spf()
        discovered_selectors.update(spf_selectors)
        
        # 2. BIMI Record Analysis - Check for BIMI which often indicates DKIM
        console.print("  [cyan]Checking BIMI records for DKIM indicators...[/cyan]")
        bimi_selectors = self._check_bimi_dkim_indicators()
        discovered_selectors.update(bimi_selectors)
        
        # 3. Email Infrastructure Detection
        console.print("  [cyan]Analyzing email infrastructure...[/cyan]")
        infra_selectors = self._analyze_email_infrastructure()
        discovered_selectors.update(infra_selectors)
        
        # 4. Enhanced common selectors with current patterns
        if use_common_selectors:
            console.print("  [cyan]Checking enhanced common selectors...[/cyan]")
            common_selectors = self._get_enhanced_common_selectors()
            common_results = self.check_dkim(common_selectors)
            for selector, record in common_results.items():
                if record and selector not in discovered_selectors:
                    discovered_selectors[selector] = record
        
        # 5. DNS Zone Walking for DKIM patterns
        console.print("  [cyan]Scanning for additional DKIM patterns...[/cyan]")
        zone_selectors = self._advanced_dkim_scanning()
        discovered_selectors.update(zone_selectors)
        
        # 6. Intelligent brute force based on discovered patterns
        if use_brute_force:
            console.print("  [cyan]Performing intelligent pattern-based discovery...[/cyan]")
            pattern_selectors = self._intelligent_pattern_discovery(discovered_selectors)
            pattern_results = self.check_dkim(pattern_selectors)
            for selector, record in pattern_results.items():
                if record and selector not in discovered_selectors:
                    discovered_selectors[selector] = record
        
        return discovered_selectors

    def _extract_dkim_from_spf(self):
        """Extract potential DKIM selectors by analyzing SPF includes."""
        selectors = {}
        
        try:
            spf_data = self.check_spf()
            for spf_record in spf_data.get('records', []):
                # Parse SPF record for include mechanisms
                parts = spf_record.split()
                for part in parts:
                    if part.startswith('include:'):
                        included_domain = part.split(':', 1)[1]
                        
                        # Extract potential selectors from included domains
                        if 'mailgun' in included_domain:
                            selectors.update(self.check_dkim(['mg', 'mailgun', 'mta']))
                        elif 'sendgrid' in included_domain:
                            selectors.update(self.check_dkim(['sendgrid', 'sg', 'em']))
                        elif 'amazonses' in included_domain or 'ses' in included_domain:
                            selectors.update(self.check_dkim(['amazonses', 'ses', 'aws']))
                        elif 'office365' in included_domain or 'outlook' in included_domain:
                            selectors.update(self.check_dkim(['selector1', 'selector2', 'microsoft']))
                        elif 'google' in included_domain or 'gmail' in included_domain:
                            # Google uses date-based selectors
                            import datetime
                            current_year = datetime.datetime.now().year
                            google_selectors = ['google', 'gmail']
                            for year in range(current_year - 2, current_year + 1):
                                for month in range(1, 13):
                                    google_selectors.append(f"{year}{month:02d}")
                            selectors.update(self.check_dkim(google_selectors))
                        elif 'mailchimp' in included_domain:
                            selectors.update(self.check_dkim(['k1', 'k2', 'mailchimp']))
                        elif 'constantcontact' in included_domain:
                            selectors.update(self.check_dkim(['cc', 'constantcontact']))
        except Exception as e:
            from rich.console import Console
            console = Console()
            console.print(f"  [yellow]SPF analysis failed: {e}[/yellow]")
        
        return {k: v for k, v in selectors.items() if v}

    def _check_bimi_dkim_indicators(self):
        """Check BIMI records which often indicate strong DKIM implementation."""
        selectors = {}
        
        try:
            # Check for BIMI record
            bimi_records, _ = self.get_txt_record(f"default._bimi.{self.name}")
            if bimi_records:
                # BIMI presence suggests sophisticated email setup, try enterprise selectors
                enterprise_selectors = [
                    'default', 'production', 'enterprise', 'corporate', 'main',
                    'primary', 'bimi', 'brand', 'marketing', 'official'
                ]
                selectors.update(self.check_dkim(enterprise_selectors))
        except Exception:
            pass
        
        return {k: v for k, v in selectors.items() if v}

    def _analyze_email_infrastructure(self):
        """Analyze email infrastructure to predict DKIM selector patterns."""
        selectors = {}
        
        try:
            # Get MX records for infrastructure analysis
            mx_records, _ = self.get_dns_records("MX")
            mx_hosts = []
            for mx_record in mx_records:
                parts = str(mx_record).split()
                if len(parts) >= 2:
                    mx_hosts.append(parts[1].lower().rstrip('.'))
            
            # Get A records to check for cloud providers
            a_records, _ = self.get_dns_records("A")
            
            # Analyze hosting patterns
            for mx_host in mx_hosts:
                if any(cloud in mx_host for cloud in ['amazonaws', 'google', 'azure', 'cloudflare']):
                    # Cloud-hosted likely uses modern selector patterns
                    cloud_selectors = ['default', 'auto', 'cloud', 'managed', 'service']
                    selectors.update(self.check_dkim(cloud_selectors))
                
                if 'protection.outlook.com' in mx_host:
                    # Office 365 / Exchange Online
                    selectors.update(self.check_dkim(['selector1', 'selector2', 'microsoft', 'o365']))
                
                if any(security in mx_host for security in ['mimecast', 'proofpoint', 'forcepoint']):
                    # Email security services often use predictable patterns
                    security_selectors = ['default', 'sec', 'security', 'filter', 'gateway']
                    selectors.update(self.check_dkim(security_selectors))
                    
        except Exception as e:
            from rich.console import Console
            console = Console()
            console.print(f"  [yellow]Infrastructure analysis failed: {e}[/yellow]")
        
        return {k: v for k, v in selectors.items() if v}

    def _get_enhanced_common_selectors(self):
        """Get an enhanced list of common selectors based on current patterns."""
        import datetime
        current_year = datetime.datetime.now().year
        current_month = datetime.datetime.now().month
        
        # Base common selectors
        selectors = [
            "default", "selector1", "selector2", "s1", "s2", "k1", "k2",
            "dkim", "mail", "email", "mx", "key1", "key2", "sig1", "sig2"
        ]
        
        # Current and recent date-based selectors (Google, Microsoft style)
        for year in [current_year - 1, current_year]:
            for month in range(1, 13):
                selectors.extend([
                    f"{year}{month:02d}",
                    f"{year}{month:02d}01", 
                    f"{year}-{month:02d}",
                    f"{str(year)[-2:]}{month:02d}"
                ])
        
        # Weekly selectors (some providers rotate weekly)
        import calendar
        for week in range(1, 54):  # 52-53 weeks per year
            selectors.extend([f"w{week}", f"week{week}", f"{current_year}w{week:02d}"])
        
        # Provider-specific modern patterns
        selectors.extend([
            # Cloud providers
            "aws", "azure", "gcp", "cloudflare", "auto", "managed",
            # Marketing platforms  
            "mailchimp", "campaign", "newsletter", "marketing", "promo",
            # Modern SaaS patterns
            "api", "service", "webhook", "notification", "system",
            # Security-conscious patterns
            "secure", "verified", "trusted", "official", "corporate"
        ])
        
        return list(set(selectors))  # Remove duplicates

    def _intelligent_pattern_discovery(self, found_selectors):
        """Generate additional selectors based on patterns found in existing ones."""
        if not found_selectors:
            return []
        
        pattern_selectors = set()
        
        for selector in found_selectors.keys():
            # Numeric pattern discovery
            if selector.isdigit():
                num = int(selector)
                # Try adjacent numbers
                for offset in [-2, -1, 1, 2]:
                    if num + offset > 0:
                        pattern_selectors.add(str(num + offset))
            
            # Date pattern discovery
            if len(selector) >= 6 and selector[:4].isdigit():
                try:
                    year = int(selector[:4])
                    if 2015 <= year <= 2030:  # Reasonable year range
                        # Try adjacent months/years
                        if len(selector) == 6:  # YYYYMM format
                            month = int(selector[4:6])
                            for m_offset in [-1, 1]:
                                new_month = month + m_offset
                                if 1 <= new_month <= 12:
                                    pattern_selectors.add(f"{year}{new_month:02d}")
                        # Try adjacent years
                        for y_offset in [-1, 1]:
                            new_year = year + y_offset
                            if 2015 <= new_year <= 2030:
                                pattern_selectors.add(str(new_year))
                except ValueError:
                    pass
            
            # Prefix/suffix pattern discovery
            if len(selector) > 1:
                # Try removing/adding common prefixes/suffixes
                prefixes = ['s', 'k', 'key', 'sel', 'dkim']
                suffixes = ['1', '2', 'a', 'b', 'prod', 'dev']
                
                for prefix in prefixes:
                    if selector.startswith(prefix):
                        base = selector[len(prefix):]
                        for new_prefix in prefixes:
                            if new_prefix != prefix:
                                pattern_selectors.add(new_prefix + base)
                
                for suffix in suffixes:
                    if selector.endswith(suffix):
                        base = selector[:-len(suffix)]
                        for new_suffix in suffixes:
                            if new_suffix != suffix:
                                pattern_selectors.add(base + new_suffix)
        
        return list(pattern_selectors)[:100]  # Limit to prevent explosion

    def _advanced_dkim_scanning(self):
        """Advanced DKIM scanning using DNS enumeration and timing analysis."""
        selectors = {}
        
        try:
            # Check for common organizational patterns
            org_patterns = self._get_organizational_patterns()
            if org_patterns:
                org_results = self.check_dkim(org_patterns)
                selectors.update({k: v for k, v in org_results.items() if v})
            
            # Time-based rotation detection
            time_patterns = self._detect_time_based_selectors()
            if time_patterns:
                time_results = self.check_dkim(time_patterns)
                selectors.update({k: v for k, v in time_results.items() if v})
                
        except Exception as e:
            from rich.console import Console
            console = Console()
            console.print(f"  [yellow]Advanced scanning failed: {e}[/yellow]")
        
        return selectors

    def _get_organizational_patterns(self):
        """Generate selectors based on domain/organization patterns."""
        patterns = []
        
        # Extract potential organization name from domain
        domain_parts = self.name.lower().split('.')
        if len(domain_parts) >= 2:
            org_name = domain_parts[0]
            
            # Generate variations
            patterns.extend([
                org_name, f"{org_name}1", f"{org_name}2",
                f"{org_name}-mail", f"{org_name}-dkim", f"{org_name}mail",
                org_name[:3], org_name[:4], org_name[:5]  # Abbreviations
            ])
            
            # Try common business suffixes/prefixes
            prefixes = ['corp', 'company', 'mail', 'email', 'smtp']
            suffixes = ['inc', 'corp', 'llc', 'ltd', 'co']
            
            for prefix in prefixes:
                patterns.append(f"{prefix}-{org_name}")
            for suffix in suffixes:
                patterns.append(f"{org_name}-{suffix}")
        
        return patterns[:50]  # Limit results

    def _detect_time_based_selectors(self):
        """Detect time-based DKIM selector rotation patterns."""
        import datetime
        import calendar
        
        patterns = []
        now = datetime.datetime.now()
        
        # Current time-based patterns
        current_patterns = [
            # Daily rotation
            now.strftime("%Y%m%d"), now.strftime("%y%m%d"),
            # Weekly rotation  
            f"{now.year}w{now.isocalendar()[1]:02d}",
            # Quarterly rotation
            f"{now.year}q{(now.month-1)//3 + 1}",
            # Seasonal rotation
            self._get_season_selector(now),
        ]
        
        # Recent patterns (last few periods)
        for days_back in [1, 7, 30, 90]:
            past_date = now - datetime.timedelta(days=days_back)
            patterns.extend([
                past_date.strftime("%Y%m%d"),
                past_date.strftime("%y%m%d"),
                f"{past_date.year}w{past_date.isocalendar()[1]:02d}",
                f"{past_date.year}q{(past_date.month-1)//3 + 1}",
                self._get_season_selector(past_date),
            ])
        
        patterns.extend(current_patterns)
        return list(set(patterns))  # Remove duplicates

    def _get_season_selector(self, date):
        """Get seasonal selector for a given date."""
        month = date.month
        year = date.year
        
        if month in [12, 1, 2]:
            return f"{year}winter"
        elif month in [3, 4, 5]:
            return f"{year}spring"
        elif month in [6, 7, 8]:
            return f"{year}summer"
        else:
            return f"{year}fall"

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

    def discover_dkim_selectors_with_progress(self, use_common_selectors=True, use_brute_force=False, progress_callback=None):
        """
        Enhanced DKIM discovery with progress tracking.
        """
        discovered_selectors = {}
        total_steps = 5
        current_step = 0
        
        def update_progress():
            nonlocal current_step
            current_step += 1
            if progress_callback:
                progress_callback(int((current_step / total_steps) * 100))
        
        # 1. SPF Record Analysis
        spf_selectors = self._extract_dkim_from_spf()
        discovered_selectors.update(spf_selectors)
        update_progress()
        
        # 2. BIMI Record Analysis
        bimi_selectors = self._check_bimi_dkim_indicators()
        discovered_selectors.update(bimi_selectors)
        update_progress()
        
        # 3. Email Infrastructure Detection
        infra_selectors = self._analyze_email_infrastructure()
        discovered_selectors.update(infra_selectors)
        update_progress()
        
        # 4. Enhanced common selectors
        if use_common_selectors:
            common_selectors = self._get_enhanced_common_selectors()
            common_results = self.check_dkim(common_selectors)
            for selector, record in common_results.items():
                if record and selector not in discovered_selectors:
                    discovered_selectors[selector] = record
        update_progress()
        
        # 5. Advanced pattern scanning
        zone_selectors = self._advanced_dkim_scanning()
        discovered_selectors.update(zone_selectors)
        
        if use_brute_force:
            pattern_selectors = self._intelligent_pattern_discovery(discovered_selectors)
            pattern_results = self.check_dkim(pattern_selectors)
            for selector, record in pattern_results.items():
                if record and selector not in discovered_selectors:
                    discovered_selectors[selector] = record
        
        update_progress()
        return discovered_selectors


class Inspector:
    """
    Coordinates the inspection process for a given domain.
    """

    def __init__(self, domain, config):
        """Create a Domain for `domain` and retain `config` settings."""
        self.domain = Domain(domain, query_delay=config.get("query_delay", QUERY_DELAY))
        self.config = config  # Configuration settings

    def _detect_email_platform(self):
        """Detect the email platform (Google, Microsoft, etc.) based on MX records and SPF."""
        try:
            mx_records, _ = self.domain.get_dns_records("MX")
            spf_data = self.domain.check_spf()
            
            mx_hosts = []
            for mx_record in mx_records:
                parts = str(mx_record).split()
                if len(parts) >= 2:
                    mx_hosts.append(parts[1].lower().rstrip('.'))
            
            # Check MX records for platform indicators
            for mx_host in mx_hosts:
                if 'google.com' in mx_host or 'googlemail.com' in mx_host:
                    return "Google Workspace (Gmail)"
                elif 'outlook.com' in mx_host or 'protection.outlook.com' in mx_host:
                    return "Microsoft 365 (Exchange Online)"
                elif 'amazonses.com' in mx_host:
                    return "Amazon SES"
                elif 'mailgun.org' in mx_host:
                    return "Mailgun"
                elif 'sendgrid.net' in mx_host:
                    return "SendGrid"
                elif 'mandrillapp.com' in mx_host:
                    return "Mandrill (Mailchimp)"
                elif 'zoho.com' in mx_host:
                    return "Zoho Mail"
                elif 'fastmail.com' in mx_host:
                    return "FastMail"
                elif 'protonmail.ch' in mx_host:
                    return "ProtonMail"
            
            # Check SPF records for additional clues
            for spf_record in spf_data.get('records', []):
                if 'include:_spf.google.com' in spf_record:
                    return "Google Workspace (Gmail)"
                elif 'include:spf.protection.outlook.com' in spf_record:
                    return "Microsoft 365 (Exchange Online)"
                elif 'include:amazonses.com' in spf_record:
                    return "Amazon SES"
                elif 'include:mailgun.org' in spf_record:
                    return "Mailgun"
                elif 'include:sendgrid.net' in spf_record:
                    return "SendGrid"
            
            return "Unknown / Self-hosted"
            
        except Exception:
            return "Unknown"

    def _detect_email_security_provider(self):
        """Detect email security providers based on MX records and DMARC."""
        try:
            mx_records, _ = self.domain.get_dns_records("MX")
            dmarc_data = self.domain.check_dmarc()
            
            mx_hosts = []
            for mx_record in mx_records:
                parts = str(mx_record).split()
                if len(parts) >= 2:
                    mx_hosts.append(parts[1].lower().rstrip('.'))
            
            # Check for security service providers in MX records
            for mx_host in mx_hosts:
                if 'mimecast.com' in mx_host:
                    return "Mimecast"
                elif 'proofpoint.com' in mx_host:
                    return "Proofpoint"
                elif 'barracuda' in mx_host:
                    return "Barracuda"
                elif 'forcepoint.com' in mx_host:
                    return "Forcepoint"
                elif 'cisco.com' in mx_host or 'ironport.com' in mx_host:
                    return "Cisco IronPort"
                elif 'symantec.com' in mx_host:
                    return "Symantec"
                elif 'trendmicro.com' in mx_host:
                    return "Trend Micro"
                elif 'sophos.com' in mx_host:
                    return "Sophos"
                elif 'microsoft.com' in mx_host or 'protection.outlook.com' in mx_host:
                    return "Microsoft Defender for Office 365"
            
            # Check DMARC RUA/RUF for security providers
            if dmarc_data.get('rua'):
                rua = dmarc_data['rua'].lower()
                if 'barracuda' in rua:
                    return "Barracuda"
                elif 'proofpoint' in rua:
                    return "Proofpoint"
                elif 'mimecast' in rua:
                    return "Mimecast"
                elif 'agari' in rua:
                    return "Agari"
                elif 'dmarcanalyzer' in rua:
                    return "DMARC Analyzer"
                elif 'valimail' in rua:
                    return "Valimail"
            
            return None
            
        except Exception:
            return None

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
            
            import time
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
            
            # Analyze email platform and security provider first
            console.print("[*] Analyzing email infrastructure...")
            email_platform = self._detect_email_platform()
            security_provider = self._detect_email_security_provider()
            
            if email_platform:
                console.print(f"  [cyan]Email Platform: {email_platform}[/cyan]")
            if security_provider:
                console.print(f"  [cyan]Email Security Provider: {security_provider}[/cyan]")
            
            # Email Authentication Records Analysis
            console.print("\n[*] Checking email authentication records...")
            console.print("  [dim]DMARC helps prevent email spoofing by specifying how to handle unauthenticated emails[/dim]")
            
            dmarc = self.domain.check_dmarc()
            results["dmarc"] = dmarc
            if not dmarc["present"]:
                console.print("  [bold red]! No DMARC record found - emails can be easily spoofed[/bold red]")
            else:
                policy_color = "green" if dmarc["policy"] in ["quarantine", "reject"] else "yellow"
                console.print(f"  DMARC policy: [{policy_color}]{dmarc['policy']}[/{policy_color}]")
                if dmarc["policy"] == "none":
                    console.print("  [bold yellow]! DMARC policy set to 'none' - provides monitoring but no protection[/bold yellow]")
                if dmarc["rua"]:
                    console.print(f"  RUA (Aggregate Reports): {dmarc['rua']}")
                if dmarc["ruf"]:
                    console.print(f"  RUF (Forensic Reports): {dmarc['ruf']}")

            console.print("  [dim]SPF specifies which servers are authorized to send email for this domain[/dim]")
            spf = self.domain.check_spf()
            results["spf"] = spf
            if not spf["records"]:
                console.print("  [bold red]! No SPF record found - no sender authentication[/bold red]")
            else:
                for rec in spf["records"]:
                    console.print(f"  SPF: {rec}")
                if spf["soft"]:
                    console.print("  [bold yellow]! SPF ends with ~all (soft fail) - allows unauthorized senders[/bold yellow]")
                if spf["neutral"]:
                    console.print("  [bold yellow]! SPF ends with ?all (neutral) - provides no protection[/bold yellow]")
                elif not spf["soft"] and not spf["neutral"]:
                    console.print("  [green]✓ SPF properly configured with hard fail (-all)[/green]")

            # Enhanced DKIM Discovery with Progress Tracking
            console.print("\n[*] Discovering DKIM selectors...")
            console.print("  [dim]DKIM provides cryptographic signatures to verify email authenticity[/dim]")
            
            start_time = time.time()
            all_dkim_results = {}
            
            # Simplified discovery without complex progress bars to avoid timeout
            dkim_selectors = self.config.get("dkim_selectors", [])
            configured_results = {}
            if dkim_selectors:
                console.print("  [cyan]Checking configured DKIM selectors...[/cyan]")
                configured_results = self.domain.check_dkim(dkim_selectors)
                all_dkim_results.update(configured_results)
            
            # Discover additional selectors if enabled
            if self.config.get("dkim_discovery", True):
                console.print("  [cyan]Performing DKIM selector discovery...[/cyan]")
                discovered_results = self.domain.discover_dkim_selectors(
                    use_common_selectors=True, 
                    use_brute_force=False  # Disable brute force to avoid timeout
                )
                all_dkim_results.update(discovered_results)
                
                # MX-based discovery
                if self.config.get("dkim_mx_analysis", True):
                    console.print("  [cyan]Analyzing MX records for DKIM patterns...[/cyan]")
                    mx_results = self.domain.enumerate_dkim_from_mx()
                    all_dkim_results.update(mx_results)
            
            discovery_time = time.time() - start_time
            console.print(f"  [dim]Discovery completed in {discovery_time:.1f} seconds[/dim]")
            
            # Display comprehensive results
            found_selectors = {k: v for k, v in all_dkim_results.items() if v}
            missing_selectors = []
            
            if found_selectors:
                console.print(f"\n  [bold green]✓ Found {len(found_selectors)} DKIM selector(s)[/bold green]")
                
                # Create detailed DKIM table
                dkim_table = Table(title="DKIM Records Found")
                dkim_table.add_column("Selector", style="cyan")
                dkim_table.add_column("Key Type", style="magenta")
                dkim_table.add_column("Algorithm", style="green")
                dkim_table.add_column("Public Key (truncated)", style="yellow")
                dkim_table.add_column("Full Record", style="dim")
                
                for selector, record in found_selectors.items():
                    if record:
                        # Parse DKIM record for details
                        key_type = "RSA"  # Default
                        algorithm = "sha256"  # Default
                        public_key_preview = "N/A"
                        
                        record_str = str(record)
                        if "k=" in record_str:
                            key_type = record_str.split("k=")[1].split(";")[0].strip()
                        if "h=" in record_str:
                            algorithm = record_str.split("h=")[1].split(";")[0].strip()
                        if "p=" in record_str:
                            pub_key = record_str.split("p=")[1].split(";")[0].strip()
                            public_key_preview = pub_key[:32] + "..." if len(pub_key) > 32 else pub_key
                        
                        dkim_table.add_row(
                            selector,
                            key_type,
                            algorithm,
                            public_key_preview,
                            record_str[:100] + "..." if len(record_str) > 100 else record_str
                        )
                
                console.print(dkim_table)
            else:
                console.print("  [bold red]✗ No DKIM selectors found[/bold red]")
            
            # Show configured selectors that weren't found
            for sel in dkim_selectors:
                if sel not in all_dkim_results or not all_dkim_results[sel]:
                    console.print(f"  [bold red]✗ Configured DKIM selector '{sel}' missing[/bold red]")
                    missing_selectors.append(sel)
            
            results["dkim"] = {
                "found_selectors": found_selectors,
                "missing_selectors": missing_selectors,
                "discovery_time": discovery_time
            }
            results["email_platform"] = email_platform
            results["security_provider"] = security_provider
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
            
            # Website security header scanning
            if not self.config.get("quick_mode", False):
                console.print("[*] Performing security header scan...")
                security_scanner = SecurityHeaderScanner(self.domain.name)
                security_results = security_scanner.scan_security_headers()
                results["security_headers"] = security_results
            else:
                results["security_headers"] = {}
        else:
            # Web security section skipped
            results["ssl"] = {}
            results["security_headers"] = {}
        
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
    
    # Validate DKIM discovery flag compatibility
    if args.dkim_discovery and (args.dns_only or args.web_only):
        parser.error("--dkim-discovery can only be used with --email-only or when all components are enabled")
    
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
