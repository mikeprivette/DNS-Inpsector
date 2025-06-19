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
import ipaddress

console = Console()

ALL_RECORD_TYPES = [rdatatype.to_text(t) for t in rdatatype.RdataType]

# Delay between DNS queries to mimic human-like behavior
QUERY_DELAY = 0.5

# Timeout for HTTP requests made by the vulnerability scanner
REQUEST_TIMEOUT = 5  # seconds


class DomainIntelligence:
    """
    Domain Intelligence Framework for DNS-based discovery enhancement.
    Analyzes DNS patterns to categorize domains and enhance discovery across all components.
    """
    
    def __init__(self, domain_name):
        self.domain_name = domain_name
        self.intelligence = {
            'category': 'unknown',
            'hosting_provider': None,
            'email_provider': None,
            'security_stack': [],
            'cdn_provider': None,
            'organization_type': None,
            'geographic_hints': [],
            'technology_stack': [],
            'subdomain_patterns': [],
            'infrastructure_complexity': 'simple'
        }
        
    def analyze_domain_patterns(self, dns_records):
        """Comprehensive analysis of DNS patterns for domain intelligence."""
        try:
            # Analyze hosting infrastructure
            if 'A' in dns_records:
                self._analyze_hosting_infrastructure(dns_records['A'])
            
            # Analyze email infrastructure  
            if 'MX' in dns_records:
                self._analyze_email_infrastructure(dns_records['MX'])
                
            # Analyze nameserver patterns
            if 'NS' in dns_records:
                self._analyze_nameserver_patterns(dns_records['NS'])
                
            # Analyze TXT records for technology stack
            if 'TXT' in dns_records:
                self._analyze_technology_stack(dns_records['TXT'])
                
            # Analyze CNAME patterns for services
            if 'CNAME' in dns_records:
                self._analyze_service_patterns(dns_records['CNAME'])
                
            # Determine organization type
            self._determine_organization_type()
            
            # Assess infrastructure complexity
            self._assess_infrastructure_complexity(dns_records)
            
        except Exception as e:
            console.print(f"[dim]Domain intelligence analysis failed: {e}[/dim]")
            
        return self.intelligence
    
    def _analyze_hosting_infrastructure(self, a_records):
        """Analyze A records for hosting provider and infrastructure patterns."""
        providers = set()
        geographic_hints = set()
        
        for ip in a_records:
            try:
                ip_obj = ipaddress.ip_address(ip)
                provider, geo_hint = self._identify_ip_provider(str(ip_obj))
                if provider:
                    providers.add(provider)
                if geo_hint:
                    geographic_hints.add(geo_hint)
            except ValueError:
                continue
                
        if providers:
            self.intelligence['hosting_provider'] = list(providers)
        if geographic_hints:
            self.intelligence['geographic_hints'] = list(geographic_hints)
            
        # Detect load balancing patterns
        if len(a_records) > 2:
            self.intelligence['technology_stack'].append('load_balancing')
    
    def _identify_ip_provider(self, ip):
        """Identify hosting provider and geographic hints from IP address."""
        # AWS IP ranges (simplified)
        aws_ranges = [
            ('13.', 'AWS', 'us-east'),
            ('52.', 'AWS', 'global'),
            ('54.', 'AWS', 'global'),
            ('3.', 'AWS', 'global'),
            ('18.', 'AWS', 'global')
        ]
        
        # Google Cloud ranges
        gcp_ranges = [
            ('34.', 'Google Cloud', 'global'),
            ('35.', 'Google Cloud', 'global'),
            ('104.154.', 'Google Cloud', 'us-central'),
            ('130.211.', 'Google Cloud', 'global')
        ]
        
        # Cloudflare ranges
        cf_ranges = [
            ('104.16.', 'Cloudflare', 'global'),
            ('104.17.', 'Cloudflare', 'global'),
            ('172.64.', 'Cloudflare', 'global'),
            ('104.18.', 'Cloudflare', 'global')
        ]
        
        # Azure ranges
        azure_ranges = [
            ('20.', 'Azure', 'global'),
            ('40.', 'Azure', 'global'),
            ('52.', 'Azure', 'global'),
            ('104.', 'Azure', 'global')
        ]
        
        for prefix, provider, geo in aws_ranges + gcp_ranges + cf_ranges + azure_ranges:
            if ip.startswith(prefix):
                return provider, geo
                
        return None, None
    
    def _analyze_email_infrastructure(self, mx_records):
        """Analyze MX records for email provider and security patterns."""
        providers = set()
        security_services = set()
        
        for mx in mx_records:
            mx_lower = str(mx).lower()
            
            # Email providers
            if any(g in mx_lower for g in ['google.com', 'googlemail.com', 'aspmx']):
                providers.add('Google Workspace')
            elif any(m in mx_lower for m in ['outlook.com', 'protection.outlook.com']):
                providers.add('Microsoft 365')
            elif 'proofpoint' in mx_lower:
                providers.add('Proofpoint')
                security_services.add('email_security')
            elif 'mimecast' in mx_lower:
                providers.add('Mimecast')
                security_services.add('email_security')
            elif 'barracuda' in mx_lower:
                providers.add('Barracuda')
                security_services.add('email_security')
            elif any(s in mx_lower for s in ['mailgun', 'sendgrid', 'ses']):
                providers.add('Transactional Email Service')
                
        if providers:
            self.intelligence['email_provider'] = list(providers)
        if security_services:
            self.intelligence['security_stack'].extend(security_services)
    
    def _analyze_nameserver_patterns(self, ns_records):
        """Analyze nameserver patterns for hosting and management insights."""
        ns_providers = set()
        
        for ns in ns_records:
            ns_lower = str(ns).lower()
            
            if 'cloudflare' in ns_lower:
                ns_providers.add('Cloudflare')
                self.intelligence['cdn_provider'] = 'Cloudflare'
            elif 'amazonaws' in ns_lower:
                ns_providers.add('AWS Route53')
            elif 'googledomains' in ns_lower:
                ns_providers.add('Google Domains')
            elif 'dnsmadeeasy' in ns_lower:
                ns_providers.add('DNS Made Easy')
            elif 'ultradns' in ns_lower:
                ns_providers.add('UltraDNS')
            elif any(managed in ns_lower for managed in ['ns1.com', 'dnsimple', 'route53']):
                ns_providers.add('Managed DNS')
                
        if ns_providers:
            self.intelligence['technology_stack'].extend(ns_providers)
    
    def _analyze_technology_stack(self, txt_records):
        """Analyze TXT records for technology stack and service verification."""
        services = set()
        
        for record in txt_records:
            record_lower = record.lower()
            
            # Service verifications
            if 'google-site-verification' in record_lower:
                services.add('Google Services')
            elif 'facebook-domain-verification' in record_lower:
                services.add('Facebook Business')
            elif 'ms=' in record_lower:
                services.add('Microsoft Services')
            elif 'apple-domain-verification' in record_lower:
                services.add('Apple Services')
            elif 'atlassian-domain-verification' in record_lower:
                services.add('Atlassian Suite')
            elif 'zoom-domain-verification' in record_lower:
                services.add('Zoom')
            elif 'shopify' in record_lower:
                services.add('Shopify')
                self.intelligence['category'] = 'ecommerce'
            elif 'hubspot' in record_lower:
                services.add('HubSpot')
                self.intelligence['category'] = 'marketing'
            elif 'salesforce' in record_lower:
                services.add('Salesforce')
                self.intelligence['category'] = 'enterprise'
                
        if services:
            self.intelligence['technology_stack'].extend(services)
    
    def _analyze_service_patterns(self, cname_records):
        """Analyze CNAME patterns for hosted services and CDN usage."""
        for cname in cname_records:
            cname_lower = str(cname).lower()
            
            if any(cdn in cname_lower for cdn in ['cloudfront', 'fastly', 'maxcdn', 'keycdn']):
                self.intelligence['cdn_provider'] = 'CDN Service'
            elif 'shopify' in cname_lower:
                self.intelligence['category'] = 'ecommerce'
            elif 'wordpress' in cname_lower:
                self.intelligence['technology_stack'].append('WordPress')
            elif 'github' in cname_lower:
                self.intelligence['technology_stack'].append('GitHub Pages')
    
    def _determine_organization_type(self):
        """Determine organization type based on domain patterns and services."""
        domain_lower = self.domain_name.lower()
        
        # Government domains
        if domain_lower.endswith('.gov') or domain_lower.endswith('.mil'):
            self.intelligence['organization_type'] = 'government'
            self.intelligence['category'] = 'government'
        # Educational domains
        elif domain_lower.endswith('.edu') or domain_lower.endswith('.ac.'):
            self.intelligence['organization_type'] = 'education'
            self.intelligence['category'] = 'education'
        # Non-profit domains
        elif domain_lower.endswith('.org'):
            self.intelligence['organization_type'] = 'non_profit'
        # Commercial domains with specific patterns
        elif any(term in domain_lower for term in ['bank', 'financial', 'credit']):
            self.intelligence['organization_type'] = 'financial'
            self.intelligence['category'] = 'financial'
        elif any(term in domain_lower for term in ['health', 'medical', 'hospital']):
            self.intelligence['organization_type'] = 'healthcare'
            self.intelligence['category'] = 'healthcare'
        elif any(term in domain_lower for term in ['shop', 'store', 'buy', 'cart']):
            self.intelligence['organization_type'] = 'ecommerce'
            self.intelligence['category'] = 'ecommerce'
    
    def _assess_infrastructure_complexity(self, dns_records):
        """Assess infrastructure complexity based on DNS record patterns."""
        complexity_score = 0
        
        # Multiple A records suggest load balancing
        if 'A' in dns_records and len(dns_records['A']) > 2:
            complexity_score += 2
            
        # Multiple MX records suggest redundancy
        if 'MX' in dns_records and len(dns_records['MX']) > 1:
            complexity_score += 1
            
        # Many TXT records suggest multiple services
        if 'TXT' in dns_records and len(dns_records['TXT']) > 5:
            complexity_score += 2
            
        # Multiple NS records suggest managed DNS
        if 'NS' in dns_records and len(dns_records['NS']) > 2:
            complexity_score += 1
        
        # CNAME records suggest service delegation
        if 'CNAME' in dns_records and len(dns_records['CNAME']) > 0:
            complexity_score += 1
            
        if complexity_score >= 5:
            self.intelligence['infrastructure_complexity'] = 'enterprise'
        elif complexity_score >= 3:
            self.intelligence['infrastructure_complexity'] = 'moderate'
        else:
            self.intelligence['infrastructure_complexity'] = 'simple'
    
    def get_targeted_subdomains(self):
        """Generate targeted subdomain lists based on domain intelligence."""
        base_subdomains = []
        
        # Category-specific subdomains
        if self.intelligence['category'] == 'ecommerce':
            base_subdomains.extend(['shop', 'store', 'cart', 'checkout', 'pay', 'payments', 'secure'])
        elif self.intelligence['category'] == 'financial':
            base_subdomains.extend(['secure', 'banking', 'online', 'mobile', 'portal', 'login'])
        elif self.intelligence['category'] == 'healthcare':
            base_subdomains.extend(['patient', 'portal', 'secure', 'records', 'appointment'])
        elif self.intelligence['category'] == 'education':
            base_subdomains.extend(['student', 'faculty', 'portal', 'library', 'courses', 'lms'])
        elif self.intelligence['category'] == 'government':
            base_subdomains.extend(['portal', 'services', 'citizen', 'secure', 'public'])
            
        # Hosting provider specific subdomains
        if 'AWS' in str(self.intelligence.get('hosting_provider', [])):
            base_subdomains.extend(['s3', 'cdn', 'assets', 'static'])
        if 'Google Cloud' in str(self.intelligence.get('hosting_provider', [])):
            base_subdomains.extend(['storage', 'cdn', 'compute'])
        if 'Cloudflare' in str(self.intelligence.get('cdn_provider', '')):
            base_subdomains.extend(['cdn', 'assets', 'static', 'media'])
            
        # Technology stack specific subdomains
        if 'WordPress' in self.intelligence.get('technology_stack', []):
            base_subdomains.extend(['blog', 'wp', 'wordpress'])
        if 'Shopify' in self.intelligence.get('technology_stack', []):
            base_subdomains.extend(['shop', 'store', 'checkout'])
        if 'Salesforce' in self.intelligence.get('technology_stack', []):
            base_subdomains.extend(['crm', 'sales', 'force'])
            
        return list(set(base_subdomains))
    
    def get_enhanced_dkim_selectors(self):
        """Generate enhanced DKIM selector lists based on domain intelligence."""
        enhanced_selectors = []
        
        # Organization type specific selectors
        if self.intelligence.get('organization_type') == 'financial':
            enhanced_selectors.extend(['secure', 'bank', 'fin', 'safe'])
        elif self.intelligence.get('organization_type') == 'healthcare':
            enhanced_selectors.extend(['hipaa', 'secure', 'med', 'health'])
        elif self.intelligence.get('organization_type') == 'government':
            enhanced_selectors.extend(['gov', 'secure', 'official', 'fed'])
        elif self.intelligence.get('organization_type') == 'education':
            enhanced_selectors.extend(['edu', 'academic', 'university', 'college'])
            
        # Infrastructure complexity selectors
        if self.intelligence.get('infrastructure_complexity') == 'enterprise':
            enhanced_selectors.extend(['enterprise', 'corp', 'internal', 'prod', 'staging'])
            
        return enhanced_selectors


class Domain:
    """
    Represents a domain and includes methods to perform various checks.
    """

    def __init__(self, name, query_delay=QUERY_DELAY):
        """Store the domain `name` and DNS `query_delay`."""
        self.name = name
        self.query_delay = query_delay
        self.intelligence = DomainIntelligence(name)
        self.dns_cache = {}  # Cache DNS records for intelligence analysis

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

    def get_enhanced_subdomains(self, base_subdomains):
        """Get enhanced subdomain list based on domain intelligence analysis."""
        try:
            # Perform domain intelligence analysis if not already done
            if not self.dns_cache:
                # Quick DNS collection for intelligence
                for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
                    try:
                        records, _ = self.get_dns_records(record_type)
                        if records:
                            self.dns_cache[record_type] = records
                    except Exception:
                        continue
                        
                # Analyze domain patterns
                self.intelligence.analyze_domain_patterns(self.dns_cache)
            
            # Get targeted subdomains from intelligence
            targeted_subs = self.intelligence.get_targeted_subdomains()
            
            # Combine with base subdomains, prioritizing intelligence-based ones
            enhanced_list = targeted_subs + [sub for sub in base_subdomains if sub not in targeted_subs]
            
            if targeted_subs:
                console.print(f"  [dim]Domain intelligence added {len(targeted_subs)} targeted subdomains[/dim]")
                
            return enhanced_list
            
        except Exception as e:
            console.print(f"  [dim]Intelligence enhancement failed: {e}[/dim]")
            return base_subdomains

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

    def check_dkim(self, selectors, show_progress=False, rate_limit=None):
        """Check DKIM TXT records for the provided selectors with improved error handling and rate limiting."""
        import time
        results = {}
        valid_selectors = []
        
        # Apply rate limiting if specified
        if rate_limit is None:
            rate_limit = 10  # Default 10 queries per second
        delay_between_queries = 1.0 / rate_limit if rate_limit > 0 else 0
        
        if show_progress and len(selectors) > 10:
            from rich.progress import Progress
            with Progress() as progress:
                task = progress.add_task("[cyan]Checking DKIM selectors...", total=len(selectors))
                
                for sel in selectors:
                    name = f"{sel}._domainkey.{self.name}"
                    records, _ = self.get_txt_record(name)
                    found = None
                    for rec in records:
                        if "v=DKIM1" in rec:
                            found = rec
                            valid_selectors.append(sel)
                            break
                    results[sel] = found
                    progress.advance(task)
                    
                    # Rate limiting
                    if delay_between_queries > 0:
                        time.sleep(delay_between_queries)
        else:
            for sel in selectors:
                name = f"{sel}._domainkey.{self.name}"
                records, _ = self.get_txt_record(name)
                found = None
                for rec in records:
                    if "v=DKIM1" in rec:
                        found = rec
                        valid_selectors.append(sel)
                        break
                results[sel] = found
                
                # Rate limiting
                if delay_between_queries > 0:
                    time.sleep(delay_between_queries)
        
        return results, valid_selectors

    def discover_dkim_selectors(self, use_common_selectors=True, use_brute_force=False, config_manager=None):
        """
        Discover DKIM selectors using enhanced smart techniques with provider-specific targeting.
        
        Args:
            use_common_selectors (bool): Check against top 40 common selector names
            use_brute_force (bool): Attempt intelligent brute force with patterns
            config_manager: Configuration manager for provider-specific settings
            
        Returns:
            dict: Dictionary with discovery results and metadata
        """
        from rich.console import Console
        console = Console()
        
        discovery_results = {
            'found_selectors': {},
            'discovery_methods': [],
            'total_checked': 0,
            'intelligence_sources': []
        }
        
        # 1. Enhanced email platform intelligence with provider-specific targeting
        console.print("  [cyan]• Analyzing email platform for targeted discovery...[/cyan]")
        platform_selectors = self._get_platform_specific_selectors(config_manager)
        if platform_selectors:
            results, valid = self.check_dkim(platform_selectors, show_progress=False)
            discovery_results['found_selectors'].update({k: v for k, v in results.items() if v})
            discovery_results['total_checked'] += len(platform_selectors)
            if valid:
                discovery_results['intelligence_sources'].append(f"Email platform patterns ({len(valid)} found)")
        
        # 2. SPF Record Analysis - Extract domains from SPF includes  
        console.print("  [cyan]• Extracting DKIM clues from SPF records...[/cyan]")
        spf_selectors = self._extract_dkim_from_spf()
        if spf_selectors:
            discovery_results['found_selectors'].update(spf_selectors)
            discovery_results['intelligence_sources'].append(f"SPF analysis ({len(spf_selectors)} found)")
        
        # 3. Domain intelligence enhanced selectors
        if hasattr(self, 'intelligence') and self.intelligence:
            console.print("  [cyan]• Applying domain intelligence for DKIM discovery...[/cyan]")
            intel_selectors = self.intelligence.get_enhanced_dkim_selectors()
            if intel_selectors:
                results, valid = self.check_dkim(intel_selectors, show_progress=False)
                discovery_results['found_selectors'].update({k: v for k, v in results.items() if v})
                discovery_results['total_checked'] += len(intel_selectors)
                if valid:
                    discovery_results['intelligence_sources'].append(f"Domain intelligence ({len(valid)} found)")
        
        # 4. Top 40 common selectors (research-based for maximum efficiency)
        if use_common_selectors and len(discovery_results['found_selectors']) < 5:
            console.print("  [cyan]• Checking top 40 DKIM selector patterns...[/cyan]")
            common_selectors = self._get_smart_common_selectors(config_manager)
            results, valid = self.check_dkim(common_selectors, show_progress=len(common_selectors) > 20)
            discovery_results['found_selectors'].update({k: v for k, v in results.items() if v})
            discovery_results['total_checked'] += len(common_selectors)
            if valid:
                discovery_results['intelligence_sources'].append(f"Top 40 patterns ({len(valid)} found)")
        
        # 5. Advanced pattern discovery (only if brute force enabled)
        if use_brute_force and len(discovery_results['found_selectors']) > 0:
            console.print("  [cyan]• Performing intelligent pattern-based discovery...[/cyan]")
            pattern_selectors = self._intelligent_pattern_discovery(discovery_results['found_selectors'])
            if pattern_selectors:
                results, valid = self.check_dkim(pattern_selectors, show_progress=True)
                discovery_results['found_selectors'].update({k: v for k, v in results.items() if v})
                discovery_results['total_checked'] += len(pattern_selectors)
                if valid:
                    discovery_results['intelligence_sources'].append(f"Pattern analysis ({len(valid)} found)")
        
        discovery_results['discovery_methods'] = [
            'Platform Intelligence', 'SPF Analysis', 'Common Patterns'
        ]
        if use_brute_force:
            discovery_results['discovery_methods'].append('Pattern Recognition')
            
        return discovery_results

    def _extract_dkim_from_spf(self):
        """Extract potential DKIM selectors by analyzing SPF includes with improved efficiency."""
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
                        candidates = []
                        if 'mailgun' in included_domain:
                            candidates = ['mg', 'mailgun', 'mta']
                        elif 'sendgrid' in included_domain:
                            candidates = ['sendgrid', 'sg', 'em']
                        elif 'amazonses' in included_domain or 'ses' in included_domain:
                            candidates = ['amazonses', 'ses', 'aws']
                        elif 'office365' in included_domain or 'outlook' in included_domain:
                            candidates = ['selector1', 'selector2', 'microsoft']
                        elif 'google' in included_domain or 'gmail' in included_domain:
                            # Google uses date-based selectors - check recent months only
                            import datetime
                            now = datetime.datetime.now()
                            candidates = ['google', 'gmail']
                            for months_back in range(6):  # Only check last 6 months
                                date = now - datetime.timedelta(days=30 * months_back)
                                candidates.append(f"{date.year}{date.month:02d}")
                        elif 'mailchimp' in included_domain:
                            candidates = ['k1', 'k2', 'mailchimp']
                        elif 'constantcontact' in included_domain:
                            candidates = ['cc', 'constantcontact']
                            
                        if candidates:
                            results, valid = self.check_dkim(candidates)
                            selectors.update({k: v for k, v in results.items() if v})
                            
        except Exception as e:
            # Silently continue - SPF analysis is optional intelligence
            pass
        
        return selectors

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
                results, valid = self.check_dkim(enterprise_selectors)
                selectors.update({k: v for k, v in results.items() if v})
        except Exception:
            pass
        
        return selectors

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
            
            # Analyze hosting patterns
            for mx_host in mx_hosts:
                candidates = []
                
                if any(cloud in mx_host for cloud in ['amazonaws', 'google', 'azure', 'cloudflare']):
                    candidates = ['default', 'auto', 'cloud', 'managed', 'service']
                elif 'protection.outlook.com' in mx_host:
                    candidates = ['selector1', 'selector2', 'microsoft', 'o365']
                elif any(security in mx_host for security in ['mimecast', 'proofpoint', 'forcepoint']):
                    candidates = ['default', 'sec', 'security', 'filter', 'gateway']
                    
                if candidates:
                    results, valid = self.check_dkim(candidates)
                    selectors.update({k: v for k, v in results.items() if v})
                    
        except Exception:
            # Silently continue - infrastructure analysis is optional
            pass
        
        return selectors

    def _get_platform_specific_selectors(self, config_manager=None):
        """Get selectors based on detected email platform for targeted discovery."""
        try:
            # Quick MX and SPF analysis to determine platform
            mx_records, _ = self.get_dns_records("MX")
            spf_data = self.check_spf()
            
            platform_selectors = set()
            
            # Analyze MX records for platform detection
            for mx_record in mx_records:
                mx_host = str(mx_record).split()[-1].lower().rstrip('.')
                
                if 'google' in mx_host:
                    # Google Workspace - uses monthly rotation
                    import datetime
                    now = datetime.datetime.now()
                    for months_back in range(6):  # Check last 6 months
                        date = now - datetime.timedelta(days=30 * months_back)
                        platform_selectors.add(f"{date.year}{date.month:02d}")
                    platform_selectors.update(['google', 'googlemail', 'gapps'])
                    
                elif 'outlook.com' in mx_host or 'protection.outlook.com' in mx_host:
                    # Microsoft 365 - uses selector1/selector2
                    platform_selectors.update(['selector1', 'selector2', 'microsoft', 'o365'])
                    
                elif 'amazonses.com' in mx_host:
                    platform_selectors.update(['amazonses', 'ses', 'aws'])
                    
                elif 'mailgun' in mx_host:
                    platform_selectors.update(['mailgun', 'mg', 'mta'])
                    
                elif 'sendgrid' in mx_host:
                    platform_selectors.update(['sendgrid', 's1', 's2'])
                    
            # Analyze SPF records for additional clues
            for spf_record in spf_data.get('records', []):
                if 'google.com' in spf_record:
                    # Add Google-specific selectors if not already added
                    import datetime
                    now = datetime.datetime.now()
                    for months_back in range(3):
                        date = now - datetime.timedelta(days=30 * months_back)
                        platform_selectors.add(f"{date.year}{date.month:02d}")
                        
            return list(platform_selectors)[:20]  # Limit to prevent excessive queries
            
        except Exception:
            return []
    
    def _get_smart_common_selectors(self, config_manager=None):
        """Get top 40 DKIM selectors based on usage statistics and research for maximum discovery efficiency."""
        # Top 40 selectors from research, ordered by frequency
        top_40_selectors = [
            # Top frequency selectors (usage statistics)
            "mail", "default", "dkim", "k1", "google", "selector2", "key1", "key2", "selector1",
            # High-frequency generic patterns
            "dk", "s1", "s2", "m1", "private", "test", "prod", "smtp", "mta", "mx", "class", "root",
            # Provider-specific selectors
            "ctct1", "ctct2", "zendesk1", "zendesk2", "sm", "litesrv", "sig1",
            # Time-based patterns (most common)
            "200608", "20150623", "20221208", "20230601", "s1024-2013-q3", "scph0920", "scph1122",
            # Numeric patterns
            "10dkim1", "11dkim1", "12dkim1", "13dkim1", "s1024", "s1024a", "dkim1024"
        ]
        
        # If config manager is available, get configured selectors
        if config_manager:
            config_selectors = config_manager.get_setting("DKIM", "selectors", fallback=[])
            # Merge with top 40, prioritizing configured selectors
            all_selectors = list(dict.fromkeys(config_selectors + top_40_selectors))
        else:
            all_selectors = top_40_selectors
        
        return all_selectors[:40]  # Ensure we maintain the top 40 limit for efficiency

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
        
        return list(pattern_selectors)[:50]  # Limit to prevent excessive queries
        
    def _parse_dkim_record(self, record):
        """Parse DKIM record and extract key information for display."""
        record_str = str(record)
        
        # Extract key type
        key_type = "RSA"  # Default
        if "k=" in record_str:
            key_match = record_str.split("k=")[1].split(";")[0].strip()
            key_type = key_match if key_match else "RSA"
            
        # Extract hash algorithm
        algorithm = "sha256"  # Default 
        if "h=" in record_str:
            hash_match = record_str.split("h=")[1].split(";")[0].strip()
            algorithm = hash_match if hash_match else "sha256"
            
        # Extract and assess public key
        public_key_preview = "N/A"
        status = "Valid"
        if "p=" in record_str:
            pub_key = record_str.split("p=")[1].split(";")[0].strip()
            if pub_key:
                # Assess RSA key strength by decoded size
                key_bits = self._estimate_rsa_key_bits(pub_key)
                if key_bits == 0:
                    status = "Invalid (malformed key)"
                elif key_bits < 1024:
                    status = "Weak (<1024-bit)"
                elif key_bits == 1024:
                    status = "Weak (1024-bit RSA)"
                elif key_bits == 2048:
                    status = "Strong (2048-bit RSA)"
                elif key_bits > 2048:
                    status = f"Strong ({key_bits}-bit RSA)"
                else:
                    status = "Standard"
                    
                public_key_preview = pub_key[:32] + "..." if len(pub_key) > 32 else pub_key
            else:
                status = "Revoked (empty key)"
                public_key_preview = "(empty)"
        
        return key_type, algorithm, status, public_key_preview
    
    def _estimate_rsa_key_bits(self, pub_key_b64):
        """Estimate RSA key bit length from base64-encoded public key."""
        try:
            import base64
            
            # Decode base64
            key_data = base64.b64decode(pub_key_b64)
            key_size = len(key_data)
            
            # RSA public key size approximations:
            # 1024-bit RSA ≈ 140-180 bytes
            # 2048-bit RSA ≈ 270-300 bytes  
            # 4096-bit RSA ≈ 540-580 bytes
            
            if key_size <= 128:
                return 512  # Very weak
            elif key_size <= 180:
                return 1024  # Weak
            elif key_size <= 320:
                return 2048  # Strong
            elif key_size <= 600:
                return 4096  # Very strong
            else:
                return 8192  # Extremely strong
                
        except Exception:
            return 0  # Unable to determine
    
    def _check_prove_email_archive(self):
        """Check archive.prove.email for historical DKIM selectors."""
        discovered_selectors = {}
        
        try:
            import requests
            import json
            
            # Query the archive.prove.email API for known selectors
            api_url = f"https://archive.prove.email/api/selectors/{self.name}"
            
            headers = {
                'User-Agent': 'DNS-Inspector-Tool/1.0',
                'Accept': 'application/json'
            }
            
            response = requests.get(api_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'selectors' in data:
                    # Validate each selector found in archive
                    for selector in data['selectors']:
                        if isinstance(selector, str) and len(selector) <= 50:  # Reasonable selector length
                            # Verify the selector still exists
                            results, _ = self.check_dkim([selector])
                            if results and results.get(selector):
                                discovered_selectors[selector] = results[selector]
                                
        except Exception:
            # Archive lookup is optional - silently continue on any error
            pass
            
        return discovered_selectors
        
    def _assess_dkim_security(self, selectors):
        """Provide security assessment of found DKIM selectors."""
        if not selectors:
            return
            
        from rich.console import Console
        console = Console()
        
        assessments = []
        strong_keys = 0
        weak_keys = 0
        revoked_keys = 0
        
        for selector, record in selectors.items():
            if record:
                record_str = str(record)
                if "p=" in record_str:
                    pub_key = record_str.split("p=")[1].split(";")[0].strip()
                    if not pub_key:
                        revoked_keys += 1
                        assessments.append(f"Selector '{selector}' has revoked key")
                    elif len(pub_key) < 200:
                        weak_keys += 1
                        assessments.append(f"Selector '{selector}' has weak key")
                    else:
                        strong_keys += 1
        
        # Overall assessment
        if strong_keys > 0 and weak_keys == 0 and revoked_keys == 0:
            console.print("  [bold green]✓ DKIM security: Excellent[/bold green]")
        elif strong_keys > 0 and (weak_keys > 0 or revoked_keys > 0):
            console.print("  [bold yellow]⚠ DKIM security: Mixed (some weak keys)[/bold yellow]")
        elif weak_keys > 0:
            console.print("  [bold yellow]⚠ DKIM security: Weak (short keys detected)[/bold yellow]")
        elif revoked_keys > 0:
            console.print("  [bold red]✗ DKIM security: Poor (revoked keys found)[/bold red]")
            
        # Show specific issues
        for assessment in assessments[:3]:  # Limit to top 3 issues
            console.print(f"  [dim]• {assessment}[/dim]")

    def _advanced_dkim_scanning(self):
        """Advanced DKIM scanning using organizational and time-based patterns."""
        selectors = {}
        
        try:
            # Check for common organizational patterns
            org_patterns = self._get_organizational_patterns()
            if org_patterns:
                results, valid = self.check_dkim(org_patterns)
                selectors.update({k: v for k, v in results.items() if v})
            
            # Time-based rotation detection (only if no patterns found yet)
            if not selectors:
                time_patterns = self._detect_time_based_selectors()
                if time_patterns:
                    results, valid = self.check_dkim(time_patterns)
                    selectors.update({k: v for k, v in results.items() if v})
                
        except Exception:
            # Silently continue - advanced scanning is optional
            pass
        
        return selectors

    def _get_organizational_patterns(self):
        """Generate selectors based on domain/organization patterns."""
        patterns = []
        
        # Extract potential organization name from domain
        domain_parts = self.name.lower().split('.')
        if len(domain_parts) >= 2:
            org_name = domain_parts[0]
            
            # Only generate patterns for reasonable org names (not too short/long)
            if 3 <= len(org_name) <= 15:
                # Basic organization patterns
                patterns.extend([
                    org_name, f"{org_name}1", f"{org_name}2",
                    f"{org_name}-mail", f"{org_name}mail"
                ])
                
                # Company abbreviation patterns
                abbrevs = self._generate_company_abbreviations(org_name)
                patterns.extend(abbrevs)
                
                # Try only most common business patterns
                for prefix in ['mail', 'email']:
                    patterns.append(f"{prefix}-{org_name}")
                    if abbrevs:
                        patterns.append(f"{prefix}-{abbrevs[0]}")
        
        return patterns[:20]  # Limit results to prevent excessive queries
    
    def _generate_company_abbreviations(self, company_name):
        """Generate likely company abbreviations for DKIM selector patterns."""
        abbrevs = []
        
        # Common abbreviation patterns
        if len(company_name) >= 4:
            # First 3-4 characters
            abbrevs.extend([company_name[:3], company_name[:4]])
            
            # Vowel removal (common IT pattern)
            no_vowels = ''.join([c for c in company_name if c not in 'aeiou'])
            if len(no_vowels) >= 2 and no_vowels != company_name:
                abbrevs.append(no_vowels[:4])
        
        # Industry-specific patterns
        common_suffixes = ['corp', 'inc', 'ltd', 'llc', 'co', 'company', 'group', 'tech', 'systems', 'solutions']
        for suffix in common_suffixes:
            if company_name.endswith(suffix):
                base = company_name[:-len(suffix)].strip()
                if len(base) >= 2:
                    abbrevs.extend([base, base[:3], base[:4]])
                break
        
        # Remove duplicates and filter reasonable length
        abbrevs = list(set([a for a in abbrevs if 2 <= len(a) <= 6]))
        return abbrevs[:5]  # Limit to prevent excessive queries

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
        Attempt to discover DKIM selectors based on MX record patterns with improved efficiency.
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
                        # Add recent Google selectors
                        import datetime
                        now = datetime.datetime.now()
                        potential_selectors.extend(["google", "googleapis", "gapps"])
                        for months_back in range(3):  # Check last 3 months
                            date = now - datetime.timedelta(days=30 * months_back)
                            potential_selectors.append(f"{date.year}{date.month:02d}")
                    elif "outlook" in mx_host.lower() or "microsoft" in mx_host.lower():
                        potential_selectors.extend(["selector1", "selector2", "microsoft"])
                    elif "amazon" in mx_host.lower() or "ses" in mx_host.lower():
                        potential_selectors.extend(["amazonses", "ses"])
                    elif "mailgun" in mx_host.lower():
                        potential_selectors.extend(["mailgun", "mg"])
                    elif "sendgrid" in mx_host.lower():
                        potential_selectors.extend(["sendgrid", "sg"])
                
                if potential_selectors:
                    results, valid = self.check_dkim(potential_selectors)
                    discovered_selectors.update({k: v for k, v in results.items() if v})
        
        except Exception:
            # Silently continue - MX analysis is optional intelligence
            pass
        
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

    def __init__(self, domain, config, config_manager=None):
        """Create a Domain for `domain` and retain `config` settings."""
        self.domain = Domain(domain, query_delay=config.get("query_delay", QUERY_DELAY))
        self.config = config  # Configuration settings
        self.config_manager = config_manager  # Store config manager for DKIM provider targeting

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
    
    def _display_domain_intelligence(self):
        """Display domain intelligence summary for enhanced discovery context."""
        try:
            # Trigger intelligence analysis if not already done
            if not self.domain.dns_cache:
                for record_type in ['A', 'MX', 'NS', 'TXT']:
                    try:
                        records, _ = self.domain.get_dns_records(record_type)
                        if records:
                            self.domain.dns_cache[record_type] = records
                    except Exception:
                        continue
                
                self.domain.intelligence.analyze_domain_patterns(self.domain.dns_cache)
            
            intel = self.domain.intelligence.intelligence
            
            # Create intelligence summary
            intelligence_items = []
            
            if intel.get('category') != 'unknown':
                intelligence_items.append(f"Category: {intel['category'].title()}")
                
            if intel.get('organization_type'):
                intelligence_items.append(f"Type: {intel['organization_type'].replace('_', ' ').title()}")
                
            if intel.get('hosting_provider'):
                providers = intel['hosting_provider']
                if isinstance(providers, list):
                    intelligence_items.append(f"Hosting: {', '.join(providers)}")
                else:
                    intelligence_items.append(f"Hosting: {providers}")
                    
            if intel.get('email_provider'):
                providers = intel['email_provider']
                if isinstance(providers, list):
                    intelligence_items.append(f"Email: {', '.join(providers)}")
                else:
                    intelligence_items.append(f"Email: {providers}")
                    
            if intel.get('cdn_provider'):
                intelligence_items.append(f"CDN: {intel['cdn_provider']}")
                
            if intel.get('infrastructure_complexity') != 'simple':
                intelligence_items.append(f"Infrastructure: {intel['infrastructure_complexity'].title()}")
                
            if intel.get('security_stack'):
                security = ', '.join(intel['security_stack'])
                intelligence_items.append(f"Security: {security}")
                
            if intelligence_items:
                console.print(f"[dim]Domain Intelligence: {' | '.join(intelligence_items)}[/dim]")
                
        except Exception as e:
            console.print(f"[dim]Domain intelligence analysis failed: {e}[/dim]")

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
        
        # Display domain intelligence summary
        self._display_domain_intelligence()
        
        results = {"domain": self.domain.name, "components": components}

        # DNS Discovery Section
        if self.config.get("run_dns", True):
            console.print("[bold blue]===== DNS DISCOVERY =====[/bold blue]")
            console.print("  [dim]Analyzing DNS infrastructure and identifying potential security issues[/dim]")
            
            # Intelligent wildcard checking - only check if we have record types
            wildcard_found = False
            if self.config["dns_record_types"]:
                console.print("\n[*] Checking for wildcard DNS configurations...")
                wildcard_found = self.domain.check_wildcard_records(self.config["dns_record_types"])
                results["wildcard"] = wildcard_found
                if wildcard_found:
                    console.print("  [bold red]⚠ Wildcard DNS records detected[/bold red]")
                    console.print("  [yellow]• Potential security risk: Could enable subdomain takeover attacks[/yellow]")
                    console.print("  [yellow]• Recommendation: Review wildcard configurations for necessity[/yellow]")
                else:
                    console.print("  [green]✓ No wildcard DNS records found[/green]")
            else:
                results["wildcard"] = False

            # Enhanced subdomain enumeration with intelligence
            subdomain_results = self._perform_intelligent_subdomain_discovery()
            subdomains = subdomain_results['subdomains']
            subdomain_count = len(subdomains)
            results["subdomains"] = sorted(subdomains)
            
            # Display subdomain results with insights
            if subdomains:
                console.print(f"\n[bold green]✓ Found {subdomain_count} subdomain(s)[/bold green]")
                if subdomain_results['sources']:
                    console.print(f"  [dim]Discovery sources: {', '.join(subdomain_results['sources'])}[/dim]")
                    
                # Create categorized subdomain table
                subdomain_table = self._create_subdomain_table(subdomains)
                console.print(subdomain_table)
                
                # Show subdomain insights
                if subdomain_results['insights']:
                    console.print("\n[bold cyan]Subdomain Analysis:[/bold cyan]")
                    for insight in subdomain_results['insights']:
                        console.print(f"  {insight}")
            elif self.config.get("subdomains") or self.config.get("zone_transfer"):
                console.print("\n  [yellow]No subdomains discovered through enumeration[/yellow]")
                console.print("  [dim]• Domain may use different naming conventions[/dim]")
                console.print("  [dim]• Consider updating wordlist or enabling additional discovery methods[/dim]")

            # Smart DNS record gathering with analysis
            if self.config["dns_record_types"]:
                console.print("\n[*] Gathering and analyzing DNS records...")
                dns_results = self._analyze_dns_records_intelligently()
                
                results["dns_records"] = dns_results["records"]
                results["meta_errors"] = dns_results["meta_errors"]
                
                # Display organized results
                if dns_results["record_table"].row_count > 0:
                    console.print(dns_results["record_table"])
                    
                # Show DNS insights
                if dns_results["insights"]:
                    console.print("\n[bold cyan]DNS Infrastructure Insights:[/bold cyan]")
                    for insight in dns_results["insights"]:
                        console.print(f"  {insight}")
                
                # Handle meta errors gracefully
                if dns_results["meta_errors"]:
                    console.print(f"\n  [dim]Note: Some DNS queries restricted by provider: {', '.join(dns_results['meta_errors'])}[/dim]")
                    
                # Enhanced DNS Summary with security assessment
                dns_summary = self._create_dns_security_summary(dns_results["records"], subdomain_count, wildcard_found)
                if dns_summary:
                    console.print(dns_summary)
            else:
                results["dns_records"] = {}
                results["meta_errors"] = []
                console.print("  [dim]No DNS record types configured for analysis[/dim]")
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

            # Enhanced DKIM Discovery with Better User Experience
            console.print("\n[*] Discovering DKIM selectors...")
            console.print("  [dim]DKIM provides cryptographic signatures to verify email authenticity[/dim]")
            
            start_time = time.time()
            all_found_selectors = {}
            configured_missing = []
            discovery_sources = []
            total_checked = 0
            
            # 1. Check configured selectors first (if any)
            dkim_selectors = self.config.get("dkim_selectors", [])
            dkim_rate_limit = self.config.get("dkim_rate_limit", 10)
            if dkim_selectors:
                console.print("  [cyan]• Checking configured DKIM selectors...[/cyan]")
                configured_results, valid_configured = self.domain.check_dkim(dkim_selectors, rate_limit=dkim_rate_limit)
                all_found_selectors.update({k: v for k, v in configured_results.items() if v})
                configured_missing = [k for k in dkim_selectors if k not in all_found_selectors]
                total_checked += len(dkim_selectors)
                if valid_configured:
                    discovery_sources.append(f"Configuration file ({len(valid_configured)} found)")
            
            # 2. Smart discovery if enabled
            if self.config.get("dkim_discovery", True):
                discovery_results = self.domain.discover_dkim_selectors(
                    use_common_selectors=True, 
                    use_brute_force=self.config.get("dkim_brute_force", False),
                    config_manager=self.config_manager
                )
                all_found_selectors.update(discovery_results['found_selectors'])
                discovery_sources.extend(discovery_results['intelligence_sources'])
                total_checked += discovery_results['total_checked']
                
                # MX-based discovery if enabled
                if self.config.get("dkim_mx_analysis", True):
                    console.print("  [cyan]• Analyzing MX records for DKIM patterns...[/cyan]")
                    mx_results = self.domain.enumerate_dkim_from_mx()
                    if mx_results:
                        all_found_selectors.update(mx_results)
                        discovery_sources.append(f"MX analysis ({len(mx_results)} found)")
                
                # Archive.prove.email lookup for historical data
                if len(all_found_selectors) < 5:
                    console.print("  [cyan]• Checking historical DKIM registry...[/cyan]")
                    archive_results = self.domain._check_prove_email_archive()
                    if archive_results:
                        all_found_selectors.update(archive_results)
                        discovery_sources.append(f"Archive registry ({len(archive_results)} found)")
            
            discovery_time = time.time() - start_time
            
            # Display results with better categorization
            if all_found_selectors:
                console.print(f"\n  [bold green]✓ Found {len(all_found_selectors)} DKIM selector(s)[/bold green]")
                if discovery_sources:
                    console.print(f"  [dim]Discovery sources: {', '.join(discovery_sources)}[/dim]")
                console.print(f"  [dim]Checked {total_checked} selectors in {discovery_time:.1f}s[/dim]")
                
                # Create enhanced DKIM table
                dkim_table = Table(title="DKIM Records Found")
                dkim_table.add_column("Selector", style="cyan", no_wrap=True)
                dkim_table.add_column("Algorithm", style="green")
                dkim_table.add_column("Key Type", style="magenta")
                dkim_table.add_column("Status", style="yellow")
                dkim_table.add_column("Public Key", style="dim", max_width=40)
                
                for selector, record in sorted(all_found_selectors.items()):
                    if record:
                        # Parse DKIM record for details
                        key_type, algorithm, status, pub_key_preview = self.domain._parse_dkim_record(record)
                        
                        # Determine if this was a configured selector
                        source_info = "Configured" if selector in dkim_selectors else "Discovered"
                        
                        dkim_table.add_row(
                            selector,
                            algorithm,
                            key_type,
                            f"{status} ({source_info})",
                            pub_key_preview
                        )
                
                console.print(dkim_table)
                
                # Security assessment
                self.domain._assess_dkim_security(all_found_selectors)
                
            else:
                console.print("  [bold red]✗ No DKIM selectors found[/bold red]")
                console.print("  [yellow]• This domain may not have DKIM configured[/yellow]")
                console.print("  [yellow]• Emails from this domain cannot be cryptographically verified[/yellow]")
            
            # Show configured selectors that are missing (only if discovery is disabled or no selectors found)
            if configured_missing and dkim_selectors and (not self.config.get("dkim_discovery", True) or not all_found_selectors):
                console.print(f"\n  [yellow]⚠ Configured selectors not found: {', '.join(configured_missing)}[/yellow]")
                console.print("  [dim]Consider updating your configuration file or checking with your email provider[/dim]")
            
            results["dkim"] = {
                "found_selectors": all_found_selectors,
                "configured_missing": configured_missing,
                "discovery_time": discovery_time,
                "total_checked": total_checked,
                "discovery_sources": discovery_sources
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
            console.print("  [dim]Analyzing website security configuration and best practices[/dim]")
            
            # Enhanced SSL/TLS Certificate validation
            console.print("\n[*] Analyzing SSL/TLS configuration...")
            ssl_validator = SSLValidator(self.domain.name)
            ssl_results = ssl_validator.validate_certificate()
            results["ssl"] = ssl_results
            
            # Comprehensive security analysis
            web_security_summary = self._create_web_security_summary(ssl_results)
            
            # Website security header scanning
            if not self.config.get("quick_mode", False):
                console.print("\n[*] Performing comprehensive security header analysis...")
                security_scanner = SecurityHeaderScanner(self.domain.name)
                security_results = security_scanner.scan_security_headers()
                results["security_headers"] = security_results
                
                # Update web security summary with header results
                if security_results:
                    web_security_summary.update(self._analyze_security_headers_summary(security_results))
            else:
                console.print("\n[*] Quick mode: Basic SSL validation only")
                results["security_headers"] = {}
                
            # Display comprehensive web security summary
            if web_security_summary:
                final_summary = self._create_final_web_security_summary(web_security_summary)
                console.print(final_summary)
                
        else:
            # Web security section skipped
            results["ssl"] = {}
            results["security_headers"] = {}
        
        console.print()
        return results

    def _analyze_dns_records_intelligently(self):
        """Analyze DNS records with intelligence and categorization."""
        meta_errors = []
        record_counts = {}
        dns_records = {}
        insights = []
        
        # Prioritize important record types first
        important_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        other_types = [t for t in self.config["dns_record_types"] if t not in important_types]
        ordered_types = [t for t in important_types if t in self.config["dns_record_types"]] + other_types
        
        record_table = Table(title="DNS Records Analysis")
        record_table.add_column("Type", style="green", no_wrap=True)
        record_table.add_column("Count", style="blue", justify="center")
        record_table.add_column("Values", style="magenta", max_width=60)
        record_table.add_column("Analysis", style="yellow", max_width=30)
        
        for record_type in ordered_types:
            records, meta_error = self.domain.get_dns_records(record_type)
            if meta_error:
                meta_errors.append(record_type)
                continue
                
            record_counts[record_type] = len(records)
            dns_records[record_type] = records
            
            if records:
                # Analyze record for insights
                analysis = self._analyze_record_type(record_type, records)
                
                # Format values for display
                display_values = ", ".join(records[:3])  # Show first 3
                if len(records) > 3:
                    display_values += f" ... (+{len(records)-3} more)"
                
                record_table.add_row(
                    record_type,
                    str(len(records)),
                    display_values,
                    analysis["summary"]
                )
                
                if analysis["insights"]:
                    insights.extend(analysis["insights"])
        
        return {
            "records": dns_records,
            "meta_errors": meta_errors,
            "record_table": record_table,
            "insights": insights
        }

    def _analyze_record_type(self, record_type, records):
        """Analyze specific DNS record types for security insights."""
        analysis = {"summary": "Standard", "insights": []}
        
        if record_type == "A":
            if len(records) > 1:
                analysis["summary"] = "Load balanced"
                analysis["insights"].append("🔵 Multiple A records detected - likely using load balancing")
            # Check for cloud providers
            cloud_ips = self._detect_cloud_providers(records)
            if cloud_ips:
                analysis["insights"].append(f"☁️ Cloud hosting detected: {', '.join(cloud_ips)}")
                
        elif record_type == "MX":
            if len(records) > 1:
                analysis["summary"] = "Redundant mail"
                analysis["insights"].append("📧 Multiple MX records - good email redundancy")
            # Analyze mail providers
            providers = self._detect_mail_providers(records)
            if providers:
                analysis["insights"].append(f"📬 Mail services: {', '.join(providers)}")
                
        elif record_type == "NS":
            if len(records) < 2:
                analysis["summary"] = "⚠ Single NS"
                analysis["insights"].append("🚨 Only one nameserver - single point of failure risk")
            elif len(records) >= 4:
                analysis["summary"] = "Excellent NS"
                analysis["insights"].append("✅ Multiple nameservers - excellent DNS redundancy")
                
        elif record_type == "TXT":
            txt_analysis = self._analyze_txt_records(records)
            analysis["summary"] = txt_analysis["summary"]
            analysis["insights"].extend(txt_analysis["insights"])
            
        elif record_type == "CNAME":
            if len(records) > 1:
                analysis["summary"] = "Multiple aliases"
                analysis["insights"].append("🔗 Multiple CNAME records detected")
                
        return analysis

    def _detect_cloud_providers(self, ip_records):
        """Detect cloud providers from IP addresses."""
        cloud_providers = []
        
        for ip in ip_records:
            # This is a simplified detection - in real implementation would use IP ranges
            if ip.startswith("13.") or ip.startswith("52.") or ip.startswith("54."):
                cloud_providers.append("AWS")
            elif ip.startswith("104.") and "cloudflare" in str(ip):
                cloud_providers.append("Cloudflare")
            elif ip.startswith("34.") or ip.startswith("35."):
                cloud_providers.append("Google Cloud")
                
        return list(set(cloud_providers))

    def _detect_mail_providers(self, mx_records):
        """Detect mail service providers from MX records."""
        providers = []
        
        for mx in mx_records:
            mx_lower = str(mx).lower()
            if "google" in mx_lower or "gmail" in mx_lower:
                providers.append("Google Workspace")
            elif "outlook" in mx_lower or "protection.outlook.com" in mx_lower:
                providers.append("Microsoft 365")
            elif "proofpoint" in mx_lower:
                providers.append("Proofpoint (Security)")
            elif "mimecast" in mx_lower:
                providers.append("Mimecast (Security)")
            elif "mailgun" in mx_lower:
                providers.append("Mailgun")
            elif "sendgrid" in mx_lower:
                providers.append("SendGrid")
                
        return list(set(providers))

    def _analyze_txt_records(self, txt_records):
        """Analyze TXT records for various purposes."""
        insights = []
        categories = []
        
        for record in txt_records:
            record_lower = record.lower()
            
            if "v=spf1" in record_lower:
                categories.append("SPF")
                insights.append("📧 SPF record found - email authentication configured")
            elif "v=dmarc1" in record_lower:
                categories.append("DMARC")
                insights.append("🛡️ DMARC policy found - email spoofing protection")
            elif "v=dkim1" in record_lower:
                categories.append("DKIM")
                insights.append("🔐 DKIM record found - email signature verification")
            elif "google-site-verification" in record_lower:
                categories.append("Google Verification")
                insights.append("🔍 Google Search Console verification")
            elif "facebook-domain-verification" in record_lower:
                categories.append("Facebook Verification")
                insights.append("📘 Facebook domain verification")
            elif "_github-challenge" in record_lower:
                categories.append("GitHub Verification")
                insights.append("🐙 GitHub Pages verification")
                
        summary = ", ".join(categories) if categories else "General TXT"
        
        return {"summary": summary, "insights": insights}

    def _perform_intelligent_subdomain_discovery(self):
        """Perform intelligent subdomain discovery with source tracking."""
        subdomains = set()
        sources = []
        insights = []
        
        # 1. Wordlist-based enumeration
        if self.config.get("subdomains"):
            console.print("\n[*] Performing targeted subdomain enumeration...")
            # Enhance subdomains with domain intelligence
            enhanced_subdomains = self.domain.get_enhanced_subdomains(self.config["subdomains"])
            found_subs = self.domain.enumerate_subdomains(
                enhanced_subdomains, 
                max_workers=self.config.get("max_workers", 10),
                recursive=self.config.get("recursive", True)
            )
            if found_subs:
                subdomains.update(found_subs)
                sources.append(f"Wordlist enumeration ({len(found_subs)} found)")
                
        # 2. Certificate Transparency Logs
        if self.config.get("ct_logs"):
            console.print("  • Querying certificate transparency logs...")
            ct_subs = self.domain.enumerate_ct_subdomains()
            if ct_subs:
                new_ct_subs = set(ct_subs) - subdomains
                subdomains.update(ct_subs)
                sources.append(f"Certificate transparency ({len(new_ct_subs)} new)")
                
        # 3. DNSDumpster
        if self.config.get("dns_dumpster"):
            console.print("  • Querying DNSDumpster...")
            dd_subs = self.domain.enumerate_dns_dumpster()
            if dd_subs:
                new_dd_subs = set(dd_subs) - subdomains
                subdomains.update(dd_subs)
                sources.append(f"DNSDumpster ({len(new_dd_subs)} new)")
                
        # 4. Alternate DNS servers
        if self.config.get("alternate_dns") and self.config.get("subdomains"):
            console.print("  • Checking via alternate DNS servers...")
            alt_subs = self.domain.enumerate_alternate_dns(self.config["subdomains"])
            if alt_subs:
                new_alt_subs = set(alt_subs) - subdomains
                subdomains.update(alt_subs)
                sources.append(f"Alternate DNS ({len(new_alt_subs)} new)")
                
        # 5. Zone transfer attempt
        if self.config.get("zone_transfer"):
            console.print("  • Attempting DNS zone transfer...")
            axfr_subs = self.domain.attempt_zone_transfer()
            if axfr_subs:
                new_axfr_subs = set(axfr_subs) - subdomains
                subdomains.update(axfr_subs)
                sources.append(f"Zone transfer ({len(new_axfr_subs)} new)")
                insights.append("🚨 Zone transfer successful - potential misconfiguration")
            
        # Analyze subdomain patterns
        if subdomains:
            pattern_insights = self._analyze_subdomain_patterns(list(subdomains))
            insights.extend(pattern_insights)
            
        return {
            "subdomains": list(subdomains),
            "sources": sources,
            "insights": insights
        }

    def _analyze_subdomain_patterns(self, subdomains):
        """Analyze subdomain patterns for insights."""
        insights = []
        
        # Count subdomain categories
        categories = {
            "dev/staging": 0,
            "api/service": 0,
            "cdn/static": 0,
            "mail/mx": 0,
            "admin/mgmt": 0
        }
        
        for sub in subdomains:
            sub_lower = sub.lower()
            if any(word in sub_lower for word in ['dev', 'test', 'staging', 'stage']):
                categories["dev/staging"] += 1
            elif any(word in sub_lower for word in ['api', 'service', 'ws', 'rest']):
                categories["api/service"] += 1
            elif any(word in sub_lower for word in ['cdn', 'static', 'assets', 'img']):
                categories["cdn/static"] += 1
            elif any(word in sub_lower for word in ['mail', 'mx', 'smtp', 'imap']):
                categories["mail/mx"] += 1
            elif any(word in sub_lower for word in ['admin', 'manage', 'panel', 'control']):
                categories["admin/mgmt"] += 1
                
        # Generate insights based on patterns
        for category, count in categories.items():
            if count > 0:
                if category == "dev/staging" and count > 2:
                    insights.append(f"🔧 Multiple development environments detected ({count} subdomains)")
                elif category == "admin/mgmt" and count > 0:
                    insights.append(f"⚠️ Administrative interfaces found ({count} subdomains) - ensure proper access controls")
                elif category == "api/service" and count > 3:
                    insights.append(f"🔌 Service-oriented architecture detected ({count} API endpoints)")
                    
        return insights

    def _create_subdomain_table(self, subdomains):
        """Create an organized subdomain table with categorization."""
        table = Table(title="Discovered Subdomains")
        table.add_column("Subdomain", style="cyan", no_wrap=True)
        table.add_column("Category", style="green")
        table.add_column("Risk Level", style="yellow", justify="center")
        
        for sub in sorted(subdomains):
            category, risk = self._categorize_subdomain(sub)
            risk_color = {"Low": "green", "Medium": "yellow", "High": "red"}.get(risk, "white")
            table.add_row(sub, category, f"[{risk_color}]{risk}[/{risk_color}]")
            
        return table

    def _categorize_subdomain(self, subdomain):
        """Categorize a subdomain and assess risk level."""
        sub_lower = subdomain.lower()
        
        # High-risk subdomains
        if any(word in sub_lower for word in ['admin', 'panel', 'manage', 'control', 'dashboard']):
            return "Administrative", "High"
        elif any(word in sub_lower for word in ['dev', 'test', 'staging', 'debug']):
            return "Development", "Medium"
        elif any(word in sub_lower for word in ['api', 'service', 'ws', 'rest']):
            return "API/Service", "Medium"
        elif any(word in sub_lower for word in ['mail', 'mx', 'smtp', 'imap', 'pop']):
            return "Email", "Low"
        elif any(word in sub_lower for word in ['cdn', 'static', 'assets', 'img', 'css', 'js']):
            return "Static/CDN", "Low"
        elif any(word in sub_lower for word in ['www', 'web', 'site']):
            return "Web Frontend", "Low"
        else:
            return "General", "Low"

    def _create_dns_security_summary(self, dns_records, subdomain_count, wildcard_found):
        """Create a comprehensive DNS security summary."""
        summary_table = Table(title="DNS Security Summary")
        summary_table.add_column("Assessment Area", style="cyan")
        summary_table.add_column("Status", justify="center")
        summary_table.add_column("Details", style="dim")
        
        # DNS Redundancy
        ns_count = len(dns_records.get("NS", []))
        if ns_count >= 3:
            ns_status = "[green]✓ Excellent[/green]"
            ns_detail = f"{ns_count} nameservers configured"
        elif ns_count == 2:
            ns_status = "[yellow]⚠ Good[/yellow]"  
            ns_detail = f"{ns_count} nameservers configured"
        else:
            ns_status = "[red]✗ Poor[/red]"
            ns_detail = f"Only {ns_count} nameserver(s) - SPOF risk"
            
        summary_table.add_row("DNS Redundancy", ns_status, ns_detail)
        
        # Wildcard Configuration
        if wildcard_found:
            wc_status = "[yellow]⚠ Present[/yellow]"
            wc_detail = "Review wildcard necessity"
        else:
            wc_status = "[green]✓ Secure[/green]"
            wc_detail = "No wildcard records"
            
        summary_table.add_row("Wildcard Records", wc_status, wc_detail)
        
        # Subdomain Exposure
        if subdomain_count > 20:
            sub_status = "[yellow]⚠ High[/yellow]"
            sub_detail = f"{subdomain_count} subdomains - review exposure"
        elif subdomain_count > 5:
            sub_status = "[blue]ℹ Medium[/blue]"
            sub_detail = f"{subdomain_count} subdomains discovered"
        else:
            sub_status = "[green]✓ Low[/green]"
            sub_detail = f"{subdomain_count} subdomains discovered"
            
        summary_table.add_row("Subdomain Exposure", sub_status, sub_detail)
        
        # Mail Infrastructure (basic check)
        mx_records = dns_records.get("MX", [])
        if mx_records:
            mail_status = "[green]✓ Configured[/green]"
            mail_detail = f"{len(mx_records)} mail server(s)"
        else:
            mail_status = "[blue]ℹ None[/blue]"
            mail_detail = "No mail servers configured"
            
        summary_table.add_row("Mail Infrastructure", mail_status, mail_detail)
        
        return summary_table

    def _create_web_security_summary(self, ssl_results):
        """Create web security summary from SSL results."""
        summary = {}
        
        if ssl_results.get("valid"):
            summary["ssl_status"] = "valid"
            summary["ssl_details"] = {
                "issuer": ssl_results.get("issuer", "Unknown"),
                "expires": ssl_results.get("expires", "Unknown")
            }
        else:
            summary["ssl_status"] = "invalid"
            summary["ssl_error"] = ssl_results.get("error", "Unknown error")
            
        return summary

    def _analyze_security_headers_summary(self, security_results):
        """Analyze security headers for summary inclusion."""
        summary = {}
        
        if security_results:
            summary["headers_grade"] = security_results.get("grade", "F")
            summary["headers_score"] = security_results.get("score", 0)
            summary["critical_missing"] = security_results.get("missing_critical", [])
            summary["recommendations"] = security_results.get("recommendations", [])
            
        return summary

    def _create_final_web_security_summary(self, web_summary):
        """Create final comprehensive web security summary table."""
        summary_table = Table(title="Web Security Assessment")
        summary_table.add_column("Security Area", style="cyan")
        summary_table.add_column("Status", justify="center")
        summary_table.add_column("Details", style="dim")
        summary_table.add_column("Recommendations", style="yellow", max_width=40)
        
        # SSL/TLS Assessment
        if web_summary.get("ssl_status") == "valid":
            ssl_status = "[green]✓ Valid[/green]"
            ssl_details = f"Issuer: {web_summary['ssl_details']['issuer'][:30]}..."
            ssl_recommendations = "Monitor expiration date"
        else:
            ssl_status = "[red]✗ Invalid[/red]"
            ssl_details = f"Error: {web_summary.get('ssl_error', 'Unknown')}"
            ssl_recommendations = "Fix SSL certificate issues immediately"
            
        summary_table.add_row("SSL/TLS Certificate", ssl_status, ssl_details, ssl_recommendations)
        
        # Security Headers Assessment
        if "headers_grade" in web_summary:
            grade = web_summary["headers_grade"]
            score = web_summary["headers_score"]
            
            if grade in ["A+", "A"]:
                headers_status = f"[green]✓ Excellent ({grade})[/green]"
                headers_recommendations = "Maintain current security posture"
            elif grade in ["B", "C"]:
                headers_status = f"[yellow]⚠ Good ({grade})[/yellow]"
                headers_recommendations = "Consider implementing missing headers"
            else:
                headers_status = f"[red]✗ Poor ({grade})[/red]"
                headers_recommendations = "Implement critical security headers"
                
            headers_details = f"Score: {score}/100"
            if web_summary.get("critical_missing"):
                headers_details += f", Missing: {', '.join(web_summary['critical_missing'][:2])}"
                
            summary_table.add_row("Security Headers", headers_status, headers_details, headers_recommendations)
        else:
            summary_table.add_row("Security Headers", "[blue]ℹ Skipped[/blue]", "Quick mode enabled", "Run full scan for analysis")
        
        # Overall Web Security Rating
        overall_rating = self._calculate_overall_web_security_rating(web_summary)
        summary_table.add_row("Overall Rating", overall_rating["status"], overall_rating["details"], overall_rating["recommendation"])
        
        return summary_table

    def _calculate_overall_web_security_rating(self, web_summary):
        """Calculate overall web security rating."""
        score = 0
        max_score = 100
        
        # SSL contributes 40% of score
        if web_summary.get("ssl_status") == "valid":
            score += 40
        
        # Headers contribute 60% of score
        if "headers_score" in web_summary:
            score += (web_summary["headers_score"] * 0.6)
        else:
            # If headers weren't checked, give partial credit for SSL
            max_score = 40
            
        percentage = (score / max_score) * 100
        
        if percentage >= 90:
            return {
                "status": "[green]✓ Excellent[/green]",
                "details": f"Security score: {percentage:.0f}%",
                "recommendation": "Maintain current security practices"
            }
        elif percentage >= 70:
            return {
                "status": "[yellow]⚠ Good[/yellow]",
                "details": f"Security score: {percentage:.0f}%",
                "recommendation": "Address remaining security gaps"
            }
        elif percentage >= 50:
            return {
                "status": "[orange]⚠ Fair[/orange]",
                "details": f"Security score: {percentage:.0f}%",
                "recommendation": "Significant security improvements needed"
            }
        else:
            return {
                "status": "[red]✗ Poor[/red]",
                "details": f"Security score: {percentage:.0f}%",
                "recommendation": "Immediate security remediation required"
            }


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
            if setting.endswith("_selectors") or setting == "selectors" or isinstance(fallback, list):
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
        config_manager
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
