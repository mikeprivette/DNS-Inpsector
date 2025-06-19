#!/usr/bin/env python3

import dns.resolver
import dns.query
import dns.zone
import dns.dnssec
import dns.message
import dns.rdataclass
import dns.rdatatype
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
import csv
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

    def check_bimi(self):
        """Comprehensive BIMI (Brand Indicators for Message Identification) analysis."""
        result = {
            "present": False,
            "records": [],
            "selectors": [],
            "logo_url": None,
            "authority_url": None,
            "version": None,
            "issues": [],
            "recommendations": []
        }
        
        # Common BIMI selectors to check
        bimi_selectors = ['default', 'v1', 'selector1', 'selector2', 'bimi']
        
        try:
            for selector in bimi_selectors:
                domain = f"{selector}._bimi.{self.name}"
                records, _ = self.get_txt_record(domain)
                
                for record in records:
                    if "v=BIMI1" in record:
                        result["present"] = True
                        result["records"].append(record)
                        result["selectors"].append(selector)
                        
                        # Parse BIMI record
                        tags = {}
                        for part in record.split(";"):
                            if "=" in part:
                                key, value = part.strip().split("=", 1)
                                tags[key.strip()] = value.strip()
                        
                        result["version"] = tags.get("v")
                        result["logo_url"] = tags.get("l")
                        result["authority_url"] = tags.get("a")
                        
                        # Validate BIMI record
                        if not result["logo_url"]:
                            result["issues"].append("Missing logo URL (l= tag)")
                        elif not result["logo_url"].startswith("https://"):
                            result["issues"].append("Logo URL must use HTTPS")
                        
                        if result["authority_url"] and not result["authority_url"].startswith("https://"):
                            result["issues"].append("Authority URL must use HTTPS")
                        
                        # Check for proper DMARC policy (required for BIMI)
                        dmarc_result = self.check_dmarc()
                        if not dmarc_result["present"]:
                            result["issues"].append("BIMI requires DMARC policy to be effective")
                        elif dmarc_result["policy"] not in ["quarantine", "reject"]:
                            result["issues"].append("BIMI requires DMARC policy of 'quarantine' or 'reject'")
        
        except Exception as e:
            result["issues"].append(f"Error checking BIMI records: {str(e)}")
        
        # Generate recommendations
        if not result["present"]:
            result["recommendations"].append("Consider implementing BIMI for brand visibility in email clients")
        elif result["issues"]:
            result["recommendations"].append("Fix BIMI configuration issues for optimal brand display")
        
        return result

    def check_mta_sts(self):
        """Check MTA-STS (Mail Transfer Agent Strict Transport Security) policy."""
        result = {
            "present": False,
            "txt_record": None,
            "policy_found": False,
            "policy_content": None,
            "version": None,
            "id": None,
            "issues": [],
            "recommendations": []
        }
        
        try:
            # Check for MTA-STS TXT record
            domain = f"_mta-sts.{self.name}"
            records, _ = self.get_txt_record(domain)
            
            for record in records:
                if "v=STSv1" in record:
                    result["present"] = True
                    result["txt_record"] = record
                    
                    # Parse MTA-STS record
                    tags = {}
                    for part in record.split(";"):
                        if "=" in part:
                            key, value = part.strip().split("=", 1)
                            tags[key.strip()] = value.strip()
                    
                    result["version"] = tags.get("v")
                    result["id"] = tags.get("id")
                    
                    # Try to fetch the policy file
                    try:
                        policy_url = f"https://mta-sts.{self.name}/.well-known/mta-sts.txt"
                        response = requests.get(policy_url, timeout=10)
                        if response.status_code == 200:
                            result["policy_found"] = True
                            result["policy_content"] = response.text
                            
                            # Parse policy content
                            policy_lines = response.text.strip().split('\n')
                            policy_dict = {}
                            for line in policy_lines:
                                if ':' in line:
                                    key, value = line.split(':', 1)
                                    policy_dict[key.strip()] = value.strip()
                            
                            # Validate policy
                            if policy_dict.get('version') != 'STSv1':
                                result["issues"].append("Policy version mismatch")
                            
                            mode = policy_dict.get('mode')
                            if mode not in ['enforce', 'testing', 'none']:
                                result["issues"].append(f"Invalid policy mode: {mode}")
                            elif mode == 'none':
                                result["issues"].append("MTA-STS policy is disabled (mode=none)")
                            
                            if not policy_dict.get('mx'):
                                result["issues"].append("No MX hosts specified in policy")
                                
                        else:
                            result["issues"].append(f"Could not fetch policy file (HTTP {response.status_code})")
                    except Exception as e:
                        result["issues"].append(f"Error fetching policy: {str(e)}")
                    
                    break
        
        except Exception as e:
            result["issues"].append(f"Error checking MTA-STS: {str(e)}")
        
        # Generate recommendations
        if not result["present"]:
            result["recommendations"].append("Consider implementing MTA-STS for enhanced email security")
        elif result["issues"]:
            result["recommendations"].append("Fix MTA-STS configuration issues")
        
        return result

    def check_tls_rpt(self):
        """Check SMTP TLS Reporting (TLS-RPT) configuration."""
        result = {
            "present": False,
            "records": [],
            "version": None,
            "rua": [],
            "issues": [],
            "recommendations": []
        }
        
        try:
            # Check for TLS-RPT record
            domain = f"_smtp._tls.{self.name}"
            records, _ = self.get_txt_record(domain)
            
            for record in records:
                if "v=TLSRPTv1" in record:
                    result["present"] = True
                    result["records"].append(record)
                    
                    # Parse TLS-RPT record
                    tags = {}
                    for part in record.split(";"):
                        if "=" in part:
                            key, value = part.strip().split("=", 1)
                            tags[key.strip()] = value.strip()
                    
                    result["version"] = tags.get("v")
                    rua_value = tags.get("rua")
                    if rua_value:
                        # Handle multiple RUA addresses
                        result["rua"] = [addr.strip() for addr in rua_value.split(",")]
                    
                    # Validate record
                    if not result["rua"]:
                        result["issues"].append("No reporting addresses specified (rua= tag missing)")
                    else:
                        for rua in result["rua"]:
                            if not (rua.startswith("mailto:") or rua.startswith("https://")):
                                result["issues"].append(f"Invalid RUA format: {rua}")
                    
                    break
        
        except Exception as e:
            result["issues"].append(f"Error checking TLS-RPT: {str(e)}")
        
        # Generate recommendations
        if not result["present"]:
            result["recommendations"].append("Consider implementing TLS-RPT for SMTP security monitoring")
        elif result["issues"]:
            result["recommendations"].append("Fix TLS-RPT configuration issues")
        
        return result

    def check_dnssec(self):
        """Check DNSSEC validation and security chain."""
        result = {
            "enabled": False,
            "valid": False,
            "ds_records": [],
            "dnskey_records": [],
            "rrsig_records": [],
            "issues": [],
            "recommendations": [],
            "validation_details": {}
        }
        
        try:
            # Check for DS records at parent zone
            ds_records, _ = self.get_dns_records("DS")
            result["ds_records"] = ds_records
            
            # Check for DNSKEY records
            dnskey_records, _ = self.get_dns_records("DNSKEY")
            result["dnskey_records"] = dnskey_records
            
            # Check for RRSIG records (signature records)
            rrsig_records, _ = self.get_dns_records("RRSIG")
            result["rrsig_records"] = rrsig_records
            
            # DNSSEC is enabled if we have any of these record types
            if ds_records or dnskey_records or rrsig_records:
                result["enabled"] = True
            
            # Try to validate DNSSEC chain
            if result["enabled"]:
                try:
                    # Create a resolver that validates DNSSEC
                    resolver = dns.resolver.Resolver()
                    resolver.use_edns(0, dns.flags.DO, 4096)
                    
                    # Test with a simple A record query
                    try:
                        response = resolver.resolve(self.name, 'A')
                        result["valid"] = True
                        result["validation_details"]["a_record_validated"] = True
                    except dns.resolver.NXDOMAIN:
                        # Domain doesn't exist, but DNSSEC might still be configured
                        result["validation_details"]["domain_not_found"] = True
                    except dns.dnssec.ValidationFailure as e:
                        result["issues"].append(f"DNSSEC validation failed: {str(e)}")
                        result["validation_details"]["validation_error"] = str(e)
                    except Exception as e:
                        result["issues"].append(f"DNSSEC validation error: {str(e)}")
                        result["validation_details"]["general_error"] = str(e)
                
                except Exception as e:
                    result["issues"].append(f"Error setting up DNSSEC validation: {str(e)}")
            
            # Analyze DNSSEC configuration
            if not result["enabled"]:
                result["recommendations"].append("Consider implementing DNSSEC for enhanced DNS security")
            else:
                if not ds_records:
                    result["issues"].append("DNSKEY found but no DS records at parent zone")
                    result["recommendations"].append("Ensure DS records are published at parent zone")
                
                if not dnskey_records:
                    result["issues"].append("DS records found but no DNSKEY records")
                    result["recommendations"].append("Publish DNSKEY records for your zone")
                
                if not rrsig_records:
                    result["issues"].append("DNSSEC keys found but no signatures (RRSIG)")
                    result["recommendations"].append("Enable DNSSEC signing for your zone")
                
                if result["valid"]:
                    result["recommendations"].append("DNSSEC is properly configured and validating")
        
        except Exception as e:
            result["issues"].append(f"Error checking DNSSEC: {str(e)}")
        
        return result

    def check_caa(self):
        """Check Certificate Authority Authorization (CAA) records."""
        result = {
            "present": False,
            "records": [],
            "authorized_cas": [],
            "issue_policies": [],
            "issuewild_policies": [],
            "iodef_contacts": [],
            "issues": [],
            "recommendations": []
        }
        
        try:
            # Check for CAA records
            caa_records, _ = self.get_dns_records("CAA")
            result["records"] = caa_records
            
            if caa_records:
                result["present"] = True
                
                for record in caa_records:
                    record_str = str(record).strip()
                    
                    # Parse CAA record format: flag property value
                    parts = record_str.split(' ', 2)
                    if len(parts) >= 3:
                        flag = parts[0]
                        property_name = parts[1]
                        value = ' '.join(parts[2:]).strip('"')
                        
                        if property_name == "issue":
                            result["issue_policies"].append(value)
                            if value and value != ";":
                                result["authorized_cas"].append(value)
                        elif property_name == "issuewild":
                            result["issuewild_policies"].append(value)
                            if value and value != ";":
                                result["authorized_cas"].append(value)
                        elif property_name == "iodef":
                            result["iodef_contacts"].append(value)
                
                # Analyze CAA configuration
                if not result["issue_policies"]:
                    result["issues"].append("No 'issue' policy found in CAA records")
                
                # Check for restrictive policies
                restrictive_issue = any(policy == ";" for policy in result["issue_policies"])
                restrictive_wild = any(policy == ";" for policy in result["issuewild_policies"])
                
                if restrictive_issue and not restrictive_wild:
                    result["issues"].append("Certificate issuance blocked but wildcard issuance not restricted")
                    result["recommendations"].append("Consider adding 'issuewild ;' to block wildcard certificates")
                
                if result["authorized_cas"]:
                    result["recommendations"].append(f"Certificates restricted to: {', '.join(set(result['authorized_cas']))}")
                else:
                    result["issues"].append("CAA records present but no certificate authorities authorized")
                
                if not result["iodef_contacts"]:
                    result["recommendations"].append("Consider adding 'iodef' property for security incident reporting")
            else:
                result["recommendations"].append("Consider implementing CAA records to restrict certificate issuance")
        
        except Exception as e:
            result["issues"].append(f"Error checking CAA records: {str(e)}")
        
        return result

    def check_dns_over_https_tls(self):
        """Check for DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) support."""
        result = {
            "doh_supported": False,
            "dot_supported": False,
            "doh_endpoints": [],
            "dot_endpoints": [],
            "issues": [],
            "recommendations": []
        }
        
        try:
            # Check for DoH support via HTTPS resource records
            https_records, _ = self.get_dns_records("HTTPS")
            svcb_records, _ = self.get_dns_records("SVCB")
            
            # Check for DoH indicators in HTTPS/SVCB records
            all_service_records = https_records + svcb_records
            for record in all_service_records:
                record_str = str(record).lower()
                if 'doh' in record_str or 'dns-query' in record_str:
                    result["doh_supported"] = True
                    result["doh_endpoints"].append(str(record))
            
            # Check for DoT support by looking for _853._tcp DNS records
            try:
                dot_srv_records, _ = self.get_dns_records("SRV", f"_853._tcp.{self.name}")
                if dot_srv_records:
                    result["dot_supported"] = True
                    result["dot_endpoints"] = dot_srv_records
            except:
                pass
            
            # Try to detect DoH/DoT by common patterns
            # Check if the domain itself might be a DoH/DoT provider
            domain_lower = self.name.lower()
            if any(keyword in domain_lower for keyword in ['dns', 'resolver', 'doh', 'dot']):
                # Try common DoH endpoint
                try:
                    doh_url = f"https://{self.name}/dns-query"
                    response = requests.head(doh_url, timeout=5)
                    if response.status_code in [200, 400, 405]:  # 400/405 might indicate DoH but wrong method
                        result["doh_supported"] = True
                        result["doh_endpoints"].append(doh_url)
                except:
                    pass
            
            # Generate recommendations
            if not result["doh_supported"] and not result["dot_supported"]:
                result["recommendations"].append("Consider supporting modern DNS protocols (DoH/DoT) for enhanced privacy")
            else:
                if result["doh_supported"]:
                    result["recommendations"].append("DNS-over-HTTPS support detected - provides encrypted DNS queries")
                if result["dot_supported"]:
                    result["recommendations"].append("DNS-over-TLS support detected - provides encrypted DNS queries")
        
        except Exception as e:
            result["issues"].append(f"Error checking DNS-over-HTTPS/TLS support: {str(e)}")
        
        return result

    def discover_cloud_infrastructure(self):
        """Comprehensive cloud infrastructure and service discovery."""
        result = {
            "cloud_providers": [],
            "detected_services": [],
            "cdn_providers": [],
            "email_services": [],
            "container_platforms": [],
            "serverless_indicators": [],
            "api_gateways": [],
            "storage_services": [],
            "details": {},
            "confidence_scores": {},
            "recommendations": []
        }
        
        try:
            # Collect all DNS records for analysis
            all_records = {}
            record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV"]
            
            for record_type in record_types:
                records, _ = self.get_dns_records(record_type)
                if records:
                    all_records[record_type] = records
            
            # Analyze A/AAAA records for cloud provider IP ranges
            self._analyze_cloud_ip_ranges(all_records, result)
            
            # Analyze CNAME records for cloud services
            self._analyze_cloud_cnames(all_records, result)
            
            # Analyze TXT records for cloud service verifications
            self._analyze_cloud_txt_records(all_records, result)
            
            # Analyze MX records for cloud email services
            self._analyze_cloud_email_services(all_records, result)
            
            # Analyze NS records for cloud DNS services
            self._analyze_cloud_dns_services(all_records, result)
            
            # Analyze SRV records for cloud services
            self._analyze_cloud_srv_records(all_records, result)
            
            # Generate confidence scores and recommendations
            self._generate_cloud_insights(result)
            
        except Exception as e:
            result["details"]["error"] = f"Error discovering cloud infrastructure: {str(e)}"
        
        return result

    def _analyze_cloud_ip_ranges(self, all_records, result):
        """Analyze IP addresses for cloud provider ranges."""
        cloud_providers = {
            'AWS': {
                'ipv4_ranges': ['13.', '52.', '54.', '3.', '18.', '34.', '35.', '50.', '99.'],
                'ipv6_ranges': ['2600:1f'],
                'confidence': 0.9
            },
            'Google Cloud': {
                'ipv4_ranges': ['34.', '35.', '104.154.', '130.211.', '146.148.', '104.196.', '104.197.'],
                'ipv6_ranges': ['2001:4860'],
                'confidence': 0.9
            },
            'Microsoft Azure': {
                'ipv4_ranges': ['13.', '20.', '40.', '52.', '104.', '168.', '51.', '23.'],
                'ipv6_ranges': ['2603:', '2620:1ec:'],
                'confidence': 0.9
            },
            'Cloudflare': {
                'ipv4_ranges': ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '172.64.', '172.65.', '172.66.', '172.67.'],
                'ipv6_ranges': ['2606:4700', '2803:f800', '2405:b500', '2405:8100'],
                'confidence': 0.95
            },
            'DigitalOcean': {
                'ipv4_ranges': ['138.197.', '159.89.', '165.227.', '167.99.', '178.62.', '188.166.', '206.189.'],
                'ipv6_ranges': ['2604:a880'],
                'confidence': 0.85
            }
        }
        
        for record_type in ['A', 'AAAA']:
            if record_type in all_records:
                for ip in all_records[record_type]:
                    ip_str = str(ip)
                    for provider, config in cloud_providers.items():
                        ranges = config['ipv4_ranges'] if record_type == 'A' else config['ipv6_ranges']
                        if any(ip_str.startswith(range_prefix) for range_prefix in ranges):
                            if provider not in result["cloud_providers"]:
                                result["cloud_providers"].append(provider)
                                result["confidence_scores"][provider] = config['confidence']
                            result["details"][f"{provider}_ips"] = result["details"].get(f"{provider}_ips", [])
                            result["details"][f"{provider}_ips"].append(ip_str)

    def _analyze_cloud_cnames(self, all_records, result):
        """Analyze CNAME records for cloud service indicators."""
        if "CNAME" not in all_records:
            return
            
        cloud_services = {
            'amazonaws.com': {'provider': 'AWS', 'service_type': 'compute', 'confidence': 0.95},
            'elb.amazonaws.com': {'provider': 'AWS', 'service_type': 'load_balancer', 'confidence': 0.99},
            'cloudfront.net': {'provider': 'AWS', 'service_type': 'cdn', 'confidence': 0.99},
            's3.amazonaws.com': {'provider': 'AWS', 'service_type': 'storage', 'confidence': 0.99},
            'googleusercontent.com': {'provider': 'Google Cloud', 'service_type': 'storage', 'confidence': 0.95},
            'googleapis.com': {'provider': 'Google Cloud', 'service_type': 'api', 'confidence': 0.95},
            'azurewebsites.net': {'provider': 'Microsoft Azure', 'service_type': 'web_app', 'confidence': 0.99},
            'blob.core.windows.net': {'provider': 'Microsoft Azure', 'service_type': 'storage', 'confidence': 0.99},
            'azureedge.net': {'provider': 'Microsoft Azure', 'service_type': 'cdn', 'confidence': 0.99},
            'cloudflare.com': {'provider': 'Cloudflare', 'service_type': 'cdn', 'confidence': 0.95},
            'herokuapp.com': {'provider': 'Heroku', 'service_type': 'paas', 'confidence': 0.99},
            'netlify.com': {'provider': 'Netlify', 'service_type': 'static_hosting', 'confidence': 0.99},
            'vercel.app': {'provider': 'Vercel', 'service_type': 'static_hosting', 'confidence': 0.99},
            'github.io': {'provider': 'GitHub Pages', 'service_type': 'static_hosting', 'confidence': 0.99},
            'fastly.com': {'provider': 'Fastly', 'service_type': 'cdn', 'confidence': 0.95},
            'maxcdn.com': {'provider': 'MaxCDN', 'service_type': 'cdn', 'confidence': 0.95},
            'keycdn.com': {'provider': 'KeyCDN', 'service_type': 'cdn', 'confidence': 0.95},
            'stackpathdns.com': {'provider': 'StackPath', 'service_type': 'cdn', 'confidence': 0.95},
            'cdnjs.com': {'provider': 'Cloudflare', 'service_type': 'cdn', 'confidence': 0.90},
            'jsdelivr.net': {'provider': 'jsDelivr', 'service_type': 'cdn', 'confidence': 0.90},
            'unpkg.com': {'provider': 'unpkg', 'service_type': 'cdn', 'confidence': 0.90},
            'akamai.net': {'provider': 'Akamai', 'service_type': 'cdn', 'confidence': 0.95},
            'akamaized.net': {'provider': 'Akamai', 'service_type': 'cdn', 'confidence': 0.95},
            'bunnycdn.com': {'provider': 'BunnyCDN', 'service_type': 'cdn', 'confidence': 0.95},
            'b-cdn.net': {'provider': 'BunnyCDN', 'service_type': 'cdn', 'confidence': 0.95}
        }
        
        for cname in all_records["CNAME"]:
            cname_str = str(cname).lower()
            for pattern, info in cloud_services.items():
                if pattern in cname_str:
                    provider = info['provider']
                    service_type = info['service_type']
                    
                    if provider not in result["cloud_providers"]:
                        result["cloud_providers"].append(provider)
                    
                    service_info = f"{provider} {service_type}"
                    if service_info not in result["detected_services"]:
                        result["detected_services"].append(service_info)
                    
                    if service_type == 'cdn' and provider not in result["cdn_providers"]:
                        result["cdn_providers"].append(provider)
                    
                    result["confidence_scores"][f"{provider}_{service_type}"] = info['confidence']
                    result["details"][f"{provider}_cnames"] = result["details"].get(f"{provider}_cnames", [])
                    result["details"][f"{provider}_cnames"].append(cname_str)

    def _analyze_cloud_txt_records(self, all_records, result):
        """Analyze TXT records for cloud service verification and configuration."""
        if "TXT" not in all_records:
            return
            
        verification_patterns = {
            'google-site-verification=': {'provider': 'Google', 'service': 'Search Console', 'confidence': 0.9},
            'MS=': {'provider': 'Microsoft', 'service': 'Office 365', 'confidence': 0.9},
            'facebook-domain-verification=': {'provider': 'Facebook', 'service': 'Business Manager', 'confidence': 0.9},
            'apple-domain-verification=': {'provider': 'Apple', 'service': 'App Store Connect', 'confidence': 0.9},
            'adobe-idp-site-verification=': {'provider': 'Adobe', 'service': 'Creative Cloud', 'confidence': 0.9},
            'amazonses:': {'provider': 'AWS', 'service': 'SES Email', 'confidence': 0.95},
            'stripe-verification=': {'provider': 'Stripe', 'service': 'Payment Processing', 'confidence': 0.9},
            'atlassian-domain-verification=': {'provider': 'Atlassian', 'service': 'Cloud Services', 'confidence': 0.9}
        }
        
        for txt_record in all_records["TXT"]:
            txt_str = str(txt_record).lower()
            for pattern, info in verification_patterns.items():
                if pattern in txt_str:
                    provider = info['provider']
                    service = info['service']
                    
                    service_info = f"{provider} {service}"
                    if service_info not in result["detected_services"]:
                        result["detected_services"].append(service_info)
                    
                    result["confidence_scores"][f"{provider}_{service}"] = info['confidence']

    def _analyze_cloud_email_services(self, all_records, result):
        """Analyze MX records for cloud email service providers."""
        if "MX" not in all_records:
            return
            
        email_providers = {
            'google.com': {'provider': 'Google Workspace', 'confidence': 0.99},
            'outlook.com': {'provider': 'Microsoft 365', 'confidence': 0.99},
            'protection.outlook.com': {'provider': 'Microsoft 365', 'confidence': 0.99},
            'amazonaws.com': {'provider': 'AWS SES', 'confidence': 0.95},
            'sendgrid.net': {'provider': 'SendGrid', 'confidence': 0.99},
            'mailgun.org': {'provider': 'Mailgun', 'confidence': 0.99},
            'zoho.com': {'provider': 'Zoho Mail', 'confidence': 0.99}
        }
        
        for mx_record in all_records["MX"]:
            mx_str = str(mx_record).lower()
            for pattern, info in email_providers.items():
                if pattern in mx_str:
                    provider = info['provider']
                    if provider not in result["email_services"]:
                        result["email_services"].append(provider)
                    result["confidence_scores"][f"email_{provider}"] = info['confidence']

    def _analyze_cloud_dns_services(self, all_records, result):
        """Analyze NS records for cloud DNS service providers."""
        if "NS" not in all_records:
            return
            
        dns_providers = {
            'amazonaws.com': {'provider': 'AWS Route 53', 'confidence': 0.99},
            'azure-dns.com': {'provider': 'Azure DNS', 'confidence': 0.99},
            'googledomains.com': {'provider': 'Google Cloud DNS', 'confidence': 0.99},
            'cloudflare.com': {'provider': 'Cloudflare DNS', 'confidence': 0.99},
            'ns1.com': {'provider': 'NS1', 'confidence': 0.99},
            'dnsimple.com': {'provider': 'DNSimple', 'confidence': 0.99}
        }
        
        for ns_record in all_records["NS"]:
            ns_str = str(ns_record).lower()
            for pattern, info in dns_providers.items():
                if pattern in ns_str:
                    provider = info['provider']
                    service_info = f"DNS: {provider}"
                    if service_info not in result["detected_services"]:
                        result["detected_services"].append(service_info)
                    result["confidence_scores"][f"dns_{provider}"] = info['confidence']

    def _analyze_cloud_srv_records(self, all_records, result):
        """Analyze SRV records for cloud service indicators."""
        if "SRV" not in all_records:
            return
            
        # SRV records often indicate specific cloud services
        srv_services = {
            '_sip': 'VoIP/Communications',
            '_xmpp': 'Messaging Services',
            '_caldav': 'Calendar Services',
            '_carddav': 'Contact Services',
            '_autodiscover': 'Microsoft Exchange',
            '_matrix': 'Matrix Communications'
        }
        
        for srv_record in all_records["SRV"]:
            srv_str = str(srv_record).lower()
            for service_name, description in srv_services.items():
                if service_name in srv_str:
                    service_info = f"Service: {description}"
                    if service_info not in result["detected_services"]:
                        result["detected_services"].append(service_info)

    def _generate_cloud_insights(self, result):
        """Generate insights and recommendations based on discovered cloud infrastructure."""
        if result["cloud_providers"]:
            if len(result["cloud_providers"]) == 1:
                result["recommendations"].append(f"Single cloud provider detected: {result['cloud_providers'][0]}")
            else:
                result["recommendations"].append(f"Multi-cloud architecture detected: {', '.join(result['cloud_providers'])}")
        
        if result["cdn_providers"]:
            result["recommendations"].append(f"CDN services in use: {', '.join(result['cdn_providers'])}")
        
        if result["email_services"]:
            result["recommendations"].append(f"Cloud email services: {', '.join(result['email_services'])}")
        
        if not result["cloud_providers"]:
            result["recommendations"].append("No major cloud providers detected - may be using traditional hosting")

    def calculate_security_score(self, results):
        """Calculate an overall security score based on various security indicators."""
        score_breakdown = {
            "dns_security": {"score": 0, "max": 25, "details": []},
            "email_security": {"score": 0, "max": 35, "details": []},
            "web_security": {"score": 0, "max": 25, "details": []},
            "infrastructure": {"score": 0, "max": 15, "details": []}
        }
        
        # DNS Security Scoring (25 points)
        dnssec = results.get("dnssec", {})
        if dnssec.get("enabled"):
            if dnssec.get("valid"):
                score_breakdown["dns_security"]["score"] += 15
                score_breakdown["dns_security"]["details"].append("DNSSEC enabled and validating (+15)")
            else:
                score_breakdown["dns_security"]["score"] += 8
                score_breakdown["dns_security"]["details"].append("DNSSEC enabled but has validation issues (+8)")
        else:
            # Deduct points for missing DNSSEC
            score_breakdown["dns_security"]["score"] = max(0, score_breakdown["dns_security"]["score"] - 5)
            score_breakdown["dns_security"]["details"].append("DNSSEC not enabled (-5)")
        
        caa = results.get("caa", {})
        if caa.get("present"):
            if caa.get("authorized_cas"):
                score_breakdown["dns_security"]["score"] += 10
                score_breakdown["dns_security"]["details"].append("CAA records properly configured (+10)")
            else:
                score_breakdown["dns_security"]["score"] += 5
                score_breakdown["dns_security"]["details"].append("CAA records present but restrictive (+5)")
        else:
            # Deduct points for missing CAA records
            score_breakdown["dns_security"]["score"] = max(0, score_breakdown["dns_security"]["score"] - 3)
            score_breakdown["dns_security"]["details"].append("No CAA records (-3)")
        
        # Email Security Scoring (35 points)
        dmarc = results.get("dmarc", {})
        if dmarc.get("present"):
            policy = dmarc.get("policy", "").lower()
            if policy == "reject":
                score_breakdown["email_security"]["score"] += 15
                score_breakdown["email_security"]["details"].append("DMARC policy set to 'reject' (+15)")
            elif policy == "quarantine":
                score_breakdown["email_security"]["score"] += 12
                score_breakdown["email_security"]["details"].append("DMARC policy set to 'quarantine' (+12)")
            elif policy == "none":
                score_breakdown["email_security"]["score"] += 5
                score_breakdown["email_security"]["details"].append("DMARC policy set to 'none' (+5)")
        else:
            # Deduct points for missing DMARC
            score_breakdown["email_security"]["score"] = max(0, score_breakdown["email_security"]["score"] - 10)
            score_breakdown["email_security"]["details"].append("No DMARC policy (-10)")
        
        spf = results.get("spf", {})
        spf_records = spf.get("records", [])
        if spf_records:
            # Check SPF policy strictness
            spf_record_text = ' '.join(spf_records).lower()
            if '-all' in spf_record_text:  # Hard fail
                score_breakdown["email_security"]["score"] += 10
                score_breakdown["email_security"]["details"].append("SPF properly configured with hard fail (+10)")
            elif '~all' in spf_record_text:  # Soft fail
                score_breakdown["email_security"]["score"] += 6
                score_breakdown["email_security"]["details"].append("SPF configured with soft fail (+6)")
            elif '?all' in spf_record_text or '+all' in spf_record_text:  # Neutral/pass
                score_breakdown["email_security"]["score"] += 3
                score_breakdown["email_security"]["details"].append("SPF configured but permissive (+3)")
            else:
                score_breakdown["email_security"]["score"] += 5
                score_breakdown["email_security"]["details"].append("SPF record present (+5)")
        else:
            # Deduct points for missing SPF
            score_breakdown["email_security"]["score"] = max(0, score_breakdown["email_security"]["score"] - 8)
            score_breakdown["email_security"]["details"].append("No SPF record (-8)")
        
        dkim = results.get("dkim", {})
        found_selectors = dkim.get("found_selectors", {})
        valid_dkim_count = len([s for s in found_selectors.values() if s])
        if valid_dkim_count >= 2:
            score_breakdown["email_security"]["score"] += 10
            score_breakdown["email_security"]["details"].append(f"Multiple DKIM selectors found ({valid_dkim_count}) (+10)")
        elif valid_dkim_count == 1:
            score_breakdown["email_security"]["score"] += 7
            score_breakdown["email_security"]["details"].append("Single DKIM selector found (+7)")
        else:
            # Deduct points for missing DKIM
            score_breakdown["email_security"]["score"] = max(0, score_breakdown["email_security"]["score"] - 5)
            score_breakdown["email_security"]["details"].append("No DKIM selectors found (-5)")
        
        # Advanced Email Security Bonus
        bimi = results.get("bimi", {})
        mta_sts = results.get("mta_sts", {})
        tls_rpt = results.get("tls_rpt", {})
        
        advanced_features = 0
        if bimi.get("present") and not bimi.get("issues"):
            advanced_features += 1
            score_breakdown["email_security"]["details"].append("BIMI properly configured (bonus)")
        if mta_sts.get("present") and mta_sts.get("policy_found"):
            advanced_features += 1
            score_breakdown["email_security"]["details"].append("MTA-STS properly configured (bonus)")
        if tls_rpt.get("present") and not tls_rpt.get("issues"):
            advanced_features += 1
            score_breakdown["email_security"]["details"].append("TLS-RPT properly configured (bonus)")
        
        if advanced_features > 0:
            bonus_points = min(advanced_features * 2, 5)  # Max 5 bonus points
            score_breakdown["email_security"]["score"] += bonus_points
        
        # Web Security Scoring (25 points)
        ssl = results.get("ssl", {})
        if ssl.get("valid"):
            score_breakdown["web_security"]["score"] += 15
            score_breakdown["web_security"]["details"].append("Valid SSL/TLS certificate (+15)")
            
            # Check for strong security
            if ssl.get("grade") and ssl.get("grade") in ["A+", "A"]:
                score_breakdown["web_security"]["score"] += 5
                score_breakdown["web_security"]["details"].append("Strong SSL/TLS configuration (+5)")
        else:
            # Deduct points for invalid/missing SSL
            score_breakdown["web_security"]["score"] = max(0, score_breakdown["web_security"]["score"] - 12)
            score_breakdown["web_security"]["details"].append("Invalid or missing SSL/TLS certificate (-12)")
        
        # Security headers check (if available)
        security_headers = results.get("security_headers", {})
        if security_headers:
            headers_count = sum(1 for header, present in security_headers.items() if present)
            if headers_count >= 4:
                score_breakdown["web_security"]["score"] += 5
                score_breakdown["web_security"]["details"].append("Good security headers coverage (+5)")
            elif headers_count >= 2:
                score_breakdown["web_security"]["score"] += 3
                score_breakdown["web_security"]["details"].append("Basic security headers present (+3)")
        
        # Infrastructure Scoring (15 points)
        cloud_infrastructure = results.get("cloud_infrastructure", {})
        cloud_providers = cloud_infrastructure.get("cloud_providers", [])
        
        if cloud_providers:
            reputable_providers = ["AWS", "Google Cloud", "Microsoft Azure", "Cloudflare"]
            reputable_count = len([p for p in cloud_providers if p in reputable_providers])
            if reputable_count > 0:
                score_breakdown["infrastructure"]["score"] += 10
                score_breakdown["infrastructure"]["details"].append("Using reputable cloud providers (+10)")
        
        cdn_providers = cloud_infrastructure.get("cdn_providers", [])
        if cdn_providers:
            score_breakdown["infrastructure"]["score"] += 5
            score_breakdown["infrastructure"]["details"].append("CDN services detected (+5)")
        
        # Calculate total score
        total_score = sum(category["score"] for category in score_breakdown.values())
        max_score = sum(category["max"] for category in score_breakdown.values())
        percentage = (total_score / max_score) * 100
        
        # Determine grade
        if percentage >= 90:
            grade = "A+"
            grade_description = "Excellent security posture"
        elif percentage >= 80:
            grade = "A"
            grade_description = "Strong security posture"
        elif percentage >= 70:
            grade = "B"
            grade_description = "Good security posture"
        elif percentage >= 60:
            grade = "C"
            grade_description = "Adequate security posture"
        elif percentage >= 50:
            grade = "D"
            grade_description = "Poor security posture"
        else:
            grade = "F"
            grade_description = "Very poor security posture"
        
        return {
            "total_score": total_score,
            "max_score": max_score,
            "percentage": round(percentage, 1),
            "grade": grade,
            "grade_description": grade_description,
            "breakdown": score_breakdown
        }

    def _check_bimi_dkim_indicators(self):
        """Check BIMI records which often indicate strong DKIM implementation."""
        selectors = {}
        
        try:
            # Use the comprehensive BIMI check
            bimi_result = self.check_bimi()
            if bimi_result["present"]:
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
                
                # Advanced DNS Security Analysis
                console.print("\n[*] Analyzing advanced DNS security configurations...")
                
                # DNSSEC Analysis
                console.print("  [dim]DNSSEC provides cryptographic authentication for DNS responses[/dim]")
                dnssec_results = self.domain.check_dnssec()
                results["dnssec"] = dnssec_results
                
                if dnssec_results["enabled"]:
                    if dnssec_results["valid"]:
                        console.print("  [bold green]✓ DNSSEC enabled and validating[/bold green]")
                    else:
                        console.print("  [bold yellow]! DNSSEC enabled but validation issues detected[/bold yellow]")
                    
                    # Show DNSSEC record details
                    if dnssec_results["ds_records"]:
                        console.print(f"  DS Records: {len(dnssec_results['ds_records'])} found")
                    if dnssec_results["dnskey_records"]:
                        console.print(f"  DNSKEY Records: {len(dnssec_results['dnskey_records'])} found")
                    if dnssec_results["rrsig_records"]:
                        console.print(f"  RRSIG Records: {len(dnssec_results['rrsig_records'])} found")
                    
                    # Display DNSSEC issues
                    for issue in dnssec_results["issues"]:
                        console.print(f"  [yellow]! {issue}[/yellow]")
                else:
                    console.print("  [dim]• DNSSEC not implemented[/dim]")
                
                # Display DNSSEC recommendations
                for recommendation in dnssec_results["recommendations"]:
                    console.print(f"  [cyan]• {recommendation}[/cyan]")

                # CAA Analysis
                console.print("\n  [dim]CAA records restrict which Certificate Authorities can issue certificates[/dim]")
                caa_results = self.domain.check_caa()
                results["caa"] = caa_results
                
                if caa_results["present"]:
                    console.print("  [bold green]✓ CAA records configured[/bold green]")
                    if caa_results["authorized_cas"]:
                        console.print(f"  Authorized CAs: {', '.join(set(caa_results['authorized_cas']))}")
                    if caa_results["iodef_contacts"]:
                        console.print(f"  Security contacts: {', '.join(caa_results['iodef_contacts'])}")
                    
                    # Display CAA issues
                    for issue in caa_results["issues"]:
                        console.print(f"  [yellow]! {issue}[/yellow]")
                else:
                    console.print("  [dim]• No CAA records found[/dim]")
                
                # Display CAA recommendations
                for recommendation in caa_results["recommendations"]:
                    console.print(f"  [cyan]• {recommendation}[/cyan]")

                # DNS-over-HTTPS/TLS Analysis
                console.print("\n  [dim]DoH/DoT provide encrypted DNS queries for enhanced privacy[/dim]")
                doh_dot_results = self.domain.check_dns_over_https_tls()
                results["dns_privacy"] = doh_dot_results
                
                if doh_dot_results["doh_supported"] or doh_dot_results["dot_supported"]:
                    privacy_features = []
                    if doh_dot_results["doh_supported"]:
                        privacy_features.append("DNS-over-HTTPS")
                    if doh_dot_results["dot_supported"]:
                        privacy_features.append("DNS-over-TLS")
                    
                    console.print(f"  [bold green]✓ Modern DNS privacy protocols supported: {', '.join(privacy_features)}[/bold green]")
                    
                    if doh_dot_results["doh_endpoints"]:
                        console.print(f"  DoH endpoints: {len(doh_dot_results['doh_endpoints'])} found")
                    if doh_dot_results["dot_endpoints"]:
                        console.print(f"  DoT endpoints: {len(doh_dot_results['dot_endpoints'])} found")
                    
                    # Display issues
                    for issue in doh_dot_results["issues"]:
                        console.print(f"  [yellow]! {issue}[/yellow]")
                else:
                    console.print("  [dim]• No modern DNS privacy protocols detected[/dim]")
                
                # Display recommendations
                for recommendation in doh_dot_results["recommendations"]:
                    console.print(f"  [cyan]• {recommendation}[/cyan]")

                # Cloud Infrastructure Discovery
                console.print("\n[*] Discovering cloud infrastructure and services...")
                console.print("  [dim]Analyzing DNS patterns for cloud provider identification[/dim]")
                cloud_results = self.domain.discover_cloud_infrastructure()
                results["cloud_infrastructure"] = cloud_results
                
                if cloud_results["cloud_providers"]:
                    console.print(f"  [bold green]✓ Cloud providers detected: {', '.join(cloud_results['cloud_providers'])}[/bold green]")
                    
                    if cloud_results["detected_services"]:
                        console.print(f"  Services identified: {len(cloud_results['detected_services'])}")
                        # Show first few services
                        services_to_show = cloud_results["detected_services"][:3]
                        for service in services_to_show:
                            console.print(f"    • {service}")
                        if len(cloud_results["detected_services"]) > 3:
                            console.print(f"    • ... and {len(cloud_results['detected_services']) - 3} more services")
                    
                    if cloud_results["cdn_providers"]:
                        console.print(f"  CDN services: {', '.join(cloud_results['cdn_providers'])}")
                    
                    if cloud_results["email_services"]:
                        console.print(f"  Email services: {', '.join(cloud_results['email_services'])}")
                else:
                    console.print("  [dim]• No major cloud providers detected[/dim]")
                
                # Display cloud recommendations
                for recommendation in cloud_results["recommendations"]:
                    console.print(f"  [cyan]• {recommendation}[/cyan]")
                    
            else:
                results["dns_records"] = {}
                results["meta_errors"] = []
                results["dnssec"] = {"enabled": False}
                results["caa"] = {"present": False}
                results["dns_privacy"] = {"doh_supported": False, "dot_supported": False}
                results["cloud_infrastructure"] = {"cloud_providers": []}
                console.print("  [dim]No DNS record types configured for analysis[/dim]")
        else:
            # DNS section skipped
            results["wildcard"] = False
            results["subdomains"] = []
            results["dns_records"] = {}
            results["meta_errors"] = []
            results["dnssec"] = {"enabled": False}
            results["caa"] = {"present": False}
            results["dns_privacy"] = {"doh_supported": False, "dot_supported": False}
            results["cloud_infrastructure"] = {"cloud_providers": []}

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

            # Advanced Email Security Analysis
            console.print("\n[*] Analyzing advanced email security configurations...")
            
            # BIMI (Brand Indicators for Message Identification) Analysis
            console.print("  [dim]BIMI enables brand logos in email clients for verified domains[/dim]")
            bimi_results = self.domain.check_bimi()
            results["bimi"] = bimi_results
            
            if bimi_results["present"]:
                console.print(f"  [bold green]✓ BIMI record found (selectors: {', '.join(bimi_results['selectors'])})[/bold green]")
                if bimi_results["logo_url"]:
                    console.print(f"  Logo URL: {bimi_results['logo_url']}")
                if bimi_results["authority_url"]:
                    console.print(f"  Authority URL: {bimi_results['authority_url']}")
                
                # Display BIMI issues
                for issue in bimi_results["issues"]:
                    console.print(f"  [yellow]! {issue}[/yellow]")
            else:
                console.print("  [dim]• No BIMI record found[/dim]")
                
            # Display BIMI recommendations
            for recommendation in bimi_results["recommendations"]:
                console.print(f"  [cyan]• {recommendation}[/cyan]")

            # MTA-STS (Mail Transfer Agent Strict Transport Security) Analysis
            console.print("\n  [dim]MTA-STS enforces TLS encryption for email transmission[/dim]")
            mta_sts_results = self.domain.check_mta_sts()
            results["mta_sts"] = mta_sts_results
            
            if mta_sts_results["present"]:
                console.print("  [bold green]✓ MTA-STS policy configured[/bold green]")
                if mta_sts_results["policy_found"]:
                    console.print("  [green]✓ Policy file accessible[/green]")
                else:
                    console.print("  [yellow]! Policy TXT record found but policy file not accessible[/yellow]")
                
                # Display MTA-STS issues
                for issue in mta_sts_results["issues"]:
                    console.print(f"  [yellow]! {issue}[/yellow]")
            else:
                console.print("  [dim]• No MTA-STS policy found[/dim]")
                
            # Display MTA-STS recommendations
            for recommendation in mta_sts_results["recommendations"]:
                console.print(f"  [cyan]• {recommendation}[/cyan]")

            # TLS-RPT (SMTP TLS Reporting) Analysis
            console.print("\n  [dim]TLS-RPT provides reporting on SMTP TLS failures[/dim]")
            tls_rpt_results = self.domain.check_tls_rpt()
            results["tls_rpt"] = tls_rpt_results
            
            if tls_rpt_results["present"]:
                console.print("  [bold green]✓ TLS-RPT configured[/bold green]")
                if tls_rpt_results["rua"]:
                    console.print(f"  Reporting addresses: {', '.join(tls_rpt_results['rua'])}")
                
                # Display TLS-RPT issues
                for issue in tls_rpt_results["issues"]:
                    console.print(f"  [yellow]! {issue}[/yellow]")
            else:
                console.print("  [dim]• No TLS-RPT configuration found[/dim]")
                
            # Display TLS-RPT recommendations
            for recommendation in tls_rpt_results["recommendations"]:
                console.print(f"  [cyan]• {recommendation}[/cyan]")
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
        
        # Cloud Infrastructure Summary
        cloud_infrastructure = results.get("cloud_infrastructure", {})
        if cloud_infrastructure and (cloud_infrastructure.get("cloud_providers") or cloud_infrastructure.get("cdn_providers")):
            console.print("\n[bold blue]===== INFRASTRUCTURE SUMMARY =====[/bold blue]")
            console.print("  [dim]Detected cloud services and infrastructure providers[/dim]")
            
            # Create infrastructure summary table
            infra_table = Table(title="Infrastructure Analysis")
            infra_table.add_column("Category", style="cyan", no_wrap=True)
            infra_table.add_column("Providers", style="green")
            infra_table.add_column("Services", style="magenta", max_width=40)
            infra_table.add_column("Confidence", style="yellow", justify="center")
            
            # Add cloud providers
            if cloud_infrastructure.get("cloud_providers"):
                providers = ', '.join(cloud_infrastructure["cloud_providers"])
                services = cloud_infrastructure.get("detected_services", [])
                cloud_services = [s for s in services if any(p in s for p in cloud_infrastructure["cloud_providers"])]
                service_text = ', '.join(cloud_services[:3])
                if len(cloud_services) > 3:
                    service_text += f" (+{len(cloud_services)-3} more)"
                confidence = "High" if len(cloud_infrastructure["cloud_providers"]) > 0 else "Medium"
                infra_table.add_row("Cloud Hosting", providers, service_text, confidence)
            
            # Add CDN providers
            if cloud_infrastructure.get("cdn_providers"):
                cdn_providers = ', '.join(cloud_infrastructure["cdn_providers"])
                infra_table.add_row("CDN Services", cdn_providers, "Content Delivery", "High")
            
            # Add email services
            if cloud_infrastructure.get("email_services"):
                email_providers = ', '.join(cloud_infrastructure["email_services"])
                infra_table.add_row("Email Services", email_providers, "Email Hosting", "High")
            
            console.print(infra_table)
            
            # Infrastructure insights
            total_services = len(cloud_infrastructure.get("detected_services", []))
            if total_services > 0:
                console.print(f"\n[bold]Infrastructure Insights:[/bold]")
                console.print(f"  📊 Total services detected: {total_services}")
                
                # Analyze infrastructure complexity
                complexity = "Enterprise" if total_services > 5 else "Standard" if total_services > 2 else "Basic"
                console.print(f"  🏗️  Infrastructure complexity: {complexity}")
                
                # Security recommendations based on infrastructure
                if cloud_infrastructure.get("cdn_providers"):
                    console.print("  ✅ CDN usage detected - good for performance and DDoS protection")
                if len(cloud_infrastructure.get("cloud_providers", [])) > 1:
                    console.print("  ⚠️  Multiple cloud providers - ensure consistent security policies")
                if not cloud_infrastructure.get("cdn_providers"):
                    console.print("  💡 Consider implementing CDN for better performance and security")
        
        # Security Score Summary
        console.print("\n[bold cyan]===== SECURITY SCORE =====[/bold cyan]")
        console.print("  [dim]Overall security posture assessment based on comprehensive analysis[/dim]")
        
        security_score = self.domain.calculate_security_score(results)
        results["security_score"] = security_score
        
        # Display overall score with appropriate color
        grade = security_score["grade"]
        percentage = security_score["percentage"]
        
        if grade in ["A+", "A"]:
            grade_color = "bold green"
        elif grade in ["B", "C"]:
            grade_color = "bold yellow"
        else:
            grade_color = "bold red"
        
        console.print(f"\n[{grade_color}]Overall Security Grade: {grade} ({percentage}%)[/{grade_color}]")
        console.print(f"[dim]{security_score['grade_description']}[/dim]")
        console.print(f"Score: {security_score['total_score']}/{security_score['max_score']} points")
        
        # Display breakdown by category
        console.print("\n[bold]Score Breakdown:[/bold]")
        for category, data in security_score["breakdown"].items():
            category_name = category.replace("_", " ").title()
            score_pct = (data["score"] / data["max"]) * 100 if data["max"] > 0 else 0
            
            if score_pct >= 80:
                status_color = "green"
            elif score_pct >= 60:
                status_color = "yellow"
            else:
                status_color = "red"
            
            console.print(f"  {category_name}: [{status_color}]{data['score']}/{data['max']} ({score_pct:.0f}%)[/{status_color}]")
            
            # Show key details
            for detail in data["details"][:2]:  # Show top 2 details
                console.print(f"    [dim]• {detail}[/dim]")
        
        # Security recommendations
        all_recommendations = []
        for category_data in security_score["breakdown"].values():
            for detail in category_data["details"]:
                if detail.startswith("No ") or "not enabled" in detail or detail.startswith("Invalid"):
                    recommendation = detail.replace("(-", "(missing -").replace("No ", "Implement ").replace(" not enabled", " to enhance security")
                    if recommendation not in all_recommendations:
                        all_recommendations.append(recommendation)
        
        if all_recommendations:
            console.print("\n[bold cyan]Priority Security Recommendations:[/bold cyan]")
            for i, rec in enumerate(all_recommendations[:5], 1):  # Show top 5 recommendations
                console.print(f"  {i}. {rec}")
        
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
    parser.add_argument(
        "--output-csv", help="Write results to the given CSV file", default=None
    )
    parser.add_argument(
        "--output-html", help="Write results to the given HTML file", default=None
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

    # Export results in requested formats
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        console.print(f"[green]JSON results written to {args.output_json}[/green]")
    
    if args.output_csv:
        export_to_csv(results, args.output_csv)
    
    if args.output_html:
        export_to_html(results, args.output_html)


def export_to_csv(results, filename):
    """Export scan results to CSV format."""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Category', 'Type', 'Name', 'Value', 'Status', 'Details'])
            
            domain = results.get('domain', 'Unknown')
            
            # DNS Records
            dns_records = results.get('dns_records', {})
            for record_type, records in dns_records.items():
                for record in records:
                    writer.writerow(['DNS', record_type, domain, str(record), 'Found', ''])
            
            # Subdomains
            subdomains = results.get('subdomains', [])
            for subdomain in subdomains:
                writer.writerow(['DNS', 'Subdomain', subdomain, '', 'Found', ''])
            
            # DNSSEC
            dnssec = results.get('dnssec', {})
            if dnssec.get('enabled'):
                status = 'Valid' if dnssec.get('valid') else 'Invalid'
                writer.writerow(['Security', 'DNSSEC', domain, '', status, f"DS: {len(dnssec.get('ds_records', []))}, DNSKEY: {len(dnssec.get('dnskey_records', []))}"])
            
            # CAA Records
            caa = results.get('caa', {})
            if caa.get('present'):
                cas = ', '.join(caa.get('authorized_cas', []))
                writer.writerow(['Security', 'CAA', domain, cas, 'Configured', ''])
            
            # Email Security
            dmarc = results.get('dmarc', {})
            if dmarc.get('present'):
                policy = dmarc.get('policy', 'Unknown')
                writer.writerow(['Email', 'DMARC', domain, policy, 'Configured', ''])
            
            spf = results.get('spf', {})
            spf_records = spf.get('records', [])
            for record in spf_records:
                writer.writerow(['Email', 'SPF', domain, record, 'Configured', ''])
            
            dkim = results.get('dkim', {})
            found_selectors = dkim.get('found_selectors', {})
            for selector, record in found_selectors.items():
                if record:
                    writer.writerow(['Email', 'DKIM', f"{selector}._domainkey.{domain}", 'Present', 'Valid', ''])
            
            # Advanced Email Security
            bimi = results.get('bimi', {})
            if bimi.get('present'):
                logo_url = bimi.get('logo_url', '')
                writer.writerow(['Email', 'BIMI', domain, logo_url, 'Configured', f"Selectors: {', '.join(bimi.get('selectors', []))}"])
            
            mta_sts = results.get('mta_sts', {})
            if mta_sts.get('present'):
                policy_status = 'Valid' if mta_sts.get('policy_found') else 'TXT only'
                writer.writerow(['Email', 'MTA-STS', domain, '', policy_status, ''])
            
            tls_rpt = results.get('tls_rpt', {})
            if tls_rpt.get('present'):
                rua = ', '.join(tls_rpt.get('rua', []))
                writer.writerow(['Email', 'TLS-RPT', domain, rua, 'Configured', ''])
            
            # Cloud Infrastructure
            cloud = results.get('cloud_infrastructure', {})
            providers = cloud.get('cloud_providers', [])
            for provider in providers:
                writer.writerow(['Infrastructure', 'Cloud Provider', domain, provider, 'Detected', ''])
            
            services = cloud.get('detected_services', [])
            for service in services:
                writer.writerow(['Infrastructure', 'Cloud Service', domain, service, 'Detected', ''])
            
            # SSL/TLS
            ssl = results.get('ssl', {})
            if ssl.get('valid'):
                issuer = ssl.get('issuer', 'Unknown')
                expiry = ssl.get('expires', 'Unknown')
                writer.writerow(['Security', 'SSL/TLS', domain, issuer, 'Valid', f"Expires: {expiry}"])
            
            # Security Score
            security_score = results.get('security_score', {})
            if security_score:
                grade = security_score.get('grade', 'Unknown')
                percentage = security_score.get('percentage', 0)
                writer.writerow(['Assessment', 'Security Score', domain, f"{grade} ({percentage}%)", 'Calculated', f"Score: {security_score.get('total_score', 0)}/{security_score.get('max_score', 100)}"])
        
        console.print(f"[green]CSV results written to {filename}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error writing CSV file: {e}[/red]")

def export_to_html(results, filename):
    """Export scan results to HTML format with enhanced styling."""
    try:
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Inspector Report - {domain}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 40px;
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }}
        .section h2 {{
            color: #333;
            margin-top: 0;
            font-size: 1.8em;
            font-weight: 400;
        }}
        .section h3 {{
            color: #666;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        .status-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .status-card {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            border-left: 4px solid #28a745;
        }}
        .status-card.warning {{
            border-left-color: #ffc107;
        }}
        .status-card.error {{
            border-left-color: #dc3545;
        }}
        .status-card.info {{
            border-left-color: #17a2b8;
        }}
        .status-card h4 {{
            margin: 0 0 10px 0;
            color: #333;
        }}
        .status-card p {{
            margin: 0;
            color: #666;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
            font-weight: 500;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 500;
        }}
        .badge.success {{ background: #d4edda; color: #155724; }}
        .badge.warning {{ background: #fff3cd; color: #856404; }}
        .badge.error {{ background: #f8d7da; color: #721c24; }}
        .badge.info {{ background: #d1ecf1; color: #0c5460; }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }}
        .code {{
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DNS Inspector Report</h1>
            <p>Domain: <strong>{domain}</strong> | Generated: {timestamp}</p>
        </div>
        
        <div class="content">
            {content}
        </div>
        
        <div class="footer">
            <p>Generated by DNS Inspector | <a href="https://github.com/mikeprivette/DNS-Inpsector">GitHub</a></p>
        </div>
    </div>
</body>
</html>
        """
        
        domain = results.get('domain', 'Unknown')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        content_sections = []
        
        # Summary Section
        summary_cards = []
        
        # DNS Summary
        dns_records = results.get('dns_records', {})
        total_records = sum(len(records) for records in dns_records.values())
        subdomains_count = len(results.get('subdomains', []))
        
        summary_cards.append(f"""
            <div class="status-card info">
                <h4>DNS Discovery</h4>
                <p>{total_records} DNS records found across {len(dns_records)} types</p>
                <p>{subdomains_count} subdomains discovered</p>
            </div>
        """)
        
        # Security Summary
        security_features = []
        if results.get('dnssec', {}).get('enabled'):
            security_features.append('DNSSEC')
        if results.get('caa', {}).get('present'):
            security_features.append('CAA')
        if results.get('dmarc', {}).get('present'):
            security_features.append('DMARC')
        
        security_status = 'success' if len(security_features) >= 2 else 'warning' if security_features else 'error'
        summary_cards.append(f"""
            <div class="status-card {security_status}">
                <h4>Security Features</h4>
                <p>{len(security_features)} security features enabled</p>
                <p>{', '.join(security_features) if security_features else 'No major security features detected'}</p>
            </div>
        """)
        
        # Cloud Infrastructure
        cloud_providers = results.get('cloud_infrastructure', {}).get('cloud_providers', [])
        cloud_status = 'info' if cloud_providers else 'warning'
        summary_cards.append(f"""
            <div class="status-card {cloud_status}">
                <h4>Cloud Infrastructure</h4>
                <p>{len(cloud_providers)} cloud providers detected</p>
                <p>{', '.join(cloud_providers[:3]) if cloud_providers else 'Traditional hosting detected'}</p>
            </div>
        """)
        
        # Security Score Summary
        security_score = results.get('security_score', {})
        if security_score:
            grade = security_score.get('grade', 'Unknown')
            percentage = security_score.get('percentage', 0)
            grade_color = 'success' if grade in ['A+', 'A'] else 'warning' if grade in ['B', 'C'] else 'error'
            
            summary_cards.append(f"""
                <div class="status-card {grade_color}">
                    <h4>Security Score</h4>
                    <p>Grade: <strong>{grade}</strong> ({percentage}%)</p>
                    <p>{security_score.get('grade_description', '')}</p>
                </div>
            """)
        
        content_sections.append(f"""
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="status-grid">
                    {''.join(summary_cards)}
                </div>
            </div>
        """)
        
        # DNS Records Section
        if dns_records:
            dns_table_rows = []
            for record_type, records in dns_records.items():
                for record in records:
                    dns_table_rows.append(f"<tr><td>{record_type}</td><td class='code'>{record}</td></tr>")
            
            content_sections.append(f"""
                <div class="section">
                    <h2>DNS Records</h2>
                    <table>
                        <thead>
                            <tr><th>Type</th><th>Value</th></tr>
                        </thead>
                        <tbody>
                            {''.join(dns_table_rows)}
                        </tbody>
                    </table>
                </div>
            """)
        
        # Security Analysis Section
        security_rows = []
        
        dnssec = results.get('dnssec', {})
        if dnssec.get('enabled'):
            status = 'Valid' if dnssec.get('valid') else 'Issues Detected'
            badge_class = 'success' if dnssec.get('valid') else 'warning'
            security_rows.append(f"<tr><td>DNSSEC</td><td><span class='badge {badge_class}'>{status}</span></td><td>DS: {len(dnssec.get('ds_records', []))}, DNSKEY: {len(dnssec.get('dnskey_records', []))}</td></tr>")
        
        caa = results.get('caa', {})
        if caa.get('present'):
            cas = ', '.join(caa.get('authorized_cas', []))
            security_rows.append(f"<tr><td>CAA</td><td><span class='badge success'>Configured</span></td><td>{cas}</td></tr>")
        
        dmarc = results.get('dmarc', {})
        if dmarc.get('present'):
            policy = dmarc.get('policy', 'Unknown')
            badge_class = 'success' if policy in ['quarantine', 'reject'] else 'warning'
            security_rows.append(f"<tr><td>DMARC</td><td><span class='badge {badge_class}'>{policy}</span></td><td>{dmarc.get('rua', 'No reporting')}</td></tr>")
        
        if security_rows:
            content_sections.append(f"""
                <div class="section">
                    <h2>Security Analysis</h2>
                    <table>
                        <thead>
                            <tr><th>Feature</th><th>Status</th><th>Details</th></tr>
                        </thead>
                        <tbody>
                            {''.join(security_rows)}
                        </tbody>
                    </table>
                </div>
            """)
        
        # Cloud Infrastructure Section  
        if cloud_providers:
            cloud_rows = []
            for provider in cloud_providers:
                cloud_rows.append(f"<tr><td>{provider}</td><td><span class='badge info'>Detected</span></td><td>Cloud Provider</td></tr>")
            
            services = results.get('cloud_infrastructure', {}).get('detected_services', [])
            for service in services[:10]:  # Limit to first 10 services
                cloud_rows.append(f"<tr><td>{service}</td><td><span class='badge info'>Active</span></td><td>Cloud Service</td></tr>")
            
            content_sections.append(f"""
                <div class="section">
                    <h2>Cloud Infrastructure</h2>
                    <table>
                        <thead>
                            <tr><th>Service</th><th>Status</th><th>Type</th></tr>
                        </thead>
                        <tbody>
                            {''.join(cloud_rows)}
                        </tbody>
                    </table>
                </div>
            """)
        
        final_html = html_template.format(
            domain=domain,
            timestamp=timestamp,
            content=''.join(content_sections)
        )
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(final_html)
        
        console.print(f"[green]HTML report written to {filename}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error writing HTML file: {e}[/red]")

def print_banner(text):
    banner = pyfiglet.figlet_format(text)
    console.print(f"[bold green]{banner}[/bold green]")


if __name__ == "__main__":
    print_banner("DNS INSPECTAH")
    main()
