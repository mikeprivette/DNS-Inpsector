#!/usr/bin/env python3

import sys
import dns.resolver
from collections import defaultdict
from termcolor import colored
from emailprotectionslib import spf as spflib
from emailprotectionslib import dmarc as dmarclib

SUBDOMAINS = ['www', 'mail', 'ftp', 'admin', 'webmail', 'blog', 'dev', 'ns1', 'ns2', 'shop']
DNS_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT']

def check_dns_records(domain, record_type):
    """
    Check DNS records of the specified type for a given domain.

    :param domain: The domain to inspect.
    :param record_type: The type of DNS record to query.
    :return: A list of DNS records.
    """
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, record_type)
        return answers
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []

def print_domains(results):
    """
    Print a list of domains and subdomains in a separate section at the top.

    :param results: A dictionary of DNS records, with subdomain as the key and a list of tuples (record type, record) as the value.
    """
    print(colored("Domains and Subdomains:", "cyan", attrs=["bold"]))
    for subdomain in results:
        print(f"  - {subdomain}")
    print("\n" + colored("=" * 80, "blue") + "\n")

def print_results(results):
    """
    Print the DNS records in a readable format, grouped by subdomain and record type.

    :param results: A dictionary of DNS records, with subdomain as the key and a list of tuples (record type, record) as the value.
    """
    for subdomain, records in results.items():
        print(colored(f"{subdomain}:", "yellow", attrs=["bold"]))
        for record_type, record in records:
            print(f"  {colored(record_type, 'green')}: {record.to_text()}")
        print("\n" + colored("-" * 80, "blue") + "\n")

def is_spf_record_strong(domain):
    strong_spf_record = True
    spf_record = spflib.SpfRecord.from_domain(domain)
    if spf_record is not None and spf_record.record is not None:
        output_info("Found SPF record:")
        output_info(str(spf_record.record))

        strong_all_string = check_spf_all_string(spf_record)
        if strong_all_string is False:

            redirect_strength = check_spf_redirect_mechanisms(spf_record)
            include_strength = check_spf_include_mechanisms(spf_record)

            strong_spf_record = False

            if redirect_strength is True:
                strong_spf_record = True

            if include_strength is True:
                strong_spf_record = True
    else:
        output_good(domain + " has no SPF record!")
        strong_spf_record = False

    return strong_spf_record

def is_dmarc_record_strong(domain):
    dmarc_record_strong = False

    dmarc = get_dmarc_record(domain)

    if dmarc is not None and dmarc.record is not None:
        dmarc_record_strong = check_dmarc_policy(dmarc)

        check_dmarc_extras(dmarc)
    elif dmarc.get_org_domain() is not None:
        output_info("No DMARC record found. Looking for organizational record")
        dmarc_record_strong = check_dmarc_org_policy(dmarc)
    else:
        output_good(domain + " has no DMARC record!")

    return dmarc_record_strong

if __name__ == "__main__":
    color_init()
    spoofable = False

    try:
        domain = sys.argv[1]

        spf_record_strength = is_spf_record_strong(domain)

        dmarc_record_strength = is_dmarc_record_strong(domain)
        if dmarc_record_strength is False:
            spoofable = True
        else:
            spoofable = False

        if spoofable:
            output_good("Spoofing possible for " + domain + "!")
        else:
            output_bad("Spoofing not possible for " + domain)

    except IndexError:
        output_error("Usage: " + sys.argv[0] + " [DOMAIN]")

def check_spoofability(domain):
    spf_strength = is_spf_record_strong(domain)
    dmarc_strength = is_dmarc_record_strong(domain)

    if not spf_strength or not dmarc_strength:
        return True

    return False

def main(domain):
    results = defaultdict(list)

    # Enumerate sub-domains and DNS records
    print(f"Inspecting domain: {domain}\n")

    for subdomain in [domain] + [f"{sd}.{domain}" for sd in SUBDOMAINS]:
        for record_type in DNS_RECORD_TYPES:
            records = check_dns_records(subdomain, record_type)
            for record in records:
                results[subdomain].append((record_type, record))

    print_domains(results)
    print_results(results)

    # Check for domain spoofability
    spoofable = check_spoofability(domain)
    if spoofable:
        print(colored(f"Spoofing possible for {domain}!", "green"))
    else:
        print(colored(f"Spoofing not possible for {domain}", "red"))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python dns_inspector.py <domain>")
        sys.exit(1)

    main(sys.argv[1])