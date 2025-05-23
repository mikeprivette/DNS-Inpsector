# DNS and Email Security Analyzer

A comprehensive Python script to analyze DNS records for a given domain. This tool enumerates a wide range of DNS record types and reports the results.

## Features

- Enumerates DNS records for all known types by default
- Users can override the record type list in `config.ini`
- Provides a detailed summary of the DNS records found
- Detects DNSSEC configuration and attempts zone transfers
- Enumerates subdomains from a configurable list
- Collects email-related DNS records (SPF, DKIM, DMARC)
- Displays SSL certificate issuer and validity dates
- Supports the latest version of Python 3

## Installation

Clone this repository or download the script directly:

```bash
git clone https://github.com/mikeprivette/DNS-Inpsector.git
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Execute the script with the target domain as an argument:

```bash
python dns_inspectah.py example.com
```

By default the tool queries all DNS record types discovered from `dnspython`.
You can limit or extend the list by editing the `types` entry in `config.ini`.

The script will display DNS records and a brief summary of the findings.
If certain metadata record types are blocked by the target's DNS server, the tool notes that these "metaqueries" are not permitted.

## Contributing

We welcome contributions to improve this script. Feel free to open an issue or submit a pull request on GitHub.

## License

This script is released under the MIT License. See the [LICENSE](LICENSE) file for more information.
