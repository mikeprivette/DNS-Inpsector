# DNS and Email Security Analyzer

A comprehensive Python script to analyze DNS records and email security settings for a given domain. This script checks for common DNS record types, SPF and DMARC configurations, and evaluates the domain's susceptibility to email spoofing.

## Features

- Enumerates common DNS records such as A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, and TXT
- Analyzes SPF and DMARC settings for email security
- Evaluates the risk of email spoofing based on SPF and DMARC settings
- Provides a detailed summary of the DNS records found
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
python dns_inspector.py example.com
```

The script will display DNS records, their summary, and the email spoofing susceptibility result.

## Contributing

We welcome contributions to improve this script. Feel free to open an issue or submit a pull request on GitHub.

## License

This script is released under the MIT License. See the [LICENSE](LICENSE) file for more information.
