# DNS and Email Security Analyzer

A comprehensive Python script to analyze DNS records for a given domain. This tool enumerates a wide range of DNS record types and reports the results.

## Features

- Enumerates DNS records for all known types by default
- Users can override the record type list in `config.ini`
- Provides a detailed summary of the DNS records found
- Supports the latest version of Python 3
- Detects wildcard DNS records across configured types
- Allows configuration of the delay between DNS queries
- Validates SSL/TLS certificates for the target domain
- Performs a basic vulnerability scan of accessible web services
- Displays colorized output using `rich` with tables for records and summaries
- Optionally enumerates common subdomains defined in `config.ini`
- Supports loading an extended subdomain wordlist via `wordlist_file`
- Pulls additional subdomains from certificate transparency logs when `ct_logs` is enabled
- Checks DMARC, SPF and DKIM records for common issues
- Can attempt a DNS zone transfer when enabled in `config.ini`

## Installation

Clone this repository or download the script directly:

```bash
git clone https://github.com/mikeprivette/DNS-Inpsector.git
```

It is recommended to run the tool in an isolated Python environment. Create a
virtual environment and install the required dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
The `rich` library is included in the requirements to provide colorful tables
and messages in the console.

## Usage

With the virtual environment activated, execute the script with the target domain as an argument:

```bash
python dns_inspectah.py example.com
```

Add `--output-json results.json` to save the findings to a file.

By default the tool queries all DNS record types discovered from `dnspython`.
You can limit or extend the list by editing the `types` entry in `config.ini`.

You can also adjust the delay between DNS queries by setting `query_delay` under
the `[Settings]` section of `config.ini`.

DKIM selectors to probe can be specified in the `[DKIM]` section using the
`selectors` option. A single selector may be given or multiple selectors can be
provided as a comma-separated list.

To perform a more thorough subdomain search, specify a wordlist file with the
`wordlist_file` option under `[Subdomains]`. Each line in the file should
contain a subdomain prefix.

Enable DNS zone transfers by setting `enabled = true` under `[ZoneTransfer]` in
`config.ini`.

Set `ct_logs = true` under `[Subdomains]` to pull additional subdomains from
certificate transparency logs.

DMARC, SPF and DKIM checks are performed automatically and any issues are
highlighted in the output.

The script will display DNS records and a brief summary of the findings.
The summary includes totals for each record type and how many subdomains were discovered.
The output is colorized with `rich`, providing easy-to-read tables like the example below:

```text
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Record Type ┃ Value                        ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ A           │ 93.184.216.34               │
│ MX          │ 10 mail.example.com.        │
└─────────────┴──────────────────────────────┘
```

## Contributing

We welcome contributions to improve this script. Feel free to open an issue or submit a pull request on GitHub.

## License

This script is released under the MIT License. See the [LICENSE](LICENSE) file for more information.
