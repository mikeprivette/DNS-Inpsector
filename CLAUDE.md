# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Environment Setup

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 dns_inspectah.py example.com
```

## Code Architecture

### Core Classes

**Domain Class** (`dns_inspectah.py:30-223`)
- Primary class for DNS inspection operations
- Key methods: `get_dns_records()`, `check_wildcard_records()`, `enumerate_subdomains()`, `attempt_zone_transfer()`
- Handles DNS queries with built-in rate limiting via `query_delay`
- Includes comprehensive email security checks: DMARC, SPF, DKIM

**Inspector Class** (`dns_inspectah.py:224-335`)
- Orchestrates the complete domain inspection workflow
- Manages rich console output and summary generation
- Coordinates between Domain, SSLValidator, and VulnerabilityScanner

**ConfigManager Class** (`dns_inspectah.py:421-489`)
- Handles configuration parsing from `config.ini`
- Supports special "ALL" keyword for DNS record types (expands to all known types)
- Merges subdomain lists from config and external wordlist files

### Configuration System

The tool is heavily driven by `config.ini` with these key sections:
- `[DNSRecords]`: Controls which DNS record types to query (supports "ALL" keyword)
- `[Subdomains]`: Subdomain enumeration settings and wordlist file path
- `[Settings]`: Query delays and general behavior
- `[DKIM]`: DKIM selectors for email security validation
- `[ZoneTransfer]`: Zone transfer attempt configuration

### DNS Record Type Handling

The application dynamically discovers all DNS record types using `dns.rdatatype.RdataType` and allows users to specify "ALL" in config to query every type. This is implemented in `ConfigManager.get_dns_record_types()`.

### Email Security Analysis

The tool performs comprehensive email security validation:
- **DMARC**: Policy parsing and security recommendations
- **SPF**: Record validation with "include" mechanism analysis
- **DKIM**: Multi-selector validation using configured selectors

### Rich Console Output

All output uses the `rich` library for enhanced formatting:
- DNS records displayed in formatted tables
- Color-coded security warnings and recommendations
- Progress indicators and summary statistics

## Testing

Currently no formal test suite exists. Test manually using:
```bash
python3 dns_inspectah.py google.com
python3 dns_inspectah.py example.com
```

## Dependencies

- `dnspython`: Core DNS operations
- `requests`: HTTP requests for vulnerability scanning
- `pyfiglet`: ASCII banner generation
- `rich`: Enhanced console output

## Key Features to Understand

1. **Rate Limiting**: All DNS queries respect configurable delays to avoid overwhelming servers
2. **Wildcard Detection**: Automatically detects wildcard DNS configurations across all record types
3. **Zone Transfer Attempts**: Can attempt AXFR transfers when enabled in config
4. **Subdomain Discovery**: Combines config-based lists with external wordlist files
5. **SSL Validation**: Checks certificate validity and expiration dates
6. **Error Handling**: Comprehensive exception handling for network operations

## Configuration Examples

Enable all DNS record types:
```ini
[DNSRecords]
types = ALL
```

Configure DKIM selectors:
```ini
[DKIM]
selectors = default,google,selector1,selector2
```

Set custom wordlist:
```ini
[Subdomains]
wordlist_file = custom_subdomains.txt
```