# Subdomain Enumeration Tool

A comprehensive Python tool for discovering subdomains using multiple enumeration techniques. This tool combines API-based enumeration, Certificate Transparency logs, and brute-force techniques with asynchronous programming for optimal performance.

## Features

### 🔍 Multiple Enumeration Methods
- **API-based enumeration**: VirusTotal, AlienVault OTX, SecurityTrails
- **Certificate Transparency logs**: crt.sh integration
- **Brute-force enumeration**: Custom wordlist support
- **Asynchronous programming**: High-performance concurrent requests

### ⚡ Performance Optimizations
- Concurrent request processing
- Configurable request limits and timeouts
- Retry logic with exponential backoff
- Data source prioritization
- Request statistics and monitoring

### 🛠️ Advanced Configuration
- JSON-based configuration system
- API key management
- Customizable enumeration settings
- Output format options
- Brute-force parameters

## Installation

1. Clone or download the project files
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Configure API keys (optional):
```bash
cp config.json.example config.json
# Edit config.json with your API keys
```

## Usage

### Basic Usage

```bash
# Basic enumeration using all methods
python subdomain_enum.py example.com

# Using specific methods only
python subdomain_enum.py example.com -m virustotal crt_sh

# With custom wordlist for brute-force
python subdomain_enum.py example.com -w wordlist.txt

# Save results to file
python subdomain_enum.py example.com -o results.json
```

### Advanced Usage

```bash
# Using the advanced version with configuration
python subdomain_enum_advanced.py example.com -c config_advanced.json

# Verbose output with statistics
python subdomain_enum_advanced.py example.com -v --stats

# Custom wordlist with specific methods
python subdomain_enum_advanced.py example.com -m virustotal brute_force -w custom_wordlist.txt
```

## Configuration

### Basic Configuration (config.json)
```json
{
  "virustotal": "YOUR_VIRUSTOTAL_API_KEY_HERE",
  "alienvault": "YOUR_ALIENVAULT_API_KEY_HERE",
  "securitytrails": "YOUR_SECURITYTRAILS_API_KEY_HERE"
}
```

### Advanced Configuration (config_advanced.json)
```json
{
  "api_keys": {
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY_HERE",
    "alienvault": "YOUR_ALIENVAULT_API_KEY_HERE",
    "securitytrails": "YOUR_SECURITYTRAILS_API_KEY_HERE"
  },
  "enumeration_settings": {
    "max_concurrent_requests": 50,
    "request_timeout": 30,
    "retry_attempts": 3,
    "retry_delay": 1
  },
  "data_source_priority": {
    "virustotal": 1,
    "securitytrails": 2,
    "alienvault": 3,
    "crt_sh": 4,
    "brute_force": 5
  },
  "output_settings": {
    "save_to_file": true,
    "output_format": "json",
    "include_timestamps": true,
    "include_additional_info": true
  },
  "brute_force_settings": {
    "max_concurrent_brute_force": 50,
    "wordlist_path": "wordlist.txt",
    "check_https": true,
    "check_http": true
  }
}
```

## API Keys Setup

### VirusTotal
1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Get your API key from your profile
3. Add it to your configuration file

### AlienVault OTX
1. Sign up at [AlienVault OTX](https://otx.alienvault.com/)
2. Generate an API key
3. Add it to your configuration file

### SecurityTrails
1. Sign up at [SecurityTrails](https://securitytrails.com/)
2. Get your API key from the dashboard
3. Add it to your configuration file

## Enumeration Methods

### 1. VirusTotal API
- Queries VirusTotal's database for known subdomains
- Requires API key
- High accuracy, limited by API rate limits

### 2. AlienVault OTX
- Uses Open Threat Exchange data
- Requires API key
- Good coverage of malicious domains

### 3. SecurityTrails
- Professional DNS and domain intelligence
- Requires API key
- High-quality data with historical information

### 4. Certificate Transparency (crt.sh)
- Free Certificate Transparency logs
- No API key required
- Good coverage of SSL-enabled subdomains

### 5. Brute-force
- Custom wordlist-based enumeration
- Checks HTTP and HTTPS
- Configurable concurrency limits

## Output Formats

### Console Output
```
============================================================
Subdomain Enumeration Results for: example.com
============================================================
Total subdomains found: 15
Time taken: 12.34 seconds
============================================================

Results by method:
  virustotal: 8 subdomains
  crt_sh: 5 subdomains
  brute_force: 2 subdomains

All subdomains:
  api.example.com
  blog.example.com
  mail.example.com
  www.example.com
```

### JSON Output
```json
{
  "domain": "example.com",
  "timestamp": 1640995200.0,
  "total_subdomains": 15,
  "statistics": {
    "total_requests": 45,
    "successful_requests": 42,
    "failed_requests": 3,
    "duration_seconds": 12.34,
    "requests_per_second": 3.65
  },
  "subdomains": [
    {
      "subdomain": "api.example.com",
      "method": "virustotal",
      "timestamp": 1640995200.0,
      "additional_info": null
    }
  ]
}
```

## Performance Tips

1. **Use API keys**: Significantly improves results from API-based methods
2. **Adjust concurrency**: Increase `max_concurrent_requests` for faster enumeration
3. **Prioritize methods**: Configure `data_source_priority` to run faster methods first
4. **Custom wordlists**: Use targeted wordlists for better brute-force results
5. **Monitor statistics**: Use `--stats` flag to analyze performance

## Examples

### Quick Enumeration
```bash
python subdomain_enum.py example.com
```

### Comprehensive Enumeration
```bash
python subdomain_enum_advanced.py example.com -c config_advanced.json -w wordlist.txt -o results.json --stats
```

### API-only Enumeration
```bash
python subdomain_enum.py example.com -m virustotal securitytrails alienvault
```

### Brute-force Only
```bash
python subdomain_enum.py example.com -m brute_force -w custom_wordlist.txt
```

## File Structure

```
subdomain/
├── subdomain_enum.py              # Basic enumeration tool
├── subdomain_enum_advanced.py     # Advanced enumeration tool
├── config.json                    # Basic configuration
├── config_advanced.json           # Advanced configuration
├── wordlist.txt                   # Default wordlist
├── requirements.txt               # Python dependencies
└── README.md                     # This file
```

## Troubleshooting

### Common Issues

1. **API Rate Limits**: Reduce `max_concurrent_requests` in configuration
2. **Timeout Errors**: Increase `request_timeout` value
3. **No Results**: Check API keys and network connectivity
4. **Slow Performance**: Adjust concurrency settings and use faster methods first

### Debug Mode
```bash
python subdomain_enum.py example.com -v
```

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission to enumerate subdomains of the target domain. Unauthorized enumeration may violate terms of service and applicable laws.
