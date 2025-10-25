#!/usr/bin/env python3
"""
Advanced Subdomain Enumeration Tool
Enhanced version with configuration management, data source prioritization,
and improved performance optimizations.
"""

import asyncio
import aiohttp
import argparse
import json
import sys
import time
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urlparse
import re
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from pathlib import Path
import signal
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EnumerationMethod(Enum):
    """Enumeration methods available"""
    VIRUSTOTAL = "virustotal"
    ALIENVAULT = "alienvault"
    SECURITYTRAILS = "securitytrails"
    CRT_SH = "crt_sh"
    BRUTE_FORCE = "brute_force"
    ALL = "all"

@dataclass
class SubdomainResult:
    """Represents a discovered subdomain"""
    subdomain: str
    method: str
    timestamp: float
    additional_info: Optional[Dict] = None
    
    def to_dict(self):
        return asdict(self)

@dataclass
class EnumerationConfig:
    """Configuration for enumeration"""
    api_keys: Dict[str, str]
    max_concurrent_requests: int = 50
    request_timeout: int = 30
    retry_attempts: int = 3
    retry_delay: float = 1.0
    data_source_priority: Dict[str, int] = None
    output_settings: Dict = None
    brute_force_settings: Dict = None
    
    def __post_init__(self):
        if self.data_source_priority is None:
            self.data_source_priority = {
                "virustotal": 1,
                "securitytrails": 2,
                "alienvault": 3,
                "crt_sh": 4,
                "brute_force": 5
            }
        if self.output_settings is None:
            self.output_settings = {
                "save_to_file": True,
                "output_format": "json",
                "include_timestamps": True,
                "include_additional_info": True
            }
        if self.brute_force_settings is None:
            self.brute_force_settings = {
                "max_concurrent_brute_force": 50,
                "wordlist_path": "wordlist.txt",
                "check_https": True,
                "check_http": True
            }

class AdvancedSubdomainEnumerator:
    """Advanced subdomain enumerator with configuration management"""
    
    def __init__(self, domain: str, config: EnumerationConfig):
        self.domain = domain
        self.config = config
        self.results: Set[str] = set()
        self.detailed_results: List[SubdomainResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'start_time': None,
            'end_time': None
        }
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.stats['start_time'] = time.time()
        
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={'User-Agent': 'AdvancedSubdomainEnumerator/2.0'},
            connector=aiohttp.TCPConnector(limit=self.config.max_concurrent_requests)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
        self.stats['end_time'] = time.time()
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate if a string is a valid subdomain"""
        if not subdomain or subdomain == self.domain:
            return False
            
        # Basic validation
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(pattern, subdomain))
    
    def _extract_subdomains_from_text(self, text: str, method: str) -> List[SubdomainResult]:
        """Extract subdomains from text content"""
        subdomains = []
        domain_pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.domain)})'
        
        matches = re.findall(domain_pattern, text, re.IGNORECASE)
        for match in matches:
            subdomain = match[0].lower()
            if self._is_valid_subdomain(subdomain.replace(f'.{self.domain}', '')):
                subdomains.append(SubdomainResult(
                    subdomain=subdomain,
                    method=method,
                    timestamp=time.time()
                ))
        
        return subdomains
    
    async def _make_request_with_retry(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with retry logic"""
        for attempt in range(self.config.retry_attempts):
            try:
                self.stats['total_requests'] += 1
                async with self.session.get(url, **kwargs) as response:
                    if response.status == 200:
                        self.stats['successful_requests'] += 1
                        return response
                    else:
                        logger.warning(f"Request failed with status {response.status} (attempt {attempt + 1})")
                        if attempt < self.config.retry_attempts - 1:
                            await asyncio.sleep(self.config.retry_delay * (attempt + 1))
            except Exception as e:
                logger.warning(f"Request failed: {e} (attempt {attempt + 1})")
                if attempt < self.config.retry_attempts - 1:
                    await asyncio.sleep(self.config.retry_delay * (attempt + 1))
        
        self.stats['failed_requests'] += 1
        return None
    
    async def enumerate_virustotal(self) -> List[SubdomainResult]:
        """Enumerate subdomains using VirusTotal API"""
        if not self.config.api_keys.get('virustotal'):
            logger.warning("VirusTotal API key not provided, skipping...")
            return []
        
        results = []
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': self.config.api_keys['virustotal'],
                'domain': self.domain
            }
            
            response = await self._make_request_with_retry(url, params=params)
            if response:
                data = await response.json()
                
                # Extract subdomains from various sections
                subdomains_text = ""
                if 'subdomains' in data:
                    subdomains_text += " ".join(data['subdomains'])
                if 'domain_siblings' in data:
                    subdomains_text += " ".join(data['domain_siblings'])
                
                results = self._extract_subdomains_from_text(subdomains_text, "virustotal")
                logger.info(f"VirusTotal: Found {len(results)} subdomains")
            
        except Exception as e:
            logger.error(f"VirusTotal enumeration failed: {e}")
        
        return results
    
    async def enumerate_alienvault(self) -> List[SubdomainResult]:
        """Enumerate subdomains using AlienVault OTX API"""
        if not self.config.api_keys.get('alienvault'):
            logger.warning("AlienVault API key not provided, skipping...")
            return []
        
        results = []
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            headers = {'X-OTX-API-KEY': self.config.api_keys['alienvault']}
            
            response = await self._make_request_with_retry(url, headers=headers)
            if response:
                data = await response.json()
                
                subdomains_text = ""
                if 'passive_dns' in data:
                    for record in data['passive_dns']:
                        if 'hostname' in record:
                            subdomains_text += record['hostname'] + " "
                
                results = self._extract_subdomains_from_text(subdomains_text, "alienvault")
                logger.info(f"AlienVault: Found {len(results)} subdomains")
            
        except Exception as e:
            logger.error(f"AlienVault enumeration failed: {e}")
        
        return results
    
    async def enumerate_securitytrails(self) -> List[SubdomainResult]:
        """Enumerate subdomains using SecurityTrails API"""
        if not self.config.api_keys.get('securitytrails'):
            logger.warning("SecurityTrails API key not provided, skipping...")
            return []
        
        results = []
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': self.config.api_keys['securitytrails']}
            
            response = await self._make_request_with_retry(url, headers=headers)
            if response:
                data = await response.json()
                
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        full_subdomain = f"{subdomain}.{self.domain}"
                        if self._is_valid_subdomain(subdomain):
                            results.append(SubdomainResult(
                                subdomain=full_subdomain,
                                method="securitytrails",
                                timestamp=time.time()
                            ))
                
                logger.info(f"SecurityTrails: Found {len(results)} subdomains")
            
        except Exception as e:
            logger.error(f"SecurityTrails enumeration failed: {e}")
        
        return results
    
    async def enumerate_crt_sh(self) -> List[SubdomainResult]:
        """Enumerate subdomains using Certificate Transparency logs (crt.sh)"""
        results = []
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            
            response = await self._make_request_with_retry(url)
            if response:
                data = await response.json()
                
                for cert in data:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip()
                            if name.endswith(f'.{self.domain}') and name != self.domain:
                                subdomain = name.lower()
                                if self._is_valid_subdomain(subdomain.replace(f'.{self.domain}', '')):
                                    results.append(SubdomainResult(
                                        subdomain=subdomain,
                                        method="crt_sh",
                                        timestamp=time.time(),
                                        additional_info={
                                            'issuer': cert.get('issuer_name', ''),
                                            'not_before': cert.get('not_before', ''),
                                            'not_after': cert.get('not_after', '')
                                        }
                                    ))
                
                logger.info(f"crt.sh: Found {len(results)} subdomains")
            
        except Exception as e:
            logger.error(f"crt.sh enumeration failed: {e}")
        
        return results
    
    async def enumerate_brute_force(self, wordlist: List[str]) -> List[SubdomainResult]:
        """Brute-force subdomains using a wordlist"""
        results = []
        max_concurrent = self.config.brute_force_settings.get('max_concurrent_brute_force', 50)
        check_https = self.config.brute_force_settings.get('check_https', True)
        check_http = self.config.brute_force_settings.get('check_http', True)
        
        async def check_subdomain(session, subdomain):
            """Check if a subdomain exists"""
            found_results = []
            
            if check_http:
                try:
                    url = f"http://{subdomain}.{self.domain}"
                    async with session.get(url, allow_redirects=True) as response:
                        if response.status < 400:
                            found_results.append(SubdomainResult(
                                subdomain=f"{subdomain}.{self.domain}",
                                method="brute_force_http",
                                timestamp=time.time(),
                                additional_info={'status_code': response.status, 'protocol': 'http'}
                            ))
                except:
                    pass
            
            if check_https:
                try:
                    url = f"https://{subdomain}.{self.domain}"
                    async with session.get(url, allow_redirects=True) as response:
                        if response.status < 400:
                            found_results.append(SubdomainResult(
                                subdomain=f"{subdomain}.{self.domain}",
                                method="brute_force_https",
                                timestamp=time.time(),
                                additional_info={'status_code': response.status, 'protocol': 'https'}
                            ))
                except:
                    pass
            
            return found_results
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_check(session, subdomain):
            async with semaphore:
                return await check_subdomain(session, subdomain)
        
        # Process wordlist
        tasks = []
        for subdomain in wordlist:
            if self._is_valid_subdomain(subdomain):
                task = limited_check(self.session, subdomain)
                tasks.append(task)
        
        # Execute all checks concurrently
        logger.info(f"Brute-forcing {len(tasks)} subdomains...")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten and filter results
        all_results = []
        for result in results:
            if isinstance(result, list):
                all_results.extend(result)
            elif not isinstance(result, Exception):
                all_results.append(result)
        
        logger.info(f"Brute-force: Found {len(all_results)} subdomains")
        return all_results
    
    async def enumerate_all(self, wordlist: Optional[List[str]] = None, 
                          methods: List[EnumerationMethod] = None) -> List[SubdomainResult]:
        """Enumerate subdomains using all available methods with prioritization"""
        if methods is None:
            methods = [EnumerationMethod.ALL]
        
        all_results = []
        
        # Sort methods by priority
        method_priority = []
        for method in methods:
            if method == EnumerationMethod.ALL:
                # Add all methods with their priorities
                for m in [EnumerationMethod.VIRUSTOTAL, EnumerationMethod.SECURITYTRAILS, 
                         EnumerationMethod.ALIENVAULT, EnumerationMethod.CRT_SH]:
                    priority = self.config.data_source_priority.get(m.value, 999)
                    method_priority.append((priority, m))
            else:
                priority = self.config.data_source_priority.get(method.value, 999)
                method_priority.append((priority, method))
        
        # Sort by priority
        method_priority.sort(key=lambda x: x[0])
        
        # Execute methods in priority order
        for priority, method in method_priority:
            logger.info(f"Executing {method.value} enumeration...")
            
            if method == EnumerationMethod.VIRUSTOTAL:
                results = await self.enumerate_virustotal()
                all_results.extend(results)
            elif method == EnumerationMethod.ALIENVAULT:
                results = await self.enumerate_alienvault()
                all_results.extend(results)
            elif method == EnumerationMethod.SECURITYTRAILS:
                results = await self.enumerate_securitytrails()
                all_results.extend(results)
            elif method == EnumerationMethod.CRT_SH:
                results = await self.enumerate_crt_sh()
                all_results.extend(results)
            elif method == EnumerationMethod.BRUTE_FORCE and wordlist:
                results = await self.enumerate_brute_force(wordlist)
                all_results.extend(results)
        
        # Deduplicate results
        seen = set()
        unique_results = []
        for result in all_results:
            if result.subdomain not in seen:
                seen.add(result.subdomain)
                unique_results.append(result)
        
        return unique_results
    
    def get_statistics(self) -> Dict:
        """Get enumeration statistics"""
        duration = 0
        if self.stats['start_time'] and self.stats['end_time']:
            duration = self.stats['end_time'] - self.stats['start_time']
        
        return {
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'duration_seconds': duration,
            'requests_per_second': self.stats['total_requests'] / duration if duration > 0 else 0
        }

def load_config(config_path: str) -> EnumerationConfig:
    """Load configuration from file"""
    try:
        with open(config_path, 'r') as f:
            data = json.load(f)
        
        return EnumerationConfig(
            api_keys=data.get('api_keys', {}),
            max_concurrent_requests=data.get('enumeration_settings', {}).get('max_concurrent_requests', 50),
            request_timeout=data.get('enumeration_settings', {}).get('request_timeout', 30),
            retry_attempts=data.get('enumeration_settings', {}).get('retry_attempts', 3),
            retry_delay=data.get('enumeration_settings', {}).get('retry_delay', 1.0),
            data_source_priority=data.get('data_source_priority', {}),
            output_settings=data.get('output_settings', {}),
            brute_force_settings=data.get('brute_force_settings', {})
        )
    except FileNotFoundError:
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return EnumerationConfig(api_keys={})
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return EnumerationConfig(api_keys={})

def load_wordlist(wordlist_path: str) -> List[str]:
    """Load wordlist from file"""
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"Wordlist file not found: {wordlist_path}")
        return []
    except Exception as e:
        logger.error(f"Error loading wordlist: {e}")
        return []

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Advanced Subdomain Enumeration Tool')
    parser.add_argument('domain', help='Target domain to enumerate')
    parser.add_argument('-m', '--methods', nargs='+', 
                       choices=[m.value for m in EnumerationMethod],
                       default=['all'], help='Enumeration methods to use')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file for brute-force')
    parser.add_argument('-c', '--config', default='config_advanced.json', 
                       help='Path to configuration file')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--stats', action='store_true', help='Show detailed statistics')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = load_config(args.config)
    
    # Load wordlist if provided
    wordlist = []
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
    elif config.brute_force_settings.get('wordlist_path'):
        wordlist = load_wordlist(config.brute_force_settings['wordlist_path'])
    
    if not wordlist and EnumerationMethod.BRUTE_FORCE in [EnumerationMethod(m) for m in args.methods]:
        logger.warning("No wordlist provided, brute-force will be skipped")
    
    # Convert method strings to enums
    methods = [EnumerationMethod(m) for m in args.methods]
    
    # Start enumeration
    logger.info(f"Starting advanced subdomain enumeration for: {args.domain}")
    
    async with AdvancedSubdomainEnumerator(args.domain, config) as enumerator:
        results = await enumerator.enumerate_all(wordlist, methods)
        stats = enumerator.get_statistics()
    
    # Display results
    print(f"\n{'='*60}")
    print(f"Advanced Subdomain Enumeration Results for: {args.domain}")
    print(f"{'='*60}")
    print(f"Total subdomains found: {len(results)}")
    print(f"Time taken: {stats['duration_seconds']:.2f} seconds")
    
    if args.stats:
        print(f"\nDetailed Statistics:")
        print(f"  Total requests: {stats['total_requests']}")
        print(f"  Successful requests: {stats['successful_requests']}")
        print(f"  Failed requests: {stats['failed_requests']}")
        print(f"  Requests per second: {stats['requests_per_second']:.2f}")
    
    print(f"{'='*60}")
    
    # Group results by method
    method_counts = {}
    for result in results:
        method_counts[result.method] = method_counts.get(result.method, 0) + 1
    
    print("\nResults by method:")
    for method, count in method_counts.items():
        print(f"  {method}: {count} subdomains")
    
    print(f"\nAll subdomains:")
    for result in sorted(results, key=lambda x: x.subdomain):
        print(f"  {result.subdomain}")
    
    # Save results to file if specified
    if args.output or config.output_settings.get('save_to_file'):
        output_file = args.output or f"{args.domain}_subdomains.json"
        
        output_data = {
            'domain': args.domain,
            'timestamp': time.time(),
            'total_subdomains': len(results),
            'statistics': stats,
            'subdomains': [r.to_dict() for r in results]
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to: {output_file}")

if __name__ == "__main__":
    asyncio.run(main())
