#!/usr/bin/env python3
"""
Subdomain Enumeration Tool
A comprehensive tool for discovering subdomains using multiple techniques:
- API-based enumeration (VirusTotal, AlienVault OTX, SecurityTrails)
- Certificate Transparency logs (crt.sh)
- Brute-force enumeration with wordlists
- Asynchronous programming for speed optimization
"""

import asyncio
import aiohttp
import argparse
import json
import sys
import time
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse
import re
from dataclasses import dataclass
from enum import Enum
import logging

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

class SubdomainEnumerator:
    """Main class for subdomain enumeration"""
    
    def __init__(self, domain: str, api_keys: Optional[Dict[str, str]] = None):
        self.domain = domain
        self.api_keys = api_keys or {}
        self.results: Set[str] = set()
        self.detailed_results: List[SubdomainResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'SubdomainEnumerator/1.0'}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
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
    
    async def enumerate_virustotal(self) -> List[SubdomainResult]:
        """Enumerate subdomains using VirusTotal API"""
        if not self.api_keys.get('virustotal'):
            logger.warning("VirusTotal API key not provided, skipping...")
            return []
        
        results = []
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': self.api_keys['virustotal'],
                'domain': self.domain
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Extract subdomains from various sections
                    subdomains_text = ""
                    if 'subdomains' in data:
                        subdomains_text += " ".join(data['subdomains'])
                    if 'domain_siblings' in data:
                        subdomains_text += " ".join(data['domain_siblings'])
                    
                    results = self._extract_subdomains_from_text(subdomains_text, "virustotal")
                    logger.info(f"VirusTotal: Found {len(results)} subdomains")
                else:
                    logger.warning(f"VirusTotal API returned status {response.status}")
                    
        except Exception as e:
            logger.error(f"VirusTotal enumeration failed: {e}")
        
        return results
    
    async def enumerate_alienvault(self) -> List[SubdomainResult]:
        """Enumerate subdomains using AlienVault OTX API"""
        if not self.api_keys.get('alienvault'):
            logger.warning("AlienVault API key not provided, skipping...")
            return []
        
        results = []
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            headers = {'X-OTX-API-KEY': self.api_keys['alienvault']}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    subdomains_text = ""
                    if 'passive_dns' in data:
                        for record in data['passive_dns']:
                            if 'hostname' in record:
                                subdomains_text += record['hostname'] + " "
                    
                    results = self._extract_subdomains_from_text(subdomains_text, "alienvault")
                    logger.info(f"AlienVault: Found {len(results)} subdomains")
                else:
                    logger.warning(f"AlienVault API returned status {response.status}")
                    
        except Exception as e:
            logger.error(f"AlienVault enumeration failed: {e}")
        
        return results
    
    async def enumerate_securitytrails(self) -> List[SubdomainResult]:
        """Enumerate subdomains using SecurityTrails API"""
        if not self.api_keys.get('securitytrails'):
            logger.warning("SecurityTrails API key not provided, skipping...")
            return []
        
        results = []
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': self.api_keys['securitytrails']}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
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
                else:
                    logger.warning(f"SecurityTrails API returned status {response.status}")
                    
        except Exception as e:
            logger.error(f"SecurityTrails enumeration failed: {e}")
        
        return results
    
    async def enumerate_crt_sh(self) -> List[SubdomainResult]:
        """Enumerate subdomains using Certificate Transparency logs (crt.sh)"""
        results = []
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            
            async with self.session.get(url) as response:
                if response.status == 200:
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
                else:
                    logger.warning(f"crt.sh returned status {response.status}")
                    
        except Exception as e:
            logger.error(f"crt.sh enumeration failed: {e}")
        
        return results
    
    async def enumerate_brute_force(self, wordlist: List[str], max_concurrent: int = 50) -> List[SubdomainResult]:
        """Brute-force subdomains using a wordlist"""
        results = []
        
        async def check_subdomain(session, subdomain):
            """Check if a subdomain exists"""
            try:
                url = f"http://{subdomain}.{self.domain}"
                async with session.get(url, allow_redirects=True) as response:
                    if response.status < 400:
                        return SubdomainResult(
                            subdomain=f"{subdomain}.{self.domain}",
                            method="brute_force",
                            timestamp=time.time(),
                            additional_info={'status_code': response.status}
                        )
            except:
                pass
            return None
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_check(session, subdomain):
            async with semaphore:
                return await check_subdomain(session, subdomain)
        
        # Process wordlist in batches
        tasks = []
        for subdomain in wordlist:
            if self._is_valid_subdomain(subdomain):
                task = limited_check(self.session, subdomain)
                tasks.append(task)
        
        # Execute all checks concurrently
        logger.info(f"Brute-forcing {len(tasks)} subdomains...")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out None results and exceptions
        valid_results = [r for r in results if r is not None and not isinstance(r, Exception)]
        
        logger.info(f"Brute-force: Found {len(valid_results)} subdomains")
        return valid_results
    
    async def enumerate_all(self, wordlist: Optional[List[str]] = None, 
                          methods: List[EnumerationMethod] = None) -> List[SubdomainResult]:
        """Enumerate subdomains using all available methods"""
        if methods is None:
            methods = [EnumerationMethod.ALL]
        
        all_results = []
        
        # API-based enumeration
        if EnumerationMethod.ALL in methods or EnumerationMethod.VIRUSTOTAL in methods:
            vt_results = await self.enumerate_virustotal()
            all_results.extend(vt_results)
        
        if EnumerationMethod.ALL in methods or EnumerationMethod.ALIENVAULT in methods:
            av_results = await self.enumerate_alienvault()
            all_results.extend(av_results)
        
        if EnumerationMethod.ALL in methods or EnumerationMethod.SECURITYTRAILS in methods:
            st_results = await self.enumerate_securitytrails()
            all_results.extend(st_results)
        
        if EnumerationMethod.ALL in methods or EnumerationMethod.CRT_SH in methods:
            crt_results = await self.enumerate_crt_sh()
            all_results.extend(crt_results)
        
        # Brute-force enumeration
        if (EnumerationMethod.ALL in methods or EnumerationMethod.BRUTE_FORCE in methods) and wordlist:
            bf_results = await self.enumerate_brute_force(wordlist)
            all_results.extend(bf_results)
        
        # Deduplicate results
        seen = set()
        unique_results = []
        for result in all_results:
            if result.subdomain not in seen:
                seen.add(result.subdomain)
                unique_results.append(result)
        
        return unique_results

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

def load_api_keys(config_path: str) -> Dict[str, str]:
    """Load API keys from configuration file"""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Config file not found: {config_path}")
        return {}
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return {}

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Subdomain Enumeration Tool')
    parser.add_argument('domain', help='Target domain to enumerate')
    parser.add_argument('-m', '--methods', nargs='+', 
                       choices=[m.value for m in EnumerationMethod],
                       default=['all'], help='Enumeration methods to use')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file for brute-force')
    parser.add_argument('-c', '--config', default='config.json', 
                       help='Path to API keys configuration file')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--max-concurrent', type=int, default=50,
                       help='Maximum concurrent requests for brute-force')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load API keys
    api_keys = load_api_keys(args.config)
    
    # Load wordlist if provided
    wordlist = []
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            logger.error("No wordlist loaded, brute-force will be skipped")
    
    # Convert method strings to enums
    methods = [EnumerationMethod(m) for m in args.methods]
    
    # Start enumeration
    logger.info(f"Starting subdomain enumeration for: {args.domain}")
    start_time = time.time()
    
    async with SubdomainEnumerator(args.domain, api_keys) as enumerator:
        results = await enumerator.enumerate_all(wordlist, methods)
    
    end_time = time.time()
    
    # Display results
    print(f"\n{'='*60}")
    print(f"Subdomain Enumeration Results for: {args.domain}")
    print(f"{'='*60}")
    print(f"Total subdomains found: {len(results)}")
    print(f"Time taken: {end_time - start_time:.2f} seconds")
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
    if args.output:
        with open(args.output, 'w') as f:
            json.dump([{
                'subdomain': r.subdomain,
                'method': r.method,
                'timestamp': r.timestamp,
                'additional_info': r.additional_info
            } for r in results], f, indent=2)
        print(f"\nResults saved to: {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
