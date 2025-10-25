#!/usr/bin/env python3
"""
Example usage of the Subdomain Enumeration Tool
This script demonstrates how to use the tool programmatically
"""

import asyncio
import json
from subdomain_enum_advanced import AdvancedSubdomainEnumerator, EnumerationConfig, EnumerationMethod

async def example_basic_enumeration():
    """Example of basic subdomain enumeration"""
    print("=== Basic Subdomain Enumeration Example ===")
    
    # Create configuration
    config = EnumerationConfig(
        api_keys={
            # Add your API keys here
            # 'virustotal': 'your_key_here',
            # 'alienvault': 'your_key_here',
            # 'securitytrails': 'your_key_here'
        },
        max_concurrent_requests=20,
        request_timeout=15
    )
    
    # Enumerate subdomains
    async with AdvancedSubdomainEnumerator('example.com', config) as enumerator:
        # Use only free methods (no API keys required)
        results = await enumerator.enumerate_all(
            methods=[EnumerationMethod.CRT_SH]
        )
        
        print(f"Found {len(results)} subdomains:")
        for result in results:
            print(f"  {result.subdomain} (via {result.method})")

async def example_with_wordlist():
    """Example with brute-force enumeration"""
    print("\n=== Enumeration with Wordlist Example ===")
    
    # Load wordlist
    wordlist = ['www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop']
    
    config = EnumerationConfig(
        api_keys={},
        brute_force_settings={
            'max_concurrent_brute_force': 10,
            'check_https': True,
            'check_http': True
        }
    )
    
    async with AdvancedSubdomainEnumerator('example.com', config) as enumerator:
        results = await enumerator.enumerate_all(
            wordlist=wordlist,
            methods=[EnumerationMethod.BRUTE_FORCE]
        )
        
        print(f"Found {len(results)} subdomains via brute-force:")
        for result in results:
            print(f"  {result.subdomain} (via {result.method})")

async def example_comprehensive():
    """Example of comprehensive enumeration"""
    print("\n=== Comprehensive Enumeration Example ===")
    
    config = EnumerationConfig(
        api_keys={
            # Add your API keys here for best results
        },
        data_source_priority={
            'crt_sh': 1,  # Run crt.sh first (free)
            'virustotal': 2,
            'securitytrails': 3,
            'alienvault': 4,
            'brute_force': 5
        }
    )
    
    # Load a small wordlist for demonstration
    wordlist = ['www', 'mail', 'ftp', 'admin', 'api']
    
    async with AdvancedSubdomainEnumerator('example.com', config) as enumerator:
        results = await enumerator.enumerate_all(
            wordlist=wordlist,
            methods=[EnumerationMethod.ALL]
        )
        
        # Get statistics
        stats = enumerator.get_statistics()
        
        print(f"Comprehensive enumeration results:")
        print(f"  Total subdomains: {len(results)}")
        print(f"  Time taken: {stats['duration_seconds']:.2f} seconds")
        print(f"  Requests made: {stats['total_requests']}")
        print(f"  Success rate: {stats['successful_requests']}/{stats['total_requests']}")
        
        # Group by method
        method_counts = {}
        for result in results:
            method_counts[result.method] = method_counts.get(result.method, 0) + 1
        
        print("\nResults by method:")
        for method, count in method_counts.items():
            print(f"  {method}: {count} subdomains")
        
        print("\nAll discovered subdomains:")
        for result in sorted(results, key=lambda x: x.subdomain):
            print(f"  {result.subdomain}")

def save_results_to_file(results, filename='example_results.json'):
    """Save results to JSON file"""
    output_data = {
        'total_subdomains': len(results),
        'subdomains': [result.to_dict() for result in results]
    }
    
    with open(filename, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nResults saved to: {filename}")

async def main():
    """Run all examples"""
    print("Subdomain Enumeration Tool - Example Usage")
    print("=" * 50)
    
    # Run examples
    await example_basic_enumeration()
    await example_with_wordlist()
    await example_comprehensive()
    
    print("\n" + "=" * 50)
    print("Examples completed!")

if __name__ == "__main__":
    asyncio.run(main())
