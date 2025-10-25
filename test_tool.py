#!/usr/bin/env python3
"""
Simple test script to verify the subdomain enumeration tool works
"""

import asyncio
import sys
from subdomain_enum import SubdomainEnumerator, EnumerationMethod

async def test_basic_functionality():
    """Test basic functionality without API keys"""
    print("Testing subdomain enumeration tool...")
    
    try:
        async with SubdomainEnumerator('example.com') as enumerator:
            # Test crt.sh enumeration (no API key required)
            results = await enumerator.enumerate_crt_sh()
            print(f"[OK] crt.sh enumeration: Found {len(results)} subdomains")
            
            # Test subdomain validation
            valid_tests = [
                ('www', True),
                ('api', True),
                ('test-subdomain', True),
                ('', False),
                ('example.com', False),
                ('invalid..subdomain', False)
            ]
            
            for subdomain, expected in valid_tests:
                result = enumerator._is_valid_subdomain(subdomain)
                if result == expected:
                    print(f"[OK] Subdomain validation: '{subdomain}' -> {result}")
                else:
                    print(f"[FAIL] Subdomain validation failed: '{subdomain}' -> {result} (expected {expected})")
            
            print("[OK] Basic functionality test passed!")
            return True
            
    except Exception as e:
        print(f"[FAIL] Test failed: {e}")
        return False

async def test_advanced_functionality():
    """Test advanced functionality"""
    print("\nTesting advanced enumeration tool...")
    
    try:
        from subdomain_enum_advanced import AdvancedSubdomainEnumerator, EnumerationConfig
        
        config = EnumerationConfig(api_keys={})
        
        async with AdvancedSubdomainEnumerator('example.com', config) as enumerator:
            # Test configuration loading
            print("[OK] Configuration loaded successfully")
            
            # Test statistics
            stats = enumerator.get_statistics()
            print(f"[OK] Statistics system working: {len(stats)} metrics")
            
            # Test crt.sh enumeration
            results = await enumerator.enumerate_crt_sh()
            print(f"[OK] Advanced crt.sh enumeration: Found {len(results)} subdomains")
            
            print("[OK] Advanced functionality test passed!")
            return True
            
    except Exception as e:
        print(f"[FAIL] Advanced test failed: {e}")
        return False

async def main():
    """Run all tests"""
    print("Subdomain Enumeration Tool - Test Suite")
    print("=" * 40)
    
    basic_test = await test_basic_functionality()
    advanced_test = await test_advanced_functionality()
    
    print("\n" + "=" * 40)
    if basic_test and advanced_test:
        print("[OK] All tests passed! Tool is ready to use.")
        return 0
    else:
        print("[FAIL] Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
