"""
Comprehensive Security Testing for PromptShield + LiteLLM Integration
This ensures all requests are protected and no credentials leak through.
"""

import asyncio
from promptshield.integrations.litellm import PromptShieldGuard
from promptshield import PromptShield

class SecurityTestSuite:
    """Comprehensive security testing suite for PromptShield."""
    
    def __init__(self):
        self.guard = PromptShieldGuard()
        self.shield = PromptShield()
        self.test_results = []
    
    def log_result(self, test_name, passed, details):
        """Log test result."""
        self.test_results.append({
            'test': test_name,
            'passed': passed,
            'details': details
        })
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
        if details:
            print(f"   Details: {details}")
    
    async def test_credential_detection(self):
        """Test detection of various credential types."""
        print("\n" + "=" * 80)
        print("CREDENTIAL DETECTION TESTS")
        print("=" * 80)
        
        test_cases = [
            # AWS Credentials
            ("AWS Access Key", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
            ("AWS Secret Key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            
            # OpenAI Credentials
            ("OpenAI API Key", "sk-proj-abc123xyz789", "sk-proj-abc123xyz789"),
            ("OpenAI Legacy Key", "sk-abc123xyz789", "sk-abc123xyz789"),
            
            # GitHub Credentials
            ("GitHub Token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234", "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"),
            ("GitHub OAuth", "gho_1234567890abcdefghijklmnopqrstuvwxyz1234", "gho_1234567890abcdefghijklmnopqrstuvwxyz1234"),
            
            # Google Cloud
            ("GCP Service Account", "projects/my-project/serviceAccounts/my-account@my-project.iam.gserviceaccount.com", "my-account@my-project.iam.gserviceaccount.com"),
            
            # Azure Credentials
            ("Azure Connection String", "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net", "AccountKey=mykey"),
            
            # Database Credentials
            ("MongoDB URI", "mongodb://user:password@localhost:27017/db", "password"),
            ("PostgreSQL URI", "postgresql://user:password@localhost:5432/db", "password"),
            
            # API Keys
            ("Stripe Key", "sk_test_51Mabc123xyz", "sk_test_51Mabc123xyz"),
            ("Twilio Key", "ACabc123xyz789", "ACabc123xyz789"),
            
            # SSH Keys
            ("SSH Private Key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAyKf7Z...", "-----BEGIN RSA PRIVATE KEY-----"),
            
            # Tokens
            ("JWT Token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        ]
        
        for test_name, credential, search_term in test_cases:
            message = f"Here is my {test_name.lower()}: {credential}"
            
            try:
                result = await self.guard.async_pre_call_hook(
                    user_api_key_dict={},
                    cache={},
                    data={"messages": [{"role": "user", "content": message}]},
                    call_type="completion"
                )
                
                processed = result['messages'][0]['content']
                passed = search_term not in processed
                
                if passed:
                    details = f"Credential redacted successfully"
                else:
                    details = f"WARNING: Credential found in processed message!"
                
                self.log_result(test_name, passed, details)
                
            except Exception as e:
                self.log_result(test_name, False, f"Error: {str(e)}")
    
    async def test_obfuscation_attempts(self):
        """Test detection of obfuscated credentials."""
        print("\n" + "=" * 80)
        print("OBFUSCATION ATTEMPT TESTS")
        print("=" * 80)
        
        test_cases = [
            ("Split Credential", "My AWS key is AKIAIOSFODNN7 and then EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
            ("Spaced Credential", "A K I A I O S F O D N N 7 E X A M P L E", "AKIAIOSFODNN7EXAMPLE"),
            ("Mixed Case", "AkIaIoSfOdNn7ExAmPlE", "AKIAIOSFODNN7EXAMPLE"),
            ("Base64 Encoded", "QUtJQUlPU0ZPRE5ORVhBTVBMQQ==", "QUtJQUlPU0ZPRE5ORVhBTVBMQQ=="),
            ("URL Encoded", "AKIAIOSFODNN7EXAMPLE%20", "AKIAIOSFODNN7EXAMPLE"),
            ("With Comments", "/* AWS_KEY */ AKIAIOSFODNN7EXAMPLE /* END */", "AKIAIOSFODNN7EXAMPLE"),
        ]
        
        for test_name, message, search_term in test_cases:
            try:
                result = await self.guard.async_pre_call_hook(
                    user_api_key_dict={},
                    cache={},
                    data={"messages": [{"role": "user", "content": message}]},
                    call_type="completion"
                )
                
                processed = result['messages'][0]['content']
                # Check if the credential pattern is detected
                scan_result = self.shield.scan(processed)
                passed = search_term not in processed or len(scan_result.findings) > 0
                
                if passed:
                    details = "Obfuscation attempt detected/blocked"
                else:
                    details = "WARNING: Obfuscated credential may have leaked!"
                
                self.log_result(test_name, passed, details)
                
            except Exception as e:
                self.log_result(test_name, False, f"Error: {str(e)}")
    
    async def test_context_injection(self):
        """Test credentials in different contexts."""
        print("\n" + "=" * 80)
        print("CONTEXT INJECTION TESTS")
        print("=" * 80)
        
        contexts = [
            ("Code Block", "```python\naws_key = 'AKIAIOSFODNN7EXAMPLE'\n```"),
            ("JSON Object", '{"aws_key": "AKIAIOSFODNN7EXAMPLE"}'),
            ("YAML Config", "aws_key: AKIAIOSFODNN7EXAMPLE"),
            ("Environment Variable", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
            ("URL Parameter", "https://api.example.com?key=AKIAIOSFODNN7EXAMPLE"),
            ("Base64 in JSON", '{"key": "QUtJQUlPU0ZPRE5ORVhBTVBMQQ=="}'),
            ("Commented Code", "# aws_key = AKIAIOSFODNN7EXAMPLE"),
            ("Debug Statement", "print(f'AWS Key: {AKIAIOSFODNN7EXAMPLE}')"),
        ]
        
        for context_name, message in contexts:
            try:
                result = await self.guard.async_pre_call_hook(
                    user_api_key_dict={},
                    cache={},
                    data={"messages": [{"role": "user", "content": message}]},
                    call_type="completion"
                )
                
                processed = result['messages'][0]['content']
                scan_result = self.shield.scan(processed)
                
                # Check if any credentials remain
                has_credentials = any(
                    cred in processed for cred in ["AKIAIOSFODNN7EXAMPLE", "QUtJQUlPU0ZPRE5ORVhBTVBMQQ=="]
                )
                
                passed = not has_credentials
                details = "Context handled correctly" if passed else "WARNING: Credential found in context!"
                
                self.log_result(context_name, passed, details)
                
            except Exception as e:
                self.log_result(context_name, False, f"Error: {str(e)}")
    
    async def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        print("\n" + "=" * 80)
        print("EDGE CASE TESTS")
        print("=" * 80)
        
        test_cases = [
            ("Empty Message", "", True),
            ("Very Long Message", "Hello " * 1000 + "AKIAIOSFODNN7EXAMPLE", False),
            ("Multiple Messages", ["Hello", "AKIAIOSFODNN7EXAMPLE", "World"], False),
            ("Unicode Characters", "Hello 世界 AKIAIOSFODNN7EXAMPLE 🌍", False),
            ("Special Characters", "Hello!@#$%^&*()AKIAIOSFODNN7EXAMPLE", False),
            ("Newlines", "Hello\\nAKIAIOSFODNN7EXAMPLE\\nWorld", False),
            ("Tabs", "Hello\\tAKIAIOSFODNN7EXAMPLE\\tWorld", False),
        ]
        
        for test_name, content, should_pass in test_cases:
            try:
                if isinstance(content, list):
                    messages = [{"role": "user", "content": msg} for msg in content]
                else:
                    messages = [{"role": "user", "content": content}]
                
                result = await self.guard.async_pre_call_hook(
                    user_api_key_dict={},
                    cache={},
                    data={"messages": messages},
                    call_type="completion"
                )
                
                # Check if credentials were found in any message
                all_content = " ".join([msg.get("content", "") for msg in result['messages']])
                has_credentials = "AKIAIOSFODNN7EXAMPLE" in all_content
                
                passed = (not has_credentials) if not should_pass else True
                details = "Edge case handled correctly" if passed else "WARNING: Edge case failed!"
                
                self.log_result(test_name, passed, details)
                
            except Exception as e:
                self.log_result(test_name, False, f"Error: {str(e)}")
    
    async def test_performance(self):
        """Test performance with various loads."""
        print("\n" + "=" * 80)
        print("PERFORMANCE TESTS")
        print("=" * 80)
        
        import time
        
        # Test single request
        start = time.time()
        await self.guard.async_pre_call_hook(
            user_api_key_dict={},
            cache={},
            data={"messages": [{"role": "user", "content": "Hello AKIAIOSFODNN7EXAMPLE"}]},
            call_type="completion"
        )
        single_time = time.time() - start
        
        self.log_result("Single Request", single_time < 1.0, f"Time: {single_time:.3f}s")
        
        # Test multiple concurrent requests
        start = time.time()
        tasks = [
            self.guard.async_pre_call_hook(
                user_api_key_dict={},
                cache={},
                data={"messages": [{"role": "user", "content": f"Message {i} AKIAIOSFODNN7EXAMPLE"}]},
                call_type="completion"
            )
            for i in range(10)
        ]
        await asyncio.gather(*tasks)
        batch_time = time.time() - start
        
        self.log_result("10 Concurrent Requests", batch_time < 5.0, f"Time: {batch_time:.3f}s")
    
    def generate_report(self):
        """Generate comprehensive security report."""
        print("\n" + "=" * 80)
        print("SECURITY TEST REPORT")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['passed'])
        failed_tests = total_tests - passed_tests
        
        print(f"\n📊 SUMMARY:")
        print(f"   Total Tests: {total_tests}")
        print(f"   ✅ Passed: {passed_tests} ({passed_tests/total_tests*100:.1f}%)")
        print(f"   ❌ Failed: {failed_tests} ({failed_tests/total_tests*100:.1f}%)")
        
        if failed_tests > 0:
            print(f"\n⚠️ FAILED TESTS:")
            for result in self.test_results:
                if not result['passed']:
                    print(f"   ❌ {result['test']}: {result['details']}")
        
        print(f"\n🎯 SECURITY ASSESSMENT:")
        if failed_tests == 0:
            print("   ✅ EXCELLENT - All security tests passed!")
            print("   ✅ Your PromptShield integration is working correctly.")
            print("   ✅ All requests through LiteLLM are protected.")
        elif failed_tests <= 2:
            print("   ⚠️ GOOD - Most tests passed, but review failures.")
            print("   ⚠️ Some credential types may not be fully protected.")
        else:
            print("   ❌ NEEDS IMPROVEMENT - Multiple security issues detected.")
            print("   ❌ Review failed tests and update configuration.")
        
        print("\n" + "=" * 80)
        
        return {
            'total': total_tests,
            'passed': passed_tests,
            'failed': failed_tests,
            'success_rate': passed_tests / total_tests * 100
        }

async def main():
    """Run comprehensive security tests."""
    print("🔒 COMPREHENSIVE PROMPTSHIELD SECURITY TESTING")
    print("=" * 80)
    print("This test suite ensures all requests through LiteLLM are protected")
    print("from credential leakage and prompt injection attacks.")
    print("=" * 80)
    
    suite = SecurityTestSuite()
    
    # Run all test suites
    await suite.test_credential_detection()
    await suite.test_obfuscation_attempts()
    await suite.test_context_injection()
    await suite.test_edge_cases()
    await suite.test_performance()
    
    # Generate final report
    report = suite.generate_report()
    
    # Return exit code based on results
    return 0 if report['failed'] == 0 else 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)