"""
Azure credentials example.

Run from project root:
  python3 examples/azure_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Azure client secret (Entra ID):
AZURE_CLIENT_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZ!@#AbCdEfG

Azure storage account key:
AZURE_STORAGE_KEY=9KZHQXqBP3Qt7Nl4rw0P8rSpP7vMXnM56k8PVrT90Hm4o6dWwPB09nDp5C9fHjK3xg1R2sT0uVwEoPzL7aA==

Azure subscription ID:
AZURE_SUBSCRIPTION_ID=12345678-1234-1234-1234-123456789abc

Azure connection string:
DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=9KZHQXqBP3Qt7Nl4rw0P8rSpP7vMXnM56k8PVrT90Hm4o6dWwPB09nDp5C9fHjK3xg1R2sT0uVwEoPzL7aA==;EndpointSuffix=core.windows.net
"""

result = shield.scan(text)

print("=" * 50)
print("Original")
print(result.original_text)
print()
print("=" * 50)
print("Redacted")
print(result.redacted_text)
print()
print("=" * 50)
print("Findings")
for finding in result.findings:
    print(f"  {finding.secret_type}")
    print(f"    detector: {finding.detector}")
    print(f"    confidence: {finding.confidence:.2f}")
    print(f"    specificity: {finding.specificity}")
    print(f"    value: {finding.value[:30]}...")
    print()
