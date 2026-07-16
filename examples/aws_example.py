"""
AWS credentials example.

Run from project root:
  python3 examples/aws_example.py
"""

from promptshield import PromptShield

shield = PromptShield()

text = """
Connect to my S3 bucket using these temporary AWS credentials.
AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJGMEQCIAEXAMPLETOKEN1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ==
List all objects in the bucket.

I accidentally pasted my AWS credentials here.

Access Key:
AKIAIOSFODNN7EXAMPLE

Secret Key:
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

Can you use these to check my EC2 instances?

{
  "provider": "aws",
  "credentials": {
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "sessionToken": "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJGMEQCIAEXAMPLETOKEN1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ=="
  },
  "region": "us-east-1"
}

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
