"""
Complete Proxy Integration Example with PromptShield ShieldMiddleware.

This demonstrates a production-ready proxy implementation that:
1. Intercepts all LLM requests
2. Scans for credentials and prompt injection
3. Sanitizes messages before forwarding to LLM providers
4. Returns normal responses to clients

To run this example:
  pip install fastapi uvicorn httpx
  python examples/proxy_integration_example.py

Then test with:
  curl http://localhost:8000/health
  curl -X POST http://localhost:8000/v1/chat/completions \\
    -H "Content-Type: application/json" \\
    -d '{"messages": [{"role": "user", "content": "Help with AWS. Key: AKIAIOSFODNN7EXAMPLE"}]}'
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from promptshield.integrations.shield_middleware import ShieldMiddleware
import httpx
import os
from typing import Dict, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Secure LLM Proxy with PromptShield",
    description="Production-ready proxy with comprehensive credential protection",
    version="1.0.0"
)

# Initialize ShieldMiddleware with production settings
guard = ShieldMiddleware(
    use_injection=True,
    injection_mode="block",
    injection_threshold=0.7
)

# Upstream LLM provider configuration
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "https://api.openai.com/v1/chat/completions")
API_KEY = os.getenv("OPENAI_API_KEY", "")

@app.get("/")
async def root():
    """Root endpoint with proxy information."""
    return {
        "service": "Secure LLM Proxy",
        "protection": "PromptShield ShieldMiddleware",
        "status": "active",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "chat": "/v1/chat/completions",
            "test": "/test"
        },
        "features": {
            "credential_detection": "45+ detectors",
            "injection_protection": "enabled",
            "performance": "<1ms overhead",
            "compatibility": "OpenAI API format"
        }
    }

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "protection": "active",
        "upstream": UPSTREAM_URL
    }

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Main proxy endpoint with PromptShield protection.
    
    This demonstrates the complete security flow:
    1. Receive request from client
    2. Extract messages
    3. Scan with ShieldMiddleware
    4. Check for blocks
    5. Forward sanitized request to upstream
    6. Return response to client
    """
    
    try:
        # Parse request body
        request_data = await request.json()
    except Exception as e:
        logger.error(f"Invalid JSON: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    
    # Validate request structure
    if "messages" not in request_data:
        raise HTTPException(status_code=400, detail="Missing 'messages' field")
    
    original_messages = request_data["messages"]
    
    logger.info(f"Received request with {len(original_messages)} messages")
    
    # STEP 1: Scan messages with ShieldMiddleware
    modified_messages, findings, injection = guard.scan_messages(original_messages)
    
    logger.info(f"ShieldMiddleware scan: {len(findings)} findings, injection threat: {injection.threat_score if injection else 0}")
    
    # Log findings for monitoring (without exposing actual credentials)
    if findings:
        logger.info(f"Protected {len(findings)} credential(s) from {len(set(f.detector for f in findings))} detector(s)")
    
    # STEP 2: Check if request should be blocked
    if error := guard.check_blocked(injection):
        logger.warning(f"Request blocked: {error}")
        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked by PromptShield",
                "reason": error,
                "threat_score": injection.threat_score if injection else 0
            }
        )
    
    # STEP 3: Forward sanitized request to upstream provider
    logger.info("Request allowed, forwarding to upstream provider")
    
    # Prepare upstream request with sanitized messages
    upstream_request = {
        **request_data,
        "messages": modified_messages  # Use sanitized messages
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                UPSTREAM_URL,
                json=upstream_request,
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json"
                },
                timeout=30.0
            )
            
            if response.status_code != 200:
                logger.error(f"Upstream error: {response.status_code}")
                return JSONResponse(
                    status_code=response.status_code,
                    content=response.json()
                )
            
            # Return upstream response to client
            logger.info("Response received from upstream provider")
            return response.json()
            
    except httpx.TimeoutException:
        logger.error("Upstream timeout")
        raise HTTPException(status_code=504, detail="Upstream timeout")
    except Exception as e:
        logger.error(f"Upstream error: {e}")
        raise HTTPException(status_code=502, detail=f"Upstream error: {e}")

@app.post("/test")
async def test_protection(request: Request):
    """
    Test endpoint to demonstrate PromptShield protection.
    This doesn't call upstream, just shows the protection in action.
    """
    
    try:
        request_data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    
    if "messages" not in request_data:
        raise HTTPException(status_code=400, detail="Missing 'messages' field")
    
    original_messages = request_data["messages"]
    
    # Scan messages
    modified_messages, findings, injection = guard.scan_messages(original_messages)
    blocked = guard.check_blocked(injection)
    
    return {
        "original_messages": original_messages,
        "modified_messages": modified_messages,
        "findings": len(findings),
        "findings_details": [
            {
                "detector": finding.detector,
                "value": finding.value[:30] + "..." if len(finding.value) > 30 else finding.value,
                "start": finding.start,
                "end": finding.end
            }
            for finding in findings
        ],
        "injection": {
            "threat_score": injection.threat_score if injection else 0,
            "blocked": blocked is not None,
            "error": blocked
        },
        "protection_status": "active" if not blocked else "blocked"
    }

@app.get("/stats")
async def stats():
    """Statistics endpoint showing protection effectiveness."""
    return {
        "protection": {
            "status": "active",
            "detectors_available": 45,
            "injection_protection": "enabled",
            "blocking_threshold": 0.7
        },
        "performance": {
            "scan_overhead": "<1ms",
            "throughput": "high",
            "latency_impact": "negligible"
        },
        "coverage": {
            "credential_types": [
                "AWS", "Azure", "GCP", "OpenAI", "GitHub", 
                "GitLab", "Database", "SSH", "JWT", "OAuth"
            ],
            "injection_types": [
                "prompt_injection", "jailbreak", "system_prompt_leak"
            ]
        }
    }

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting Secure LLM Proxy with PromptShield")
    print(f"   Upstream URL: {UPSTREAM_URL}")
    print(f"   Protection: ShieldMiddleware (injection_mode='block')")
    print(f"   Endpoints:")
    print(f"     - http://localhost:8000/")
    print(f"     - http://localhost:8000/health")
    print(f"     - http://localhost:8000/v1/chat/completions")
    print(f"     - http://localhost:8000/test")
    print(f"     - http://localhost:8000/stats")
    print()
    print("📚 Example Usage:")
    print("   curl http://localhost:8000/health")
    print("   curl -X POST http://localhost:8000/test \\")
    print('     -H "Content-Type: application/json" \\')
    print('     -d \'{"messages": [{"role": "user", "content": "Help with AWS. Key: AKIAIOSFODNN7EXAMPLE"}]}\'')
    print()
    
    uvicorn.run(app, host="0.0.0.0", port=8000)