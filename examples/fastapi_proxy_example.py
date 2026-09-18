"""
Real FastAPI Proxy with PromptShield ShieldMiddleware Integration.
This demonstrates how PromptShield works with any proxy system.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from promptshield.integrations.shield_middleware import ShieldMiddleware
import httpx
import os
from typing import Dict, Any

# Initialize FastAPI app
app = FastAPI(title="Secure LLM Proxy with PromptShield")

# Initialize ShieldMiddleware
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
        "endpoints": {
            "health": "/health",
            "chat": "/v1/chat/completions"
        }
    }

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "protection": "active"}

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Main proxy endpoint with PromptShield protection.
    
    This demonstrates the complete flow:
    1. Receive request from client
    2. Extract messages
    3. Scan with ShieldMiddleware
    4. Check for blocks
    5. Forward sanitized request to upstream
    6. Return response to client
    """
    
    # Parse request body
    try:
        request_data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    
    # Validate request structure
    if "messages" not in request_data:
        raise HTTPException(status_code=400, detail="Missing 'messages' field")
    
    original_messages = request_data["messages"]
    
    print(f"📥 Incoming request: {len(original_messages)} messages")
    print(f"   First message: {original_messages[0].get('content', '')[:50]}...")
    
    # STEP 1: Scan messages with ShieldMiddleware
    modified_messages, findings, injection = guard.scan_messages(original_messages)
    
    print(f"🔍 ShieldMiddleware scan results:")
    print(f"   Findings: {len(findings)}")
    print(f"   Injection threat: {injection.threat_score if injection else 0}")
    
    # Log findings for monitoring
    if findings:
        print(f"   🔒 Protected credentials:")
        for i, finding in enumerate(findings, 1):
            print(f"      {i}. {finding.detector}: {finding.value[:20]}...")
    
    # STEP 2: Check if request should be blocked
    if error := guard.check_blocked(injection):
        print(f"🚫 Request blocked: {error}")
        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked by PromptShield",
                "reason": error,
                "threat_score": injection.threat_score if injection else 0
            }
        )
    
    # STEP 3: Forward sanitized request to upstream provider
    print(f"✅ Request allowed, forwarding to upstream provider")
    
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
                print(f"⚠️ Upstream error: {response.status_code}")
                return JSONResponse(
                    status_code=response.status_code,
                    content=response.json()
                )
            
            # Return upstream response to client
            print(f"✅ Response received from upstream provider")
            return response.json()
            
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Upstream timeout")
    except Exception as e:
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
    
    uvicorn.run(app, host="0.0.0.0", port=8000)