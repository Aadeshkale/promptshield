"""
Example: Building a custom LLM proxy with PromptShield.

This demonstrates how to use ShieldMiddleware to build your own
proxy for any web framework.

To run:
  pip install fastapi uvicorn httpx
  python examples/custom_proxy_example.py
"""

from promptshield.integrations.shield_middleware import ShieldMiddleware

# Initialize once — this creates the PromptShield instance
guard = ShieldMiddleware(
    use_injection=True,
    injection_mode="block",
    injection_threshold=0.7,
)


def on_incoming_request(request_body: dict) -> dict:
    """
    Intercept an LLM API request, scan and redact it.

    This is a framework-agnostic example. In a real app you'd
    wire this into your FastAPI/Flask/aiohttp route handler.
    """
    messages = request_body.get("messages", [])

    # Scan and redact all message content
    modified_messages, findings, injection = guard.scan_messages(messages)

    # Check if the request should be blocked
    error = guard.check_blocked(injection)
    if error:
        return {"status": 403, "error": error}

    # Build the modified request body with redacted messages
    modified_body = {**request_body, "messages": modified_messages}

    return {
        "status": 200,
        "body": modified_body,
        "summary": {
            "findings": len(findings),
            "secrets_redacted": len(findings) > 0,
            "injection_threat": round(injection.threat_score, 4) if injection else 0.0,
        },
    }


# --- Framework-specific integration examples ---

def fastapi_example():
    """
    FastAPI integration (pseudocode):

    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    import httpx

    app = FastAPI()
    client = httpx.AsyncClient()
    guard = ShieldMiddleware()

    UPSTREAM_URL = "https://api.openai.com/v1/chat/completions"

    @app.post("/v1/chat/completions")
    async def proxy(request: Request):
        body = await request.json()
        messages, findings, injection = guard.scan_messages(body["messages"])

        error = guard.check_blocked(injection)
        if error:
            return JSONResponse(status_code=403, content={"error": error})

        body["messages"] = messages
        resp = await client.post(UPSTREAM_URL, json=body, headers=request.headers)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    """
    pass


def aiohttp_example():
    """
    aiohttp integration (pseudocode):

    from aiohttp import web
    import httpx

    guard = ShieldMiddleware()
    UPSTREAM = "https://api.openai.com/v1/chat/completions"

    async def handle(request):
        body = await request.json()
        messages, findings, injection = guard.scan_messages(body["messages"])

        error = guard.check_blocked(injection)
        if error:
            return web.json_response({"error": error}, status=403)

        body["messages"] = messages
        async with httpx.AsyncClient() as client:
            resp = await client.post(UPSTREAM, json=body)
        return web.json_response(resp.json())
    """
    pass


# --- Quick test ---

if __name__ == "__main__":
    # Simulate a request with a leaked API key
    test_body = {
        "model": "gpt-4",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Here's my OpenAI key: sk-proj-"
                    "T3BlbkFJSS1Rlc3RLZXlWYWx1ZUhlcmUxMjM0NTY"
                    ". Also what's the weather?"
                ),
            }
        ],
    }

    result = on_incoming_request(test_body)
    print(f"Status: {result['status']}")
    if result["status"] == 200:
        print(f"Redacted messages: {result['body']['messages']}")
        print(f"Summary: {result['summary']}")
    else:
        print(f"Blocked: {result['error']}")
