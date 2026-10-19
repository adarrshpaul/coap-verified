import asyncio
import subprocess
import sys
import time
from aiocoap import *

async def run_interop_client(port=56883):
    context = await Context.create_client_context()
    uri = f"coap://127.0.0.1:{port}/temperature"
    print(f"[Python aiocoap] Sending GET to {uri}...")

    request = Message(code=GET, uri=uri)
    try:
        response = await asyncio.wait_for(context.request(request).response, timeout=3.0)
        print(f"[Python aiocoap] Result Code: {response.code}")
        print(f"[Python aiocoap] Result Payload: {response.payload.decode('utf-8')}")
        assert response.code.is_successful(), f"Expected success code, got {response.code}"
        assert response.payload == b"Hello from Rust CoAP Verified!", "Payload mismatch"
        print("✅ aiocoap Interoperability Verification: PASSED!")
        return 0
    except Exception as e:
        print(f"❌ Interop failed: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 56883
    sys.exit(asyncio.run(run_interop_client(port)))
