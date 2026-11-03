"""Local HTTP transport surrogate; never reads provider settings or credentials."""

import json
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from evidencesoc.config import Settings


@contextmanager
def model_surrogate(*, proposals=(), failure=None):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body)
            if failure == "timeout":
                time.sleep(0.5)
            if failure == "503":
                status, response = (
                    503,
                    {"error": {"message": "local surrogate unavailable"}},
                )
            else:
                output = (
                    {"action": "call", "arguments": {}, "rationale": "missing tool"}
                    if failure == "invalid"
                    else proposals[min(len(requests) - 1, len(proposals) - 1)]
                    if proposals
                    else {"action": "stop", "rationale": "Late local response."}
                )
                message = {"role": "assistant", "content": json.dumps(output)}
                if body.get("tools"):
                    message = {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "local-call",
                                "type": "function",
                                "function": {
                                    "name": body["tools"][0]["function"]["name"],
                                    "arguments": json.dumps(output),
                                },
                            }
                        ],
                    }
                status, response = (
                    200,
                    {
                        "id": "local-response",
                        "object": "chat.completion",
                        "created": 0,
                        "model": "local-surrogate",
                        "choices": [
                            {"index": 0, "message": message, "finish_reason": "stop"}
                        ],
                        "usage": {
                            "prompt_tokens": 1,
                            "completion_tokens": 1,
                            "total_tokens": 2,
                        },
                    },
                )
            encoded = json.dumps(response).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass  # A timed-out adapter intentionally disconnects.

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    settings = Settings(
        _env_file=None,
        llm_mode="deepseek",
        deepseek_api_key="local-surrogate-only",
        deepseek_base_url=f"http://127.0.0.1:{server.server_port}/v1",
        deepseek_model="local-surrogate",
    )
    try:
        yield settings, requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
