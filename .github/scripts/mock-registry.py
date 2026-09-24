#!/usr/bin/env python3
"""Mock keypackage/account registry for the chat-cli CI smoketest.

A path-keyed store: each POST body is kept under its path, and a GET to the
same path returns it.

  * POST (any)  -> 200, body stored under the path
  * GET  (any)  -> 200 with the stored body, or 404 if nothing was posted there

Account logs are posted and fetched at the same `/v1/account/<addr>` path, so
the client reads back what it published. Keypackages post to one path and are
fetched from another, so their GETs stay 404. Threaded because the client holds
one keep-alive connection per HTTP client. This validates nothing — it only
unblocks the smoketest; protocol-level behavior is covered by the workspace tests.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    # Match the client's HTTP/1.1 requests so reqwest frames the response body.
    protocol_version = "HTTP/1.1"
    store = {}  # path -> last body POSTed there

    def _drain(self):
        # Consume the request body so the client's request completes cleanly.
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)

    def _reply(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.store[self.path] = self.rfile.read(length) if length else b""
        self._reply(200)

    def do_GET(self):
        self._drain()
        body = self.store.get(self.path)
        if body is None:
            return self._reply(404)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
