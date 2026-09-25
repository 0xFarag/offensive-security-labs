"""Real loopback HTTP redirect; both servers are temporary fixtures owned by this process."""
import contextlib
import http.server
import json
import threading
import urllib.error
import urllib.parse
import urllib.request

MARKER = "SYNTHETIC_METADATA_ONLY"


def origin(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("credentials/fragments are not allowed")
    return parsed.scheme, parsed.hostname, parsed.port


@contextlib.contextmanager
def fixtures():
    hits = []

    class Backend(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(MARKER.encode())

        def log_message(self, *args):
            pass

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    backend_url = f"http://127.0.0.1:{backend.server_port}"

    class Frontend(Backend):
        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", backend_url + "/metadata")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"PUBLIC_FIXTURE_OK")

    frontend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Frontend)
    front_url = f"http://127.0.0.1:{frontend.server_port}"
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (backend, frontend)]
    for thread in threads:
        thread.start()
    try:
        yield front_url, backend_url, hits
    finally:
        for server in (backend, frontend):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def fetch_fixture(path, front_url, backend_url, *, fixed):
    """No arbitrary target CLI. Transport permits only the two passed loopback fixture ports."""
    allowed = {origin(front_url), origin(backend_url)}
    if any(scheme != "http" or host != "127.0.0.1" or port is None
           for scheme, host, port in allowed):
        raise ValueError("fixture origins must be explicit loopback ports")
    if path not in ("/redirect", "/public"):
        raise ValueError("unknown fixture path")

    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if origin(newurl) not in allowed:
                raise ValueError("outside fixture transport boundary")
            if fixed and origin(newurl) != origin(front_url):
                raise ValueError("redirect target is outside the application allowlist")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
    with opener.open(front_url + path, timeout=2) as response:
        return response.read(1024).decode()


def demo():
    with fixtures() as (front, back, hits):
        vulnerable = fetch_fixture("/redirect", front, back, fixed=False)
        before = len(hits)
        try:
            fetch_fixture("/redirect", front, back, fixed=True)
            fixed_reaches = True
        except ValueError:
            fixed_reaches = False
        legitimate = fetch_fixture("/public", front, back, fixed=True)
        return {"attack": "An allowed HTTP origin redirects to a forbidden fixture origin",
                "vulnerable_accepts": vulnerable == MARKER, "fixed_accepts": fixed_reaches,
                "legitimate_accepts": legitimate == "PUBLIC_FIXTURE_OK",
                "returned_body": vulnerable, "backend_requests_before_fix": before,
                "backend_requests_after_fix": len(hits),
                "boundary": "Real HTTP on two ephemeral 127.0.0.1 ports; no cloud metadata accessed"}


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
