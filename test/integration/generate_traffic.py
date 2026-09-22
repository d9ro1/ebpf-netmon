import http.server
import socketserver
import threading
import urllib.request

PORT = 8765


def serve():
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("127.0.0.1", PORT), handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=2).read()
        except Exception as exc:
            print(f"request failed: {exc}")
    print("traffic generation done")
