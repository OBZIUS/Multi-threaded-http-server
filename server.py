#!/usr/bin/env python3
"""
Multi-threaded HTTP Server (assignment)
Supports:
 - GET (HTML rendering and binary downloads)
 - POST (application/json, saved to resources/uploads/)
 - Thread pool with connection queue
 - Keep-Alive (HTTP/1.1 default), timeouts, max requests per connection
 - Host header validation
 - Path traversal protection
 - Logging with timestamps and thread names
"""

import argparse
import socket
import threading
import queue
import os
import sys
import time
import uuid
import json
from datetime import datetime
from email.utils import formatdate
from urllib.parse import unquote, urlparse
import logging

# ---------- Configuration ----------
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_POOL = 10
LISTEN_BACKLOG = 50
CONN_QUEUE_MAX = 1000  # application-level pending queue
MAX_REQUEST_SIZE = 8192  # bytes to read for headers
PERSISTENT_TIMEOUT = 30  # seconds
PERSISTENT_MAX_REQUESTS = 100
SERVER_NAME = "Multi-threaded HTTP Server"

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(threadName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("http-server")

# ---------- Utility functions ----------
def http_date_now():
    # RFC 7231 format (GMT)
    return formatdate(timeval=None, localtime=False, usegmt=True)

def build_status_line(code, reason):
    return f"HTTP/1.1 {code} {reason}\r\n"

def safe_path_join(resources_dir, requested_path):
    """
    Canonicalize and ensure requested_path is within resources_dir.
    Explicitly reject path traversal attempts and unsafe patterns.
    """
    # Reject traversal attempts early
    if ".." in requested_path or "./" in requested_path or requested_path.startswith("//") or requested_path.startswith("///"):
        return None
    # strip leading slash
    relative = requested_path.lstrip("/")
    # Avoid absolute paths
    if os.path.isabs(relative):
        return None
    # join and canonicalize
    joined = os.path.realpath(os.path.join(resources_dir, relative))
    resources_real = os.path.realpath(resources_dir)
    if not joined.startswith(resources_real):
        return None
    return joined

def send_all(sock, data: bytes):
    total_sent = 0
    while total_sent < len(data):
        sent = sock.send(data[total_sent:])
        if sent == 0:
            raise ConnectionError("socket connection broken while sending")
        total_sent += sent
    return total_sent

def read_exact(sock, nbytes, timeout=PERSISTENT_TIMEOUT):
    """
    Read exactly nbytes from socket (blocking, with timeout).
    """
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < nbytes:
        chunk = sock.recv(min(4096, nbytes - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)

# ---------- HTTP Handling ----------
class HTTPHandler:
    def __init__(self, conn, addr, resources_dir, server_hostport):
        self.conn = conn
        self.addr = addr
        self.resources_dir = resources_dir
        self.server_hostport = server_hostport  # e.g. "localhost:8080" or "127.0.0.1:8080"
        self.request_count = 0
        self.keep_alive = False

    def handle(self):
        thread_name = threading.current_thread().name
        logger.info(f"Connection from {self.addr[0]}:{self.addr[1]}")
        try:
            self.conn.settimeout(PERSISTENT_TIMEOUT)
            self.request_count = 0
            while True:
                # Read up to MAX_REQUEST_SIZE to get request headers
                try:
                    raw = self.conn.recv(MAX_REQUEST_SIZE)
                except socket.timeout:
                    logger.info("Connection timeout waiting for request headers")
                    break
                if not raw:
                    break  # client closed

                # If we received more than headers (body included), handle appropriately
                header_end = raw.find(b"\r\n\r\n")
                if header_end == -1:
                    # no full header received - treat as bad request
                    self.send_error(400, "Bad Request", "Malformed or too large headers.")
                    break

                header_bytes = raw[:header_end + 4]
                remainder = raw[header_end + 4:]  # may contain part (or all) of body
                header_text = header_bytes.decode("iso-8859-1")
                lines = header_text.split("\r\n")
                request_line = lines[0]
                headers = {}
                for line in lines[1:]:
                    if line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            headers[parts[0].strip()] = parts[1].strip()

                # Parse request line
                try:
                    method, path_raw, version = request_line.split()
                except ValueError:
                    self.send_error(400, "Bad Request", "Malformed request line")
                    break

                # Host header validation
                host_header = headers.get("Host")
                if host_header is None:
                    self.send_error(400, "Bad Request", "Missing Host header")
                    break
                if host_header != self.server_hostport:
                    logger.warning(f"Host validation fail: received Host: {host_header}")
                    self.send_error(403, "Forbidden", "Host header mismatch")
                    break

                # Connection header handling
                conn_hdr = headers.get("Connection", "").lower()
                if version == "HTTP/1.0":
                    self.keep_alive = (conn_hdr == "keep-alive")
                else:  # HTTP/1.1 default keep-alive
                    self.keep_alive = (conn_hdr != "close")

                # Log request
                logger.info(f"Request: {method} {path_raw} {version}")
                logger.info(f"Host validation: {host_header} ✓")

                # Dispatch by method
                if method == "GET":
                    self.handle_get(path_raw, version, headers)
                elif method == "POST":
                    # Need to read body. Determine Content-Length
                    content_length = int(headers.get("Content-Length", "0"))
                    body = remainder
                    # If remainder doesn't contain full body, read the rest
                    if len(body) < content_length:
                        more = read_exact(self.conn, content_length - len(body))
                        body += more
                    self.handle_post(path_raw, version, headers, body)
                else:
                    self.send_error(405, "Method Not Allowed", f"{method} not supported")
                self.request_count += 1

                if self.request_count >= PERSISTENT_MAX_REQUESTS:
                    logger.info("Max requests reached for persistent connection, closing")
                    break
                if not self.keep_alive:
                    break
                self.conn.settimeout(PERSISTENT_TIMEOUT)

        except Exception as e:
            logger.exception("Internal server error while handling connection")
            try:
                self.send_error(500, "Internal Server Error", "Server encountered an error.")
            except Exception:
                pass
        finally:
            try:
                self.conn.close()
            except Exception:
                pass
            logger.info("Connection closed")

    def handle_get(self, path_raw, version, headers):
        # Remove query string
        parsed = urlparse(path_raw)
        path = unquote(parsed.path)

        # Default root to index.html
        if path == "/":
            path = "/index.html"

        # Path traversal protection
        target = safe_path_join(self.resources_dir, path)
        if target is None:
            logger.warning(f"Path traversal attempt or bad path: {path}")
            self.send_error(403, "Forbidden", "Unauthorized path access attempt.")
            return

        if not os.path.exists(target) or not os.path.isfile(target):
            self.send_error(404, "Not Found", "Requested resource doesn't exist.")
            return

        filename = os.path.basename(target)
        ext = os.path.splitext(filename)[1].lower()
        if ext == ".html":
            with open(target, "rb") as f:
                body = f.read()
            headers_out = {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": str(len(body)),
                "Date": http_date_now(),
                "Server": SERVER_NAME,
                "Connection": "keep-alive" if self.keep_alive else "close"
            }
            if self.keep_alive:
                headers_out["Keep-Alive"] = f"timeout={PERSISTENT_TIMEOUT}, max={PERSISTENT_MAX_REQUESTS}"
            self.send_response(200, "OK", headers_out, body)
            logger.info(f"Sending HTML file: {filename} ({len(body)} bytes)")
            return
        elif ext in (".png", ".jpg", ".jpeg", ".txt"):
            size = os.path.getsize(target)
            headers_out = {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Date": http_date_now(),
                "Server": SERVER_NAME,
                "Connection": "keep-alive" if self.keep_alive else "close"
            }
            if self.keep_alive:
                headers_out["Keep-Alive"] = f"timeout={PERSISTENT_TIMEOUT}, max={PERSISTENT_MAX_REQUESTS}"
            header_bytes = self.build_headers_bytes(200, "OK", headers_out)
            send_all(self.conn, header_bytes)
            logger.info(f"Sending binary file: {filename} ({size} bytes)")
            with open(target, "rb") as stream:
                chunk_size = 8192
                sent = 0
                while True:
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        break
                    send_all(self.conn, chunk)
                    sent += len(chunk)
            logger.info(f"Response: 200 OK ({size} bytes transferred)")
            return
        else:
            self.send_error(415, "Unsupported Media Type", "File type not supported.")
            return

    def handle_post(self, path_raw, version, headers, body_bytes: bytes):
        parsed = urlparse(path_raw)
        path = unquote(parsed.path)

        if path != "/upload" and not path.startswith("/uploads"):
            self.send_error(404, "Not Found", "POST target not found")
            return

        content_type = headers.get("Content-Type", "")
        if "application/json" not in content_type:
            self.send_error(415, "Unsupported Media Type", "Only application/json accepted")
            return

        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception as e:
            logger.info("Invalid JSON received")
            self.send_error(400, "Bad Request", "Invalid JSON")
            return

        uploads_dir = os.path.join(self.resources_dir, "uploads")
        os.makedirs(uploads_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rand_id = uuid.uuid4().hex[:6]
        filename = f"upload_{timestamp}_{rand_id}.json"
        target_path = os.path.join(uploads_dir, filename)
        try:
            with open(target_path, "w", encoding="utf-8") as fw:
                json.dump(payload, fw, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.exception("Failed to write upload file")
            self.send_error(500, "Internal Server Error", "Could not write file")
            return

        response_body = json.dumps({
            "status": "success",
            "message": "File created successfully",
            "filepath": f"/uploads/{filename}"
        }).encode("utf-8")

        headers_out = {
            "Content-Type": "application/json",
            "Content-Length": str(len(response_body)),
            "Date": http_date_now(),
            "Server": SERVER_NAME,
            "Connection": "keep-alive" if self.keep_alive else "close"
        }
        if self.keep_alive:
            headers_out["Keep-Alive"] = f"timeout={PERSISTENT_TIMEOUT}, max={PERSISTENT_MAX_REQUESTS}"

        self.send_response(201, "Created", headers_out, response_body)
        logger.info(f"Created upload file: {target_path}")

    def build_headers_bytes(self, code, reason, headers_map):
        status_line = build_status_line(code, reason)
        headers_lines = "".join(f"{k}: {v}\r\n" for k, v in headers_map.items())
        header_bytes = (status_line + headers_lines + "\r\n").encode("iso-8859-1")
        return header_bytes

    def send_response(self, code, reason, headers_map, body_bytes: bytes):
        header_bytes = self.build_headers_bytes(code, reason, headers_map)
        try:
            send_all(self.conn, header_bytes)
            if body_bytes:
                send_all(self.conn, body_bytes)
        except Exception:
            raise

    def send_error(self, code, reason, message):
        body = f"<html><body><h1>{code} {reason}</h1><p>{message}</p></body></html>".encode("utf-8")
        headers_out = {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Date": http_date_now(),
            "Server": SERVER_NAME,
            "Connection": "close"
        }
        header_bytes = self.build_headers_bytes(code, reason, headers_out)
        try:
            send_all(self.conn, header_bytes)
            send_all(self.conn, body)
        except Exception:
            pass

# ---------- Thread pool worker ----------
def worker_loop(conn_queue, resources_dir, server_hostport, stats):
    while True:
        conn, addr = conn_queue.get()
        try:
            handler = HTTPHandler(conn, addr, resources_dir, server_hostport)
            handler.handle()
        except Exception:
            logger.exception("Unhandled exception in worker")
        finally:
            conn_queue.task_done()
            with stats["lock"]:
                stats["active"] -= 1

# ---------- Main server ----------
def main():
    parser = argparse.ArgumentParser(description="Multi-threaded HTTP Server")
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT, help="Port number (default 8080)")
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST, help="Host address (default 127.0.0.1)")
    parser.add_argument("pool", nargs="?", type=int, default=DEFAULT_POOL, help="Thread pool size (default 10)")
    args = parser.parse_args()

    host = args.host
    port = args.port
    pool_size = max(1, args.pool)

    project_dir = os.getcwd()
    resources_dir = os.path.join(project_dir, "resources")
    uploads_dir = os.path.join(resources_dir, "uploads")
    os.makedirs(uploads_dir, exist_ok=True)

    server_hostport = f"{host}:{port}"

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(LISTEN_BACKLOG)

    logger.info(f"HTTP Server started on http://{host}:{port}")
    logger.info(f"Thread pool size: {pool_size}")
    logger.info(f"Serving files from '{resources_dir}'")
    logger.info("Press Ctrl+C to stop the server")

    conn_queue = queue.Queue(maxsize=CONN_QUEUE_MAX)
    stats = {"active": 0, "lock": threading.Lock()}

    for i in range(pool_size):
        t = threading.Thread(target=worker_loop, name=f"Thread-{i+1}", args=(conn_queue, resources_dir, server_hostport, stats), daemon=True)
        t.start()

    try:
        while True:
            try:
                conn, addr = srv.accept()
                if conn_queue.full():
                    logger.warning("Thread pool saturated, rejecting connection with 503")
                    try:
                        body = b"<html><body><h1>503 Service Unavailable</h1><p>Server busy. Try again later.</p></body></html>"
                        headers = {
                            "Content-Type": "text/html; charset=utf-8",
                            "Content-Length": str(len(body)),
                            "Retry-After": "5",
                            "Date": http_date_now(),
                            "Server": SERVER_NAME,
                            "Connection": "close"
                        }
                        resp = build_status_line(503, "Service Unavailable") + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
                        conn.sendall(resp.encode("iso-8859-1") + body)
                    except Exception:
                        pass
                    finally:
                        conn.close()
                    continue

                if conn_queue.qsize() >= pool_size:
                    logger.warning("Thread pool saturated, queuing connection")
                with stats["lock"]:
                    stats["active"] += 1
                conn_queue.put((conn, addr))
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt received, shutting down.")
                break
            except Exception:
                logger.exception("Error in accept loop")
    finally:
        try:
            srv.close()
        except Exception:
            pass
        logger.info("Server stopped")

if __name__ == "__main__":
    main()
