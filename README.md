# Multi-threaded HTTP Server

A custom HTTP server implemented from scratch using Python sockets and threading.  
Supports GET (HTML, binary files), POST (JSON upload), thread pool, host validation, and keep-alive.

## Run
```bash
python3 server.py
# or specify arguments:
python3 server.py 8000 0.0.0.0 20
