# ── Gunicorn Config ───────────────────────────────────────────────────────
# Used by Render and other cloud platforms that inject a dynamic $PORT

import multiprocessing
import os

# Server socket — Render sets $PORT; default to 5000 for local/Docker use
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"

# Workers — 2 x CPU cores + 1 is standard
workers = multiprocessing.cpu_count() * 2 + 1
threads = 4
worker_class = "gthread"

# Timeouts
timeout = 120
keepalive = 5

# Logging
accesslog = "-"    # stdout
errorlog  = "-"    # stderr
loglevel  = "info"

# Restart workers after this many requests (prevents memory leaks)
max_requests = 1000
max_requests_jitter = 100

# Security
limit_request_line = 4096
limit_request_fields = 100