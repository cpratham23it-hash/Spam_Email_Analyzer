# ── PhishGuard Dockerfile ────────────────────────────────────────────────
# Multi-stage build: keeps final image small by separating build from runtime

# ── Stage 1: Builder ─────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt && \
    pip install --no-cache-dir --prefix=/install gunicorn


# ── Stage 2: Runtime ─────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Create non-root user for security
RUN groupadd -r phishguard && useradd -r -g phishguard phishguard

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application files
COPY App.py .
COPY incident_report.py .
COPY index.html .
COPY Login.html .
COPY Dashboard.html .

# Create model directory (empty — model trained separately)
RUN mkdir -p model

# Set ownership
RUN chown -R phishguard:phishguard /app

# Switch to non-root user
USER phishguard

# Expose port
EXPOSE 5000

# Environment defaults (override at runtime)
ENV FLASK_DEBUG=false \
    MONGO_URI=mongodb://mongo:27017 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/login')" || exit 1

# Start with gunicorn (production WSGI server)
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "2", \
     "--threads", "4", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "App:app"]