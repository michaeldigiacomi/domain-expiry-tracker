FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for whois
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY alert_manager.py .
COPY domain_tracker.py .
COPY templates/ templates/

# Create data directory for persistent storage
RUN mkdir -p /data

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CONFIG_PATH=/data/domains.json
ENV FLASK_APP=app.py
ENV WHOIS_TIMEOUT=8
ENV CACHE_TTL=43200

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Run with gunicorn (60s timeout to handle slow WHOIS, but individual lookups timeout at 8s)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "--timeout", "60", "--keep-alive", "5", "app:app"]
