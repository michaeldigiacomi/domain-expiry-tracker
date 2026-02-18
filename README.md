# Domain Expiry Tracker

A web application to monitor domain expiration dates and get alerts when domains are expiring soon.

## Features

- 🌐 **Web Dashboard** - View all domains at a glance with status indicators
- 🔒 **SSL Certificate Tracking** - Monitor SSL cert expiry alongside domain expiry
- ➕ **Easy Management** - Add/remove domains via web UI
- 🚨 **Visual Alerts** - Color-coded status (OK, Expiring Soon, Expired, Error)
- 💾 **Persistent Storage** - Data stored in persistent volume
- 🔔 **Discord Notifications** - Optional webhook alerts
- ☸️ **Kubernetes Ready** - Complete K8s manifests included
- 🔄 **Auto-refresh** - Dashboard refreshes every 60 seconds

## Quick Start (Kubernetes)

### 1. Clone and Build

```bash
git clone http://git.digitaladrenalin.net/Shared-workspace/domain-expiry-tracker.git
cd domain-expiry-tracker

# Build Docker image
docker build -t 192.168.4.162:5000/domain-expiry-tracker:latest .
docker push 192.168.4.162:5000/domain-expiry-tracker:latest
```

### 2. Deploy to Kubernetes

```bash
# Create namespace and deploy
kubectl apply -k k8s/

# Add your Discord webhook (optional)
kubectl create secret generic domain-tracker-secrets \
  --from-literal=discord-webhook='YOUR_DISCORD_WEBHOOK_URL' \
  -n domain-tracker --dry-run=client -o yaml | kubectl apply -f -
```

### 3. Access the App

```bash
# Port forward for local access
kubectl port-forward svc/domain-tracker -n domain-tracker 8080:80

# Open http://localhost:8080
```

Or expose via Ingress/LoadBalancer by adding a route.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_PATH` | `/data/domains.json` | Path to domain data file |
| `ALERT_DAYS` | `5` | Days before expiry to trigger alert |
| `DISCORD_WEBHOOK_URL` | - | Discord webhook for notifications |
| `SECRET_KEY` | `dev-key` | Flask secret key (change in prod) |

### Discord Webhook Setup

1. In Discord, go to Server Settings → Integrations → Webhooks
2. Create a new webhook and copy the URL
3. Add to K8s secret:
   ```bash
   kubectl create secret generic domain-tracker-secrets \
     --from-literal=discord-webhook='YOUR_WEBHOOK_URL' \
     -n domain-tracker
   ```

## Using the Web App

1. **Add Domain**: Enter domain name (e.g., `digitaladrenalin.net`) and optional notes
2. **View Status**: See all domains with color-coded status:
   - 🟢 **OK** - More than 5 days until expiry
   - 🟡 **Expiring Soon** - 5 days or less
   - 🔴 **Expired** - Already expired
   - 🟠 **Error** - WHOIS lookup failed
3. **SSL Certificate Status**: Check the SSL Certificate column for:
   - 🔒 **Valid** - Green badge with days remaining
   - ⚠️ **Expiring Soon** - Purple badge (same threshold as domains)
   - 🔓 **Expired** - Red badge
   - ❌ **Error** - Orange badge (connection issues or no HTTPS)
4. **Remove Domain**: Click "Remove" to stop tracking

## SSL Certificate Tracking

The app now monitors SSL certificate expiry in addition to domain registration:

- **Separate from domain expiry**: SSL certs often expire on different schedules
- **Same alert threshold**: Uses `ALERT_DAYS` environment variable
- **Independent caching**: 12-hour cache like domain WHOIS data
- **Error handling**: Shows connection errors for non-HTTPS sites or timeouts

This helps catch SSL certificates that expire separately from domain registrations - a common cause of "Your connection is not private" browser errors.

## API Endpoints

- `GET /` - Web dashboard
- `GET /api/status` - JSON API with all domains (includes `ssl` field for each domain)
- `GET /health` - Health check (includes both domain and SSL cache info)
- `POST /add` - Add domain (form data: `domain`, `notes`)
- `GET /remove/<domain>` - Remove domain
- `GET /check/<domain>` - Check single domain status (includes SSL certificate info)

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python app.py

# Open http://localhost:5000
```

## CLI Mode (Still Available)

The original CLI tool is still included:

```bash
# Add domain
python domain_tracker.py add example.com --notes "My site"

# List domains
python domain_tracker.py list

# Check and alert
python domain_tracker.py check --days 5
```

## Files

```
domain-expiry-tracker/
├── app.py                    # Flask web application
├── domain_tracker.py         # Original CLI tool
├── requirements.txt          # Python dependencies
├── Dockerfile               # Container image
├── templates/
│   └── index.html           # Web UI
├── k8s/                     # Kubernetes manifests
│   ├── namespace.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── pvc.yaml
│   ├── secret.yaml
│   └── kustomization.yaml
└── README.md
```

## Requirements

- Python 3.11+ (for local dev)
- Kubernetes cluster (for deployment)
- Docker registry access
- `whois` system package (included in container)

## License

MIT
# Trigger build Wed Feb 18 19:57:50 UTC 2026
# Trigger build 2 Wed Feb 18 19:58:14 UTC 2026
# Trigger build 3 Wed Feb 18 19:59:15 UTC 2026
# Trigger build 4 Wed Feb 18 20:02:54 UTC 2026
# Trigger build 5 Wed Feb 18 20:05:22 UTC 2026
# Trigger build 6 Wed Feb 18 20:06:01 UTC 2026
