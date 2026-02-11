# Domain Expiry Tracker

A simple Python tool to monitor domain expiration dates and alert when domains are expiring soon (default: 5 days).

## Features

- Track multiple domains via JSON config
- Check expiration dates via WHOIS
- Console output with color-coded status
- Discord webhook notifications
- Easy to run manually or via cron/Gitea Actions

## Installation

```bash
# Clone the repo
git clone http://git.digitaladrenalin.net/admin/domain-expiry-tracker.git
cd domain-expiry-tracker

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Add a domain to track

```bash
python domain_tracker.py add digitaladrenalin.net --notes "Main website"
python domain_tracker.py add screensprout.com --notes "Product domain"
```

### List all tracked domains

```bash
python domain_tracker.py list
```

Output:
```
Domain                         Expires In      Expiry Date          Notes
=====================================================================================
digitaladrenalin.net           245 days        2026-10-15           Main website
screensprout.com               ⚠️ ALERT: 3 days  2026-02-13        Product domain
```

### Check domains and send alerts

```bash
# Check with default 5-day alert threshold
python domain_tracker.py check

# Check with custom threshold
python domain_tracker.py check --days 30

# Check and send Discord alert
python domain_tracker.py check --webhook "https://discord.com/api/webhooks/..."

# Or use environment variable
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
python domain_tracker.py check
```

### Remove a domain

```bash
python domain_tracker.py remove example.com
```

## Automation

### Run via Cron (daily at 9 AM)

```bash
# Edit crontab
crontab -e

# Add line:
0 9 * * * cd /path/to/domain-expiry-tracker && python domain_tracker.py check >> /var/log/domain-tracker.log 2>&1
```

### Run via Gitea Actions

A sample workflow is included in `.gitea/workflows/check-domains.yaml`. It runs daily at 9 AM UTC.

To use it:
1. Set the `DISCORD_WEBHOOK_URL` secret in your Gitea repo settings
2. Update `domains.json` with your domains
3. Push to trigger the workflow

## Discord Alerts

When domains are expiring soon, you'll get alerts like:

```
🚨 Domain Expiry Alert 🚨

The following domains expire in 5 days or less:

⚠️ screensprout.com - expires in 3 days (2026-02-13)
   📝 Product domain

🔴 expired-domain.com - EXPIRED (2 days ago) (2026-02-08)
   📝 Needs renewal ASAP
```

## Configuration

Domains are stored in `domains.json`:

```json
[
  {
    "domain": "digitaladrenalin.net",
    "notes": "Main website",
    "added": "2026-02-10T10:30:00"
  }
]
```

## Environment Variables

- `DISCORD_WEBHOOK_URL` - Discord webhook URL for alerts

## Requirements

- Python 3.7+
- `whois` library

## License

MIT
