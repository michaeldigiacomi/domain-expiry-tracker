from flask import Flask, render_template, request, redirect, url_for, flash
import whois
import json
import os
from datetime import datetime, timedelta
from threading import Thread
import time

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

CONFIG_PATH = os.environ.get('CONFIG_PATH', '/data/domains.json')
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK_URL', '')
ALERT_DAYS = int(os.environ.get('ALERT_DAYS', '5'))


def load_domains():
    """Load domains from config file."""
    if not os.path.exists(CONFIG_PATH):
        return []
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)


def save_domains(domains):
    """Save domains to config file."""
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(domains, f, indent=2)


def check_domain(domain):
    """Check a single domain's expiration date."""
    try:
        info = whois.whois(domain)
        expiry_date = info.expiration_date
        
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        
        if not expiry_date:
            return {'error': 'No expiration date found'}
        
        now = datetime.now()
        days_left = (expiry_date - now).days
        
        return {
            'expiry_date': expiry_date.strftime('%Y-%m-%d'),
            'days_left': days_left,
            'expired': days_left < 0,
            'alert': days_left <= ALERT_DAYS
        }
    except Exception as e:
        return {'error': str(e)}


def get_all_domains_status():
    """Get status for all domains."""
    domains = load_domains()
    results = []
    
    for domain_info in domains:
        domain = domain_info['domain']
        status = check_domain(domain)
        
        results.append({
            'domain': domain,
            'notes': domain_info.get('notes', ''),
            'added': domain_info.get('added', ''),
            **status
        })
    
    # Sort: alerts first, then by days left
    results.sort(key=lambda x: (
        0 if x.get('alert') else 1,
        0 if x.get('expired') else 1,
        x.get('days_left', 9999)
    ))
    
    return results


@app.route('/')
def index():
    """Main dashboard showing all domains."""
    domains = get_all_domains_status()
    
    # Count stats
    total = len(domains)
    alerts = sum(1 for d in domains if d.get('alert') and not d.get('expired'))
    expired = sum(1 for d in domains if d.get('expired'))
    errors = sum(1 for d in domains if 'error' in d)
    
    return render_template('index.html', 
                         domains=domains, 
                         total=total, 
                         alerts=alerts,
                         expired=expired,
                         errors=errors,
                         alert_days=ALERT_DAYS)


@app.route('/add', methods=['POST'])
def add_domain():
    """Add a new domain to track."""
    domain = request.form.get('domain', '').strip().lower()
    notes = request.form.get('notes', '').strip()
    
    if not domain:
        flash('Domain is required', 'error')
        return redirect(url_for('index'))
    
    # Validate domain
    if not '.' in domain:
        flash('Invalid domain format', 'error')
        return redirect(url_for('index'))
    
    domains = load_domains()
    
    # Check if already exists
    if any(d['domain'] == domain for d in domains):
        flash(f'{domain} is already being tracked', 'warning')
        return redirect(url_for('index'))
    
    # Test WHOIS lookup
    test = check_domain(domain)
    if 'error' in test and 'No expiration' not in test['error']:
        flash(f'Error checking domain: {test["error"]}', 'error')
        return redirect(url_for('index'))
    
    domains.append({
        'domain': domain,
        'notes': notes,
        'added': datetime.now().isoformat()
    })
    
    save_domains(domains)
    flash(f'Added {domain} to tracking', 'success')
    return redirect(url_for('index'))


@app.route('/remove/<domain>')
def remove_domain(domain):
    """Remove a domain from tracking."""
    domains = load_domains()
    domains = [d for d in domains if d['domain'] != domain]
    save_domains(domains)
    flash(f'Removed {domain}', 'success')
    return redirect(url_for('index'))


@app.route('/check/<domain>')
def check_single(domain):
    """Check a single domain's status."""
    status = check_domain(domain)
    return {'domain': domain, **status}


@app.route('/api/status')
def api_status():
    """API endpoint for domain status."""
    return {'domains': get_all_domains_status(), 'alert_days': ALERT_DAYS}


@app.route('/health')
def health():
    """Health check endpoint."""
    return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
