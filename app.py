from flask import Flask, render_template, request, redirect, url_for, flash
import whois
import json
import os
from datetime import datetime, timedelta
from threading import Thread, Lock
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import time
import socket

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

CONFIG_PATH = os.environ.get('CONFIG_PATH', '/data/domains.json')
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK_URL', '')
ALERT_DAYS = int(os.environ.get('ALERT_DAYS', '5'))
WHOIS_TIMEOUT = int(os.environ.get('WHOIS_TIMEOUT', '8'))  # seconds
CACHE_TTL = int(os.environ.get('CACHE_TTL', '43200'))  # 12 hours default

# In-memory cache for domain WHOIS results
# Structure: {domain: {'data': {...}, 'timestamp': datetime, 'fetching': bool}}
_whois_cache = {}
_cache_lock = Lock()


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


def _whois_lookup_with_timeout(domain, timeout=WHOIS_TIMEOUT):
    """Perform WHOIS lookup with timeout using thread pool."""
    def _lookup():
        # Set socket timeout for this thread
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return whois.whois(domain)
        finally:
            socket.setdefaulttimeout(old_timeout)
    
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_lookup)
        try:
            return future.result(timeout=timeout)
        except FutureTimeout:
            raise TimeoutError(f"WHOIS lookup for {domain} timed out after {timeout}s")


def check_domain(domain, use_cache=True):
    """Check a single domain's expiration date with caching and timeout handling."""
    now = datetime.now()
    
    # Check cache first
    if use_cache:
        with _cache_lock:
            cached = _whois_cache.get(domain)
            if cached:
                age = (now - cached['timestamp']).total_seconds()
                if age < CACHE_TTL:
                    # Return cached data with metadata
                    result = cached['data'].copy()
                    result['cached'] = True
                    result['cache_age_minutes'] = int(age / 60)
                    return result
                # Cache expired, will refresh
    
    # Perform WHOIS lookup with timeout
    try:
        info = _whois_lookup_with_timeout(domain)
        expiry_date = info.expiration_date
        
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        
        if not expiry_date:
            result = {'error': 'No expiration date found', 'cached': False}
        else:
            days_left = (expiry_date - now).days
            result = {
                'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                'days_left': days_left,
                'expired': days_left < 0,
                'alert': days_left <= ALERT_DAYS,
                'cached': False
            }
    except TimeoutError as e:
        # Return cached data if available, even if expired
        with _cache_lock:
            cached = _whois_cache.get(domain)
            if cached:
                result = cached['data'].copy()
                result['cached'] = True
                result['stale'] = True
                result['error'] = f"WHOIS timeout, showing cached data: {str(e)}"
                return result
        result = {'error': f'WHOIS lookup timed out: {str(e)}', 'cached': False}
    except Exception as e:
        # Return cached data if available on any error
        with _cache_lock:
            cached = _whois_cache.get(domain)
            if cached:
                result = cached['data'].copy()
                result['cached'] = True
                result['stale'] = True
                result['error'] = f"WHOIS error, showing cached data: {str(e)}"
                return result
        result = {'error': str(e), 'cached': False}
    
    # Update cache with successful result (even if it's an error without cached fallback)
    if 'error' not in result or not result.get('stale'):
        with _cache_lock:
            _whois_cache[domain] = {
                'data': result.copy(),
                'timestamp': now
            }
    
    return result


def get_all_domains_status():
    """Get status for all domains."""
    domains = load_domains()
    results = []
    
    for domain_info in domains:
        domain = domain_info['domain']
        status = check_domain(domain, use_cache=True)
        
        results.append({
            'domain': domain,
            'notes': domain_info.get('notes', ''),
            'added': domain_info.get('added', ''),
            **status
        })
    
    # Sort: alerts first, then by days left
    results.sort(key=lambda x: (
        0 if x.get('alert') and not x.get('expired') else 1,
        0 if x.get('expired') else 1,
        x.get('days_left', 9999)
    ))
    
    return results


def refresh_cache_background():
    """Background thread to refresh WHOIS cache for all domains."""
    def _refresh():
        domains = load_domains()
        for domain_info in domains:
            domain = domain_info['domain']
            try:
                check_domain(domain, use_cache=False)
                time.sleep(1)  # Be nice to WHOIS servers
            except Exception:
                pass  # Silently fail on background refresh
    
    thread = Thread(target=_refresh, daemon=True)
    thread.start()


@app.route('/')
def index():
    """Main dashboard showing all domains."""
    domains = get_all_domains_status()
    
    # Count stats
    total = len(domains)
    alerts = sum(1 for d in domains if d.get('alert') and not d.get('expired'))
    expired = sum(1 for d in domains if d.get('expired'))
    errors = sum(1 for d in domains if 'error' in d)
    cached = sum(1 for d in domains if d.get('cached'))
    stale = sum(1 for d in domains if d.get('stale'))
    
    return render_template('index.html', 
                         domains=domains, 
                         total=total, 
                         alerts=alerts,
                         expired=expired,
                         errors=errors,
                         cached=cached,
                         stale=stale,
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
    
    # Test WHOIS lookup (no cache for new domain)
    test = check_domain(domain, use_cache=False)
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
    
    # Clear from cache
    with _cache_lock:
        _whois_cache.pop(domain, None)
    
    flash(f'Removed {domain}', 'success')
    return redirect(url_for('index'))


@app.route('/check/<domain>')
def check_single(domain):
    """Check a single domain's status (force refresh)."""
    status = check_domain(domain, use_cache=False)
    return {'domain': domain, **status}


@app.route('/api/status')
def api_status():
    """API endpoint for domain status."""
    return {'domains': get_all_domains_status(), 'alert_days': ALERT_DAYS}


@app.route('/api/refresh', methods=['POST'])
def api_refresh():
    """Force refresh of all domain WHOIS data."""
    refresh_cache_background()
    return {'status': 'refresh started'}


@app.route('/health')
def health():
    """Health check endpoint."""
    cache_info = {
        domain: {
            'age_minutes': int((datetime.now() - data['timestamp']).total_seconds() / 60)
        }
        for domain, data in _whois_cache.items()
    }
    return {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'cache_size': len(_whois_cache),
        'cache_entries': cache_info
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
