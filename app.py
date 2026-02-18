from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import whois
import json
import os
from datetime import datetime, timedelta
from threading import Thread, Lock
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import time
import socket
import ssl
import subprocess
import requests
import asyncio
import random
from alert_manager import get_alert_manager, AlertManager, AlertType

# SQLAlchemy imports
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

# APScheduler for background jobs
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

# Flask-Login for authentication
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# WHOIS Cache
from whois_cache import get_whois_cache_manager, WhoisCacheManager

Base = declarative_base()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

# Admin credentials from environment variables
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme')


class User(UserMixin):
    """Simple user class for Flask-Login."""
    def __init__(self, id, username):
        self.id = id
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID."""
    if user_id == '1':
        return User('1', ADMIN_USERNAME)
    return None

CONFIG_PATH = os.environ.get('CONFIG_PATH', '/data/domains.json')
DATABASE_PATH = os.environ.get('DATABASE_PATH', '/data/domain_tracker.db')

# Database setup
database_url = os.environ.get('DATABASE_URL', f'sqlite:///{DATABASE_PATH}')
engine = create_engine(database_url, connect_args={'check_same_thread': False} if 'sqlite' in database_url else {})
Session = scoped_session(sessionmaker(bind=engine))


class UptimeCheck(Base):
    """Model for storing uptime check results."""
    __tablename__ = 'uptime_checks'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Float, nullable=True)
    is_up = Column(Boolean, default=False, nullable=False)
    error_message = Column(String(500), nullable=True)


class AlertConfigModel(Base):
    """Model for storing webhook alert configurations."""
    __tablename__ = 'alert_configs'
    
    id = Column(String(32), primary_key=True)
    domain_id = Column(String(255), nullable=False, index=True)
    webhook_url = Column(String(1024), nullable=False)
    webhook_type = Column(String(32), nullable=False)  # 'discord' or 'slack'
    alert_types = Column(String(255), nullable=False)  # JSON array: ["domain_expiry", "ssl_expiry", "uptime_down"]
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


# Create tables
Base.metadata.create_all(engine)
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK_URL', '')
ALERT_DAYS = int(os.environ.get('ALERT_DAYS', '5'))
WHOIS_TIMEOUT = int(os.environ.get('WHOIS_TIMEOUT', '8'))  # seconds
CACHE_TTL = int(os.environ.get('CACHE_TTL', '43200'))  # 12 hours default
UPTIME_CHECK_INTERVAL = int(os.environ.get('UPTIME_CHECK_INTERVAL', '300'))  # 5 minutes default
UPTIME_TIMEOUT = int(os.environ.get('UPTIME_TIMEOUT', '10'))  # seconds

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# In-memory cache for domain WHOIS results
# Structure: {domain: {'data': {...}, 'timestamp': datetime, 'fetching': bool}}
_whois_cache = {}
_cache_lock = Lock()

# In-memory cache for SSL certificate results
# Structure: {domain: {'data': {...}, 'timestamp': datetime}}
_ssl_cache = {}
_ssl_cache_lock = Lock()


def check_domain_uptime(domain):
    """Check HTTP uptime for a domain."""
    # Clean domain - ensure proper URL format
    clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    urls_to_try = [
        f'https://{clean_domain}',
        f'http://{clean_domain}'
    ]
    
    for url in urls_to_try:
        try:
            start_time = time.time()
            response = requests.get(
                url,
                timeout=UPTIME_TIMEOUT,
                allow_redirects=True,
                headers={'User-Agent': 'DomainExpiryTracker/1.0'}
            )
            response_time_ms = (time.time() - start_time) * 1000
            
            return {
                'is_up': True,
                'status_code': response.status_code,
                'response_time_ms': round(response_time_ms, 2),
                'error_message': None
            }
        except requests.exceptions.SSLError:
            # SSL error but server is responding
            response_time_ms = (time.time() - start_time) * 1000
            return {
                'is_up': True,
                'status_code': None,
                'response_time_ms': round(response_time_ms, 2),
                'error_message': 'SSL certificate error'
            }
        except requests.exceptions.ConnectionError as e:
            # Try next URL (http vs https)
            continue
        except requests.exceptions.Timeout:
            return {
                'is_up': False,
                'status_code': None,
                'response_time_ms': None,
                'error_message': 'Request timed out'
            }
        except Exception as e:
            return {
                'is_up': False,
                'status_code': None,
                'response_time_ms': None,
                'error_message': str(e)[:500]
            }
    
    return {
        'is_up': False,
        'status_code': None,
        'response_time_ms': None,
        'error_message': 'Could not connect to domain'
    }


def perform_uptime_checks():
    """Background job to check uptime for all monitored domains."""
    try:
        domains = load_domains()
        session = Session()
        
        for domain_info in domains:
            domain = domain_info['domain']
            try:
                result = check_domain_uptime(domain)
                
                uptime_check = UptimeCheck(
                    domain=domain,
                    timestamp=datetime.utcnow(),
                    status_code=result['status_code'],
                    response_time_ms=result['response_time_ms'],
                    is_up=result['is_up'],
                    error_message=result['error_message']
                )
                session.add(uptime_check)
                
            except Exception as e:
                # Log error but continue checking other domains
                uptime_check = UptimeCheck(
                    domain=domain,
                    timestamp=datetime.utcnow(),
                    is_up=False,
                    error_message=str(e)[:500]
                )
                session.add(uptime_check)
        
        session.commit()
        session.close()
        
        # Clean up old records (keep last 30 days)
        cleanup_old_uptime_checks()
        
    except Exception as e:
        print(f"Error in uptime check job: {e}")


def cleanup_old_uptime_checks():
    """Remove uptime checks older than 30 days to prevent database bloat."""
    try:
        session = Session()
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        session.query(UptimeCheck).filter(UptimeCheck.timestamp < cutoff_date).delete(synchronize_session=False)
        session.commit()
        session.close()
    except Exception as e:
        print(f"Error cleaning up old uptime checks: {e}")


# Schedule uptime checks
scheduler.add_job(
    perform_uptime_checks,
    trigger=IntervalTrigger(seconds=UPTIME_CHECK_INTERVAL),
    id='uptime_check_job',
    name='Uptime Check Job',
    replace_existing=True
)

# Run initial check on startup (after a short delay to let app start)
def schedule_initial_check():
    time.sleep(5)
    perform_uptime_checks()

Thread(target=schedule_initial_check, daemon=True).start()


def check_ssl_certificate(domain, use_cache=True):
    """Check SSL certificate expiration for a domain."""
    now = datetime.now()
    
    # Check cache first
    if use_cache:
        with _ssl_cache_lock:
            cached = _ssl_cache.get(domain)
            if cached:
                age = (now - cached['timestamp']).total_seconds()
                if age < CACHE_TTL:
                    result = cached['data'].copy()
                    result['cached'] = True
                    result['cache_age_minutes'] = int(age / 60)
                    return result
    
    # Clean domain - remove any protocol or path
    clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Set timeout for socket operations
        with socket.create_connection((clean_domain, 443), timeout=WHOIS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                
                if not cert:
                    return {'error': 'No SSL certificate found', 'cached': False}
                
                # Parse expiration date
                expiry_str = cert.get('notAfter')
                if not expiry_str:
                    return {'error': 'Could not determine certificate expiration', 'cached': False}
                
                # Parse the date string (format: 'May 30 12:00:00 2025 GMT')
                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                
                days_left = (expiry_date - now).days
                
                # Get issuer info
                issuer = cert.get('issuer', [])
                issuer_name = 'Unknown'
                for item in issuer:
                    for key, value in item:
                        if key == 'organizationName':
                            issuer_name = value
                            break
                    if issuer_name != 'Unknown':
                        break
                
                # Get subject alternative names
                san = cert.get('subjectAltName', [])
                alt_names = [name[1] for name in san if name[0] == 'DNS']
                
                result = {
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'days_left': days_left,
                    'expired': days_left < 0,
                    'alert': days_left <= ALERT_DAYS,
                    'issuer': issuer_name,
                    'alt_names': alt_names[:5],  # Limit to first 5
                    'cached': False
                }
    except socket.timeout:
        # Return cached data if available
        with _ssl_cache_lock:
            cached = _ssl_cache.get(domain)
            if cached:
                result = cached['data'].copy()
                result['cached'] = True
                result['stale'] = True
                result['error'] = 'SSL check timed out, showing cached data'
                return result
        result = {'error': 'SSL connection timed out', 'cached': False}
    except socket.gaierror:
        result = {'error': 'Could not resolve domain for SSL check', 'cached': False}
    except ssl.SSLCertVerificationError as e:
        result = {'error': f'SSL certificate verification failed: {str(e)}', 'cached': False}
    except ssl.SSLError as e:
        result = {'error': f'SSL error: {str(e)}', 'cached': False}
    except ConnectionRefusedError:
        result = {'error': 'Connection refused - no HTTPS service', 'cached': False}
    except Exception as e:
        # Return cached data if available on any error
        with _ssl_cache_lock:
            cached = _ssl_cache.get(domain)
            if cached:
                result = cached['data'].copy()
                result['cached'] = True
                result['stale'] = True
                result['error'] = f'SSL error, showing cached data: {str(e)}'
                return result
        result = {'error': str(e), 'cached': False}
    
    # Update cache with successful result
    if 'error' not in result or not result.get('stale'):
        with _ssl_cache_lock:
            _ssl_cache[domain] = {
                'data': result.copy(),
                'timestamp': now
            }
    
    return result


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
    """Get status for all domains including SSL certificate info."""
    domains = load_domains()
    results = []
    
    for domain_info in domains:
        domain = domain_info['domain']
        domain_status = check_domain(domain, use_cache=True)
        ssl_status = check_ssl_certificate(domain, use_cache=True)
        
        results.append({
            'domain': domain,
            'notes': domain_info.get('notes', ''),
            'added': domain_info.get('added', ''),
            **domain_status,
            'ssl': ssl_status
        })
    
    # Sort: domain alerts first, then SSL alerts, then by domain days left
    results.sort(key=lambda x: (
        0 if x.get('alert') and not x.get('expired') else 1,
        0 if x.get('ssl', {}).get('alert') and not x.get('ssl', {}).get('expired') else 1,
        0 if x.get('expired') else 1,
        x.get('days_left', 9999)
    ))
    
    return results


def refresh_cache_background():
    """Background thread to refresh WHOIS and SSL cache for all domains."""
    def _refresh():
        domains = load_domains()
        for domain_info in domains:
            domain = domain_info['domain']
            try:
                check_domain(domain, use_cache=False)
                time.sleep(0.5)
            except Exception:
                pass  # Silently fail on background refresh
            try:
                check_ssl_certificate(domain, use_cache=False)
                time.sleep(0.5)
            except Exception:
                pass
    
    thread = Thread(target=_refresh, daemon=True)
    thread.start()


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    # If already logged in, redirect to index
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect(url_for('login'))
        
        # Validate credentials
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            user = User('1', ADMIN_USERNAME)
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            
            # Redirect to the page they were trying to access, or index
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    """Main dashboard showing all domains with SSL status."""
    domains = get_all_domains_status()
    
    # Count domain stats
    total = len(domains)
    alerts = sum(1 for d in domains if d.get('alert') and not d.get('expired'))
    expired = sum(1 for d in domains if d.get('expired'))
    errors = sum(1 for d in domains if 'error' in d)
    cached = sum(1 for d in domains if d.get('cached'))
    stale = sum(1 for d in domains if d.get('stale'))
    
    # Count SSL stats
    ssl_alerts = sum(1 for d in domains if d.get('ssl', {}).get('alert') and not d.get('ssl', {}).get('expired'))
    ssl_expired = sum(1 for d in domains if d.get('ssl', {}).get('expired'))
    ssl_errors = sum(1 for d in domains if 'error' in d.get('ssl', {}))
    
    return render_template('index.html', 
                         domains=domains, 
                         total=total, 
                         alerts=alerts,
                         expired=expired,
                         errors=errors,
                         cached=cached,
                         stale=stale,
                         alert_days=ALERT_DAYS,
                         ssl_alerts=ssl_alerts,
                         ssl_expired=ssl_expired,
                         ssl_errors=ssl_errors)


@app.route('/domains/<domain>/alerts')
@login_required
def domain_alerts(domain):
    """Alert settings page for a specific domain."""
    # Check if domain exists
    domains = load_domains()
    domain_info = next((d for d in domains if d['domain'] == domain), None)
    
    if not domain_info:
        flash(f'Domain {domain} not found', 'error')
        return redirect(url_for('index'))
    
    # Get alert configurations for this domain
    alert_manager = get_alert_manager()
    configs = alert_manager.get_configs_for_domain(domain)
    
    return render_template('alerts.html',
                         domain=domain_info,
                         configs=configs)


@app.route('/add', methods=['POST'])
@login_required
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
@login_required
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
@login_required
def check_single(domain):
    """Check a single domain's status including SSL (force refresh)."""
    status = check_domain(domain, use_cache=False)
    ssl_status = check_ssl_certificate(domain, use_cache=False)
    return {'domain': domain, **status, 'ssl': ssl_status}


@app.route('/api/status')
@login_required
def api_status():
    """API endpoint for domain status."""
    return {'domains': get_all_domains_status(), 'alert_days': ALERT_DAYS}


@app.route('/api/refresh', methods=['POST'])
@login_required
def api_refresh():
    """Force refresh of all domain WHOIS data."""
    refresh_cache_background()
    return {'status': 'refresh started'}


@app.route('/health')
def health():
    """Health check endpoint."""
    now = datetime.now()
    cache_info = {
        domain: {
            'age_minutes': int((now - data['timestamp']).total_seconds() / 60)
        }
        for domain, data in _whois_cache.items()
    }
    ssl_cache_info = {
        domain: {
            'age_minutes': int((now - data['timestamp']).total_seconds() / 60)
        }
        for domain, data in _ssl_cache.items()
    }
    return {
        'status': 'healthy',
        'timestamp': now.isoformat(),
        'domain_cache_size': len(_whois_cache),
        'domain_cache_entries': cache_info,
        'ssl_cache_size': len(_ssl_cache),
        'ssl_cache_entries': ssl_cache_info
    }


@app.route('/api/domains/<domain>/uptime')
@login_required
def api_domain_uptime(domain):
    """Get uptime check history for a domain (last 24 hours)."""
    session = Session()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        checks = session.query(UptimeCheck).filter(
            UptimeCheck.domain == domain,
            UptimeCheck.timestamp >= cutoff
        ).order_by(UptimeCheck.timestamp.desc()).all()
        
        result = {
            'domain': domain,
            'period_hours': 24,
            'total_checks': len(checks),
            'checks': [
                {
                    'timestamp': check.timestamp.isoformat(),
                    'status_code': check.status_code,
                    'response_time_ms': check.response_time_ms,
                    'is_up': check.is_up,
                    'error_message': check.error_message
                }
                for check in checks
            ]
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/domains/<domain>/uptime/summary')
@login_required
def api_domain_uptime_summary(domain):
    """Get uptime summary for a domain (last 24 hours)."""
    session = Session()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        checks = session.query(UptimeCheck).filter(
            UptimeCheck.domain == domain,
            UptimeCheck.timestamp >= cutoff
        ).all()
        
        total_checks = len(checks)
        if total_checks == 0:
            return jsonify({
                'domain': domain,
                'period_hours': 24,
                'uptime_percentage': None,
                'avg_response_time_ms': None,
                'total_checks': 0,
                'successful_checks': 0,
                'failed_checks': 0,
                'message': 'No uptime data available for this period'
            })
        
        successful_checks = sum(1 for check in checks if check.is_up)
        failed_checks = total_checks - successful_checks
        uptime_percentage = round((successful_checks / total_checks) * 100, 2)
        
        # Calculate average response time (only for successful checks with response time)
        response_times = [check.response_time_ms for check in checks if check.is_up and check.response_time_ms is not None]
        avg_response_time_ms = round(sum(response_times) / len(response_times), 2) if response_times else None
        
        return jsonify({
            'domain': domain,
            'period_hours': 24,
            'uptime_percentage': uptime_percentage,
            'avg_response_time_ms': avg_response_time_ms,
            'total_checks': total_checks,
            'successful_checks': successful_checks,
            'failed_checks': failed_checks,
            'last_check': checks[-1].timestamp.isoformat() if checks else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


# Ensure database directory exists
os.makedirs(os.path.dirname(DATABASE_PATH) if os.path.dirname(DATABASE_PATH) else '.', exist_ok=True)


@app.teardown_appcontext
def shutdown_session(exception=None):
    """Remove database session at end of request."""
    Session.remove()


import atexit


def shutdown_scheduler():
    """Shutdown the scheduler on exit."""
    scheduler.shutdown()


atexit.register(shutdown_scheduler)


# ==================== Alert Configuration API Endpoints ====================

@app.route('/api/domains/<domain>/alerts', methods=['POST'])
@login_required
def create_alert_config(domain):
    """Create a new alert configuration for a domain."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400
        
        webhook_url = data.get('webhook_url')
        webhook_type = data.get('webhook_type')
        alert_types = data.get('alert_types', [])
        
        # Validate required fields
        if not webhook_url:
            return jsonify({'error': 'webhook_url is required'}), 400
        if not webhook_type:
            return jsonify({'error': 'webhook_type is required'}), 400
        if not alert_types:
            return jsonify({'error': 'alert_types is required'}), 400
        
        # Validate webhook_type
        valid_types = ['discord', 'slack']
        if webhook_type not in valid_types:
            return jsonify({'error': f'webhook_type must be one of: {valid_types}'}), 400
        
        # Validate alert_types
        valid_alert_types = ['domain_expiry', 'ssl_expiry', 'uptime_down']
        for at in alert_types:
            if at not in valid_alert_types:
                return jsonify({'error': f'Invalid alert_type: {at}. Must be one of: {valid_alert_types}'}), 400
        
        # Check if domain exists
        domains = load_domains()
        if not any(d['domain'] == domain for d in domains):
            return jsonify({'error': f'Domain {domain} not found'}), 404
        
        alert_manager = get_alert_manager()
        config = alert_manager.create_config(
            domain_id=domain,
            webhook_url=webhook_url,
            webhook_type=webhook_type,
            alert_types=alert_types
        )
        
        return jsonify({
            'message': 'Alert configuration created successfully',
            'config': config.to_dict()
        }), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to create alert config: {str(e)}'}), 500


@app.route('/api/domains/<domain>/alerts', methods=['GET'])
@login_required
def list_alert_configs(domain):
    """List all alert configurations for a domain."""
    try:
        alert_manager = get_alert_manager()
        configs = alert_manager.get_configs_for_domain(domain)
        
        return jsonify({
            'domain': domain,
            'configs': [c.to_dict() for c in configs],
            'count': len(configs)
        })
    except Exception as e:
        return jsonify({'error': f'Failed to list alert configs: {str(e)}'}), 500


@app.route('/api/alerts/<config_id>', methods=['DELETE'])
@login_required
def delete_alert_config(config_id):
    """Delete an alert configuration."""
    try:
        alert_manager = get_alert_manager()
        
        # Verify config exists
        config = alert_manager.get_config(config_id)
        if not config:
            return jsonify({'error': f'Alert configuration {config_id} not found'}), 404
        
        if alert_manager.delete_config(config_id):
            return jsonify({
                'message': f'Alert configuration {config_id} deleted successfully'
            })
        else:
            return jsonify({'error': 'Failed to delete alert configuration'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Failed to delete alert config: {str(e)}'}), 500


@app.route('/api/alerts', methods=['GET'])
@login_required
def list_all_alert_configs():
    """List all alert configurations (admin endpoint)."""
    try:
        alert_manager = get_alert_manager()
        configs = alert_manager.list_all_configs()
        
        return jsonify({
            'configs': [c.to_dict() for c in configs],
            'count': len(configs)
        })
    except Exception as e:
        return jsonify({'error': f'Failed to list alert configs: {str(e)}'}), 500


@app.route('/api/alerts/test', methods=['POST'])
@login_required
def test_alert_webhook():
    """Test a webhook URL by sending a test message."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400
        
        webhook_url = data.get('webhook_url')
        webhook_type = data.get('webhook_type', 'discord')
        
        if not webhook_url:
            return jsonify({'error': 'webhook_url is required'}), 400
        
        alert_manager = get_alert_manager()
        
        # Create test payload
        if webhook_type == 'discord':
            payload = {
                "embeds": [{
                    "title": "🧪 Test Alert",
                    "description": "This is a test message from Domain Expiry Tracker.",
                    "color": 0x00FF00,
                    "fields": [
                        {"name": "Status", "value": "✅ Webhook is working!", "inline": True}
                    ],
                    "timestamp": datetime.now().isoformat()
                }]
            }
        else:  # slack
            payload = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🧪 Test Alert",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "This is a test message from Domain Expiry Tracker."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Status:* ✅ Webhook is working!"
                        }
                    }
                ]
            }
        
        # Send test webhook
        async def send_test():
            return await alert_manager._send_webhook(webhook_url, payload)
        
        success = asyncio.run(send_test())
        
        if success:
            return jsonify({'message': 'Test webhook sent successfully', 'success': True})
        else:
            return jsonify({'error': 'Failed to send test webhook', 'success': False}), 500
            
    except Exception as e:
        return jsonify({'error': f'Test failed: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
