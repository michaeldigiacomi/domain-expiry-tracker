#!/usr/bin/env python3
"""
Domain Expiry Tracker
Monitors domain expiration dates and sends alerts when domains are expiring soon.
"""

import whois
import json
import os
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import argparse


class DomainExpiryTracker:
    """Track domain expirations and send alerts."""
    
    DEFAULT_ALERT_DAYS = 5
    
    def __init__(self, config_path: str = "domains.json"):
        self.config_path = config_path
        self.domains = self._load_config()
    
    def _load_config(self) -> List[Dict]:
        """Load domain configuration from JSON file."""
        if not os.path.exists(self.config_path):
            return []
        
        with open(self.config_path, 'r') as f:
            return json.load(f)
    
    def _save_config(self):
        """Save domain configuration to JSON file."""
        with open(self.config_path, 'w') as f:
            json.dump(self.domains, f, indent=2)
    
    def add_domain(self, domain: str, notes: str = ""):
        """Add a domain to track."""
        # Check if domain already exists
        for d in self.domains:
            if d['domain'].lower() == domain.lower():
                print(f"Domain {domain} is already being tracked.")
                return False
        
        # Verify domain is valid by checking WHOIS
        try:
            info = whois.whois(domain)
            if not info.expiration_date:
                print(f"Could not find expiration date for {domain}")
                return False
        except Exception as e:
            print(f"Error checking domain {domain}: {e}")
            return False
        
        self.domains.append({
            'domain': domain.lower(),
            'notes': notes,
            'added': datetime.now().isoformat()
        })
        self._save_config()
        print(f"Added {domain} to tracking.")
        return True
    
    def remove_domain(self, domain: str):
        """Remove a domain from tracking."""
        original_count = len(self.domains)
        self.domains = [d for d in self.domains if d['domain'].lower() != domain.lower()]
        
        if len(self.domains) < original_count:
            self._save_config()
            print(f"Removed {domain} from tracking.")
            return True
        else:
            print(f"Domain {domain} not found in tracking list.")
            return False
    
    def list_domains(self):
        """List all tracked domains with their expiry info."""
        if not self.domains:
            print("No domains being tracked.")
            return
        
        print(f"\n{'Domain':<30} {'Expires In':<15} {'Expiry Date':<20} {'Notes'}")
        print("=" * 85)
        
        for domain_info in self.domains:
            domain = domain_info['domain']
            result = self._check_domain(domain)
            
            if result['error']:
                status = f"ERROR: {result['error']}"
                expiry_str = "N/A"
                days_left = "N/A"
            else:
                expiry_str = result['expiry_date'].strftime('%Y-%m-%d')
                days_left = result['days_left']
                
                if days_left < 0:
                    status = f"EXPIRED ({abs(days_left)} days ago)"
                elif days_left <= self.DEFAULT_ALERT_DAYS:
                    status = f"ALERT: {days_left} days"
                else:
                    status = f"{days_left} days"
            
            notes = domain_info.get('notes', '')[:20]
            print(f"{domain:<30} {status:<15} {expiry_str:<20} {notes}")
        
        print()
    
    def _check_domain(self, domain: str) -> Dict:
        """Check a single domain's expiration date."""
        try:
            info = whois.whois(domain)
            
            expiry_date = info.expiration_date
            
            # Handle different date formats
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            
            if not expiry_date:
                return {
                    'domain': domain,
                    'expiry_date': None,
                    'days_left': None,
                    'error': 'No expiration date found'
                }
            
            # Calculate days left
            now = datetime.now()
            if isinstance(expiry_date, datetime):
                days_left = (expiry_date - now).days
            else:
                return {
                    'domain': domain,
                    'expiry_date': None,
                    'days_left': None,
                    'error': f'Unexpected date format: {type(expiry_date)}'
                }
            
            return {
                'domain': domain,
                'expiry_date': expiry_date,
                'days_left': days_left,
                'error': None
            }
            
        except Exception as e:
            return {
                'domain': domain,
                'expiry_date': None,
                'days_left': None,
                'error': str(e)
            }
    
    def check_all(self, alert_days: int = None) -> Tuple[List[Dict], List[Dict]]:
        """
        Check all domains and return alerts and errors.
        
        Returns:
            Tuple of (expiring_soon, errors)
        """
        if alert_days is None:
            alert_days = self.DEFAULT_ALERT_DAYS
        
        expiring_soon = []
        errors = []
        
        for domain_info in self.domains:
            domain = domain_info['domain']
            result = self._check_domain(domain)
            
            if result['error']:
                errors.append(result)
            elif result['days_left'] <= alert_days:
                expiring_soon.append({
                    **result,
                    'notes': domain_info.get('notes', '')
                })
        
        return expiring_soon, errors
    
    def send_alerts(self, webhook_url: str = None, alert_days: int = None):
        """Send alerts for domains expiring soon."""
        expiring_soon, errors = self.check_all(alert_days)
        
        if not expiring_soon and not errors:
            print("No alerts needed. All domains are safe.")
            return
        
        # Build alert message
        lines = []
        
        if expiring_soon:
            lines.append("🚨 **Domain Expiry Alert** 🚨")
            lines.append(f"\nThe following domains expire in {alert_days or self.DEFAULT_ALERT_DAYS} days or less:\n")
            
            for domain in expiring_soon:
                days = domain['days_left']
                expiry = domain['expiry_date'].strftime('%Y-%m-%d')
                emoji = "🔴" if days < 0 else "⚠️" if days <= 2 else "🟡"
                
                status = f"EXPIRED ({abs(days)} days ago)" if days < 0 else f"expires in {days} days"
                lines.append(f"{emoji} **{domain['domain']}** - {status} ({expiry})")
                
                if domain.get('notes'):
                    lines.append(f"   📝 {domain['notes']}")
        
        if errors:
            lines.append("\n⚠️ **Errors checking domains:**")
            for error in errors:
                lines.append(f"❌ {error['domain']}: {error['error']}")
        
        message = "\n".join(lines)
        print(message)
        
        # Send webhook if configured
        webhook_url = webhook_url or os.environ.get('DISCORD_WEBHOOK_URL')
        if webhook_url and (expiring_soon or errors):
            self._send_discord_webhook(webhook_url, message)
    
    def _send_discord_webhook(self, webhook_url: str, message: str):
        """Send alert to Discord webhook."""
        import urllib.request
        import urllib.parse
        
        payload = json.dumps({
            'content': message[:2000]  # Discord has 2000 char limit
        }).encode('utf-8')
        
        try:
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            urllib.request.urlopen(req)
            print("\n✅ Alert sent to Discord")
        except Exception as e:
            print(f"\n❌ Failed to send Discord alert: {e}")


def main():
    parser = argparse.ArgumentParser(description='Domain Expiry Tracker')
    parser.add_argument('--config', '-c', default='domains.json', help='Config file path')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Add domain
    add_parser = subparsers.add_parser('add', help='Add a domain to track')
    add_parser.add_argument('domain', help='Domain name to track')
    add_parser.add_argument('--notes', '-n', default='', help='Notes about the domain')
    
    # Remove domain
    remove_parser = subparsers.add_parser('remove', help='Remove a domain from tracking')
    remove_parser.add_argument('domain', help='Domain name to remove')
    
    # List domains
    subparsers.add_parser('list', help='List all tracked domains')
    
    # Check domains
    check_parser = subparsers.add_parser('check', help='Check domains and send alerts')
    check_parser.add_argument('--days', '-d', type=int, default=5, help='Alert threshold in days')
    check_parser.add_argument('--webhook', '-w', help='Discord webhook URL')
    
    args = parser.parse_args()
    
    tracker = DomainExpiryTracker(args.config)
    
    if args.command == 'add':
        tracker.add_domain(args.domain, args.notes)
    
    elif args.command == 'remove':
        tracker.remove_domain(args.domain)
    
    elif args.command == 'list':
        tracker.list_domains()
    
    elif args.command == 'check':
        tracker.send_alerts(args.webhook, args.days)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
