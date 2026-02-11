"""
Alert Manager Module
Handles webhook configurations and sends alerts to Discord/Slack.
"""

import json
import os
import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import socket
import ssl


class WebhookType(Enum):
    DISCORD = "discord"
    SLACK = "slack"


class AlertType(Enum):
    DOMAIN_EXPIRY = "domain_expiry"
    SSL_EXPIRY = "ssl_expiry"
    UPTIME_DOWN = "uptime_down"


@dataclass
class AlertConfig:
    """Alert configuration for a domain."""
    id: str
    domain_id: str
    webhook_url: str
    webhook_type: str  # 'discord' or 'slack'
    alert_types: List[str]  # ['domain_expiry', 'ssl_expiry', 'uptime_down']
    created_at: str
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'AlertConfig':
        return cls(**data)


class AlertManager:
    """Manage alert configurations and send webhook notifications."""
    
    DEFAULT_CONFIG_PATH = '/data/alert_configs.json'
    
    # Alert thresholds
    DOMAIN_EXPIRY_DAYS = 5
    SSL_EXPIRY_DAYS = 14
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or os.environ.get('ALERT_CONFIG_PATH', self.DEFAULT_CONFIG_PATH)
        self._configs: List[AlertConfig] = []
        self._load_configs()
    
    def _load_configs(self):
        """Load alert configurations from JSON file."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                data = json.load(f)
                self._configs = [AlertConfig.from_dict(c) for c in data]
    
    def _save_configs(self):
        """Save alert configurations to JSON file."""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump([c.to_dict() for c in self._configs], f, indent=2)
    
    def _generate_id(self) -> str:
        """Generate a unique ID for a new config."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def create_config(self, domain_id: str, webhook_url: str, webhook_type: str, 
                      alert_types: List[str]) -> AlertConfig:
        """Create a new alert configuration."""
        # Validate webhook_type
        if webhook_type not in [wt.value for wt in WebhookType]:
            raise ValueError(f"Invalid webhook_type: {webhook_type}. Must be one of: {[wt.value for wt in WebhookType]}")
        
        # Validate alert_types
        valid_alert_types = [at.value for at in AlertType]
        for at in alert_types:
            if at not in valid_alert_types:
                raise ValueError(f"Invalid alert_type: {at}. Must be one of: {valid_alert_types}")
        
        config = AlertConfig(
            id=self._generate_id(),
            domain_id=domain_id,
            webhook_url=webhook_url,
            webhook_type=webhook_type,
            alert_types=alert_types,
            created_at=datetime.now().isoformat()
        )
        
        self._configs.append(config)
        self._save_configs()
        return config
    
    def get_configs_for_domain(self, domain_id: str) -> List[AlertConfig]:
        """Get all alert configurations for a domain."""
        return [c for c in self._configs if c.domain_id == domain_id]
    
    def get_config(self, config_id: str) -> Optional[AlertConfig]:
        """Get a specific alert configuration by ID."""
        for c in self._configs:
            if c.id == config_id:
                return c
        return None
    
    def delete_config(self, config_id: str) -> bool:
        """Delete an alert configuration."""
        original_count = len(self._configs)
        self._configs = [c for c in self._configs if c.id != config_id]
        if len(self._configs) < original_count:
            self._save_configs()
            return True
        return False
    
    def list_all_configs(self) -> List[AlertConfig]:
        """List all alert configurations."""
        return self._configs.copy()
    
    # ==================== Webhook Formatters ====================
    
    def _format_discord_embed(self, title: str, description: str, fields: List[Dict], 
                              color: int = 0xFFA500) -> Dict:
        """Format a Discord embed message."""
        return {
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "timestamp": datetime.now().isoformat(),
                "footer": {
                    "text": "Domain Expiry Tracker"
                }
            }]
        }
    
    def _format_slack_blocks(self, title: str, description: str, fields: List[Dict]) -> Dict:
        """Format a Slack block message."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": title,
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": description
                }
            }
        ]
        
        # Add fields as a section
        if fields:
            fields_text = "\n".join([f"*{f['name']}:* {f['value']}" for f in fields])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": fields_text
                }
            })
        
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"_Domain Expiry Tracker • {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}_"
                }
            ]
        })
        
        return {"blocks": blocks}
    
    def _format_domain_expiry_alert(self, domain: str, days_left: int, 
                                    expiry_date: str, webhook_type: str) -> Dict:
        """Format a domain expiry alert."""
        if days_left < 0:
            title = "🔴 Domain EXPIRED"
            description = f"**{domain}** has expired!"
            color = 0xFF0000  # Red
            emoji = "🔴"
        elif days_left <= 2:
            title = "🚨 Domain Expiring VERY SOON"
            description = f"**{domain}** expires in {days_left} days!"
            color = 0xFF0000  # Red
            emoji = "🚨"
        else:
            title = "⚠️ Domain Expiring Soon"
            description = f"**{domain}** expires in {days_left} days."
            color = 0xFFA500  # Orange
            emoji = "⚠️"
        
        fields = [
            {"name": "Domain", "value": domain, "inline": True},
            {"name": "Days Left", "value": str(days_left), "inline": True},
            {"name": "Expiry Date", "value": expiry_date, "inline": True}
        ]
        
        if webhook_type == WebhookType.DISCORD.value:
            return self._format_discord_embed(title, description, fields, color)
        else:
            return self._format_slack_blocks(f"{emoji} {title}", description, fields)
    
    def _format_ssl_expiry_alert(self, domain: str, days_left: int, 
                                 expiry_date: str, issuer: str, webhook_type: str) -> Dict:
        """Format an SSL certificate expiry alert."""
        if days_left < 0:
            title = "🔴 SSL Certificate EXPIRED"
            description = f"SSL certificate for **{domain}** has expired!"
            color = 0xFF0000
            emoji = "🔴"
        elif days_left <= 7:
            title = "🚨 SSL Certificate Expiring VERY SOON"
            description = f"SSL certificate for **{domain}** expires in {days_left} days!"
            color = 0xFF0000
            emoji = "🚨"
        else:
            title = "🔒 SSL Certificate Expiring Soon"
            description = f"SSL certificate for **{domain}** expires in {days_left} days."
            color = 0xFFA500
            emoji = "🔒"
        
        fields = [
            {"name": "Domain", "value": domain, "inline": True},
            {"name": "Days Left", "value": str(days_left), "inline": True},
            {"name": "Expiry Date", "value": expiry_date, "inline": True},
            {"name": "Issuer", "value": issuer or "Unknown", "inline": True}
        ]
        
        if webhook_type == WebhookType.DISCORD.value:
            return self._format_discord_embed(title, description, fields, color)
        else:
            return self._format_slack_blocks(f"{emoji} {title}", description, fields)
    
    def _format_uptime_down_alert(self, domain: str, error: str, 
                                  webhook_type: str) -> Dict:
        """Format an uptime down alert."""
        title = "❌ Site DOWN"
        description = f"**{domain}** is not responding!"
        color = 0xFF0000
        emoji = "❌"
        
        fields = [
            {"name": "Domain", "value": domain, "inline": True},
            {"name": "Error", "value": error[:1000], "inline": False}
        ]
        
        if webhook_type == WebhookType.DISCORD.value:
            return self._format_discord_embed(title, description, fields, color)
        else:
            return self._format_slack_blocks(f"{emoji} {title}", description, fields)
    
    # ==================== Alert Senders ====================
    
    async def _send_webhook(self, webhook_url: str, payload: Dict) -> bool:
        """Send a webhook payload asynchronously."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    return response.status in (200, 201, 204)
        except Exception as e:
            print(f"Error sending webhook: {e}")
            return False
    
    async def send_alert(self, config: AlertConfig, alert_type: str, 
                         domain_data: Dict) -> bool:
        """Send an alert based on configuration and alert type."""
        if alert_type not in config.alert_types:
            return False  # Alert type not enabled for this config
        
        webhook_type = config.webhook_type
        
        if alert_type == AlertType.DOMAIN_EXPIRY.value:
            payload = self._format_domain_expiry_alert(
                domain=domain_data['domain'],
                days_left=domain_data['days_left'],
                expiry_date=domain_data['expiry_date'],
                webhook_type=webhook_type
            )
        elif alert_type == AlertType.SSL_EXPIRY.value:
            payload = self._format_ssl_expiry_alert(
                domain=domain_data['domain'],
                days_left=domain_data['ssl_days_left'],
                expiry_date=domain_data['ssl_expiry_date'],
                issuer=domain_data.get('ssl_issuer', 'Unknown'),
                webhook_type=webhook_type
            )
        elif alert_type == AlertType.UPTIME_DOWN.value:
            payload = self._format_uptime_down_alert(
                domain=domain_data['domain'],
                error=domain_data.get('error', 'Unknown error'),
                webhook_type=webhook_type
            )
        else:
            return False
        
        return await self._send_webhook(config.webhook_url, payload)
    
    # ==================== Trigger Checks ====================
    
    async def check_and_send_domain_expiry_alerts(self, domain_data: Dict):
        """Check domain expiry and send alerts if needed."""
        days_left = domain_data.get('days_left')
        if days_left is None:
            return
        
        # Only alert if domain expires in < 5 days
        if days_left > self.DOMAIN_EXPIRY_DAYS:
            return
        
        domain = domain_data['domain']
        configs = self.get_configs_for_domain(domain)
        
        tasks = []
        for config in configs:
            if AlertType.DOMAIN_EXPIRY.value in config.alert_types:
                tasks.append(self.send_alert(config, AlertType.DOMAIN_EXPIRY.value, domain_data))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def check_and_send_ssl_expiry_alerts(self, domain_data: Dict):
        """Check SSL expiry and send alerts if needed."""
        ssl_data = domain_data.get('ssl', {})
        days_left = ssl_data.get('days_left')
        
        if days_left is None:
            return
        
        # Only alert if SSL expires in < 14 days
        if days_left > self.SSL_EXPIRY_DAYS:
            return
        
        domain = domain_data['domain']
        configs = self.get_configs_for_domain(domain)
        
        # Prepare SSL data for alert
        ssl_alert_data = {
            'domain': domain,
            'ssl_days_left': days_left,
            'ssl_expiry_date': ssl_data.get('expiry_date'),
            'ssl_issuer': ssl_data.get('issuer', 'Unknown')
        }
        
        tasks = []
        for config in configs:
            if AlertType.SSL_EXPIRY.value in config.alert_types:
                tasks.append(self.send_alert(config, AlertType.SSL_EXPIRY.value, ssl_alert_data))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def check_and_send_uptime_down_alerts(self, domain: str, error: str):
        """Send uptime down alerts."""
        configs = self.get_configs_for_domain(domain)
        
        down_data = {
            'domain': domain,
            'error': error
        }
        
        tasks = []
        for config in configs:
            if AlertType.UPTIME_DOWN.value in config.alert_types:
                tasks.append(self.send_alert(config, AlertType.UPTIME_DOWN.value, down_data))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


# Global alert manager instance
_alert_manager: Optional[AlertManager] = None


def get_alert_manager() -> AlertManager:
    """Get or create the global alert manager instance."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager
