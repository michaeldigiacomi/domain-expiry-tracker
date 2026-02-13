#!/usr/bin/env python3
"""
WHOIS Cache Module
Provides persistent caching for WHOIS lookups using SQLite.
"""

import json
import os
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict

from sqlalchemy import create_engine, Column, String, DateTime, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

Base = declarative_base()


class WhoisCacheEntry(Base):
    """Database model for WHOIS cache entries."""
    __tablename__ = 'whois_cache'
    
    domain = Column(String(255), primary_key=True)
    expiry_date = Column(String(20), nullable=True)  # YYYY-MM-DD format
    days_left = Column(Integer, nullable=True)
    registrar = Column(String(500), nullable=True)
    name_servers = Column(Text, nullable=True)  # JSON list
    status = Column(String(100), nullable=True)
    raw_data = Column(Text, nullable=True)  # Full WHOIS response for debugging
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    lookup_count = Column(Integer, default=1)
    success_count = Column(Integer, default=1)
    last_error = Column(Text, nullable=True)
    consecutive_failures = Column(Integer, default=0)


@dataclass
class WhoisCacheResult:
    """Result from cache lookup."""
    domain: str
    expiry_date: Optional[str]
    days_left: Optional[int]
    registrar: Optional[str]
    cached: bool
    stale: bool
    cache_age_days: float
    from_persistent_cache: bool
    error: Optional[str] = None


class WhoisCacheManager:
    """Manages persistent WHOIS caching."""
    
    # Cache TTL settings (in days)
    DEFAULT_SUCCESS_TTL_DAYS = 7  # Cache successful lookups for 7 days
    DEFAULT_FAILURE_TTL_HOURS = 1  # Cache failures for 1 hour (avoid hammering)
    MAX_FAILURE_AGE_DAYS = 30  # Keep failure records for 30 days max
    
    def __init__(self, database_url: str = None):
        self.database_url = database_url or os.environ.get(
            'DATABASE_URL', 
            'sqlite:////data/domain_tracker.db'
        )
        self.engine = create_engine(
            self.database_url,
            connect_args={'check_same_thread': False} if 'sqlite' in self.database_url else {}
        )
        # Create tables
        Base.metadata.create_all(self.engine)
        self.Session = scoped_session(sessionmaker(bind=self.engine))
    
    def get(
        self, 
        domain: str, 
        success_ttl_days: int = None,
        failure_ttl_hours: int = None
    ) -> Optional[WhoisCacheResult]:
        """
        Get cached WHOIS data for a domain.
        
        Returns None if no cache entry or cache has expired.
        Returns result with stale=True if cache is expired but available.
        """
        success_ttl_days = success_ttl_days or self.DEFAULT_SUCCESS_TTL_DAYS
        failure_ttl_hours = failure_ttl_hours or self.DEFAULT_FAILURE_TTL_HOURS
        
        session = self.Session()
        try:
            entry = session.query(WhoisCacheEntry).filter_by(domain=domain).first()
            if not entry:
                return None
            
            now = datetime.utcnow()
            age = now - entry.updated_at
            age_days = age.total_seconds() / 86400
            
            # Determine if cache is fresh based on success/failure
            has_error = entry.last_error is not None and entry.consecutive_failures > 0
            
            if has_error:
                # For failed lookups, use shorter TTL
                ttl_days = failure_ttl_hours / 24
            else:
                ttl_days = success_ttl_days
            
            is_stale = age_days > ttl_days
            
            return WhoisCacheResult(
                domain=domain,
                expiry_date=entry.expiry_date,
                days_left=entry.days_left,
                registrar=entry.registrar,
                cached=True,
                stale=is_stale,
                cache_age_days=age_days,
                from_persistent_cache=True,
                error=entry.last_error if has_error else None
            )
        finally:
            session.close()
    
    def set(
        self, 
        domain: str, 
        expiry_date: str = None,
        days_left: int = None,
        registrar: str = None,
        name_servers: list = None,
        status: str = None,
        raw_data: str = None,
        error: str = None
    ):
        """Store WHOIS lookup result in cache."""
        session = self.Session()
        try:
            entry = session.query(WhoisCacheEntry).filter_by(domain=domain).first()
            now = datetime.utcnow()
            
            if entry is None:
                entry = WhoisCacheEntry(domain=domain)
                session.add(entry)
            
            # Update fields
            entry.updated_at = now
            entry.lookup_count = (entry.lookup_count or 0) + 1
            
            if error:
                entry.last_error = error[:1000] if error else None  # Limit error size
                entry.consecutive_failures = (entry.consecutive_failures or 0) + 1
            else:
                # Successful lookup - update data
                entry.expiry_date = expiry_date
                entry.days_left = days_left
                entry.registrar = registrar
                entry.name_servers = json.dumps(name_servers) if name_servers else None
                entry.status = status
                entry.raw_data = raw_data[:5000] if raw_data else None  # Limit size
                entry.last_error = None
                entry.consecutive_failures = 0
                entry.success_count = (entry.success_count or 0) + 1
            
            session.commit()
        finally:
            session.close()
    
    def should_refresh(self, domain: str, min_age_hours: int = 1) -> bool:
        """
        Check if we should attempt a fresh lookup.
        
        Returns True if:
        - No cache entry exists
        - Cache is stale
        - Last lookup was a failure
        - Cache is older than min_age_hours
        """
        result = self.get(domain)
        if not result:
            return True
        if result.stale:
            return True
        if result.error:
            return True
        if result.cache_age_days * 24 > min_age_hours:
            return True
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        session = self.Session()
        try:
            total = session.query(WhoisCacheEntry).count()
            with_expiry = session.query(WhoisCacheEntry).filter(
                WhoisCacheEntry.expiry_date.isnot(None)
            ).count()
            with_errors = session.query(WhoisCacheEntry).filter(
                WhoisCacheEntry.last_error.isnot(None)
            ).count()
            
            # Stale entries (> 7 days old)
            cutoff = datetime.utcnow() - timedelta(days=7)
            stale = session.query(WhoisCacheEntry).filter(
                WhoisCacheEntry.updated_at < cutoff
            ).count()
            
            return {
                'total_entries': total,
                'with_expiry': with_expiry,
                'with_errors': with_errors,
                'stale_entries': stale
            }
        finally:
            session.close()
    
    def cleanup_old_entries(self, max_age_days: int = 90):
        """Remove cache entries older than max_age_days."""
        session = self.Session()
        try:
            cutoff = datetime.utcnow() - timedelta(days=max_age_days)
            deleted = session.query(WhoisCacheEntry).filter(
                WhoisCacheEntry.updated_at < cutoff
            ).delete(synchronize_session=False)
            session.commit()
            return deleted
        finally:
            session.close()


# Global cache manager instance
_cache_manager: Optional[WhoisCacheManager] = None


def get_whois_cache_manager() -> WhoisCacheManager:
    """Get or create the global WHOIS cache manager."""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = WhoisCacheManager()
    return _cache_manager
