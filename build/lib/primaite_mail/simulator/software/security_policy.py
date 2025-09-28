"""Email security policy data models and core logic."""

import ipaddress
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union
from dataclasses import dataclass, field

from pydantic import BaseModel, Field


@dataclass
class SecurityEvent:
    """Individual security event record."""
    
    timestamp: str
    event_type: str  # "blocked_sender", "blocked_ip", "policy_change", "connection_refused", "authentication_failure", "rate_limit_exceeded"
    reason: str
    sender: Optional[str] = None
    ip_address: Optional[str] = None
    agent: Optional[str] = None
    severity: str = "medium"  # low, medium, high
    additional_data: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Validate event data after initialization."""
        valid_event_types = [
            "blocked_sender", "blocked_ip", "policy_change", "connection_refused",
            "authentication_failure", "rate_limit_exceeded", "suspicious_activity",
            "policy_violation", "security_scan_detected"
        ]
        if self.event_type not in valid_event_types:
            raise ValueError(f"Invalid event_type: {self.event_type}. Valid types: {valid_event_types}")
        
        if self.severity not in ["low", "medium", "high"]:
            raise ValueError(f"Invalid severity: {self.severity}")
        
        # Initialize additional_data if None
        if self.additional_data is None:
            self.additional_data = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert SecurityEvent to dictionary for serialization."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "reason": self.reason,
            "sender": self.sender,
            "ip_address": self.ip_address,
            "agent": self.agent,
            "severity": self.severity,
            "additional_data": self.additional_data or {}
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        """Create SecurityEvent from dictionary."""
        return cls(
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            reason=data["reason"],
            sender=data.get("sender"),
            ip_address=data.get("ip_address"),
            agent=data.get("agent"),
            severity=data.get("severity", "medium"),
            additional_data=data.get("additional_data")
        )
    
    def matches_filter(self, event_type: Optional[str] = None, 
                      severity: Optional[str] = None,
                      sender: Optional[str] = None,
                      ip_address: Optional[str] = None,
                      agent: Optional[str] = None) -> bool:
        """Check if this event matches the given filter criteria."""
        if event_type and self.event_type != event_type:
            return False
        
        if severity and self.severity != severity:
            return False
        
        if sender and (not self.sender or sender.lower() not in self.sender.lower()):
            return False
        
        if ip_address and (not self.ip_address or ip_address not in self.ip_address):
            return False
        
        if agent and (not self.agent or agent not in self.agent):
            return False
        
        return True
    
    def get_summary(self) -> str:
        """Get a human-readable summary of the security event."""
        summary_parts = [f"[{self.severity.upper()}]", self.event_type.replace('_', ' ').title()]
        
        if self.sender:
            summary_parts.append(f"Sender: {self.sender}")
        
        if self.ip_address:
            summary_parts.append(f"IP: {self.ip_address}")
        
        if self.agent:
            summary_parts.append(f"Agent: {self.agent}")
        
        summary_parts.append(f"- {self.reason}")
        
        return " | ".join(summary_parts)


class SecurityEventLog(BaseModel):
    """Security event logging for email policies."""
    
    events: List[SecurityEvent] = Field(default_factory=list)
    max_events: int = Field(default=1000, description="Rolling log size")
    auto_rotate: bool = Field(default=True, description="Automatically rotate logs when max_events is reached")
    rotation_threshold: float = Field(default=0.9, description="Rotate when log reaches this percentage of max_events")
    alert_threshold: int = Field(default=10, description="Number of high severity events to trigger alert")
    alert_time_window_hours: float = Field(default=1.0, description="Time window for alert threshold checking")
    
    def log_blocked_email(self, sender: str, ip: str, reason: str, severity: str = "medium", 
                         additional_data: Optional[Dict[str, Any]] = None) -> None:
        """Log a blocked email event."""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type="blocked_sender",
            sender=sender,
            ip_address=ip,
            reason=reason,
            severity=severity,
            additional_data=additional_data
        )
        self._add_event(event)
    
    def log_blocked_ip(self, ip: str, reason: str, severity: str = "medium", 
                      additional_data: Optional[Dict[str, Any]] = None) -> None:
        """Log a blocked IP connection event."""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type="blocked_ip",
            ip_address=ip,
            reason=reason,
            severity=severity,
            additional_data=additional_data
        )
        self._add_event(event)
    
    def log_connection_refused(self, ip: str, reason: str, severity: str = "high",
                              additional_data: Optional[Dict[str, Any]] = None) -> None:
        """Log a connection refusal event."""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type="connection_refused",
            ip_address=ip,
            reason=reason,
            severity=severity,
            additional_data=additional_data
        )
        self._add_event(event)
    
    def log_policy_change(self, agent: str, action: str, target: str, severity: str = "low",
                         additional_data: Optional[Dict[str, Any]] = None) -> None:
        """Log a policy modification event."""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type="policy_change",
            agent=agent,
            reason=f"Policy {action}: {target}",
            severity=severity,
            additional_data=additional_data
        )
        self._add_event(event)
    
    def log_security_event(self, event_type: str, reason: str, severity: str = "medium",
                          sender: Optional[str] = None, ip_address: Optional[str] = None,
                          agent: Optional[str] = None, additional_data: Optional[Dict[str, Any]] = None) -> None:
        """Log a generic security event."""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            reason=reason,
            severity=severity,
            sender=sender,
            ip_address=ip_address,
            agent=agent,
            additional_data=additional_data
        )
        self._add_event(event)
    
    def _add_event(self, event: SecurityEvent) -> None:
        """Add event to log with rolling window management."""
        self.events.append(event)
        
        # Check if rotation is needed
        if self.auto_rotate and len(self.events) > self.max_events:
            self._rotate_log()
    
    def _rotate_log(self) -> None:
        """Rotate the log by removing oldest events."""
        if len(self.events) > self.max_events:
            # Keep only the most recent max_events
            self.events = self.events[-self.max_events:]
    
    def force_rotation(self) -> int:
        """Force log rotation and return number of events removed."""
        original_count = len(self.events)
        self._rotate_log()
        return original_count - len(self.events)
    
    def set_max_events(self, max_events: int) -> None:
        """Update maximum events and rotate if necessary."""
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        
        self.max_events = max_events
        if len(self.events) > max_events:
            self._rotate_log()
    
    def get_recent_events(self, limit: int = 50) -> List[SecurityEvent]:
        """Get recent security events."""
        return self.events[-limit:] if limit > 0 else self.events
    
    def get_events_by_time_range(self, hours: float, limit: int = 50) -> List[SecurityEvent]:
        """Get events within the specified time range (in hours)."""
        if hours <= 0:
            return self.get_recent_events(limit)
        
        try:
            from datetime import datetime, timedelta
            cutoff_time = datetime.now() - timedelta(hours=hours)
            cutoff_iso = cutoff_time.isoformat()
            
            filtered_events = []
            for event in self.events:
                if event.timestamp >= cutoff_iso:
                    filtered_events.append(event)
            
            # Return most recent events up to limit
            return filtered_events[-limit:] if limit > 0 else filtered_events
            
        except (ImportError, ValueError, TypeError):
            # Fallback to recent events if datetime operations fail
            return self.get_recent_events(limit)
    
    def get_events_by_type(self, event_type: str, limit: int = 50) -> List[SecurityEvent]:
        """Get events filtered by event type."""
        filtered_events = []
        for event in self.events:
            if event.event_type == event_type:
                filtered_events.append(event)
        
        # Return most recent events up to limit
        return filtered_events[-limit:] if limit > 0 else filtered_events
    
    def get_filtered_events(self, event_type: Optional[str] = None, 
                          time_range_hours: Optional[float] = None, 
                          severity: Optional[str] = None,
                          sender: Optional[str] = None,
                          ip_address: Optional[str] = None,
                          agent: Optional[str] = None,
                          limit: int = 50) -> List[SecurityEvent]:
        """Get events with comprehensive filtering capabilities."""
        events = self.events
        
        # Apply time range filter first
        if time_range_hours is not None and time_range_hours > 0:
            try:
                from datetime import datetime, timedelta
                cutoff_time = datetime.now() - timedelta(hours=time_range_hours)
                cutoff_iso = cutoff_time.isoformat()
                
                events = [event for event in events if event.timestamp >= cutoff_iso]
            except (ImportError, ValueError, TypeError):
                # Keep all events if datetime operations fail
                pass
        
        # Apply event type filter
        if event_type:
            events = [event for event in events if event.event_type == event_type]
        
        # Apply severity filter
        if severity:
            events = [event for event in events if event.severity == severity]
        
        # Apply sender filter (case-insensitive partial match)
        if sender:
            sender_lower = sender.lower()
            events = [event for event in events 
                     if event.sender and sender_lower in event.sender.lower()]
        
        # Apply IP address filter (supports partial matching for subnets)
        if ip_address:
            events = [event for event in events 
                     if event.ip_address and ip_address in event.ip_address]
        
        # Apply agent filter
        if agent:
            events = [event for event in events 
                     if event.agent and agent in event.agent]
        
        # Return most recent events up to limit
        return events[-limit:] if limit > 0 else events
    
    def get_events_by_severity(self, severity: str, limit: int = 50) -> List[SecurityEvent]:
        """Get events filtered by severity level."""
        if severity not in ["low", "medium", "high"]:
            raise ValueError(f"Invalid severity: {severity}. Must be one of: low, medium, high")
        
        filtered_events = [event for event in self.events if event.severity == severity]
        return filtered_events[-limit:] if limit > 0 else filtered_events
    
    def get_events_by_ip_range(self, ip_range: str, limit: int = 50) -> List[SecurityEvent]:
        """Get events from a specific IP range (supports CIDR notation)."""
        try:
            import ipaddress
            if '/' in ip_range:
                # CIDR range
                network = ipaddress.ip_network(ip_range, strict=False)
                filtered_events = []
                for event in self.events:
                    if event.ip_address:
                        try:
                            ip_addr = ipaddress.ip_address(event.ip_address)
                            if ip_addr in network:
                                filtered_events.append(event)
                        except ValueError:
                            # Skip invalid IP addresses
                            continue
            else:
                # Single IP or partial match
                filtered_events = [event for event in self.events 
                                 if event.ip_address and ip_range in event.ip_address]
            
            return filtered_events[-limit:] if limit > 0 else filtered_events
        except (ImportError, ValueError):
            # Fallback to simple string matching
            filtered_events = [event for event in self.events 
                             if event.ip_address and ip_range in event.ip_address]
            return filtered_events[-limit:] if limit > 0 else filtered_events
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get blocking statistics."""
        stats = {
            "total_events": len(self.events),
            "blocked_senders": 0,
            "blocked_ips": 0,
            "policy_changes": 0,
            "events_by_severity": {"low": 0, "medium": 0, "high": 0}
        }
        
        for event in self.events:
            if event.event_type == "blocked_sender":
                stats["blocked_senders"] += 1
            elif event.event_type in ["blocked_ip", "connection_refused"]:
                stats["blocked_ips"] += 1
            elif event.event_type == "policy_change":
                stats["policy_changes"] += 1
            
            stats["events_by_severity"][event.severity] += 1
        
        return stats
    
    def get_detailed_statistics(self, time_range_hours: Optional[float] = None) -> Dict[str, Any]:
        """Get detailed statistics with optional time range filtering."""
        # Get events for the specified time range
        if time_range_hours is not None:
            events = self.get_events_by_time_range(time_range_hours, limit=0)  # No limit for stats
        else:
            events = self.events
        
        stats = {
            "total_events": len(events),
            "blocked_senders": 0,
            "blocked_ips": 0,
            "policy_changes": 0,
            "connection_refused": 0,
            "events_by_severity": {"low": 0, "medium": 0, "high": 0},
            "events_by_type": {},
            "unique_senders": set(),
            "unique_ips": set(),
            "agents_active": set(),
            "log_health": {
                "current_size": len(self.events),
                "max_size": self.max_events,
                "utilization_percent": round((len(self.events) / self.max_events) * 100, 2) if self.max_events > 0 else 0,
                "auto_rotate_enabled": self.auto_rotate,
                "rotation_threshold": self.rotation_threshold
            }
        }
        
        for event in events:
            # Count by event type
            if event.event_type not in stats["events_by_type"]:
                stats["events_by_type"][event.event_type] = 0
            stats["events_by_type"][event.event_type] += 1
            
            # Legacy counters
            if event.event_type == "blocked_sender":
                stats["blocked_senders"] += 1
                if event.sender:
                    stats["unique_senders"].add(event.sender)
            elif event.event_type in ["blocked_ip"]:
                stats["blocked_ips"] += 1
            elif event.event_type == "connection_refused":
                stats["connection_refused"] += 1
            elif event.event_type == "policy_change":
                stats["policy_changes"] += 1
            
            # Count by severity
            stats["events_by_severity"][event.severity] += 1
            
            # Track unique IPs from all events (both sender blocks and IP blocks)
            if event.ip_address:
                stats["unique_ips"].add(event.ip_address)
            
            # Track active agents
            if event.agent:
                stats["agents_active"].add(event.agent)
        
        # Convert sets to counts for JSON serialization
        stats["unique_senders_count"] = len(stats["unique_senders"])
        stats["unique_ips_count"] = len(stats["unique_ips"])
        stats["agents_active_count"] = len(stats["agents_active"])
        
        # Remove sets (not JSON serializable)
        del stats["unique_senders"]
        del stats["unique_ips"]
        del stats["agents_active"]
        
        return stats
    
    def get_log_health_status(self) -> Dict[str, Any]:
        """Get log health and rotation status."""
        current_size = len(self.events)
        utilization = (current_size / self.max_events) * 100 if self.max_events > 0 else 0
        
        return {
            "current_size": current_size,
            "max_size": self.max_events,
            "utilization_percent": round(utilization, 2),
            "auto_rotate_enabled": self.auto_rotate,
            "rotation_threshold_percent": round(self.rotation_threshold * 100, 2),
            "needs_rotation": utilization >= (self.rotation_threshold * 100),
            "events_until_rotation": max(0, self.max_events - current_size),
            "status": "healthy" if utilization < 80 else "warning" if utilization < 95 else "critical"
        }
    
    def export_events(self, format_type: str = "dict", 
                     filters: Optional[Dict[str, Any]] = None) -> Union[List[Dict[str, Any]], str]:
        """Export events in various formats with optional filtering."""
        # Apply filters if provided
        if filters:
            events = self.get_filtered_events(**filters)
        else:
            events = self.events
        
        if format_type == "dict":
            return [event.to_dict() for event in events]
        elif format_type == "json":
            import json
            return json.dumps([event.to_dict() for event in events], indent=2)
        elif format_type == "csv":
            # Simple CSV format
            if not events:
                return "timestamp,event_type,severity,sender,ip_address,agent,reason\n"
            
            lines = ["timestamp,event_type,severity,sender,ip_address,agent,reason"]
            for event in events:
                line = f"{event.timestamp},{event.event_type},{event.severity}," \
                       f"{event.sender or ''},{event.ip_address or ''},{event.agent or ''}," \
                       f"\"{event.reason}\""
                lines.append(line)
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported format_type: {format_type}. Supported: dict, json, csv")
    
    def check_alert_conditions(self) -> Dict[str, Any]:
        """Check if alert conditions are met based on recent high-severity events."""
        try:
            # Get high severity events within the alert time window
            high_severity_events = self.get_filtered_events(
                severity="high",
                time_range_hours=self.alert_time_window_hours,
                limit=0  # No limit for alert checking
            )
            
            alert_triggered = len(high_severity_events) >= self.alert_threshold
            
            return {
                "alert_triggered": alert_triggered,
                "high_severity_count": len(high_severity_events),
                "alert_threshold": self.alert_threshold,
                "time_window_hours": self.alert_time_window_hours,
                "recent_high_severity_events": [event.to_dict() for event in high_severity_events[-5:]]  # Last 5 for context
            }
        except Exception:
            # Return safe default if any error occurs
            return {
                "alert_triggered": False,
                "high_severity_count": 0,
                "alert_threshold": self.alert_threshold,
                "time_window_hours": self.alert_time_window_hours,
                "recent_high_severity_events": [],
                "error": "Failed to check alert conditions"
            }
    
    def get_audit_trail(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit trail of all security events for compliance reporting."""
        events = self.get_recent_events(limit)
        
        audit_trail = []
        for event in events:
            audit_entry = {
                "timestamp": event.timestamp,
                "event_id": f"{event.event_type}_{event.timestamp}",
                "event_type": event.event_type,
                "severity": event.severity,
                "description": event.reason,
                "affected_entity": event.sender or event.ip_address or "system",
                "initiating_agent": event.agent or "system",
                "additional_context": event.additional_data or {}
            }
            audit_trail.append(audit_entry)
        
        return audit_trail
    
    def get_compliance_report(self, time_range_hours: Optional[float] = 24.0) -> Dict[str, Any]:
        """Generate compliance report for security events within specified time range."""
        if time_range_hours:
            events = self.get_events_by_time_range(time_range_hours, limit=0)
        else:
            events = self.events
        
        # Categorize events for compliance reporting
        blocked_actions = [e for e in events if e.event_type in ["blocked_sender", "blocked_ip", "connection_refused"]]
        policy_changes = [e for e in events if e.event_type == "policy_change"]
        security_incidents = [e for e in events if e.severity == "high"]
        
        return {
            "report_period_hours": time_range_hours,
            "total_events": len(events),
            "security_actions": {
                "blocked_emails": len([e for e in blocked_actions if e.event_type == "blocked_sender"]),
                "blocked_connections": len([e for e in blocked_actions if e.event_type in ["blocked_ip", "connection_refused"]]),
                "total_blocked_actions": len(blocked_actions)
            },
            "policy_management": {
                "policy_changes": len(policy_changes),
                "agents_involved": len(set(e.agent for e in policy_changes if e.agent))
            },
            "security_incidents": {
                "high_severity_events": len(security_incidents),
                "incident_types": list(set(e.event_type for e in security_incidents))
            },
            "severity_distribution": {
                "low": len([e for e in events if e.severity == "low"]),
                "medium": len([e for e in events if e.severity == "medium"]),
                "high": len([e for e in events if e.severity == "high"])
            },
            "unique_entities": {
                "senders": len(set(e.sender for e in events if e.sender)),
                "ip_addresses": len(set(e.ip_address for e in events if e.ip_address)),
                "agents": len(set(e.agent for e in events if e.agent))
            }
        }
    
    def clear_old_events(self, hours: float) -> int:
        """Clear events older than specified hours. Returns number of events removed."""
        if hours <= 0:
            return 0
        
        try:
            from datetime import datetime, timedelta
            cutoff_time = datetime.now() - timedelta(hours=hours)
            cutoff_iso = cutoff_time.isoformat()
            
            original_count = len(self.events)
            self.events = [event for event in self.events if event.timestamp >= cutoff_iso]
            return original_count - len(self.events)
        except (ImportError, ValueError, TypeError):
            # If datetime operations fail, don't remove any events
            return 0
    
    def configure_rotation(self, max_events: int, auto_rotate: bool = True, 
                          rotation_threshold: float = 0.9) -> None:
        """Configure log rotation settings."""
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        if not 0.1 <= rotation_threshold <= 1.0:
            raise ValueError("rotation_threshold must be between 0.1 and 1.0")
        
        self.max_events = max_events
        self.auto_rotate = auto_rotate
        self.rotation_threshold = rotation_threshold
        
        # Apply rotation if needed
        if auto_rotate and len(self.events) > max_events:
            self._rotate_log()
    
    def configure_alerts(self, alert_threshold: int, time_window_hours: float = 1.0) -> None:
        """Configure alert settings for high-severity events."""
        if alert_threshold < 1:
            raise ValueError("alert_threshold must be at least 1")
        if time_window_hours <= 0:
            raise ValueError("time_window_hours must be positive")
        
        self.alert_threshold = alert_threshold
        self.alert_time_window_hours = time_window_hours


class EmailSecurityPolicy(BaseModel):
    """Email security policy configuration with performance optimization and error handling."""
    
    blocked_senders: Set[str] = Field(default_factory=set)
    blocked_ips: Set[str] = Field(default_factory=set)  # Supports CIDR notation
    enable_logging: bool = Field(default=True)
    default_action: str = Field(default="reject")  # reject, quarantine, or allow
    
    # Performance optimization: Pre-compiled IP networks for faster CIDR matching
    compiled_ip_networks: List[ipaddress.IPv4Network] = Field(default_factory=list, exclude=True)
    compiled_ipv6_networks: List[ipaddress.IPv6Network] = Field(default_factory=list, exclude=True)
    exact_ips: Set[str] = Field(default_factory=set, exclude=True)
    
    # Rate limiting for policy modifications
    rate_limit_window: int = Field(default=60, exclude=True)  # 1 minute window
    max_modifications_per_window: int = Field(default=100, exclude=True)  # Max 100 changes per minute
    modification_timestamps: List[float] = Field(default_factory=list, exclude=True)
    
    # Input validation patterns
    email_pattern: re.Pattern = Field(default=None, exclude=True)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Initialize email validation pattern
        self.email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        # Rebuild optimized data structures
        self._rebuild_ip_structures()
    
    def _validate_email_format(self, email: str) -> bool:
        """Validate email address format using regex."""
        if not email or not isinstance(email, str):
            return False
        
        email = email.strip()
        if not email:
            return False
        
        # Basic length check
        if len(email) > 254:  # RFC 5321 limit
            return False
        
        # Check for basic structure
        if email.count('@') != 1:
            return False
        
        local, domain = email.split('@', 1)
        
        # Local part validation
        if not local or len(local) > 64:  # RFC 5321 limit
            return False
        
        # Domain part validation
        if not domain or len(domain) > 253:  # RFC 5321 limit
            return False
        
        # Use regex for detailed validation
        return bool(self.email_pattern.match(email))
    
    def _validate_ip_format(self, ip_str: str) -> tuple:
        """
        Validate IP address or CIDR format.
        
        Returns:
            tuple: (is_valid, error_message)
        """
        if not ip_str or not isinstance(ip_str, str):
            return False, "IP address must be a non-empty string"
        
        ip_str = ip_str.strip()
        if not ip_str:
            return False, "IP address cannot be empty"
        
        try:
            if '/' in ip_str:
                # CIDR notation
                network = ipaddress.ip_network(ip_str, strict=False)
                return True, None
            else:
                # Single IP address
                ipaddress.ip_address(ip_str)
                return True, None
        except ValueError as e:
            return False, f"Invalid IP format: {str(e)}"
    
    def _check_rate_limit(self) -> tuple:
        """
        Check if policy modification rate limit is exceeded.
        
        Returns:
            tuple: (is_allowed, error_message)
        """
        current_time = time.time()
        
        # Remove timestamps outside the current window
        cutoff_time = current_time - self.rate_limit_window
        self.modification_timestamps = [
            ts for ts in self.modification_timestamps if ts > cutoff_time
        ]
        
        # Check if we're at the limit
        if len(self.modification_timestamps) >= self.max_modifications_per_window:
            return False, f"Rate limit exceeded: max {self.max_modifications_per_window} modifications per {self.rate_limit_window} seconds"
        
        # Record this modification attempt
        self.modification_timestamps.append(current_time)
        return True, None
    
    def _rebuild_ip_structures(self) -> None:
        """Rebuild optimized IP data structures for faster lookups."""
        self.compiled_ip_networks.clear()
        self.compiled_ipv6_networks.clear()
        self.exact_ips.clear()
        
        for ip_str in self.blocked_ips:
            try:
                if '/' in ip_str:
                    # CIDR notation
                    network = ipaddress.ip_network(ip_str, strict=False)
                    if isinstance(network, ipaddress.IPv4Network):
                        self.compiled_ip_networks.append(network)
                    else:
                        self.compiled_ipv6_networks.append(network)
                else:
                    # Exact IP
                    self.exact_ips.add(ip_str)
            except ValueError:
                # Skip invalid entries (should not happen with proper validation)
                continue
    
    def is_sender_blocked(self, sender: str) -> bool:
        """Check if sender email address is blocked (optimized for performance)."""
        if not sender:
            return False
        
        # Normalize sender address to lowercase for comparison
        sender_normalized = sender.lower().strip()
        
        # Use set membership for O(1) lookup performance
        # Pre-normalize all blocked senders to avoid repeated normalization
        return sender_normalized in {s.lower().strip() for s in self.blocked_senders}
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP address is blocked (optimized for performance with pre-compiled networks)."""
        if not ip:
            return False
        
        try:
            ip_addr = ipaddress.ip_address(ip)
        except ValueError:
            # Invalid IP address format
            return False
        
        # Fast exact IP lookup using set
        if ip in self.exact_ips:
            return True
        
        # Check against pre-compiled networks for faster CIDR matching
        if isinstance(ip_addr, ipaddress.IPv4Address):
            for network in self.compiled_ip_networks:
                if ip_addr in network:
                    return True
        else:  # IPv6
            for network in self.compiled_ipv6_networks:
                if ip_addr in network:
                    return True
        
        return False
    
    def add_blocked_sender(self, sender: str) -> bool:
        """Add sender to blocklist with comprehensive validation and rate limiting."""
        # Check rate limit first
        rate_allowed, rate_error = self._check_rate_limit()
        if not rate_allowed:
            raise ValueError(rate_error)
        
        if not sender or not sender.strip():
            return False  # Invalid input, return False instead of raising exception
        
        sender_normalized = sender.lower().strip()
        
        # Comprehensive email format validation
        if not self._validate_email_format(sender_normalized):
            return False  # Invalid format, return False instead of raising exception
        
        # Check if already blocked
        if sender_normalized in {s.lower().strip() for s in self.blocked_senders}:
            return False  # Already exists, no change needed
        
        self.blocked_senders.add(sender_normalized)
        return True
    
    def remove_blocked_sender(self, sender: str) -> bool:
        """Remove sender from blocklist with rate limiting."""
        # Check rate limit first
        rate_allowed, rate_error = self._check_rate_limit()
        if not rate_allowed:
            raise ValueError(rate_error)
        
        if not sender:
            raise ValueError("Sender address cannot be empty")
        
        sender_normalized = sender.lower().strip()
        
        # Find and remove the original case version
        to_remove = None
        for s in self.blocked_senders:
            if s.lower().strip() == sender_normalized:
                to_remove = s
                break
        
        if to_remove:
            self.blocked_senders.remove(to_remove)
            return True
        
        return False
    
    def add_blocked_ip(self, ip: str) -> bool:
        """Add IP or CIDR range to blocklist with comprehensive validation and rate limiting."""
        # Check rate limit first
        rate_allowed, rate_error = self._check_rate_limit()
        if not rate_allowed:
            raise ValueError(rate_error)
        
        if not ip or not ip.strip():
            return False  # Invalid input, return False instead of raising exception
        
        ip_normalized = ip.strip()
        
        # Comprehensive IP format validation
        is_valid, error_msg = self._validate_ip_format(ip_normalized)
        if not is_valid:
            return False  # Invalid format, return False instead of raising exception
        
        # Check if already blocked
        if ip_normalized in self.blocked_ips:
            return False  # Already exists, no change needed
        
        self.blocked_ips.add(ip_normalized)
        # Rebuild optimized structures for performance
        self._rebuild_ip_structures()
        return True
    
    def remove_blocked_ip(self, ip: str) -> bool:
        """Remove IP or CIDR range from blocklist with rate limiting."""
        # Check rate limit first
        rate_allowed, rate_error = self._check_rate_limit()
        if not rate_allowed:
            raise ValueError(rate_error)
        
        if not ip:
            raise ValueError("IP address cannot be empty")
        
        ip_normalized = ip.strip()
        
        if ip_normalized in self.blocked_ips:
            self.blocked_ips.remove(ip_normalized)
            # Rebuild optimized structures for performance
            self._rebuild_ip_structures()
            return True
        
        return False
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get summary of current security policies."""
        return {
            "blocked_senders_count": len(self.blocked_senders),
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_senders": list(self.blocked_senders),
            "blocked_ips": list(self.blocked_ips),
            "default_action": self.default_action,
            "logging_enabled": self.enable_logging
        }
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for policy checking."""
        return {
            "blocked_senders_count": len(self.blocked_senders),
            "blocked_ips_count": len(self.blocked_ips),
            "compiled_ipv4_networks": len(self.compiled_ip_networks),
            "compiled_ipv6_networks": len(self.compiled_ipv6_networks),
            "exact_ips": len(self.exact_ips),
            "rate_limit_window": self.rate_limit_window,
            "max_modifications_per_window": self.max_modifications_per_window,
            "recent_modifications": len(self.modification_timestamps),
            "optimization_enabled": True
        }
    
    def configure_rate_limiting(self, window_seconds: int, max_modifications: int) -> None:
        """Configure rate limiting parameters."""
        if window_seconds <= 0:
            raise ValueError("Rate limit window must be positive")
        if max_modifications <= 0:
            raise ValueError("Max modifications must be positive")
        
        self.rate_limit_window = window_seconds
        self.max_modifications_per_window = max_modifications
        # Clear existing timestamps as the window has changed
        self.modification_timestamps.clear()
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get current rate limiting status."""
        current_time = time.time()
        cutoff_time = current_time - self.rate_limit_window
        
        # Count recent modifications
        recent_count = len([ts for ts in self.modification_timestamps if ts > cutoff_time])
        
        return {
            "window_seconds": self.rate_limit_window,
            "max_modifications": self.max_modifications_per_window,
            "recent_modifications": recent_count,
            "remaining_modifications": max(0, self.max_modifications_per_window - recent_count),
            "rate_limit_active": recent_count >= self.max_modifications_per_window
        }
    
    def bulk_add_blocked_senders(self, senders: List[str], skip_invalid: bool = True) -> Dict[str, Any]:
        """
        Add multiple senders to blocklist efficiently.
        
        Args:
            senders: List of sender email addresses
            skip_invalid: If True, skip invalid emails; if False, raise on first invalid
            
        Returns:
            Dict with results summary
        """
        results = {
            "added": 0,
            "skipped_invalid": 0,
            "skipped_existing": 0,
            "errors": []
        }
        
        for sender in senders:
            try:
                if self.add_blocked_sender(sender):
                    results["added"] += 1
                else:
                    results["skipped_existing"] += 1
            except ValueError as e:
                if skip_invalid:
                    results["skipped_invalid"] += 1
                    results["errors"].append(f"Invalid sender '{sender}': {str(e)}")
                else:
                    raise
        
        return results
    
    def bulk_add_blocked_ips(self, ips: List[str], skip_invalid: bool = True) -> Dict[str, Any]:
        """
        Add multiple IPs to blocklist efficiently.
        
        Args:
            ips: List of IP addresses or CIDR ranges
            skip_invalid: If True, skip invalid IPs; if False, raise on first invalid
            
        Returns:
            Dict with results summary
        """
        results = {
            "added": 0,
            "skipped_invalid": 0,
            "skipped_existing": 0,
            "errors": []
        }
        
        for ip in ips:
            try:
                if self.add_blocked_ip(ip):
                    results["added"] += 1
                else:
                    results["skipped_existing"] += 1
            except ValueError as e:
                if skip_invalid:
                    results["skipped_invalid"] += 1
                    results["errors"].append(f"Invalid IP '{ip}': {str(e)}")
                else:
                    raise
        
        return results
    
    def remove_blocked_sender(self, sender: str) -> bool:
        """
        Remove a sender from the blocklist.
        
        Args:
            sender: Email address to remove
            
        Returns:
            True if sender was removed, False if not found or invalid
        """
        if not sender or not sender.strip():
            return False  # Invalid input
        
        sender_normalized = sender.lower().strip()
        
        # Find and remove the sender (case insensitive)
        for blocked_sender in list(self.blocked_senders):
            if blocked_sender.lower().strip() == sender_normalized:
                self.blocked_senders.remove(blocked_sender)
                return True
        
        return False  # Not found
    
    def remove_blocked_ip(self, ip: str) -> bool:
        """
        Remove an IP address from the blocklist.
        
        Args:
            ip: IP address or CIDR range to remove
            
        Returns:
            True if IP was removed, False if not found or invalid
        """
        if not ip or not ip.strip():
            return False  # Invalid input
        
        ip_normalized = ip.strip()
        
        if ip_normalized in self.blocked_ips:
            self.blocked_ips.remove(ip_normalized)
            # Rebuild optimization structures
            self._rebuild_ip_structures()
            return True
        
        return False  # Not found
    
    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if an IP address is blocked.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is blocked, False otherwise
        """
        if not ip or not ip.strip():
            return False
        
        ip_normalized = ip.strip()
        
        # Check exact matches first
        if ip_normalized in self.blocked_ips:
            return True
        
        # Check if IP matches any CIDR ranges
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip_normalized)
            
            for blocked_ip in self.blocked_ips:
                if '/' in blocked_ip:  # CIDR range
                    try:
                        network = ipaddress.ip_network(blocked_ip, strict=False)
                        if ip_obj in network:
                            return True
                    except (ipaddress.AddressValueError, ValueError):
                        continue
        except (ipaddress.AddressValueError, ValueError):
            return False
        
        return False
    
    def is_sender_blocked(self, sender: str) -> bool:
        """
        Check if a sender email address is blocked.
        
        Args:
            sender: Email address to check
            
        Returns:
            True if sender is blocked, False otherwise
        """
        if not sender or not sender.strip():
            return False
        
        sender_normalized = sender.lower().strip()
        
        # Check if sender is in the blocked list (case insensitive)
        for blocked_sender in self.blocked_senders:
            if blocked_sender.lower().strip() == sender_normalized:
                return True
        
        return False
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Get performance statistics for the security policy.
        
        Returns:
            Dict with performance metrics
        """
        return {
            "total_blocked_senders": len(self.blocked_senders),
            "total_blocked_ips": len(self.blocked_ips),
            "exact_ips": len([ip for ip in self.blocked_ips if '/' not in ip]),
            "compiled_ipv4_networks": len([ip for ip in self.blocked_ips if '/' in ip and ':' not in ip]),
            "compiled_ipv6_networks": len([ip for ip in self.blocked_ips if '/' in ip and ':' in ip]),
            "rate_limit_window": self.rate_limit_window,
            "max_modifications_per_window": self.max_modifications_per_window,
            "recent_modifications": len([ts for ts in self.modification_timestamps 
                                       if time.time() - ts < self.rate_limit_window])
        }
    
    def validate_policy_integrity(self) -> Dict[str, Any]:
        """Validate the integrity of all policy data."""
        issues = []
        
        # Validate all blocked senders
        invalid_senders = []
        for sender in self.blocked_senders:
            if not self._validate_email_format(sender):
                invalid_senders.append(sender)
        
        # Validate all blocked IPs
        invalid_ips = []
        for ip in self.blocked_ips:
            is_valid, _ = self._validate_ip_format(ip)
            if not is_valid:
                invalid_ips.append(ip)
        
        # Check optimization structures consistency
        optimization_issues = []
        expected_networks = len([ip for ip in self.blocked_ips if '/' in ip])
        expected_exact = len([ip for ip in self.blocked_ips if '/' not in ip])
        actual_networks = len(self.compiled_ip_networks) + len(self.compiled_ipv6_networks)
        actual_exact = len(self.exact_ips)
        
        if expected_networks != actual_networks:
            optimization_issues.append(f"Network count mismatch: expected {expected_networks}, got {actual_networks}")
        
        if expected_exact != actual_exact:
            optimization_issues.append(f"Exact IP count mismatch: expected {expected_exact}, got {actual_exact}")
        
        return {
            "valid": len(invalid_senders) == 0 and len(invalid_ips) == 0 and len(optimization_issues) == 0,
            "invalid_senders": invalid_senders,
            "invalid_ips": invalid_ips,
            "optimization_issues": optimization_issues,
            "total_senders": len(self.blocked_senders),
            "total_ips": len(self.blocked_ips)
        }
    
    def show(self) -> None:
        """Display security policy status using built-in PrimAITE display patterns."""
        print(f"📋 Email Security Policy Status")
        print(f"   🚫 Blocked Senders: {len(self.blocked_senders)}")
        print(f"   🌐 Blocked IPs: {len(self.blocked_ips)}")
        print(f"   📊 Default Action: {self.default_action}")
        print(f"   📝 Logging Enabled: {self.enable_logging}")
        
        # Show performance metrics
        perf_stats = self.get_performance_stats()
        print(f"   ⚡ Performance Stats:")
        print(f"      • Exact IPs: {perf_stats['exact_ips']}")
        print(f"      • IPv4 Networks: {perf_stats['compiled_ipv4_networks']}")
        print(f"      • IPv6 Networks: {perf_stats['compiled_ipv6_networks']}")
        
        # Show recent modifications
        recent_mods = perf_stats['recent_modifications']
        print(f"   🔄 Recent Modifications: {recent_mods}")
        
        # Show sample blocked entries (first few)
        if self.blocked_senders:
            sample_senders = list(self.blocked_senders)[:3]
            print(f"   📧 Sample Blocked Senders: {', '.join(sample_senders)}")
        
        if self.blocked_ips:
            sample_ips = list(self.blocked_ips)[:3]
            print(f"   🌐 Sample Blocked IPs: {', '.join(sample_ips)}")