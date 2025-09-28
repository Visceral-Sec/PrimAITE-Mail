"""Unit tests for email security policy data models and core logic."""

import pytest
from datetime import datetime
from unittest.mock import patch

from primaite_mail.simulator.software.security_policy import (
    SecurityEvent,
    SecurityEventLog,
    EmailSecurityPolicy
)


class TestSecurityEvent:
    """Test SecurityEvent dataclass."""
    
    def test_security_event_creation(self):
        """Test basic SecurityEvent creation."""
        event = SecurityEvent(
            timestamp="2024-01-15T10:30:00Z",
            event_type="blocked_sender",
            reason="Sender blocked by policy",
            sender="malicious@attacker.com",
            ip_address="192.168.1.100"
        )
        
        assert event.timestamp == "2024-01-15T10:30:00Z"
        assert event.event_type == "blocked_sender"
        assert event.reason == "Sender blocked by policy"
        assert event.sender == "malicious@attacker.com"
        assert event.ip_address == "192.168.1.100"
        assert event.severity == "medium"  # default
        assert event.agent is None  # default
    
    def test_security_event_with_all_fields(self):
        """Test SecurityEvent with all fields specified."""
        event = SecurityEvent(
            timestamp="2024-01-15T10:30:00Z",
            event_type="policy_change",
            reason="Added sender block",
            sender="test@example.com",
            ip_address="10.0.0.1",
            agent="blue_agent_1",
            severity="high"
        )
        
        assert event.agent == "blue_agent_1"
        assert event.severity == "high"
    
    def test_invalid_event_type(self):
        """Test SecurityEvent with invalid event type."""
        with pytest.raises(ValueError, match="Invalid event_type"):
            SecurityEvent(
                timestamp="2024-01-15T10:30:00Z",
                event_type="invalid_type",
                reason="Test"
            )
    
    def test_invalid_severity(self):
        """Test SecurityEvent with invalid severity."""
        with pytest.raises(ValueError, match="Invalid severity"):
            SecurityEvent(
                timestamp="2024-01-15T10:30:00Z",
                event_type="blocked_sender",
                reason="Test",
                severity="invalid"
            )
    
    def test_valid_event_types(self):
        """Test all valid event types."""
        valid_types = ["blocked_sender", "blocked_ip", "policy_change", "connection_refused"]
        
        for event_type in valid_types:
            event = SecurityEvent(
                timestamp="2024-01-15T10:30:00Z",
                event_type=event_type,
                reason="Test"
            )
            assert event.event_type == event_type
    
    def test_valid_severities(self):
        """Test all valid severity levels."""
        valid_severities = ["low", "medium", "high"]
        
        for severity in valid_severities:
            event = SecurityEvent(
                timestamp="2024-01-15T10:30:00Z",
                event_type="blocked_sender",
                reason="Test",
                severity=severity
            )
            assert event.severity == severity
    
    def test_to_dict_conversion(self):
        """Test converting SecurityEvent to dictionary."""
        event = SecurityEvent(
            timestamp="2024-01-15T10:30:00Z",
            event_type="blocked_sender",
            reason="Test block",
            sender="test@example.com",
            ip_address="192.168.1.1",
            agent="blue_agent_1",
            severity="high",
            additional_data={"key": "value"}
        )
        
        event_dict = event.to_dict()
        
        assert event_dict["timestamp"] == "2024-01-15T10:30:00Z"
        assert event_dict["event_type"] == "blocked_sender"
        assert event_dict["reason"] == "Test block"
        assert event_dict["sender"] == "test@example.com"
        assert event_dict["ip_address"] == "192.168.1.1"
        assert event_dict["agent"] == "blue_agent_1"
        assert event_dict["severity"] == "high"
        assert event_dict["additional_data"] == {"key": "value"}
    
    def test_from_dict_creation(self):
        """Test creating SecurityEvent from dictionary."""
        event_data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_type": "blocked_ip",
            "reason": "IP blocked",
            "ip_address": "192.168.1.100",
            "severity": "medium"
        }
        
        event = SecurityEvent.from_dict(event_data)
        
        assert event.timestamp == "2024-01-15T10:30:00Z"
        assert event.event_type == "blocked_ip"
        assert event.reason == "IP blocked"
        assert event.ip_address == "192.168.1.100"
        assert event.severity == "medium"
        assert event.sender is None
        assert event.agent is None
    
    def test_matches_filter(self):
        """Test event filtering functionality."""
        event = SecurityEvent(
            timestamp="2024-01-15T10:30:00Z",
            event_type="blocked_sender",
            reason="Test block",
            sender="malicious@attacker.com",
            ip_address="192.168.1.100",
            agent="blue_agent_1",
            severity="high"
        )
        
        # Test exact matches
        assert event.matches_filter(event_type="blocked_sender")
        assert event.matches_filter(severity="high")
        assert event.matches_filter(sender="malicious@attacker.com")
        assert event.matches_filter(ip_address="192.168.1.100")
        assert event.matches_filter(agent="blue_agent_1")
        
        # Test partial matches
        assert event.matches_filter(sender="malicious")
        assert event.matches_filter(sender="attacker.com")
        assert event.matches_filter(ip_address="192.168.1")
        assert event.matches_filter(agent="blue_agent")
        
        # Test non-matches
        assert not event.matches_filter(event_type="blocked_ip")
        assert not event.matches_filter(severity="low")
        assert not event.matches_filter(sender="different@example.com")
        assert not event.matches_filter(ip_address="10.0.0.1")
        assert not event.matches_filter(agent="red_agent")
        
        # Test combined filters
        assert event.matches_filter(event_type="blocked_sender", severity="high")
        assert not event.matches_filter(event_type="blocked_sender", severity="low")
    
    def test_get_summary(self):
        """Test getting human-readable event summary."""
        event = SecurityEvent(
            timestamp="2024-01-15T10:30:00Z",
            event_type="blocked_sender",
            reason="Sender blocked by policy",
            sender="malicious@attacker.com",
            ip_address="192.168.1.100",
            agent="blue_agent_1",
            severity="high"
        )
        
        summary = event.get_summary()
        
        assert "[HIGH]" in summary
        assert "Blocked Sender" in summary
        assert "Sender: malicious@attacker.com" in summary
        assert "IP: 192.168.1.100" in summary
        assert "Agent: blue_agent_1" in summary
        assert "Sender blocked by policy" in summary
    
    def test_get_summary_minimal(self):
        """Test getting summary with minimal event data."""
        event = SecurityEvent(
            timestamp="2024-01-15T10:30:00Z",
            event_type="policy_change",
            reason="Policy updated",
            severity="low"
        )
        
        summary = event.get_summary()
        
        assert "[LOW]" in summary
        assert "Policy Change" in summary
        assert "Policy updated" in summary
        # Should not contain sender, IP, or agent info
        assert "Sender:" not in summary
        assert "IP:" not in summary
        assert "Agent:" not in summary


class TestSecurityEventLog:
    """Test SecurityEventLog class."""
    
    def test_empty_log_creation(self):
        """Test creating empty security event log."""
        log = SecurityEventLog()
        
        assert len(log.events) == 0
        assert log.max_events == 1000
        assert log.get_recent_events() == []
    
    def test_log_blocked_email(self):
        """Test logging blocked email event."""
        log = SecurityEventLog()
        
        with patch('primaite_mail.simulator.software.security_policy.datetime') as mock_datetime:
            mock_datetime.now.return_value.isoformat.return_value = "2024-01-15T10:30:00Z"
            
            log.log_blocked_email("malicious@attacker.com", "192.168.1.100", "Sender blocked")
        
        assert len(log.events) == 1
        event = log.events[0]
        assert event.event_type == "blocked_sender"
        assert event.sender == "malicious@attacker.com"
        assert event.ip_address == "192.168.1.100"
        assert event.reason == "Sender blocked"
        assert event.severity == "medium"
    
    def test_log_blocked_ip(self):
        """Test logging blocked IP event."""
        log = SecurityEventLog()
        
        with patch('primaite_mail.simulator.software.security_policy.datetime') as mock_datetime:
            mock_datetime.now.return_value.isoformat.return_value = "2024-01-15T10:30:00Z"
            
            log.log_blocked_ip("192.168.1.100", "IP blocked by policy")
        
        assert len(log.events) == 1
        event = log.events[0]
        assert event.event_type == "blocked_ip"
        assert event.ip_address == "192.168.1.100"
        assert event.reason == "IP blocked by policy"
        assert event.severity == "medium"
    
    def test_log_policy_change(self):
        """Test logging policy change event."""
        log = SecurityEventLog()
        
        with patch('primaite_mail.simulator.software.security_policy.datetime') as mock_datetime:
            mock_datetime.now.return_value.isoformat.return_value = "2024-01-15T10:30:00Z"
            
            log.log_policy_change("blue_agent_1", "add_sender_block", "malicious@attacker.com")
        
        assert len(log.events) == 1
        event = log.events[0]
        assert event.event_type == "policy_change"
        assert event.agent == "blue_agent_1"
        assert event.reason == "Policy add_sender_block: malicious@attacker.com"
        assert event.severity == "low"
    
    def test_rolling_log_management(self):
        """Test rolling log size management."""
        log = SecurityEventLog(max_events=3)
        
        # Add more events than max_events
        for i in range(5):
            log.log_blocked_ip(f"192.168.1.{i}", f"Test event {i}")
        
        # Should only keep the last 3 events
        assert len(log.events) == 3
        assert log.events[0].ip_address == "192.168.1.2"
        assert log.events[1].ip_address == "192.168.1.3"
        assert log.events[2].ip_address == "192.168.1.4"
    
    def test_get_recent_events_with_limit(self):
        """Test getting recent events with limit."""
        log = SecurityEventLog()
        
        # Add 5 events
        for i in range(5):
            log.log_blocked_ip(f"192.168.1.{i}", f"Test event {i}")
        
        # Get last 3 events
        recent = log.get_recent_events(3)
        assert len(recent) == 3
        assert recent[0].ip_address == "192.168.1.2"
        assert recent[1].ip_address == "192.168.1.3"
        assert recent[2].ip_address == "192.168.1.4"
    
    def test_get_recent_events_no_limit(self):
        """Test getting all events when limit is 0."""
        log = SecurityEventLog()
        
        for i in range(3):
            log.log_blocked_ip(f"192.168.1.{i}", f"Test event {i}")
        
        all_events = log.get_recent_events(0)
        assert len(all_events) == 3
    
    def test_get_statistics_empty_log(self):
        """Test statistics for empty log."""
        log = SecurityEventLog()
        stats = log.get_statistics()
        
        expected = {
            "total_events": 0,
            "blocked_senders": 0,
            "blocked_ips": 0,
            "policy_changes": 0,
            "events_by_severity": {"low": 0, "medium": 0, "high": 0}
        }
        assert stats == expected
    
    def test_get_statistics_with_events(self):
        """Test statistics with various event types."""
        log = SecurityEventLog()
        
        # Add different types of events
        log.log_blocked_email("test1@example.com", "192.168.1.1", "Blocked sender")
        log.log_blocked_email("test2@example.com", "192.168.1.2", "Blocked sender")
        log.log_blocked_ip("192.168.1.100", "Blocked IP")
        log.log_policy_change("blue_agent_1", "add_rule", "test@example.com")
        
        stats = log.get_statistics()
        
        assert stats["total_events"] == 4
        assert stats["blocked_senders"] == 2
        assert stats["blocked_ips"] == 1
        assert stats["policy_changes"] == 1
        assert stats["events_by_severity"]["medium"] == 3  # blocked events
        assert stats["events_by_severity"]["low"] == 1     # policy change
    
    def test_get_events_by_type(self):
        """Test filtering events by type."""
        log = SecurityEventLog()
        
        # Add different types of events
        log.log_blocked_email("test1@example.com", "192.168.1.1", "Blocked sender")
        log.log_blocked_email("test2@example.com", "192.168.1.2", "Blocked sender")
        log.log_blocked_ip("192.168.1.100", "Blocked IP")
        log.log_policy_change("blue_agent_1", "add_rule", "test@example.com")
        
        # Test filtering by event type
        sender_events = log.get_events_by_type("blocked_sender")
        assert len(sender_events) == 2
        assert all(event.event_type == "blocked_sender" for event in sender_events)
        
        ip_events = log.get_events_by_type("blocked_ip")
        assert len(ip_events) == 1
        assert ip_events[0].event_type == "blocked_ip"
        
        policy_events = log.get_events_by_type("policy_change")
        assert len(policy_events) == 1
        assert policy_events[0].event_type == "policy_change"
        
        # Test non-existent type
        nonexistent = log.get_events_by_type("nonexistent_type")
        assert len(nonexistent) == 0
    
    def test_get_events_by_type_with_limit(self):
        """Test filtering events by type with limit."""
        log = SecurityEventLog()
        
        # Add multiple events of same type
        for i in range(5):
            log.log_blocked_email(f"test{i}@example.com", f"192.168.1.{i}", "Blocked sender")
        
        # Test with limit
        events = log.get_events_by_type("blocked_sender", limit=3)
        assert len(events) == 3
        # Should get the most recent 3 events
        assert events[0].sender == "test2@example.com"
        assert events[1].sender == "test3@example.com"
        assert events[2].sender == "test4@example.com"
    
    def test_get_events_by_time_range_basic(self):
        """Test basic time range filtering functionality."""
        log = SecurityEventLog()
        
        # Add some events
        log.log_blocked_email("test1@example.com", "192.168.1.1", "Test event 1")
        log.log_blocked_email("test2@example.com", "192.168.1.2", "Test event 2")
        
        # Test with very large time range (should get all events)
        all_events = log.get_events_by_time_range(24.0)  # Last 24 hours
        assert len(all_events) == 2
        
        # Test with zero time range (should fallback to recent events)
        zero_events = log.get_events_by_time_range(0.0)
        assert len(zero_events) == 2
        
        # Test with negative time range (should fallback to recent events)
        negative_events = log.get_events_by_time_range(-1.0)
        assert len(negative_events) == 2
    
    def test_get_events_by_time_range_invalid_input(self):
        """Test time range filtering with invalid input."""
        log = SecurityEventLog()
        
        # Add some events
        log.log_blocked_email("test@example.com", "192.168.1.1", "Test event")
        
        # Test with invalid time range (should fallback to recent events)
        events = log.get_events_by_time_range(-1.0)  # Negative hours
        assert len(events) == 1  # Should return recent events
        
        events = log.get_events_by_time_range(0.0)  # Zero hours
        assert len(events) == 1  # Should return recent events
    
    def test_get_filtered_events_combined(self):
        """Test combined filtering by type and time range."""
        log = SecurityEventLog()
        
        # Add different types of events
        log.log_blocked_email("sender1@example.com", "192.168.1.1", "Sender block 1")
        log.log_blocked_email("sender2@example.com", "192.168.1.2", "Sender block 2")
        log.log_blocked_ip("192.168.1.100", "IP block")
        log.log_policy_change("blue_agent_1", "add_rule", "test@example.com")
        
        # Test filtering by event type only
        sender_events = log.get_filtered_events(event_type="blocked_sender")
        assert len(sender_events) == 2
        assert all(event.event_type == "blocked_sender" for event in sender_events)
        
        ip_events = log.get_filtered_events(event_type="blocked_ip")
        assert len(ip_events) == 1
        assert ip_events[0].event_type == "blocked_ip"
        
        # Test with limit
        limited_events = log.get_filtered_events(event_type="blocked_sender", limit=1)
        assert len(limited_events) == 1
        assert limited_events[0].sender == "sender2@example.com"  # Most recent
        
        # Test with no filters (should return all events)
        all_events = log.get_filtered_events()
        assert len(all_events) == 4
    
    def test_get_detailed_statistics(self):
        """Test detailed statistics functionality."""
        log = SecurityEventLog()
        
        # Add various events
        log.log_blocked_email("sender1@example.com", "192.168.1.1", "Blocked sender")
        log.log_blocked_email("sender2@example.com", "192.168.1.2", "Blocked sender")
        log.log_blocked_email("sender1@example.com", "192.168.1.3", "Blocked sender again")  # Duplicate sender
        log.log_blocked_ip("192.168.1.100", "Blocked IP")
        log.log_blocked_ip("192.168.1.101", "Blocked IP")
        log.log_blocked_ip("192.168.1.100", "Blocked IP again")  # Duplicate IP
        log.log_policy_change("blue_agent_1", "add_rule", "test@example.com")
        log.log_policy_change("blue_agent_2", "remove_rule", "old@example.com")
        
        stats = log.get_detailed_statistics()
        
        # Check basic counts
        assert stats["total_events"] == 8
        assert stats["blocked_senders"] == 3
        assert stats["blocked_ips"] == 3
        assert stats["policy_changes"] == 2
        
        # Check unique counts
        assert stats["unique_senders_count"] == 2  # sender1 and sender2
        assert stats["unique_ips_count"] == 5      # 192.168.1.1, 192.168.1.2, 192.168.1.3 (from sender blocks), 192.168.1.100, 192.168.1.101 (from IP blocks)
        assert stats["agents_active_count"] == 2   # blue_agent_1 and blue_agent_2
        
        # Check events by type
        assert stats["events_by_type"]["blocked_sender"] == 3
        assert stats["events_by_type"]["blocked_ip"] == 3
        assert stats["events_by_type"]["policy_change"] == 2
        
        # Check severity distribution
        assert stats["events_by_severity"]["medium"] == 6  # blocked events
        assert stats["events_by_severity"]["low"] == 2     # policy changes
        assert stats["events_by_severity"]["high"] == 0
    
    def test_get_detailed_statistics_basic(self):
        """Test detailed statistics functionality."""
        log = SecurityEventLog()
        
        # Add various events
        log.log_blocked_email("sender1@example.com", "192.168.1.1", "Blocked sender")
        log.log_blocked_email("sender2@example.com", "192.168.1.2", "Blocked sender")
        log.log_blocked_ip("192.168.1.100", "Blocked IP")
        log.log_policy_change("blue_agent_1", "add_rule", "test@example.com")
        
        stats = log.get_detailed_statistics()
        
        # Check basic counts
        assert stats["total_events"] == 4
        assert stats["blocked_senders"] == 2
        assert stats["blocked_ips"] == 1
        assert stats["policy_changes"] == 1
        
        # Check unique counts
        assert stats["unique_senders_count"] == 2  # sender1@example.com, sender2@example.com
        assert stats["unique_ips_count"] == 3      # 192.168.1.1, 192.168.1.2 (from sender blocks), 192.168.1.100 (from IP block)
        assert stats["agents_active_count"] == 1   # blue_agent_1
        
        # Check events by type
        assert stats["events_by_type"]["blocked_sender"] == 2
        assert stats["events_by_type"]["blocked_ip"] == 1
        assert stats["events_by_type"]["policy_change"] == 1


class TestEmailSecurityPolicy:
    """Test EmailSecurityPolicy class."""
    
    def test_empty_policy_creation(self):
        """Test creating empty security policy."""
        policy = EmailSecurityPolicy()
        
        assert len(policy.blocked_senders) == 0
        assert len(policy.blocked_ips) == 0
        assert policy.enable_logging is True
        assert policy.default_action == "reject"
    
    def test_is_sender_blocked_empty_policy(self):
        """Test sender blocking check with empty policy."""
        policy = EmailSecurityPolicy()
        
        assert not policy.is_sender_blocked("test@example.com")
        assert not policy.is_sender_blocked("")
        assert not policy.is_sender_blocked(None)
    
    def test_is_sender_blocked_with_blocked_senders(self):
        """Test sender blocking check with blocked senders."""
        policy = EmailSecurityPolicy()
        policy.blocked_senders.add("malicious@attacker.com")
        policy.blocked_senders.add("spam@badactor.net")
        
        assert policy.is_sender_blocked("malicious@attacker.com")
        assert policy.is_sender_blocked("MALICIOUS@ATTACKER.COM")  # case insensitive
        assert policy.is_sender_blocked(" malicious@attacker.com ")  # whitespace handling
        assert policy.is_sender_blocked("spam@badactor.net")
        assert not policy.is_sender_blocked("legitimate@company.com")
        assert not policy.is_sender_blocked("")
    
    def test_add_blocked_sender_valid(self):
        """Test adding valid sender to blocklist."""
        policy = EmailSecurityPolicy()
        
        assert policy.add_blocked_sender("test@example.com")
        assert "test@example.com" in policy.blocked_senders
        
        # Test case normalization
        assert policy.add_blocked_sender("TEST@EXAMPLE.ORG")
        assert "test@example.org" in policy.blocked_senders
    
    def test_add_blocked_sender_invalid(self):
        """Test adding invalid sender to blocklist."""
        policy = EmailSecurityPolicy()
        
        # Invalid email formats
        assert not policy.add_blocked_sender("")
        assert not policy.add_blocked_sender("   ")
        assert not policy.add_blocked_sender("invalid-email")
        assert not policy.add_blocked_sender("no-at-symbol.com")
        assert not policy.add_blocked_sender("no-domain@")
        assert not policy.add_blocked_sender("@no-local-part.com")
        
        assert len(policy.blocked_senders) == 0
    
    def test_remove_blocked_sender(self):
        """Test removing sender from blocklist."""
        policy = EmailSecurityPolicy()
        policy.blocked_senders.add("test@example.com")
        policy.blocked_senders.add("other@example.org")
        
        assert policy.remove_blocked_sender("test@example.com")
        assert "test@example.com" not in policy.blocked_senders
        assert "other@example.org" in policy.blocked_senders
        
        # Test case insensitive removal
        policy.blocked_senders.add("Case@Example.Com")
        assert policy.remove_blocked_sender("case@example.com")
        assert len([s for s in policy.blocked_senders if s.lower() == "case@example.com"]) == 0
    
    def test_remove_blocked_sender_not_found(self):
        """Test removing sender that's not in blocklist."""
        policy = EmailSecurityPolicy()
        policy.blocked_senders.add("test@example.com")
        
        assert not policy.remove_blocked_sender("notfound@example.com")
        assert not policy.remove_blocked_sender("")
        assert "test@example.com" in policy.blocked_senders
    
    def test_is_ip_blocked_empty_policy(self):
        """Test IP blocking check with empty policy."""
        policy = EmailSecurityPolicy()
        
        assert not policy.is_ip_blocked("192.168.1.1")
        assert not policy.is_ip_blocked("")
        assert not policy.is_ip_blocked(None)
    
    def test_is_ip_blocked_exact_match(self):
        """Test IP blocking with exact IP matches."""
        policy = EmailSecurityPolicy()
        policy.blocked_ips.add("192.168.1.100")
        policy.blocked_ips.add("10.0.0.1")
        
        assert policy.is_ip_blocked("192.168.1.100")
        assert policy.is_ip_blocked("10.0.0.1")
        assert not policy.is_ip_blocked("192.168.1.101")
        assert not policy.is_ip_blocked("192.168.2.100")
    
    def test_is_ip_blocked_cidr_ranges(self):
        """Test IP blocking with CIDR ranges."""
        policy = EmailSecurityPolicy()
        policy.blocked_ips.add("192.168.1.0/24")
        policy.blocked_ips.add("10.0.0.0/8")
        
        # Test /24 range
        assert policy.is_ip_blocked("192.168.1.1")
        assert policy.is_ip_blocked("192.168.1.100")
        assert policy.is_ip_blocked("192.168.1.254")
        assert not policy.is_ip_blocked("192.168.2.1")
        
        # Test /8 range
        assert policy.is_ip_blocked("10.0.0.1")
        assert policy.is_ip_blocked("10.255.255.255")
        assert not policy.is_ip_blocked("11.0.0.1")
    
    def test_is_ip_blocked_invalid_ip(self):
        """Test IP blocking with invalid IP addresses."""
        policy = EmailSecurityPolicy()
        policy.blocked_ips.add("192.168.1.100")
        
        # Invalid IP formats should return False, not raise exceptions
        assert not policy.is_ip_blocked("invalid-ip")
        assert not policy.is_ip_blocked("999.999.999.999")
        assert not policy.is_ip_blocked("192.168.1")
        assert not policy.is_ip_blocked("192.168.1.1.1")
    
    def test_add_blocked_ip_valid(self):
        """Test adding valid IP addresses to blocklist."""
        policy = EmailSecurityPolicy()
        
        # Valid single IPs
        assert policy.add_blocked_ip("192.168.1.100")
        assert "192.168.1.100" in policy.blocked_ips
        
        assert policy.add_blocked_ip("10.0.0.1")
        assert "10.0.0.1" in policy.blocked_ips
        
        # Valid CIDR ranges
        assert policy.add_blocked_ip("192.168.1.0/24")
        assert "192.168.1.0/24" in policy.blocked_ips
        
        assert policy.add_blocked_ip("10.0.0.0/8")
        assert "10.0.0.0/8" in policy.blocked_ips
    
    def test_add_blocked_ip_invalid(self):
        """Test adding invalid IP addresses to blocklist."""
        policy = EmailSecurityPolicy()
        
        # Invalid formats
        assert not policy.add_blocked_ip("")
        assert not policy.add_blocked_ip("   ")
        assert not policy.add_blocked_ip("invalid-ip")
        assert not policy.add_blocked_ip("999.999.999.999")
        assert not policy.add_blocked_ip("192.168.1")
        assert not policy.add_blocked_ip("192.168.1.1.1")
        assert not policy.add_blocked_ip("192.168.1.0/99")  # Invalid CIDR
        
        assert len(policy.blocked_ips) == 0
    
    def test_remove_blocked_ip(self):
        """Test removing IP from blocklist."""
        policy = EmailSecurityPolicy()
        policy.blocked_ips.add("192.168.1.100")
        policy.blocked_ips.add("10.0.0.0/8")
        
        assert policy.remove_blocked_ip("192.168.1.100")
        assert "192.168.1.100" not in policy.blocked_ips
        assert "10.0.0.0/8" in policy.blocked_ips
        
        assert policy.remove_blocked_ip("10.0.0.0/8")
        assert "10.0.0.0/8" not in policy.blocked_ips
    
    def test_remove_blocked_ip_not_found(self):
        """Test removing IP that's not in blocklist."""
        policy = EmailSecurityPolicy()
        policy.blocked_ips.add("192.168.1.100")
        
        assert not policy.remove_blocked_ip("192.168.1.101")
        assert not policy.remove_blocked_ip("")
        assert "192.168.1.100" in policy.blocked_ips
    
    def test_get_policy_summary(self):
        """Test getting policy summary."""
        policy = EmailSecurityPolicy()
        policy.blocked_senders.add("malicious@attacker.com")
        policy.blocked_senders.add("spam@badactor.net")
        policy.blocked_ips.add("192.168.1.100")
        policy.blocked_ips.add("10.0.0.0/8")
        
        summary = policy.get_policy_summary()
        
        assert summary["blocked_senders_count"] == 2
        assert summary["blocked_ips_count"] == 2
        assert "malicious@attacker.com" in summary["blocked_senders"]
        assert "spam@badactor.net" in summary["blocked_senders"]
        assert "192.168.1.100" in summary["blocked_ips"]
        assert "10.0.0.0/8" in summary["blocked_ips"]
        assert summary["default_action"] == "reject"
        assert summary["logging_enabled"] is True
    
    def test_policy_with_custom_settings(self):
        """Test policy with custom configuration."""
        policy = EmailSecurityPolicy(
            enable_logging=False,
            default_action="quarantine"
        )
        
        summary = policy.get_policy_summary()
        assert summary["default_action"] == "quarantine"
        assert summary["logging_enabled"] is False


class TestSecurityEventLogAdvanced:
    """Advanced tests for SecurityEventLog functionality."""
    
    def test_log_rotation_configuration(self):
        """Test configuring log rotation settings."""
        log = SecurityEventLog()
        
        # Test valid configuration
        log.configure_rotation(max_events=500, auto_rotate=True, rotation_threshold=0.8)
        assert log.max_events == 500
        assert log.auto_rotate is True
        assert log.rotation_threshold == 0.8
        
        # Test invalid configurations
        with pytest.raises(ValueError, match="max_events must be at least 1"):
            log.configure_rotation(max_events=0)
        
        with pytest.raises(ValueError, match="rotation_threshold must be between 0.1 and 1.0"):
            log.configure_rotation(max_events=100, rotation_threshold=1.5)
        
        with pytest.raises(ValueError, match="rotation_threshold must be between 0.1 and 1.0"):
            log.configure_rotation(max_events=100, rotation_threshold=0.05)
    
    def test_log_rotation_with_configuration(self):
        """Test log rotation with custom configuration."""
        log = SecurityEventLog()
        log.configure_rotation(max_events=3, auto_rotate=True, rotation_threshold=0.8)
        
        # Add events up to threshold
        for i in range(5):
            log.log_blocked_ip(f"192.168.1.{i}", f"Test event {i}")
        
        # Should have rotated to keep only max_events
        assert len(log.events) == 3
        assert log.events[0].ip_address == "192.168.1.2"
        assert log.events[1].ip_address == "192.168.1.3"
        assert log.events[2].ip_address == "192.168.1.4"
    
    def test_alert_configuration(self):
        """Test configuring alert settings."""
        log = SecurityEventLog()
        
        # Test valid configuration
        log.configure_alerts(alert_threshold=5, time_window_hours=2.0)
        assert log.alert_threshold == 5
        assert log.alert_time_window_hours == 2.0
        
        # Test invalid configurations
        with pytest.raises(ValueError, match="alert_threshold must be at least 1"):
            log.configure_alerts(alert_threshold=0)
        
        with pytest.raises(ValueError, match="time_window_hours must be positive"):
            log.configure_alerts(alert_threshold=5, time_window_hours=0)
        
        with pytest.raises(ValueError, match="time_window_hours must be positive"):
            log.configure_alerts(alert_threshold=5, time_window_hours=-1.0)
    
    def test_alert_conditions_checking(self):
        """Test checking alert conditions based on high-severity events."""
        log = SecurityEventLog()
        log.configure_alerts(alert_threshold=3, time_window_hours=24.0)
        
        # Add some high severity events
        log.log_security_event("security_scan_detected", "Suspicious scanning activity", severity="high")
        log.log_security_event("authentication_failure", "Multiple failed logins", severity="high")
        log.log_security_event("policy_violation", "Unauthorized access attempt", severity="high")
        
        # Add some lower severity events
        log.log_blocked_email("test@example.com", "192.168.1.1", "Normal block", severity="medium")
        
        alert_status = log.check_alert_conditions()
        
        assert alert_status["alert_triggered"] is True
        assert alert_status["high_severity_count"] == 3
        assert alert_status["alert_threshold"] == 3
        assert len(alert_status["recent_high_severity_events"]) == 3
    
    def test_alert_conditions_no_alert(self):
        """Test alert conditions when threshold is not met."""
        log = SecurityEventLog()
        log.configure_alerts(alert_threshold=5, time_window_hours=24.0)
        
        # Add fewer high severity events than threshold
        log.log_security_event("security_scan_detected", "Minor scanning", severity="high")
        log.log_security_event("authentication_failure", "Single failed login", severity="high")
        
        alert_status = log.check_alert_conditions()
        
        assert alert_status["alert_triggered"] is False
        assert alert_status["high_severity_count"] == 2
        assert alert_status["alert_threshold"] == 5
    
    def test_audit_trail_generation(self):
        """Test generating audit trail for compliance."""
        log = SecurityEventLog()
        
        # Add various events
        log.log_blocked_email("malicious@attacker.com", "192.168.1.100", "Sender blocked")
        log.log_policy_change("blue_agent_1", "add_sender_block", "spam@example.com")
        log.log_security_event("authentication_failure", "Failed login attempt", severity="high", ip_address="192.168.1.200")
        
        audit_trail = log.get_audit_trail(limit=10)
        
        assert len(audit_trail) == 3
        
        # Check audit entry structure
        entry = audit_trail[0]
        assert "timestamp" in entry
        assert "event_id" in entry
        assert "event_type" in entry
        assert "severity" in entry
        assert "description" in entry
        assert "affected_entity" in entry
        assert "initiating_agent" in entry
        assert "additional_context" in entry
        
        # Check specific values
        assert entry["event_type"] == "blocked_sender"
        assert entry["affected_entity"] == "malicious@attacker.com"
        assert entry["initiating_agent"] == "system"
    
    def test_compliance_report_generation(self):
        """Test generating compliance reports."""
        log = SecurityEventLog()
        
        # Add various events for comprehensive report
        log.log_blocked_email("sender1@attacker.com", "192.168.1.1", "Blocked sender")
        log.log_blocked_email("sender2@attacker.com", "192.168.1.2", "Blocked sender")
        log.log_blocked_ip("192.168.1.100", "Blocked IP")
        log.log_connection_refused("192.168.1.101", "Connection refused", severity="high")
        log.log_policy_change("blue_agent_1", "add_rule", "new_rule")
        log.log_policy_change("blue_agent_2", "remove_rule", "old_rule")
        log.log_security_event("security_scan_detected", "Scanning detected", severity="high")
        
        report = log.get_compliance_report(time_range_hours=24.0)
        
        # Check report structure
        assert "report_period_hours" in report
        assert "total_events" in report
        assert "security_actions" in report
        assert "policy_management" in report
        assert "security_incidents" in report
        assert "severity_distribution" in report
        assert "unique_entities" in report
        
        # Check specific values
        assert report["total_events"] == 7
        assert report["security_actions"]["blocked_emails"] == 2
        assert report["security_actions"]["blocked_connections"] == 2  # blocked_ip + connection_refused
        assert report["policy_management"]["policy_changes"] == 2
        assert report["policy_management"]["agents_involved"] == 2
        assert report["security_incidents"]["high_severity_events"] == 2
        assert report["severity_distribution"]["high"] == 2
        assert report["severity_distribution"]["medium"] == 3  # blocked_sender (2) + blocked_ip (1)
        assert report["severity_distribution"]["low"] == 2   # policy changes (2)
    
    def test_clear_old_events(self):
        """Test clearing old events by time."""
        log = SecurityEventLog()
        
        # Add some events (they will have current timestamp)
        log.log_blocked_email("test1@example.com", "192.168.1.1", "Test 1")
        log.log_blocked_email("test2@example.com", "192.168.1.2", "Test 2")
        log.log_blocked_email("test3@example.com", "192.168.1.3", "Test 3")
        
        original_count = len(log.events)
        assert original_count == 3
        
        # Try to clear events older than 1 hour (should not remove any since they're current)
        removed_count = log.clear_old_events(hours=1.0)
        assert removed_count == 0
        assert len(log.events) == 3
        
        # Try to clear with invalid hours
        removed_count = log.clear_old_events(hours=0)
        assert removed_count == 0
        assert len(log.events) == 3
        
        removed_count = log.clear_old_events(hours=-1)
        assert removed_count == 0
        assert len(log.events) == 3
    
    def test_export_events_json_format(self):
        """Test exporting events in JSON format."""
        log = SecurityEventLog()
        
        log.log_blocked_email("test@example.com", "192.168.1.1", "Test block")
        log.log_policy_change("blue_agent_1", "add_rule", "test_rule")
        
        # Test JSON export
        json_export = log.export_events(format_type="json")
        
        import json
        parsed_data = json.loads(json_export)
        
        assert len(parsed_data) == 2
        assert parsed_data[0]["event_type"] == "blocked_sender"
        assert parsed_data[0]["sender"] == "test@example.com"
        assert parsed_data[1]["event_type"] == "policy_change"
        assert parsed_data[1]["agent"] == "blue_agent_1"
    
    def test_export_events_csv_format(self):
        """Test exporting events in CSV format."""
        log = SecurityEventLog()
        
        log.log_blocked_email("test@example.com", "192.168.1.1", "Test block")
        log.log_blocked_ip("192.168.1.100", "IP blocked")
        
        # Test CSV export
        csv_export = log.export_events(format_type="csv")
        
        lines = csv_export.strip().split('\n')
        assert len(lines) == 3  # Header + 2 data lines
        assert lines[0] == "timestamp,event_type,severity,sender,ip_address,agent,reason"
        assert "blocked_sender" in lines[1]
        assert "test@example.com" in lines[1]
        assert "blocked_ip" in lines[2]
        assert "192.168.1.100" in lines[2]
    
    def test_export_events_with_filters(self):
        """Test exporting events with filtering."""
        log = SecurityEventLog()
        
        log.log_blocked_email("sender1@example.com", "192.168.1.1", "Block 1")
        log.log_blocked_email("sender2@example.com", "192.168.1.2", "Block 2")
        log.log_blocked_ip("192.168.1.100", "IP block")
        log.log_policy_change("blue_agent_1", "add_rule", "rule")
        
        # Export only blocked_sender events
        filtered_export = log.export_events(
            format_type="dict",
            filters={"event_type": "blocked_sender"}
        )
        
        assert len(filtered_export) == 2
        assert all(event["event_type"] == "blocked_sender" for event in filtered_export)
    
    def test_export_events_invalid_format(self):
        """Test exporting events with invalid format."""
        log = SecurityEventLog()
        log.log_blocked_email("test@example.com", "192.168.1.1", "Test")
        
        with pytest.raises(ValueError, match="Unsupported format_type"):
            log.export_events(format_type="invalid_format")
    
    def test_get_events_by_severity_validation(self):
        """Test severity filtering with validation."""
        log = SecurityEventLog()
        
        log.log_security_event("suspicious_activity", "Test", severity="low")
        log.log_security_event("suspicious_activity", "Test", severity="medium")
        log.log_security_event("suspicious_activity", "Test", severity="high")
        
        # Valid severities
        low_events = log.get_events_by_severity("low")
        assert len(low_events) == 1
        assert low_events[0].severity == "low"
        
        medium_events = log.get_events_by_severity("medium")
        assert len(medium_events) == 1
        assert medium_events[0].severity == "medium"
        
        high_events = log.get_events_by_severity("high")
        assert len(high_events) == 1
        assert high_events[0].severity == "high"
        
        # Invalid severity
        with pytest.raises(ValueError, match="Invalid severity"):
            log.get_events_by_severity("invalid")
    
    def test_get_events_by_ip_range_cidr(self):
        """Test filtering events by IP range with CIDR notation."""
        log = SecurityEventLog()
        
        # Add events with various IP addresses
        log.log_blocked_ip("192.168.1.10", "IP block 1")
        log.log_blocked_ip("192.168.1.20", "IP block 2")
        log.log_blocked_ip("192.168.2.10", "IP block 3")
        log.log_blocked_ip("10.0.0.1", "IP block 4")
        
        # Test CIDR range filtering
        range_events = log.get_events_by_ip_range("192.168.1.0/24")
        assert len(range_events) == 2
        assert all("192.168.1." in event.ip_address for event in range_events)
        
        # Test single IP filtering
        single_ip_events = log.get_events_by_ip_range("192.168.1.10")
        assert len(single_ip_events) == 1
        assert single_ip_events[0].ip_address == "192.168.1.10"
        
        # Test partial IP matching
        partial_events = log.get_events_by_ip_range("192.168.1")
        assert len(partial_events) == 2
    
    def test_get_log_health_status_detailed(self):
        """Test detailed log health status reporting."""
        log = SecurityEventLog(max_events=10, rotation_threshold=0.8)
        
        # Add events to test different health states
        for i in range(7):  # 70% utilization
            log.log_blocked_ip(f"192.168.1.{i}", f"Test {i}")
        
        health = log.get_log_health_status()
        
        assert health["current_size"] == 7
        assert health["max_size"] == 10
        assert health["utilization_percent"] == 70.0
        assert health["auto_rotate_enabled"] is True
        assert health["rotation_threshold_percent"] == 80.0
        assert health["needs_rotation"] is False
        assert health["events_until_rotation"] == 3
        assert health["status"] == "healthy"
        
        # Add more events to trigger warning state
        for i in range(7, 9):  # 90% utilization
            log.log_blocked_ip(f"192.168.1.{i}", f"Test {i}")
        
        health = log.get_log_health_status()
        assert health["utilization_percent"] == 90.0
        assert health["status"] == "warning"
        
        # Add one more to trigger critical state
        log.log_blocked_ip("192.168.1.9", "Test 9")  # 100% utilization
        
        health = log.get_log_health_status()
        assert health["utilization_percent"] == 100.0
        assert health["status"] == "critical"


class TestSecurityPolicyIntegration:
    """Integration tests for security policy components."""
    
    def test_policy_and_logging_integration(self):
        """Test integration between policy and event logging."""
        policy = EmailSecurityPolicy()
        log = SecurityEventLog()
        
        # Add some policies
        policy.add_blocked_sender("malicious@attacker.com")
        policy.add_blocked_ip("192.168.1.100")
        
        # Simulate policy enforcement and logging
        if policy.is_sender_blocked("malicious@attacker.com"):
            log.log_blocked_email("malicious@attacker.com", "192.168.1.50", "Sender blocked by policy")
        
        if policy.is_ip_blocked("192.168.1.100"):
            log.log_blocked_ip("192.168.1.100", "IP blocked by policy")
        
        # Verify logging
        assert len(log.events) == 2
        stats = log.get_statistics()
        assert stats["blocked_senders"] == 1
        assert stats["blocked_ips"] == 1
    
    def test_complex_cidr_scenarios(self):
        """Test complex CIDR range scenarios."""
        policy = EmailSecurityPolicy()
        
        # Add overlapping ranges
        policy.add_blocked_ip("192.168.0.0/16")  # Larger range
        policy.add_blocked_ip("192.168.1.0/24")  # Smaller range within larger
        policy.add_blocked_ip("192.168.1.100")   # Specific IP within ranges
        
        # All should be blocked due to overlapping ranges
        assert policy.is_ip_blocked("192.168.1.50")   # In both ranges
        assert policy.is_ip_blocked("192.168.1.100")  # Exact match and in ranges
        assert policy.is_ip_blocked("192.168.2.1")    # Only in /16 range
        
        # Outside all ranges
        assert not policy.is_ip_blocked("192.169.1.1")
        assert not policy.is_ip_blocked("10.0.0.1")
    
    def test_comprehensive_logging_workflow(self):
        """Test comprehensive logging workflow with policy enforcement."""
        policy = EmailSecurityPolicy()
        log = SecurityEventLog(max_events=50, alert_threshold=3, alert_time_window_hours=1.0)
        
        # Simulate a security incident workflow
        
        # 1. Initial policy setup
        policy.add_blocked_sender("known_bad@attacker.com")
        policy.add_blocked_ip("192.168.100.0/24")
        log.log_policy_change("admin", "initial_setup", "Security policies configured")
        
        # 2. Normal blocking activity
        log.log_blocked_email("known_bad@attacker.com", "192.168.100.5", "Known malicious sender")
        log.log_blocked_ip("192.168.100.10", "IP in blocked range")
        
        # 3. Escalating security incident
        log.log_security_event("authentication_failure", "Multiple failed login attempts", 
                              severity="high", ip_address="192.168.100.20")
        log.log_security_event("security_scan_detected", "Port scanning detected", 
                              severity="high", ip_address="192.168.100.21")
        log.log_security_event("policy_violation", "Unauthorized access attempt", 
                              severity="high", ip_address="192.168.100.22")
        
        # 4. Blue agent response
        policy.add_blocked_ip("192.168.100.20")
        policy.add_blocked_ip("192.168.100.21")
        policy.add_blocked_ip("192.168.100.22")
        log.log_policy_change("blue_agent_1", "emergency_block", "Blocked attacking IPs")
        
        # Verify comprehensive logging
        assert len(log.events) == 7  # 2 policy changes + 2 blocking events + 3 security incidents
        
        # Check alert conditions
        alert_status = log.check_alert_conditions()
        assert alert_status["alert_triggered"] is True
        assert alert_status["high_severity_count"] == 3
        
        # Generate compliance report
        report = log.get_compliance_report()
        assert report["total_events"] == 7
        assert report["security_incidents"]["high_severity_events"] == 3
        assert report["policy_management"]["policy_changes"] == 2
        assert report["security_actions"]["blocked_emails"] == 1
        assert report["security_actions"]["blocked_connections"] == 1
        
        # Test audit trail
        audit_trail = log.get_audit_trail()
        assert len(audit_trail) == 7
        
        # Verify all events are properly categorized
        event_types = [event.event_type for event in log.events]
        assert "policy_change" in event_types
        assert "blocked_sender" in event_types
        assert "blocked_ip" in event_types
        assert "authentication_failure" in event_types
        assert "security_scan_detected" in event_types
        assert "policy_violation" in event_types