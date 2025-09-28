"""Unit tests for SMTP server security policy methods."""

import pytest
from unittest.mock import Mock

from primaite_mail.simulator.software.security_policy import EmailSecurityPolicy, SecurityEventLog


class TestSMTPSecurityMethods:
    """Test SMTP server security policy methods in isolation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.security_policy = EmailSecurityPolicy()
        self.security_log = SecurityEventLog()

    def test_ip_blocking_basic(self):
        """Test basic IP blocking functionality."""
        # Add IP to blocklist
        blocked_ip = "192.168.1.100"
        result = self.security_policy.add_blocked_ip(blocked_ip)
        assert result is True
        
        # Test blocking check
        is_blocked = self.security_policy.is_ip_blocked(blocked_ip)
        assert is_blocked is True
        
        # Test non-blocked IP
        allowed_ip = "192.168.1.200"
        is_blocked = self.security_policy.is_ip_blocked(allowed_ip)
        assert is_blocked is False

    def test_sender_blocking_basic(self):
        """Test basic sender blocking functionality."""
        # Add sender to blocklist
        blocked_sender = "malicious@attacker.com"
        result = self.security_policy.add_blocked_sender(blocked_sender)
        assert result is True
        
        # Test blocking check
        is_blocked = self.security_policy.is_sender_blocked(blocked_sender)
        assert is_blocked is True
        
        # Test non-blocked sender
        allowed_sender = "legitimate@company.com"
        is_blocked = self.security_policy.is_sender_blocked(allowed_sender)
        assert is_blocked is False

    def test_cidr_range_blocking(self):
        """Test CIDR range blocking functionality."""
        # Add CIDR range to blocklist
        cidr_range = "192.168.1.0/24"
        result = self.security_policy.add_blocked_ip(cidr_range)
        assert result is True
        
        # Test IPs within the range
        blocked_ips = ["192.168.1.1", "192.168.1.100", "192.168.1.255"]
        for ip in blocked_ips:
            is_blocked = self.security_policy.is_ip_blocked(ip)
            assert is_blocked is True, f"IP {ip} should be blocked by CIDR range {cidr_range}"
        
        # Test IPs outside the range
        allowed_ips = ["192.168.2.1", "10.0.0.1", "172.16.0.1"]
        for ip in allowed_ips:
            is_blocked = self.security_policy.is_ip_blocked(ip)
            assert is_blocked is False, f"IP {ip} should not be blocked by CIDR range {cidr_range}"

    def test_case_insensitive_email_blocking(self):
        """Test that email blocking is case-insensitive."""
        # Add lowercase email to blocklist
        self.security_policy.add_blocked_sender("spam@evil.com")
        
        # Test various case combinations
        test_cases = [
            "spam@evil.com",
            "SPAM@EVIL.COM", 
            "Spam@Evil.Com",
            "SPAM@evil.com",
            "spam@EVIL.COM"
        ]
        
        for email in test_cases:
            is_blocked = self.security_policy.is_sender_blocked(email)
            assert is_blocked is True, f"Email {email} should be blocked (case-insensitive)"

    def test_invalid_email_format_handling(self):
        """Test handling of invalid email formats."""
        # Try to add invalid email formats
        invalid_emails = ["notanemail", "@domain.com", "user@", "user@domain", ""]
        
        for invalid_email in invalid_emails:
            result = self.security_policy.add_blocked_sender(invalid_email)
            assert result is False, f"Invalid email {invalid_email} should not be added"
        
        # Verify no invalid emails were added
        assert len(self.security_policy.blocked_senders) == 0

    def test_invalid_ip_format_handling(self):
        """Test handling of invalid IP formats."""
        # Try to add invalid IP formats
        invalid_ips = ["not.an.ip", "999.999.999.999", "192.168.1", "192.168.1.1/99", ""]
        
        for invalid_ip in invalid_ips:
            result = self.security_policy.add_blocked_ip(invalid_ip)
            assert result is False, f"Invalid IP {invalid_ip} should not be added"
        
        # Verify no invalid IPs were added
        assert len(self.security_policy.blocked_ips) == 0

    def test_security_event_logging(self):
        """Test security event logging functionality."""
        # Test sender blocking logging
        sender = "attacker@evil.com"
        ip = "192.168.1.100"
        reason = "Sender blocked by policy"
        
        self.security_log.log_blocked_email(sender, ip, reason)
        
        # Verify event was logged
        events = self.security_log.get_recent_events()
        assert len(events) == 1
        
        event = events[0]
        assert event.event_type == "blocked_sender"
        assert event.sender == sender
        assert event.ip_address == ip
        assert event.reason == reason
        assert event.severity == "medium"

    def test_security_log_statistics(self):
        """Test security log statistics functionality."""
        # Add various events
        self.security_log.log_blocked_email("spam@evil.com", "192.168.1.100", "Sender blocked")
        self.security_log.log_blocked_ip("192.168.1.101", "IP blocked")
        self.security_log.log_policy_change("blue_agent", "add_blocked_sender", "malware@virus.com")
        
        # Get statistics
        stats = self.security_log.get_statistics()
        
        assert stats["total_events"] == 3
        assert stats["blocked_senders"] == 1
        assert stats["blocked_ips"] == 1
        assert stats["policy_changes"] == 1
        assert stats["events_by_severity"]["medium"] == 2
        assert stats["events_by_severity"]["low"] == 1

    def test_policy_summary(self):
        """Test security policy summary functionality."""
        # Add some policies
        self.security_policy.add_blocked_sender("spam@evil.com")
        self.security_policy.add_blocked_sender("phishing@fake.net")
        self.security_policy.add_blocked_ip("192.168.1.100")
        self.security_policy.add_blocked_ip("10.0.0.0/8")
        
        # Get summary
        summary = self.security_policy.get_policy_summary()
        
        assert summary["blocked_senders_count"] == 2
        assert summary["blocked_ips_count"] == 2
        assert "spam@evil.com" in summary["blocked_senders"]
        assert "phishing@fake.net" in summary["blocked_senders"]
        assert "192.168.1.100" in summary["blocked_ips"]
        assert "10.0.0.0/8" in summary["blocked_ips"]
        assert summary["default_action"] == "reject"
        assert summary["logging_enabled"] is True

    def test_remove_blocked_sender(self):
        """Test removing blocked senders."""
        # Add sender
        sender = "spam@evil.com"
        self.security_policy.add_blocked_sender(sender)
        assert self.security_policy.is_sender_blocked(sender) is True
        
        # Remove sender
        result = self.security_policy.remove_blocked_sender(sender)
        assert result is True
        assert self.security_policy.is_sender_blocked(sender) is False
        
        # Try to remove non-existent sender
        result = self.security_policy.remove_blocked_sender("nonexistent@test.com")
        assert result is False

    def test_remove_blocked_ip(self):
        """Test removing blocked IPs."""
        # Add IP
        ip = "192.168.1.100"
        self.security_policy.add_blocked_ip(ip)
        assert self.security_policy.is_ip_blocked(ip) is True
        
        # Remove IP
        result = self.security_policy.remove_blocked_ip(ip)
        assert result is True
        assert self.security_policy.is_ip_blocked(ip) is False
        
        # Try to remove non-existent IP
        result = self.security_policy.remove_blocked_ip("10.0.0.1")
        assert result is False

    def test_empty_and_none_values_handling(self):
        """Test handling of empty and None values."""
        # Test with None values
        assert self.security_policy.is_ip_blocked(None) is False
        assert self.security_policy.is_sender_blocked(None) is False
        
        # Test with empty strings
        assert self.security_policy.is_ip_blocked("") is False
        assert self.security_policy.is_sender_blocked("") is False
        
        # Test adding None/empty values
        assert self.security_policy.add_blocked_ip(None) is False
        assert self.security_policy.add_blocked_ip("") is False
        assert self.security_policy.add_blocked_sender(None) is False
        assert self.security_policy.add_blocked_sender("") is False

    def test_rolling_log_management(self):
        """Test that security log maintains rolling window."""
        # Set small max_events for testing
        self.security_log.max_events = 3
        
        # Add more events than max
        for i in range(5):
            self.security_log.log_blocked_email(f"spam{i}@evil.com", "192.168.1.100", f"Event {i}")
        
        # Verify only max_events are kept
        events = self.security_log.get_recent_events()
        assert len(events) == 3
        
        # Verify it's the most recent events
        assert events[0].sender == "spam2@evil.com"  # First kept event
        assert events[2].sender == "spam4@evil.com"  # Last event