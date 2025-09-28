"""Integration tests for SMTP server security policy enforcement methods."""

import pytest
from unittest.mock import Mock

from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.security_policy import EmailSecurityPolicy, SecurityEventLog
from primaite_mail.simulator.network.protocols.smtp import SMTPCommand, SMTPPacket, SMTPStatusCode, EmailMessage


class TestSMTPSecurityPolicyEnforcement:
    """Test SMTP server security policy enforcement methods."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create a mock SMTP server with just the security methods we need to test
        self.smtp_server = Mock(spec=SMTPServer)
        
        # Set up the security policy components
        self.smtp_server.security_policy = EmailSecurityPolicy()
        self.smtp_server.security_log = SecurityEventLog()
        
        # Mock sys_log
        self.smtp_server.sys_log = Mock()
        self.smtp_server.sys_log.hostname = "test-server"
        self.smtp_server.sys_log.info = Mock()
        self.smtp_server.sys_log.warning = Mock()
        self.smtp_server.sys_log.error = Mock()
        self.smtp_server.sys_log.debug = Mock()
        self.smtp_server.sys_log.get_current_time = Mock(return_value="2024-01-01T12:00:00Z")
        
        # Mock other required attributes
        self.smtp_server.name = "smtp-server"
        
        # Add the actual security methods to the mock
        self.smtp_server._check_security_policies = SMTPServer._check_security_policies.__get__(self.smtp_server)
        self.smtp_server._enforce_ip_blocking = SMTPServer._enforce_ip_blocking.__get__(self.smtp_server)
        self.smtp_server._enforce_sender_blocking = SMTPServer._enforce_sender_blocking.__get__(self.smtp_server)

    def test_ip_blocking_at_connection_level(self):
        """Test that blocked IPs are refused at connection level."""
        # Add IP to blocklist
        blocked_ip = "192.168.1.100"
        self.smtp_server.security_policy.add_blocked_ip(blocked_ip)
        
        # Test connection from blocked IP
        result = self.smtp_server._enforce_ip_blocking(blocked_ip)
        assert result is False
        
        # Verify logging
        self.smtp_server.sys_log.warning.assert_called()
        
        # Test connection from allowed IP
        allowed_ip = "192.168.1.200"
        result = self.smtp_server._enforce_ip_blocking(allowed_ip)
        assert result is True

    def test_sender_blocking_during_mail_from(self):
        """Test that blocked senders are rejected during MAIL FROM."""
        # Add sender to blocklist
        blocked_sender = "malicious@attacker.com"
        self.smtp_server.security_policy.add_blocked_sender(blocked_sender)
        
        # Test MAIL FROM with blocked sender
        result = self.smtp_server._enforce_sender_blocking(blocked_sender, "192.168.1.50")
        assert result is False
        
        # Verify logging
        self.smtp_server.sys_log.warning.assert_called()
        
        # Test MAIL FROM with allowed sender
        allowed_sender = "legitimate@company.com"
        result = self.smtp_server._enforce_sender_blocking(allowed_sender, "192.168.1.50")
        assert result is True

    def test_cidr_range_blocking(self):
        """Test that CIDR ranges are properly blocked."""
        # Add CIDR range to blocklist
        cidr_range = "192.168.1.0/24"
        self.smtp_server.security_policy.add_blocked_ip(cidr_range)
        
        # Test IPs within the range
        blocked_ips = ["192.168.1.1", "192.168.1.100", "192.168.1.255"]
        for ip in blocked_ips:
            result = self.smtp_server._enforce_ip_blocking(ip)
            assert result is False, f"IP {ip} should be blocked by CIDR range {cidr_range}"
        
        # Test IPs outside the range
        allowed_ips = ["192.168.2.1", "10.0.0.1", "172.16.0.1"]
        for ip in allowed_ips:
            result = self.smtp_server._enforce_ip_blocking(ip)
            assert result is True, f"IP {ip} should not be blocked by CIDR range {cidr_range}"

    def test_smtp_security_method_integration(self):
        """Test integration of security methods with SMTP server logic."""
        # Add policies
        blocked_sender = "spam@badactor.net"
        blocked_ip = "10.0.0.100"
        
        self.smtp_server.security_policy.add_blocked_sender(blocked_sender)
        self.smtp_server.security_policy.add_blocked_ip(blocked_ip)
        
        # Test _enforce_sender_blocking method
        result = self.smtp_server._enforce_sender_blocking(blocked_sender, "192.168.1.50")
        assert result is False
        
        result = self.smtp_server._enforce_sender_blocking("user@company.com", "192.168.1.50")
        assert result is True
        
        # Test _enforce_ip_blocking method
        result = self.smtp_server._enforce_ip_blocking(blocked_ip)
        assert result is False
        
        result = self.smtp_server._enforce_ip_blocking("192.168.1.50")
        assert result is True

    def test_security_policy_integration(self):
        """Test integration of security policies with SMTP server methods."""
        # Add policies
        self.smtp_server.security_policy.add_blocked_sender("spam@evil.com")
        self.smtp_server.security_policy.add_blocked_ip("192.168.1.100")
        
        # Test _check_security_policies method
        is_allowed, reason = self.smtp_server._check_security_policies("spam@evil.com", "192.168.1.50")
        assert is_allowed is False
        assert "sender address blocked" in reason.lower()
        
        is_allowed, reason = self.smtp_server._check_security_policies("user@company.com", "192.168.1.100")
        assert is_allowed is False
        assert "ip address blocked" in reason.lower()
        
        is_allowed, reason = self.smtp_server._check_security_policies("user@company.com", "192.168.1.50")
        assert is_allowed is True
        assert reason == ""

    def test_security_event_logging(self):
        """Test that security events are properly logged."""
        # Add policies
        blocked_sender = "attacker@evil.com"
        blocked_ip = "192.168.1.100"
        
        self.smtp_server.security_policy.add_blocked_sender(blocked_sender)
        self.smtp_server.security_policy.add_blocked_ip(blocked_ip)
        
        # Test sender blocking logging
        self.smtp_server._enforce_sender_blocking(blocked_sender, "192.168.1.50")
        
        # Verify event was logged
        events = self.smtp_server.security_log.get_recent_events()
        assert len(events) > 0
        
        sender_events = [e for e in events if e.event_type == "blocked_sender"]
        assert len(sender_events) > 0
        assert sender_events[0].sender == blocked_sender
        
        # Test IP blocking logging
        self.smtp_server._enforce_ip_blocking(blocked_ip)
        
        # Verify IP event was logged (connection_refused for IP blocking)
        events = self.smtp_server.security_log.get_recent_events()
        ip_events = [e for e in events if e.event_type == "connection_refused"]
        assert len(ip_events) > 0
        assert ip_events[0].ip_address == blocked_ip

    def test_check_security_policies_method(self):
        """Test the comprehensive security policy checking method."""
        # Add policies
        blocked_sender = "malware@virus.com"
        blocked_ip = "192.168.1.100"
        
        self.smtp_server.security_policy.add_blocked_sender(blocked_sender)
        self.smtp_server.security_policy.add_blocked_ip(blocked_ip)
        
        # Test blocked sender
        is_allowed, reason = self.smtp_server._check_security_policies(blocked_sender, "192.168.1.50")
        assert is_allowed is False
        assert "sender address blocked" in reason.lower()
        
        # Test blocked IP
        is_allowed, reason = self.smtp_server._check_security_policies("user@company.com", blocked_ip)
        assert is_allowed is False
        assert "ip address blocked" in reason.lower()
        
        # Test allowed combination
        is_allowed, reason = self.smtp_server._check_security_policies("user@company.com", "192.168.1.50")
        assert is_allowed is True
        assert reason == ""

    def test_comprehensive_security_check(self):
        """Test comprehensive security checking with multiple policies."""
        # Add multiple policies
        self.smtp_server.security_policy.add_blocked_sender("phishing@scam.com")
        self.smtp_server.security_policy.add_blocked_sender("malware@virus.net")
        self.smtp_server.security_policy.add_blocked_ip("192.168.1.100")
        self.smtp_server.security_policy.add_blocked_ip("10.0.0.0/8")
        
        # Test various combinations
        test_cases = [
            ("phishing@scam.com", "192.168.1.50", False, "sender"),
            ("user@company.com", "192.168.1.100", False, "ip"),
            ("malware@virus.net", "10.0.0.50", False, "sender"),  # Both blocked, sender checked first
            ("user@company.com", "192.168.1.50", True, ""),
        ]
        
        for sender, ip, expected_allowed, expected_reason_type in test_cases:
            is_allowed, reason = self.smtp_server._check_security_policies(sender, ip)
            assert is_allowed == expected_allowed, f"Failed for {sender}@{ip}"
            
            if not expected_allowed:
                assert expected_reason_type in reason.lower(), f"Wrong reason type for {sender}@{ip}: {reason}"

    def test_invalid_email_format_handling(self):
        """Test handling of invalid email formats in security policies."""
        # Try to add invalid email formats
        invalid_emails = ["notanemail", "@domain.com", "user@", "user@domain", ""]
        
        for invalid_email in invalid_emails:
            result = self.smtp_server.security_policy.add_blocked_sender(invalid_email)
            assert result is False, f"Invalid email {invalid_email} should not be added"
        
        # Verify no invalid emails were added
        assert len(self.smtp_server.security_policy.blocked_senders) == 0

    def test_invalid_ip_format_handling(self):
        """Test handling of invalid IP formats in security policies."""
        # Try to add invalid IP formats
        invalid_ips = ["not.an.ip", "999.999.999.999", "192.168.1", "192.168.1.1/99", ""]
        
        for invalid_ip in invalid_ips:
            result = self.smtp_server.security_policy.add_blocked_ip(invalid_ip)
            assert result is False, f"Invalid IP {invalid_ip} should not be added"
        
        # Verify no invalid IPs were added
        assert len(self.smtp_server.security_policy.blocked_ips) == 0

    def test_case_insensitive_email_blocking(self):
        """Test that email blocking is case-insensitive."""
        # Add lowercase email to blocklist
        self.smtp_server.security_policy.add_blocked_sender("spam@evil.com")
        
        # Test various case combinations
        test_cases = [
            "spam@evil.com",
            "SPAM@EVIL.COM", 
            "Spam@Evil.Com",
            "SPAM@evil.com",
            "spam@EVIL.COM"
        ]
        
        for email in test_cases:
            is_blocked = self.smtp_server.security_policy.is_sender_blocked(email)
            assert is_blocked is True, f"Email {email} should be blocked (case-insensitive)"

    def test_empty_and_none_values_handling(self):
        """Test handling of empty and None values in security checks."""
        # Test with None values
        assert self.smtp_server._enforce_ip_blocking(None) is True
        assert self.smtp_server._enforce_sender_blocking(None, "192.168.1.1") is True
        
        # Test with empty strings
        assert self.smtp_server._enforce_ip_blocking("") is True
        assert self.smtp_server._enforce_sender_blocking("", "192.168.1.1") is True
        
        # Test check_security_policies with None/empty values
        is_allowed, reason = self.smtp_server._check_security_policies(None, None)
        assert is_allowed is True
        
        is_allowed, reason = self.smtp_server._check_security_policies("", "")
        assert is_allowed is True