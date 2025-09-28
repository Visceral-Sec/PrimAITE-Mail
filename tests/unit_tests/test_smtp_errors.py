"""Unit tests for SMTP error code generation and security rejections."""

import pytest
from unittest.mock import Mock, patch

from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.security_policy import EmailSecurityPolicy, SecurityEventLog
from primaite_mail.simulator.network.protocols.smtp import SMTPCommand, SMTPPacket, SMTPStatusCode, EmailMessage


class TestSMTPErrorCodes:
    """Test SMTP error code generation for security rejections."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create a mock SMTP server with security components
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
        
        # Mock other required attributes
        self.smtp_server.name = "smtp-server"
        
        # Add the actual methods to the mock
        self.smtp_server._log_security_rejection = SMTPServer._log_security_rejection.__get__(self.smtp_server)
        self.smtp_server._handle_mail_from = SMTPServer._handle_mail_from.__get__(self.smtp_server)
        self.smtp_server._enforce_sender_blocking = SMTPServer._enforce_sender_blocking.__get__(self.smtp_server)
        self.smtp_server._enforce_ip_blocking = SMTPServer._enforce_ip_blocking.__get__(self.smtp_server)

    def test_smtp_550_error_for_blocked_sender(self):
        """Test that blocked senders receive SMTP 550 error code."""
        # Add sender to blocklist
        blocked_sender = "malicious@attacker.com"
        self.smtp_server.security_policy.add_blocked_sender(blocked_sender)
        
        # Create MAIL FROM packet
        packet = SMTPPacket(
            command=SMTPCommand.MAIL,
            arguments=f"FROM:<{blocked_sender}>"
        )
        
        # Mock session in greeted state
        session = {"state": "greeted", "recipients": []}
        
        # Process MAIL FROM command
        response = self.smtp_server._handle_mail_from(packet, session, "192.168.1.50")
        
        # Verify SMTP 550 error code
        assert response.status_code == SMTPStatusCode.MAILBOX_UNAVAILABLE
        assert response.status_code.value == 550
        assert "mailbox unavailable" in response.message.lower()

    def test_connection_refusal_for_blocked_ip(self):
        """Test that blocked IPs are refused at connection level."""
        # Add IP to blocklist
        blocked_ip = "192.168.1.100"
        self.smtp_server.security_policy.add_blocked_ip(blocked_ip)
        
        # Test IP blocking enforcement
        result = self.smtp_server._enforce_ip_blocking(blocked_ip)
        
        # Verify connection is refused
        assert result is False

    def test_security_rejection_logging_for_sender(self):
        """Test security event logging for sender rejections."""
        sender = "spam@evil.com"
        client_ip = "192.168.1.50"
        
        # Test sender rejection logging
        self.smtp_server._log_security_rejection("sender", sender, client_ip, SMTPStatusCode.MAILBOX_UNAVAILABLE)
        
        # Verify sys_log was called
        self.smtp_server.sys_log.warning.assert_called()
        
        # Verify security event was logged
        events = self.smtp_server.security_log.get_recent_events()
        assert len(events) > 0
        
        sender_events = [e for e in events if e.event_type == "blocked_sender"]
        assert len(sender_events) > 0
        assert sender_events[0].sender == sender
        assert sender_events[0].ip_address == client_ip
        assert "550" in sender_events[0].reason

    def test_security_rejection_logging_for_ip(self):
        """Test security event logging for IP rejections."""
        client_ip = "192.168.1.100"
        
        # Test IP rejection logging
        self.smtp_server._log_security_rejection("ip", None, client_ip, None)
        
        # Verify sys_log was called
        self.smtp_server.sys_log.warning.assert_called()
        
        # Verify security event was logged
        events = self.smtp_server.security_log.get_recent_events()
        assert len(events) > 0
        
        ip_events = [e for e in events if e.event_type == "blocked_ip"]
        assert len(ip_events) > 0
        assert ip_events[0].ip_address == client_ip
        assert "connection refused" in ip_events[0].reason.lower()

    def test_smtp_error_message_format(self):
        """Test that SMTP error messages follow proper format."""
        # Add sender to blocklist
        blocked_sender = "phishing@scam.com"
        self.smtp_server.security_policy.add_blocked_sender(blocked_sender)
        
        # Create MAIL FROM packet
        packet = SMTPPacket(
            command=SMTPCommand.MAIL,
            arguments=f"FROM:<{blocked_sender}>"
        )
        
        # Mock session in greeted state
        session = {"state": "greeted", "recipients": []}
        
        # Process MAIL FROM command
        response = self.smtp_server._handle_mail_from(packet, session, "192.168.1.50")
        
        # Verify error message format
        assert response.status_code == SMTPStatusCode.MAILBOX_UNAVAILABLE
        assert response.message == "Requested action not taken: mailbox unavailable"

    def test_multiple_security_rejections(self):
        """Test handling of multiple security rejections."""
        # Add multiple blocked entities
        self.smtp_server.security_policy.add_blocked_sender("spam1@evil.com")
        self.smtp_server.security_policy.add_blocked_sender("spam2@evil.com")
        self.smtp_server.security_policy.add_blocked_ip("192.168.1.100")
        self.smtp_server.security_policy.add_blocked_ip("192.168.1.101")
        
        # Test multiple sender rejections
        senders = ["spam1@evil.com", "spam2@evil.com"]
        for sender in senders:
            packet = SMTPPacket(
                command=SMTPCommand.MAIL,
                arguments=f"FROM:<{sender}>"
            )
            session = {"state": "greeted", "recipients": []}
            response = self.smtp_server._handle_mail_from(packet, session, "192.168.1.50")
            
            assert response.status_code == SMTPStatusCode.MAILBOX_UNAVAILABLE
            assert response.status_code.value == 550

        # Test multiple IP rejections
        ips = ["192.168.1.100", "192.168.1.101"]
        for ip in ips:
            result = self.smtp_server._enforce_ip_blocking(ip)
            assert result is False

    def test_valid_smtp_transactions_not_affected(self):
        """Test that valid SMTP transactions are not affected by security policies."""
        # Add some blocked entities
        self.smtp_server.security_policy.add_blocked_sender("blocked@evil.com")
        self.smtp_server.security_policy.add_blocked_ip("192.168.1.100")
        
        # Test valid sender
        valid_sender = "user@company.com"
        packet = SMTPPacket(
            command=SMTPCommand.MAIL,
            arguments=f"FROM:<{valid_sender}>"
        )
        session = {"state": "greeted", "recipients": []}
        response = self.smtp_server._handle_mail_from(packet, session, "192.168.1.50")
        
        # Verify success
        assert response.status_code == SMTPStatusCode.OK_COMPLETED
        assert response.status_code.value == 250
        assert "sender ok" in response.message.lower()

        # Test valid IP
        valid_ip = "192.168.1.50"
        result = self.smtp_server._enforce_ip_blocking(valid_ip)
        assert result is True

    def test_smtp_error_codes_enum_values(self):
        """Test that SMTP error codes have correct enum values."""
        # Test key SMTP status codes used in security rejections
        assert SMTPStatusCode.MAILBOX_UNAVAILABLE.value == 550
        assert SMTPStatusCode.OK_COMPLETED.value == 250
        assert SMTPStatusCode.BAD_SEQUENCE.value == 503
        assert SMTPStatusCode.SYNTAX_ERROR.value == 500

    def test_security_logging_disabled(self):
        """Test behavior when security logging is disabled."""
        # Disable security logging
        self.smtp_server.security_policy.enable_logging = False
        
        sender = "spam@evil.com"
        client_ip = "192.168.1.50"
        
        # Test sender rejection logging
        initial_event_count = len(self.smtp_server.security_log.events)
        self.smtp_server._log_security_rejection("sender", sender, client_ip, SMTPStatusCode.MAILBOX_UNAVAILABLE)
        
        # Verify sys_log was still called (always logged)
        self.smtp_server.sys_log.warning.assert_called()
        
        # Verify security event was NOT logged to security_log when disabled
        final_event_count = len(self.smtp_server.security_log.events)
        assert final_event_count == initial_event_count

    def test_invalid_mail_from_syntax_error(self):
        """Test that invalid MAIL FROM syntax returns proper error code."""
        # Test invalid MAIL FROM syntax - only cases that don't contain "FROM:"
        invalid_packets = [
            SMTPPacket(command=SMTPCommand.MAIL, arguments="INVALID"),
            SMTPPacket(command=SMTPCommand.MAIL, arguments=""),
            SMTPPacket(command=SMTPCommand.MAIL, arguments=None),
        ]
        
        session = {"state": "greeted", "recipients": []}
        
        for packet in invalid_packets:
            response = self.smtp_server._handle_mail_from(packet, session, "192.168.1.50")
            assert response.status_code == SMTPStatusCode.SYNTAX_ERROR
            assert response.status_code.value == 500
            assert "syntax error" in response.message.lower()
        
        # Test "FROM:" with empty sender - this should succeed but with empty sender
        empty_from_packet = SMTPPacket(command=SMTPCommand.MAIL, arguments="FROM:")
        response = self.smtp_server._handle_mail_from(empty_from_packet, session, "192.168.1.50")
        # This will succeed because empty sender is not blocked
        assert response.status_code == SMTPStatusCode.OK_COMPLETED

    def test_mail_from_without_helo_error(self):
        """Test that MAIL FROM without HELO returns proper error code."""
        # Test MAIL FROM without HELO
        packet = SMTPPacket(
            command=SMTPCommand.MAIL,
            arguments="FROM:<user@company.com>"
        )
        
        # Session not in greeted state
        session = {"state": "connected", "recipients": []}
        
        response = self.smtp_server._handle_mail_from(packet, session, "192.168.1.50")
        
        assert response.status_code == SMTPStatusCode.BAD_SEQUENCE
        assert response.status_code.value == 503
        assert "helo" in response.message.lower()

    def test_cidr_range_ip_blocking_error_codes(self):
        """Test that CIDR range IP blocking works with proper error handling."""
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

    def test_security_rejection_logging_with_disabled_logging(self):
        """Test security rejection logging when security logging is disabled."""
        # Disable security logging
        self.smtp_server.security_policy.enable_logging = False
        
        sender = "test@example.com"
        client_ip = "192.168.1.50"
        
        # Log rejection - should still log to sys_log but not security_log
        initial_event_count = len(self.smtp_server.security_log.events)
        self.smtp_server._log_security_rejection("sender", sender, client_ip, SMTPStatusCode.MAILBOX_UNAVAILABLE)
        
        # Verify sys_log was called (always logged)
        self.smtp_server.sys_log.warning.assert_called()
        
        # Verify security event was NOT added when logging disabled
        final_event_count = len(self.smtp_server.security_log.events)
        assert final_event_count == initial_event_count

    def test_empty_and_none_values_in_rejection_logging(self):
        """Test handling of empty and None values in rejection logging."""
        # Test with None sender
        self.smtp_server._log_security_rejection("sender", None, "192.168.1.50", SMTPStatusCode.MAILBOX_UNAVAILABLE)
        
        # Test with empty sender
        self.smtp_server._log_security_rejection("sender", "", "192.168.1.50", SMTPStatusCode.MAILBOX_UNAVAILABLE)
        
        # Test with None IP
        self.smtp_server._log_security_rejection("ip", None, "", None)
        
        # All should complete without errors
        assert True  # If we get here, no exceptions were raised