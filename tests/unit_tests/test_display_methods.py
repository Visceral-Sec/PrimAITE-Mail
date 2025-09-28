from unittest.mock import Mock
"""Unit tests for SMTP server display methods."""

import pytest
from unittest.mock import patch, MagicMock
from io import StringIO
import sys
from pathlib import Path
import tempfile

from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.security_policy import EmailSecurityPolicy, SecurityEventLog, SecurityEvent
from primaite.simulator.file_system.file_system import FileSystem
from primaite.simulator.system.core.sys_log import SysLog


class TestSMTPServerDisplayMethods:
    """Test SMTP server display methods."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create required dependencies
        self.sys_log = SysLog("test-host")
        self.sim_root = Path(tempfile.mkdtemp())
        self.file_system = FileSystem(sys_log=self.sys_log, sim_root=self.sim_root)
        
        # Create SMTP server with security policies
        self.smtp_server = SMTPServer(file_system=self.file_system, sys_log=self.sys_log)
        
        # Add some test data
        self.smtp_server.security_policy.add_blocked_sender("malicious@attacker.com")
        self.smtp_server.security_policy.add_blocked_sender("spam@badactor.net")
        self.smtp_server.security_policy.add_blocked_ip("192.168.1.100")
        self.smtp_server.security_policy.add_blocked_ip("10.0.0.0/8")
        
        # Add some security events
        self.smtp_server.security_log.log_blocked_email(
            "malicious@attacker.com", "192.168.1.100", 
            "Sender blocked by policy", "high"
        )
        self.smtp_server.security_log.log_blocked_ip(
            "192.168.1.100", "IP blocked by policy", "medium"
        )
        self.smtp_server.security_log.log_policy_change(
            "block_sender", "malicious@attacker.com", "blue_agent_1", "low"
        )
        
        # Create some mailboxes for testing
        self.smtp_server.mailbox_manager.create_mailbox("alice")
        self.smtp_server.mailbox_manager.create_mailbox("bob")
    
    def create_smtp_server(self):
        """Helper method to create a new SMTPServer instance with required dependencies."""
        return SMTPServer(file_system=self.file_system, sys_log=self.sys_log)

    def capture_output(self, func, *args, **kwargs):
        """Capture stdout output from a function."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        try:
            func(*args, **kwargs)
            return captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

    def test_show_method_includes_security_info(self):
        """Test that the enhanced show method includes security policy information."""
        output = self.capture_output(self.smtp_server.show)
        
        # Check that security information is included
        assert "Security Logging" in output
        assert "Blocked Senders" in output
        assert "Blocked IPs" in output
        assert "Security Events" in output
        
        # Check values
        assert "2" in output  # 2 blocked senders
        assert "2" in output  # 2 blocked IPs
        assert "3" in output  # 3 security events

    def test_show_method_markdown_format(self):
        """Test that the show method works with markdown format."""
        output = self.capture_output(self.smtp_server.show, markdown=True)
        
        # Markdown tables should contain pipe characters
        assert "|" in output
        assert "Security Logging" in output

    def test_show_security_policies_basic(self):
        """Test basic security policies display."""
        output = self.capture_output(self.smtp_server.show_security_policies)
        
        # Check policy overview
        assert "Security Policy Configuration" in output
        assert "Security Logging" in output
        assert "Default Action" in output
        assert "Total Blocked Senders" in output
        assert "Total Blocked IPs" in output
        
        # Check blocked senders section
        assert "Blocked Senders" in output
        assert "malicious@attacker.com" in output
        assert "spam@badactor.net" in output
        
        # Check blocked IPs section
        assert "Blocked IP Addresses" in output
        assert "192.168.1.100" in output
        assert "10.0.0.0/8" in output
        assert "Single IP" in output
        assert "CIDR Range" in output
        
        # Check statistics section
        assert "Security Statistics" in output
        assert "Total Security Events" in output
        assert "Blocked Emails" in output
        assert "Policy Changes" in output

    def test_show_security_policies_empty_lists(self):
        """Test security policies display with empty blocklists."""
        # Create server with no blocked items
        empty_server = self.create_smtp_server()
        
        output = self.capture_output(empty_server.show_security_policies)
        
        assert "No blocked senders configured" in output
        assert "No blocked IP addresses configured" in output
        assert "Security Policy Configuration" in output

    def test_show_security_policies_markdown(self):
        """Test security policies display with markdown format."""
        output = self.capture_output(self.smtp_server.show_security_policies, markdown=True)
        
        # Markdown tables should contain pipe characters
        assert "|" in output
        assert "Security Policy Configuration" in output

    def test_show_security_events_basic(self):
        """Test basic security events display."""
        output = self.capture_output(self.smtp_server.show_security_events)
        
        # Check table headers
        assert "Recent Security Events" in output
        assert "Time" in output
        assert "Type" in output
        assert "Severity" in output
        assert "Source" in output
        assert "Agent" in output
        assert "Reason" in output
        
        # Check event content
        assert "Blocked Sender" in output or "blocked_sender" in output
        assert "Blocked Ip" in output or "blocked_ip" in output
        assert "Policy Change" in output or "policy_change" in output
        assert "malicious@attacker.com" in output
        assert "192.168.1.100" in output
        assert "blue_a" in output  # Agent name may be truncated in display

    def test_show_security_events_with_filters(self):
        """Test security events display with various filters."""
        # Test event type filter
        output = self.capture_output(
            self.smtp_server.show_security_events, 
            event_type="blocked_sender"
        )
        assert "type: blocked_sender" in output
        assert "malicious@attacker.com" in output
        
        # Test severity filter
        output = self.capture_output(
            self.smtp_server.show_security_events, 
            severity="high"
        )
        assert "severity: high" in output
        
        # Test limit
        output = self.capture_output(
            self.smtp_server.show_security_events, 
            limit=1
        )
        assert "showing last 1" in output

    def test_show_security_events_time_range_filter(self):
        """Test security events display with time range filter."""
        output = self.capture_output(
            self.smtp_server.show_security_events, 
            time_range_hours=24.0
        )
        assert "last 24.0h" in output

    def test_show_security_events_no_events(self):
        """Test security events display when no events match filters."""
        output = self.capture_output(
            self.smtp_server.show_security_events, 
            event_type="nonexistent_type"
        )
        assert "No security events found" in output
        assert "type=nonexistent_type" in output

    def test_show_security_events_markdown(self):
        """Test security events display with markdown format."""
        output = self.capture_output(
            self.smtp_server.show_security_events, 
            markdown=True
        )
        
        # Markdown tables should contain pipe characters
        assert "|" in output
        assert "Recent Security Events" in output

    def test_show_security_events_with_event_type_summary(self):
        """Test that event type summary is shown for diverse events."""
        # Add more diverse events
        self.smtp_server.security_log.log_security_event(
            "authentication_failure", "Invalid credentials", "medium"
        )
        self.smtp_server.security_log.log_security_event(
            "rate_limit_exceeded", "Too many requests", "low"
        )
        
        output = self.capture_output(self.smtp_server.show_security_events)
        
        # Should show the events (basic functionality test)
        assert "Recent Security Events" in output
        assert "Authentication Failure" in output
        assert "Rate Limit Exceeded" in output

    def test_display_methods_with_long_content(self):
        """Test display methods handle long content properly."""
        # Add items with long names
        long_email = "very.long.email.address.that.exceeds.normal.length@extremely.long.domain.name.example.com"
        long_ip = "192.168.1.100"  # Will be truncated in display
        
        self.smtp_server.security_policy.add_blocked_sender(long_email)
        self.smtp_server.security_log.log_blocked_email(
            long_email, long_ip, 
            "This is a very long reason that should be truncated in the display to prevent table formatting issues",
            "high"
        )
        
        # Test that methods don't crash with long content
        output = self.capture_output(self.smtp_server.show_security_policies)
        assert long_email in output
        
        output = self.capture_output(self.smtp_server.show_security_events)
        assert "..." in output  # Should show truncation

    def test_display_methods_error_handling(self):
        """Test display methods handle errors gracefully."""
        # Test with corrupted security log
        corrupted_event = SecurityEvent(
            timestamp="invalid-timestamp",
            event_type="suspicious_activity",
            reason="Test reason"
        )
        self.smtp_server.security_log.events.append(corrupted_event)
        
        # Should not crash
        output = self.capture_output(self.smtp_server.show_security_events)
        assert "Recent Security Events" in output

    @patch('prettytable.PrettyTable')
    def test_display_methods_use_prettytable(self, mock_prettytable):
        """Test that display methods use PrettyTable correctly."""
        mock_table = MagicMock()
        mock_prettytable.return_value = mock_table
        
        # Test show method
        self.smtp_server.show()
        assert mock_prettytable.called
        assert mock_table.add_row.called
        
        # Reset mock
        mock_prettytable.reset_mock()
        mock_table.reset_mock()
        
        # Test show_security_policies
        self.smtp_server.show_security_policies()
        assert mock_prettytable.called
        assert mock_table.add_row.called
        
        # Reset mock
        mock_prettytable.reset_mock()
        mock_table.reset_mock()
        
        # Test show_security_events
        self.smtp_server.show_security_events()
        assert mock_prettytable.called
        assert mock_table.add_row.called

    def test_security_statistics_accuracy(self):
        """Test that security statistics in display are accurate."""
        # Clear existing events and add known events
        self.smtp_server.security_log.events.clear()
        
        # Add specific events
        self.smtp_server.security_log.log_blocked_email(
            "test1@example.com", "1.1.1.1", "Test block 1", "high"
        )
        self.smtp_server.security_log.log_blocked_email(
            "test2@example.com", "2.2.2.2", "Test block 2", "medium"
        )
        self.smtp_server.security_log.log_blocked_ip(
            "3.3.3.3", "Test IP block", "low"
        )
        self.smtp_server.security_log.log_policy_change(
            "agent1", "block_sender", "test@example.com", "low"
        )
        
        output = self.capture_output(self.smtp_server.show_security_policies)
        
        # Verify statistics are correct
        stats = self.smtp_server.security_log.get_detailed_statistics()
        assert str(stats["total_events"]) in output
        assert str(stats["blocked_senders"]) in output
        assert str(stats["policy_changes"]) in output

    def test_display_formatting_consistency(self):
        """Test that display formatting is consistent across methods."""
        # All methods should produce output
        show_output = self.capture_output(self.smtp_server.show)
        policies_output = self.capture_output(self.smtp_server.show_security_policies)
        events_output = self.capture_output(self.smtp_server.show_security_events)
        
        # All should contain table formatting
        for output in [show_output, policies_output, events_output]:
            assert len(output.strip()) > 0
            # Should contain table borders or content
            assert any(char in output for char in ['+', '-', '|', '='])

    def test_show_security_events_severity_indicators(self):
        """Test that security events show severity indicators correctly."""
        # Add events with different severities
        self.smtp_server.security_log.events.clear()
        self.smtp_server.security_log.log_security_event(
            "suspicious_activity", "High severity event", "high"
        )
        self.smtp_server.security_log.log_security_event(
            "authentication_failure", "Medium severity event", "medium"
        )
        self.smtp_server.security_log.log_security_event(
            "rate_limit_exceeded", "Low severity event", "low"
        )
        
        output = self.capture_output(self.smtp_server.show_security_events)
        
        # Check for severity indicators (emojis or text)
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output

    def test_log_health_status_display(self):
        """Test that log health status is displayed correctly."""
        output = self.capture_output(self.smtp_server.show_security_policies)
        
        # Should show log health information
        assert "Event Log Size" in output
        assert "Log Utilization" in output
        assert "Auto Rotation" in output
        
        # Values should be reasonable
        log_health = self.smtp_server.security_log.get_log_health_status()
        assert str(log_health['current_size']) in output
        assert str(log_health['max_size']) in output


class TestDisplayMethodsIntegration:
    """Integration tests for display methods with real data."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create required dependencies
        self.sys_log = SysLog("test-host")
        self.sim_root = Path(tempfile.mkdtemp())
        self.file_system = FileSystem(sys_log=self.sys_log, sim_root=self.sim_root)

    def test_display_methods_with_full_scenario(self):
        """Test display methods with a complete security scenario."""
        # Create server and simulate a security incident
        server = SMTPServer(file_system=self.file_system, sys_log=self.sys_log)
        
        # Blue agent blocks malicious sender
        server.security_policy.add_blocked_sender("attacker@evil.com")
        server.security_log.log_policy_change(
            "blue_agent_1", "block_sender", "attacker@evil.com", "low"
        )
        
        # Red agent attempts to send email (blocked)
        server.security_log.log_blocked_email(
            "attacker@evil.com", "192.168.1.50", 
            "Email blocked by sender policy", "high"
        )
        
        # Blue agent blocks the IP as well
        server.security_policy.add_blocked_ip("192.168.1.50")
        server.security_log.log_policy_change(
            "blue_agent_1", "block_ip", "192.168.1.50", "low"
        )
        
        # Red agent attempts connection from blocked IP
        server.security_log.log_connection_refused(
            "192.168.1.50", "Connection refused - IP blocked", "high"
        )
        
        # Test all display methods work with this scenario
        show_output = server.show()  # Should not crash
        policies_output = server.show_security_policies()  # Should not crash
        events_output = server.show_security_events()  # Should not crash
        
        # Verify content appears in appropriate displays
        policies_output_str = StringIO()
        sys.stdout = policies_output_str
        server.show_security_policies()
        sys.stdout = sys.__stdout__
        policies_content = policies_output_str.getvalue()
        
        assert "attacker@evil.com" in policies_content
        assert "192.168.1.50" in policies_content
        
        events_output_str = StringIO()
        sys.stdout = events_output_str
        server.show_security_events()
        sys.stdout = sys.__stdout__
        events_content = events_output_str.getvalue()
        
        assert "blue_agent_1" in events_content
        assert "Policy Change" in events_content or "policy_change" in events_content

    def test_display_performance_with_many_events(self):
        """Test display methods performance with many security events."""
        server = SMTPServer(file_system=self.file_system, sys_log=self.sys_log)
        
        # Add many events
        for i in range(100):
            server.security_log.log_blocked_email(
                f"spam{i}@example.com", f"192.168.1.{i % 255}", 
                f"Blocked spam email {i}", "medium"
            )
        
        # Display methods should handle large datasets
        import time
        
        start_time = time.time()
        server.show_security_events(limit=50)
        duration = time.time() - start_time
        
        # Should complete reasonably quickly (less than 1 second)
        assert duration < 1.0
        
        # Should respect limit
        events_output_str = StringIO()
        sys.stdout = events_output_str
        server.show_security_events(limit=10)
        sys.stdout = sys.__stdout__
        events_content = events_output_str.getvalue()
        
        # Should mention the limit
        assert "10" in events_content