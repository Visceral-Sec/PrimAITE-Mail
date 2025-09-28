"""Simple unit tests for SMTP server display methods."""

import pytest
from unittest.mock import patch
from io import StringIO
import sys


class TestSMTPServerDisplaySimple:
    """Simple test for SMTP server display methods."""

    def test_smtp_server_has_display_methods(self, smtp_server):
        """Test that SMTP server has the required display methods."""
        assert hasattr(smtp_server, 'show')
        assert hasattr(smtp_server, 'show_security_policies')
        assert hasattr(smtp_server, 'show_security_events')
        
        # Test methods are callable
        assert callable(smtp_server.show)
        assert callable(smtp_server.show_security_policies)
        assert callable(smtp_server.show_security_events)

    def test_show_method_executes(self, smtp_server):
        """Test that show method executes without error."""
        # Capture stdout to prevent output during test
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            # Should not raise an exception
            smtp_server.show()
        finally:
            sys.stdout = old_stdout

    def test_show_security_policies_executes(self, smtp_server):
        """Test that show_security_policies method executes without error."""
        # Capture stdout to prevent output during test
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            # Should not raise an exception
            smtp_server.show_security_policies()
        finally:
            sys.stdout = old_stdout

    def test_show_security_events_executes(self, smtp_server):
        """Test that show_security_events method executes without error."""
        # Capture stdout to prevent output during test
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            # Should not raise an exception
            smtp_server.show_security_events()
        finally:
            sys.stdout = old_stdout

    def test_show_methods_with_data(self, smtp_server):
        """Test display methods with some test data."""
        # Add some test data
        smtp_server.security_policy.add_blocked_sender("test@example.com")
        smtp_server.security_policy.add_blocked_ip("192.168.1.1")
        
        # Add a security event
        smtp_server.security_log.log_blocked_email(
            "test@example.com", "192.168.1.1", "Test block", "medium"
        )
        
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        
        try:
            smtp_server.show()
            output = captured_output.getvalue()
            
            # Should contain some expected content
            assert len(output) > 0
            
        finally:
            sys.stdout = old_stdout

    def test_show_security_policies_with_data(self, smtp_server):
        """Test show_security_policies with test data."""
        # Add test data
        smtp_server.security_policy.add_blocked_sender("malicious@attacker.com")
        smtp_server.security_policy.add_blocked_ip("10.0.0.0/8")
        
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        
        try:
            smtp_server.show_security_policies()
            output = captured_output.getvalue()
            
            # Should contain the blocked items
            assert "malicious@attacker.com" in output
            assert "10.0.0.0/8" in output
            
        finally:
            sys.stdout = old_stdout

    def test_show_security_events_with_data(self, smtp_server):
        """Test show_security_events with test data."""
        # Add test events
        smtp_server.security_log.log_blocked_email(
            "spam@example.com", "1.2.3.4", "Blocked spam", "high"
        )
        smtp_server.security_log.log_policy_change(
            "blue_agent", "block_sender", "spam@example.com", "low"
        )
        
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        
        try:
            smtp_server.show_security_events()
            output = captured_output.getvalue()
            
            # Should contain event information
            assert "spam@example.com" in output or "Recent Security Events" in output
            
        finally:
            sys.stdout = old_stdout

    def test_show_methods_with_markdown(self, smtp_server):
        """Test that markdown parameter works."""
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            # Should not raise exceptions with markdown=True
            smtp_server.show(markdown=True)
            smtp_server.show_security_policies(markdown=True)
            smtp_server.show_security_events(markdown=True)
        finally:
            sys.stdout = old_stdout

    def test_show_security_events_with_filters(self, smtp_server):
        """Test show_security_events with various filter parameters."""
        # Add test events
        smtp_server.security_log.log_blocked_email(
            "test@example.com", "1.1.1.1", "Test event", "high"
        )
        
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            # Test with different filter parameters
            smtp_server.show_security_events(limit=10)
            smtp_server.show_security_events(event_type="blocked_sender")
            smtp_server.show_security_events(severity="high")
            smtp_server.show_security_events(time_range_hours=24.0)
        finally:
            sys.stdout = old_stdout