"""
Unit tests for POP3 email retrieval functionality.

This module tests the POP3 email retrieval system to prevent regression of the bug
where retrieve_emails_pop3 was returning empty lists despite emails being present
in the mailbox.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from ipaddress import IPv4Address

from primaite.simulator.network.container import Network
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.pop3_server import POP3Server
from primaite_mail.simulator.software.email_client import EmailClient
from primaite_mail.simulator.network.protocols.smtp import EmailMessage
from primaite.interface.request import RequestResponse


class TestPOP3EmailRetrieval:
    """Test POP3 email retrieval functionality."""

    def setup_method(self):
        """Set up test environment for each test."""
        # Create network and nodes
        self.network = Network()
        
        # Create mail server
        self.mail_server = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
            "start_up_duration": 0,
        })
        self.mail_server.power_on()
        self.network.add_node(self.mail_server)
        
        # Create client
        self.client_pc = Computer.from_config({
            "type": "computer",
            "hostname": "client_pc",
            "ip_address": "192.168.1.22",
            "subnet_mask": "255.255.255.0",
            "start_up_duration": 0,
        })
        self.client_pc.power_on()
        self.network.add_node(self.client_pc)
        
        # Connect them
        self.network.connect(self.mail_server.network_interface[1], self.client_pc.network_interface[1])
        
        # Set network references
        self.mail_server.network = self.network
        self.client_pc.network = self.network
        
        # Install services
        self.mail_server.software_manager.install(SMTPServer)
        self.mail_server.software_manager.install(POP3Server)
        self.client_pc.software_manager.install(EmailClient)
        
        # Get service references
        self.smtp_server = self.mail_server.software_manager.software.get("smtp-server")
        self.pop3_server = self.mail_server.software_manager.software.get("pop3-server")
        self.email_client = self.client_pc.software_manager.software.get("email-client")
        
        # Configure email client
        self.email_client.config.username = "testuser@company.com"
        self.email_client.config.default_pop3_server = str(self.mail_server.config.ip_address)
        self.email_client.run()
        
        # Share mailbox manager and disable auth for testing
        self.pop3_server.mailbox_manager = self.smtp_server.mailbox_manager
        self.pop3_server.config.require_auth = False

    def test_pop3_retrieval_with_single_email(self):
        """Test POP3 retrieval with a single email in mailbox."""
        # Create mailbox and add email
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        test_email = EmailMessage(
            sender="sender@company.com",
            recipients=["testuser@company.com"],
            subject="Test Email",
            body="This is a test email."
        )
        
        mailbox = self.smtp_server.mailbox_manager.get_mailbox("testuser")
        mailbox.add_message(test_email)
        
        # Inject server reference for testing (simulates working network discovery)
        self.email_client._test_pop3_server = self.pop3_server
        
        # Retrieve emails
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="password"
        )
        
        # Verify results
        assert emails is not None, "POP3 retrieval should not return None"
        assert len(emails) == 1, f"Expected 1 email, got {len(emails)}"
        assert emails[0].subject == "Test Email"
        assert emails[0].sender == "sender@company.com"
        assert emails[0].body == "This is a test email."

    def test_pop3_retrieval_with_multiple_emails(self):
        """Test POP3 retrieval with multiple emails in mailbox."""
        # Create mailbox and add multiple emails
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        mailbox = self.smtp_server.mailbox_manager.get_mailbox("testuser")
        
        emails_to_add = [
            EmailMessage(
                sender="sender1@company.com",
                recipients=["testuser@company.com"],
                subject="First Email",
                body="This is the first email."
            ),
            EmailMessage(
                sender="sender2@company.com",
                recipients=["testuser@company.com"],
                subject="Second Email",
                body="This is the second email."
            ),
            EmailMessage(
                sender="sender3@company.com",
                recipients=["testuser@company.com"],
                subject="Third Email",
                body="This is the third email."
            )
        ]
        
        for email in emails_to_add:
            mailbox.add_message(email)
        
        # Inject server reference for testing
        self.email_client._test_pop3_server = self.pop3_server
        
        # Retrieve emails
        retrieved_emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="password"
        )
        
        # Verify results
        assert retrieved_emails is not None, "POP3 retrieval should not return None"
        assert len(retrieved_emails) == 3, f"Expected 3 emails, got {len(retrieved_emails)}"
        
        # Check that all emails were retrieved
        subjects = [email.subject for email in retrieved_emails]
        assert "First Email" in subjects
        assert "Second Email" in subjects
        assert "Third Email" in subjects

    def test_pop3_retrieval_with_empty_mailbox(self):
        """Test POP3 retrieval with empty mailbox."""
        # Create empty mailbox
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        
        # Inject server reference for testing
        self.email_client._test_pop3_server = self.pop3_server
        
        # Retrieve emails
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="password"
        )
        
        # Verify results
        assert emails is not None, "POP3 retrieval should not return None for empty mailbox"
        assert len(emails) == 0, f"Expected 0 emails for empty mailbox, got {len(emails)}"

    def test_pop3_retrieval_nonexistent_mailbox(self):
        """Test POP3 retrieval with nonexistent mailbox."""
        # Don't create mailbox
        
        # Inject server reference for testing
        self.email_client._test_pop3_server = self.pop3_server
        
        # Retrieve emails
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="nonexistent",
            password="password"
        )
        
        # Verify results
        assert emails is None, "POP3 retrieval should return None for nonexistent mailbox"

    def test_pop3_retrieval_server_not_found(self):
        """Test POP3 retrieval when server cannot be found."""
        # Create mailbox
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        
        # Don't inject server reference (simulate network discovery failure)
        
        # Retrieve emails
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address("192.168.1.99"),  # Non-existent server
            username="testuser",
            password="password"
        )
        
        # Verify results
        assert emails is None, "POP3 retrieval should return None when server not found"

    def test_pop3_retrieval_service_not_operational(self):
        """Test POP3 retrieval when email client service is not operational."""
        # Create mailbox and add email
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        test_email = EmailMessage(
            sender="sender@company.com",
            recipients=["testuser@company.com"],
            subject="Test Email",
            body="This is a test email."
        )
        mailbox = self.smtp_server.mailbox_manager.get_mailbox("testuser")
        mailbox.add_message(test_email)
        
        # Stop the email client service
        self.email_client.close()
        
        # Retrieve emails
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="password"
        )
        
        # Verify results
        assert emails is None, "POP3 retrieval should return None when service not operational"

    def test_pop3_retrieval_with_auto_extract_disabled(self):
        """Test POP3 retrieval with auto-extract disabled (basic functionality test)."""
        # Create mailbox and add email
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        test_email = EmailMessage(
            sender="sender@company.com",
            recipients=["testuser@company.com"],
            subject="Auto Extract Test",
            body="This email tests auto-extract disabled functionality."
        )
        
        mailbox = self.smtp_server.mailbox_manager.get_mailbox("testuser")
        mailbox.add_message(test_email)
        
        # Inject server reference for testing
        self.email_client._test_pop3_server = self.pop3_server
        
        # Retrieve emails without auto-extraction
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="password",
            auto_extract_attachments=False
        )
        
        # Verify results
        assert emails is not None, "POP3 retrieval should not return None"
        assert len(emails) == 1, f"Expected 1 email, got {len(emails)}"
        assert emails[0].subject == "Auto Extract Test"
        assert emails[0].sender == "sender@company.com"

    def test_pop3_retrieval_authentication_failure(self):
        """Test POP3 retrieval with authentication failure."""
        # Create mailbox
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        
        # Enable authentication
        self.pop3_server.config.require_auth = True
        
        # Create a mock POP3 server that fails authentication
        mock_pop3_server = Mock()
        mock_pop3_server.apply_request.return_value = RequestResponse(
            status="failure", 
            data={"reason": "Authentication failed"}
        )
        
        # Inject mock server
        self.email_client._test_pop3_server = mock_pop3_server
        
        # Retrieve emails with wrong credentials
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="wrongpassword"
        )
        
        # Verify results
        assert emails is None, "POP3 retrieval should return None on authentication failure"

    def test_pop3_retrieval_message_list_failure(self):
        """Test POP3 retrieval when message list retrieval fails."""
        # Create mailbox
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        
        # Create a mock POP3 server that succeeds auth but fails message list
        mock_pop3_server = Mock()
        mock_pop3_server.apply_request.side_effect = [
            RequestResponse(status="success", data={"username": "testuser", "authenticated": True}),  # Auth success
            RequestResponse(status="failure", data={"reason": "Message list unavailable"})  # List failure
        ]
        
        # Inject mock server
        self.email_client._test_pop3_server = mock_pop3_server
        
        # Retrieve emails
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="password"
        )
        
        # Verify results
        assert emails is None, "POP3 retrieval should return None when message list fails"

    def test_pop3_retrieval_partial_message_failure(self):
        """Test POP3 retrieval when some messages fail to retrieve."""
        # Create mailbox
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        
        # Create a mock POP3 server that succeeds for some messages but fails for others
        mock_pop3_server = Mock()
        mock_pop3_server.apply_request.side_effect = [
            RequestResponse(status="success", data={"username": "testuser", "authenticated": True}),  # Auth success
            RequestResponse(status="success", data={"message_count": 2, "total_size": 200}),  # List success
            RequestResponse(status="success", data={  # Message 1 success
                "sender": "sender1@company.com",
                "recipients": ["testuser@company.com"],
                "subject": "First Email",
                "body": "This is the first email.",
                "message_id": "msg1"
            }),
            RequestResponse(status="failure", data={"reason": "Message not found"})  # Message 2 failure
        ]
        
        # Inject mock server
        self.email_client._test_pop3_server = mock_pop3_server
        
        # Retrieve emails
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="password"
        )
        
        # Verify results - should return successfully retrieved messages
        assert emails is not None, "POP3 retrieval should not return None on partial failure"
        assert len(emails) == 1, f"Expected 1 email (partial success), got {len(emails)}"
        assert emails[0].subject == "First Email"

    def test_pop3_retrieval_exception_handling(self):
        """Test POP3 retrieval exception handling."""
        # Create mailbox
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        
        # Create a mock POP3 server that raises an exception
        mock_pop3_server = Mock()
        mock_pop3_server.apply_request.side_effect = Exception("Server error")
        
        # Inject mock server
        self.email_client._test_pop3_server = mock_pop3_server
        
        # Retrieve emails
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="password"
        )
        
        # Verify results
        assert emails is None, "POP3 retrieval should return None on exception"

    def test_pop3_session_cleanup(self):
        """Test that POP3 session state is properly cleaned up."""
        # Create mailbox and add email
        self.smtp_server.mailbox_manager.create_mailbox("testuser")
        test_email = EmailMessage(
            sender="sender@company.com",
            recipients=["testuser@company.com"],
            subject="Test Email",
            body="This is a test email."
        )
        mailbox = self.smtp_server.mailbox_manager.get_mailbox("testuser")
        mailbox.add_message(test_email)
        
        # Inject server reference for testing
        self.email_client._test_pop3_server = self.pop3_server
        
        # Retrieve emails
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="testuser",
            password="password"
        )
        
        # Verify session cleanup
        assert not hasattr(self.email_client, '_pop3_session'), "POP3 session should be cleaned up after retrieval"
        assert emails is not None, "Email retrieval should succeed"

    def test_pop3_retrieval_regression_empty_list_bug(self):
        """
        Regression test for the specific bug where retrieve_emails_pop3 
        returned empty list despite emails being present.
        
        This test ensures the bug doesn't reoccur.
        """
        # Create mailbox and add email (exactly like the original bug scenario)
        self.smtp_server.mailbox_manager.create_mailbox("bob")
        test_email = EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com"],
            subject="Test Email",
            body="This is a test email for POP3 retrieval."
        )
        
        mailbox = self.smtp_server.mailbox_manager.get_mailbox("bob")
        mailbox.add_message(test_email)
        
        # Verify email is in mailbox (this was working in the original bug)
        assert len(mailbox.get_messages()) == 1, "Email should be in mailbox"
        
        # Verify POP3 server can see the email (this was working in the original bug)
        list_response = self.pop3_server.apply_request(["get_message_list", {"username": "bob"}], {})
        assert list_response.status == "success", "POP3 server should list messages successfully"
        assert list_response.data["message_count"] == 1, "POP3 server should see 1 message"
        
        # Inject server reference for testing
        self.email_client._test_pop3_server = self.pop3_server
        
        # This was the failing part in the original bug - should NOT return empty list
        emails = self.email_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="bob",
            password="password123"
        )
        
        # THE CRITICAL ASSERTION - this was failing before the fix
        assert emails is not None, "POP3 retrieval should not return None (regression test)"
        assert len(emails) > 0, "POP3 retrieval should NOT return empty list when emails exist (REGRESSION TEST)"
        assert len(emails) == 1, f"Expected 1 email, got {len(emails)} (regression test)"
        assert emails[0].subject == "Test Email", "Retrieved email should have correct subject"
        assert emails[0].sender == "alice@company.com", "Retrieved email should have correct sender"


class TestPOP3ServerDiscovery:
    """Test POP3 server discovery mechanisms."""

    def setup_method(self):
        """Set up test environment."""
        # Create a minimal network setup for the email client
        self.network = Network()
        self.client_pc = Computer.from_config({
            "type": "computer",
            "hostname": "test_client",
            "ip_address": "192.168.1.100",
            "subnet_mask": "255.255.255.0",
            "start_up_duration": 0,
        })
        self.client_pc.power_on()
        self.network.add_node(self.client_pc)
        
        # Install and configure email client
        self.client_pc.software_manager.install(EmailClient)
        self.email_client = self.client_pc.software_manager.software.get("email-client")
        self.email_client.config.username = "test@company.com"
        self.email_client.run()

    def test_find_pop3_server_with_injected_reference(self):
        """Test server discovery with injected test reference."""
        mock_server = Mock()
        self.email_client._test_pop3_server = mock_server
        
        result = self.email_client._find_pop3_server_direct(IPv4Address("192.168.1.10"))
        
        assert result == mock_server, "Should return injected test server"

    def test_find_pop3_server_no_software_manager(self):
        """Test server discovery when email client has no software manager."""
        # Remove software manager
        if hasattr(self.email_client, 'software_manager'):
            delattr(self.email_client, 'software_manager')
        
        result = self.email_client._find_pop3_server_direct(IPv4Address("192.168.1.10"))
        
        assert result is None, "Should return None when no software manager"

    def test_find_pop3_server_no_network_interfaces(self):
        """Test server discovery when node has no network interfaces."""
        # Mock software manager and node without network interfaces
        mock_node = Mock()
        mock_node.network_interface = {}
        
        mock_software_manager = Mock()
        mock_software_manager.node = mock_node
        
        self.email_client.software_manager = mock_software_manager
        
        result = self.email_client._find_pop3_server_direct(IPv4Address("192.168.1.10"))
        
        assert result is None, "Should return None when no network interfaces"


if __name__ == "__main__":
    pytest.main([__file__])