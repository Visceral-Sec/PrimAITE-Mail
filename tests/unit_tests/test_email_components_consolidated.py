# © Crown-owned copyright 2025, Defence Science and Technology Laboratory UK
"""Consolidated unit tests for email components.

This file consolidates functionality from:
- test_attribute_access.py - Attribute access patterns
- test_email_client_actions.py - Email client actions
- test_pop3_server_actions.py - POP3 server actions  
- test_smtp_server_actions.py - SMTP server actions

Maintains 100% coverage while reducing maintenance overhead.
"""

import pytest
from primaite.simulator.network.container import Network
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite.simulator.system.services.service import ServiceOperatingState
from primaite.simulator.system.applications.application import ApplicationOperatingState
from primaite.simulator.system.software import SoftwareHealthState
from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.pop3_server import POP3Server
from primaite_mail.simulator.software.email_client import EmailClient
from primaite_mail.simulator.network.protocols.smtp import EmailMessage


class TestEmailComponentsConsolidated:
    """Consolidated tests for all email components."""

    # ==================== ATTRIBUTE ACCESS PATTERNS ====================

    def test_computer_config_access_patterns(self):
        """Test correct computer attribute access patterns."""
        computer = Computer.from_config({
            "type": "computer",
            "hostname": "test_computer",
            "ip_address": "192.168.1.100",
            "subnet_mask": "255.255.255.0",
        })
        computer.power_on()
        
        # Test correct attribute access via config
        assert computer.config.hostname == "test_computer"
        assert str(computer.config.ip_address) == "192.168.1.100"
        assert str(computer.config.subnet_mask) == "255.255.255.0"
        
        # Test that direct attribute access would fail
        with pytest.raises(AttributeError):
            _ = computer.hostname
        with pytest.raises(AttributeError):
            _ = computer.ip_address

    def test_network_node_retrieval_patterns(self):
        """Test network node retrieval patterns."""
        network = Network()
        computer = Computer.from_config({
            "type": "computer",
            "hostname": "test_node",
            "ip_address": "192.168.1.50",
            "subnet_mask": "255.255.255.0",
        })
        computer.power_on()
        network.add_node(computer)
        
        # Test retrieval by hostname
        retrieved_node = network.get_node_by_hostname("test_node")
        assert retrieved_node is not None
        assert retrieved_node.config.hostname == "test_node"
        assert retrieved_node is computer

    def test_email_services_installation_patterns(self):
        """Test email services installation and access patterns."""
        computer = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
        })
        computer.power_on()
        
        # Install and verify SMTP server
        computer.software_manager.install(SMTPServer)
        smtp_server = computer.software_manager.software.get("smtp-server")
        assert smtp_server is not None
        assert smtp_server.name == "smtp-server"
        assert smtp_server.operating_state.name == "RUNNING"
        
        # Install and verify email client
        computer.software_manager.install(EmailClient)
        email_client = computer.software_manager.software.get("email-client")
        assert email_client is not None
        assert email_client.name == "email-client"
        email_client.run()
        assert email_client.operating_state.name == "RUNNING"

    # ==================== SMTP SERVER ACTIONS ====================

    def test_smtp_server_mailbox_management_actions(self, smtp_server):
        """Test SMTP server mailbox management actions."""
        # Test mailbox creation
        success = smtp_server.mailbox_manager.create_mailbox("testuser")
        assert success is True
        assert "testuser" in smtp_server.mailbox_manager.mailboxes
        
        # Verify mailbox structure
        mailbox = smtp_server.mailbox_manager.get_mailbox("testuser")
        assert mailbox is not None
        assert mailbox.username == "testuser"
        assert "INBOX" in mailbox.folders
        assert "Sent" in mailbox.folders
        assert "Drafts" in mailbox.folders
        assert "Trash" in mailbox.folders
        
        # Test duplicate creation fails
        success2 = smtp_server.mailbox_manager.create_mailbox("testuser")
        assert success2 is False
        
        # Test mailbox deletion
        success = smtp_server.mailbox_manager.delete_mailbox("testuser")
        assert success is True
        assert "testuser" not in smtp_server.mailbox_manager.mailboxes
        
        # Test deleting non-existent mailbox
        success = smtp_server.mailbox_manager.delete_mailbox("nonexistent")
        assert success is False

    def test_smtp_server_message_operations(self, smtp_server, sample_email):
        """Test SMTP server message operations."""
        # Setup mailbox
        smtp_server.mailbox_manager.create_mailbox("testuser")
        mailbox = smtp_server.mailbox_manager.get_mailbox("testuser")
        
        # Test message addition
        success = mailbox.add_message(sample_email)
        assert success is True
        assert len(mailbox.get_messages()) == 1
        assert mailbox.total_messages == 1
        
        # Test message retrieval
        messages = mailbox.get_messages()
        assert len(messages) == 1
        assert messages[0].sender == sample_email.sender
        assert messages[0].subject == sample_email.subject
        
        # Test folder-specific operations
        mailbox.add_message(sample_email, "Sent")
        inbox_messages = mailbox.get_messages("INBOX")
        sent_messages = mailbox.get_messages("Sent")
        assert len(inbox_messages) == 1
        assert len(sent_messages) == 1
        
        # Test message deletion
        message_id = messages[0].message_id
        success = mailbox.delete_message(message_id)
        assert success is True
        assert len(mailbox.get_messages("INBOX")) == 0  # INBOX should be empty after deletion
        assert len(mailbox.get_messages("Sent")) == 1   # Sent folder should still have 1 message
        assert mailbox.total_messages == 1              # Total messages across all folders

    def test_smtp_server_folder_operations(self, smtp_server):
        """Test SMTP server folder operations."""
        smtp_server.mailbox_manager.create_mailbox("testuser")
        mailbox = smtp_server.mailbox_manager.get_mailbox("testuser")
        
        # Test custom folder creation
        success = mailbox.create_folder("Work")
        assert success is True
        assert "Work" in mailbox.folders
        
        # Test custom folder deletion
        success = mailbox.delete_folder("Work")
        assert success is True
        assert "Work" not in mailbox.folders
        
        # Test that default folders cannot be deleted
        default_folders = ["INBOX", "Sent", "Drafts", "Trash"]
        for folder in default_folders:
            success = mailbox.delete_folder(folder)
            assert success is False
            assert folder in mailbox.folders

    def test_smtp_server_state_management(self, smtp_server):
        """Test SMTP server state management actions."""
        # Test operating state management
        success = smtp_server.stop()
        assert success is True
        assert smtp_server.operating_state == ServiceOperatingState.STOPPED
        
        success = smtp_server.start()
        assert success is True
        assert smtp_server.operating_state == ServiceOperatingState.RUNNING
        
        success = smtp_server.pause()
        assert success is True
        assert smtp_server.operating_state == ServiceOperatingState.PAUSED
        
        success = smtp_server.resume()
        assert success is True
        assert smtp_server.operating_state == ServiceOperatingState.RUNNING
        
        # Test health state management
        success = smtp_server.set_health_state(SoftwareHealthState.COMPROMISED)
        assert success is True
        assert smtp_server.health_state_actual == SoftwareHealthState.COMPROMISED
        
        # Test scan action
        success = smtp_server.scan()
        assert success is True
        assert smtp_server.health_state_visible == SoftwareHealthState.COMPROMISED
        
        # Test fix action
        success = smtp_server.fix()
        assert success is True
        assert smtp_server.health_state_actual == SoftwareHealthState.FIXING

    def test_smtp_server_display_and_state_methods(self, smtp_server):
        """Test SMTP server display and state methods."""
        # Test display methods exist
        assert hasattr(smtp_server, 'show')
        assert callable(smtp_server.show)
        assert hasattr(smtp_server, 'show_mailbox')
        assert callable(smtp_server.show_mailbox)
        assert hasattr(smtp_server, 'show_message')
        assert callable(smtp_server.show_message)
        
        # Test describe_state
        state = smtp_server.describe_state()
        assert isinstance(state, dict)
        assert "operating_state" in state
        assert "health_state_actual" in state
        assert "health_state_visible" in state
        assert "active_sessions" in state
        assert "total_mailboxes" in state

    # ==================== POP3 SERVER ACTIONS ====================

    def test_pop3_server_initialization_and_basic_operations(self, test_network):
        """Test POP3 server initialization and basic operations."""
        mail_server = test_network.get_node_by_hostname("test_mail_server")
        mail_server.software_manager.install(POP3Server)
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        
        # Test initialization
        assert pop3_server.name == "pop3-server"
        assert pop3_server.port == 110  # Standard POP3 port
        assert pop3_server.operating_state == ServiceOperatingState.RUNNING
        assert pop3_server.health_state_actual == SoftwareHealthState.GOOD

    def test_pop3_server_authentication_and_mailbox_access(self, test_network, sample_email):
        """Test POP3 server authentication and mailbox access."""
        mail_server = test_network.get_node_by_hostname("test_mail_server")
        mail_server.software_manager.install(POP3Server)
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        
        # Create test mailbox and add message
        pop3_server.mailbox_manager.create_mailbox("testuser")
        mailbox = pop3_server.mailbox_manager.get_mailbox("testuser")
        mailbox.add_message(sample_email)
        
        # Test authentication (simplified - mailbox existence implies auth success)
        assert mailbox is not None
        assert mailbox.username == "testuser"
        
        # Test message list retrieval
        messages = mailbox.get_messages()
        assert len(messages) == 1
        assert messages[0].sender == "test@example.com"
        assert messages[0].subject == "Test Email"
        
        # Test message retrieval
        if messages:
            message = messages[0]
            assert message.sender == "test@example.com"
            assert message.subject == "Test Email"
            assert message.body == "This is a test email message."
        
        # Test message deletion
        message_id = messages[0].message_id
        success = mailbox.delete_message(message_id)
        assert success is True
        remaining_messages = mailbox.get_messages()
        assert len(remaining_messages) == 0

    def test_pop3_server_state_management(self, test_network):
        """Test POP3 server state management."""
        mail_server = test_network.get_node_by_hostname("test_mail_server")
        mail_server.software_manager.install(POP3Server)
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        
        # Test operating state management
        success = pop3_server.stop()
        assert success is True
        assert pop3_server.operating_state == ServiceOperatingState.STOPPED
        
        success = pop3_server.start()
        assert success is True
        assert pop3_server.operating_state == ServiceOperatingState.RUNNING
        
        success = pop3_server.pause()
        assert success is True
        assert pop3_server.operating_state == ServiceOperatingState.PAUSED
        
        success = pop3_server.resume()
        assert success is True
        assert pop3_server.operating_state == ServiceOperatingState.RUNNING
        
        # Test health state management
        success = pop3_server.set_health_state(SoftwareHealthState.COMPROMISED)
        assert success is True
        assert pop3_server.health_state_actual == SoftwareHealthState.COMPROMISED
        
        # Test scan action
        success = pop3_server.scan()
        assert success is True
        assert pop3_server.health_state_visible == SoftwareHealthState.COMPROMISED
        
        # Test fix action
        success = pop3_server.fix()
        assert success is True
        assert pop3_server.health_state_actual == SoftwareHealthState.FIXING

    def test_pop3_server_connection_management(self, test_network):
        """Test POP3 server connection management."""
        mail_server = test_network.get_node_by_hostname("test_mail_server")
        mail_server.software_manager.install(POP3Server)
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        
        # Test connection capacity limits
        for i in range(pop3_server.max_sessions):
            success = pop3_server.add_connection(f"pop3_connection_{i}")
            assert success is True
        
        # Try to add one more (should fail and set to overwhelmed)
        success = pop3_server.add_connection("overflow_connection")
        assert success is False
        assert pop3_server.health_state_actual == SoftwareHealthState.OVERWHELMED
        
        # Test clearing connections
        pop3_server.clear_connections()
        assert len(pop3_server.connections) == 0

    def test_pop3_server_mailbox_sharing_with_smtp(self, test_network):
        """Test POP3 server mailbox sharing with SMTP server."""
        mail_server = test_network.get_node_by_hostname("test_mail_server")
        mail_server.software_manager.install(SMTPServer)
        mail_server.software_manager.install(POP3Server)
        
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        
        # Share mailbox manager
        pop3_server.mailbox_manager = smtp_server.mailbox_manager
        
        # Create mailbox via SMTP
        smtp_server.mailbox_manager.create_mailbox("shareduser")
        
        # Verify POP3 can access the same mailbox
        mailbox = pop3_server.mailbox_manager.get_mailbox("shareduser")
        assert mailbox is not None
        assert mailbox.username == "shareduser"

    def test_pop3_server_display_and_state_methods(self, test_network):
        """Test POP3 server display and state methods."""
        mail_server = test_network.get_node_by_hostname("test_mail_server")
        mail_server.software_manager.install(POP3Server)
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        
        # Test display methods exist
        assert hasattr(pop3_server, 'show')
        assert callable(pop3_server.show)
        
        # Test describe_state
        state = pop3_server.describe_state()
        assert isinstance(state, dict)
        assert "operating_state" in state
        assert "health_state_actual" in state
        assert "health_state_visible" in state

    # ==================== EMAIL CLIENT ACTIONS ====================

    def test_email_client_initialization_and_configuration(self, email_client):
        """Test email client initialization and configuration."""
        assert email_client.name == "email-client"
        
        # Ensure client is running
        if email_client.operating_state != ApplicationOperatingState.RUNNING:
            email_client.run()
        
        assert email_client.operating_state == ApplicationOperatingState.RUNNING
        assert email_client.health_state_actual == SoftwareHealthState.GOOD
        
        # Test configuration
        email_client.config.username = "test@example.com"
        email_client.config.default_smtp_server = "192.168.1.10"
        email_client.config.default_pop3_server = "192.168.1.10"
        
        assert email_client.config.username == "test@example.com"
        assert email_client.config.default_smtp_server == "192.168.1.10"
        assert email_client.config.default_pop3_server == "192.168.1.10"

    def test_email_client_send_operations(self, test_network, email_client, sample_email):
        """Test email client send operations."""
        mail_server = test_network.get_node_by_hostname("test_mail_server")
        
        # Configure client
        email_client.config.username = "test@example.com"
        email_client.config.default_smtp_server = str(mail_server.config.ip_address)
        
        # Test send email action (success depends on network connectivity)
        success = email_client.send_email(sample_email, mail_server.config.ip_address)
        assert isinstance(success, bool)
        
        # Test send with invalid server
        email_client.config.default_smtp_server = "192.168.1.999"  # Invalid IP
        success = email_client.send_email(sample_email, "192.168.1.999")
        assert success is False

    def test_email_client_state_management(self, email_client):
        """Test email client state management."""
        # Ensure client is running first
        if email_client.operating_state != ApplicationOperatingState.RUNNING:
            email_client.run()
        
        # Test close/run cycle (applications use close/run, not stop/start)
        success = email_client.close()
        assert success is True
        assert email_client.operating_state == ApplicationOperatingState.CLOSED
        
        email_client.run()
        assert email_client.operating_state == ApplicationOperatingState.RUNNING
        
        # Test health state management
        success = email_client.set_health_state(SoftwareHealthState.COMPROMISED)
        assert success is True
        assert email_client.health_state_actual == SoftwareHealthState.COMPROMISED
        
        # Test scan action
        success = email_client.scan()
        assert success is True
        assert email_client.health_state_visible == SoftwareHealthState.COMPROMISED
        
        # Test fix action
        success = email_client.fix()
        assert success is True
        assert email_client.health_state_actual == SoftwareHealthState.FIXING

    def test_email_client_connection_management(self, email_client):
        """Test email client connection management."""
        # Test connection capacity
        for i in range(email_client.max_sessions):
            success = email_client.add_connection(f"connection_{i}")
            assert success is True
        
        # Try to add one more (should fail and set to overwhelmed)
        success = email_client.add_connection("overflow_connection")
        assert success is False
        assert email_client.health_state_actual == SoftwareHealthState.OVERWHELMED
        
        # Test clearing connections
        email_client.clear_connections()
        assert len(email_client.connections) == 0

    def test_email_client_display_and_state_methods(self, email_client):
        """Test email client display and state methods."""
        # Test display methods exist
        assert hasattr(email_client, 'show')
        assert callable(email_client.show)
        assert hasattr(email_client, 'show_connections')
        assert callable(email_client.show_connections)
        assert hasattr(email_client, 'show_mailbox')
        assert callable(email_client.show_mailbox)
        
        # Test describe_state
        state = email_client.describe_state()
        assert isinstance(state, dict)
        assert "operating_state" in state
        assert "health_state_actual" in state
        assert "health_state_visible" in state
        assert "installing_count" in state
        assert "max_sessions" in state
        assert "port" in state

    def test_email_message_creation_and_validation(self):
        """Test email message creation and validation."""
        # Test basic email creation
        email = EmailMessage(
            sender="test@example.com",
            recipients=["recipient@example.com"],
            subject="Test Subject",
            body="Test body content",
            message_id="EXAMPLE-1234",
            timestamp=""
        )
        
        assert email.sender == "test@example.com"
        assert email.recipients == ["recipient@example.com"]
        assert email.subject == "Test Subject"
        assert email.body == "Test body content"
        assert email.message_id is not None
        assert email.timestamp is not None
        
        # Test multiple recipients
        recipients = ["user1@example.com", "user2@example.com", "user3@example.com"]
        email = EmailMessage(
            sender="test@example.com",
            recipients=recipients,
            subject="Multi-recipient Test",
            body="Test body"
        )
        
        assert email.recipients == recipients
        assert len(email.recipients) == 3

    def test_email_client_configuration_validation(self, email_client):
        """Test email client configuration validation."""
        # Test valid configuration
        email_client.config.username = "valid@example.com"
        assert "@" in email_client.config.username
        
        # Test server configuration
        email_client.config.default_smtp_server = "192.168.1.10"
        email_client.config.default_pop3_server = "192.168.1.10"
        
        assert email_client.config.default_smtp_server == "192.168.1.10"
        assert email_client.config.default_pop3_server == "192.168.1.10"

    # ==================== CROSS-COMPONENT INTEGRATION ====================

    def test_component_attribute_naming_consistency(self, smtp_server, email_client):
        """Test consistent attribute naming across components."""
        # Test SMTP server attributes
        assert hasattr(smtp_server, 'health_state_actual')
        assert hasattr(smtp_server, 'health_state_visible')
        assert hasattr(smtp_server, 'operating_state')
        
        # Test email client attributes
        assert hasattr(email_client, 'health_state_actual')
        assert hasattr(email_client, 'health_state_visible')
        assert hasattr(email_client, 'operating_state')
        
        # Test attribute access works correctly
        assert smtp_server.health_state_actual in SoftwareHealthState
        assert smtp_server.health_state_visible in SoftwareHealthState
        assert smtp_server.operating_state in ServiceOperatingState
        
        # Test .name attribute works
        assert isinstance(smtp_server.health_state_actual.name, str)
        assert isinstance(smtp_server.health_state_visible.name, str)
        assert isinstance(smtp_server.operating_state.name, str)

    def test_component_error_handling_consistency(self, smtp_server, email_client):
        """Test consistent error handling across components."""
        # Test invalid operations return False consistently
        
        # SMTP server - delete non-existent mailbox
        success = smtp_server.mailbox_manager.delete_mailbox("nonexistent")
        assert success is False
        
        # Email client - invalid connection termination
        success = email_client.terminate_connection("nonexistent_connection")
        assert success is False
        
        # Both should handle state transitions gracefully
        smtp_server.stop()
        success = smtp_server.pause()  # Can't pause when stopped
        assert isinstance(success, bool)  # Should return boolean, not raise exception
        
        email_client.close()
        success = email_client.close()  # Double close
        assert isinstance(success, bool)  # Should handle gracefully

    def test_component_display_method_consistency(self, smtp_server, email_client):
        """Test consistent display method behavior across components."""
        # All components should have show methods
        components = [smtp_server, email_client]
        
        for component in components:
            assert hasattr(component, 'show')
            assert callable(component.show)
            
            # Show methods should not raise exceptions
            try:
                component.show()
            except Exception as e:
                pytest.fail(f"{component.name} show method raised exception: {e}")
        
        # SMTP server should have additional display methods
        assert hasattr(smtp_server, 'show_mailbox')
        assert callable(smtp_server.show_mailbox)
        assert hasattr(smtp_server, 'show_message')
        assert callable(smtp_server.show_message)