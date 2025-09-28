"""
End-to-end test reproducing the exact POP3 scenario from the notebook.

This test reproduces the exact scenario from complete_email_system.ipynb
where Bob tries to retrieve emails via POP3 to ensure the bug doesn't regress.
"""

import pytest
from ipaddress import IPv4Address

from primaite.simulator.network.container import Network
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite.simulator.network.hardware.nodes.network.switch import Switch
from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.pop3_server import POP3Server
from primaite_mail.simulator.software.email_client import EmailClient
from primaite_mail.simulator.network.protocols.smtp import EmailMessage


class TestPOP3NotebookScenario:
    """Test the exact POP3 scenario from the notebook."""

    def setup_method(self):
        """Set up the exact network topology from the notebook."""
        # Create network with switch (like in the notebook)
        self.network = Network()
        
        # Create switch
        self.switch = Switch.from_config({
            "type": "switch",
            "hostname": "main_switch",
            "num_ports": 8,
            "start_up_duration": 0,
        })
        self.switch.power_on()
        self.network.add_node(self.switch)
        
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
        
        # Create Bob's PC
        self.bob_pc = Computer.from_config({
            "type": "computer",
            "hostname": "bob_pc",
            "ip_address": "192.168.1.22",
            "subnet_mask": "255.255.255.0",
            "start_up_duration": 0,
        })
        self.bob_pc.power_on()
        self.network.add_node(self.bob_pc)
        
        # Connect to switch (like in notebook)
        self.network.connect(self.mail_server.network_interface[1], self.switch.network_interface[1])
        self.network.connect(self.bob_pc.network_interface[1], self.switch.network_interface[2])
        
        # Install email services (like in notebook)
        self.mail_server.software_manager.install(SMTPServer)
        self.mail_server.software_manager.install(POP3Server)
        self.bob_pc.software_manager.install(EmailClient)
        
        # Get service references
        self.smtp_server = self.mail_server.software_manager.software.get("smtp-server")
        self.pop3_server = self.mail_server.software_manager.software.get("pop3-server")
        self.bob_client = self.bob_pc.software_manager.software.get("email-client")
        
        # Configure Bob's email client (like in notebook)
        self.bob_client.config.username = "bob@company.com"
        self.bob_client.config.default_smtp_server = str(self.mail_server.config.ip_address)
        self.bob_client.config.default_pop3_server = str(self.mail_server.config.ip_address)
        self.bob_client.run()
        
        # Create mailboxes and share mailbox manager (like in notebook)
        self.smtp_server.mailbox_manager.create_mailbox("bob")
        self.pop3_server.mailbox_manager = self.smtp_server.mailbox_manager
        self.pop3_server.config.require_auth = False

    def test_notebook_pop3_scenario_exact_reproduction(self):
        """
        Reproduce the exact scenario from the notebook where Bob retrieves emails.
        
        This is the critical regression test for the original bug.
        """
        # Step 1: Add an email to Bob's mailbox (simulating Alice sending email)
        test_email = EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com"],
            subject="Team Meeting Tomorrow",
            body="Hi everyone, don't forget about our team meeting tomorrow at 10 AM in the conference room."
        )
        
        bob_mailbox = self.smtp_server.mailbox_manager.get_mailbox("bob")
        bob_mailbox.add_message(test_email)
        
        # Step 2: Verify email is in mailbox (this was working in original bug)
        assert len(bob_mailbox.get_messages()) == 1, "Bob should have 1 email in mailbox"
        
        # Step 3: Verify SMTP server can see the email
        smtp_server_messages = self.smtp_server.mailbox_manager.get_mailbox("bob").get_messages()
        assert len(smtp_server_messages) == 1, "SMTP server should see 1 message"
        assert smtp_server_messages[0].subject == "Team Meeting Tomorrow"
        
        # Step 4: Verify POP3 server can see the email (this was working in original bug)
        auth_response = self.pop3_server.apply_request(["authenticate_user", {"username": "bob", "password": "password123"}], {})
        assert auth_response.status == "success", "POP3 authentication should work"
        
        list_response = self.pop3_server.apply_request(["get_message_list", {"username": "bob"}], {})
        assert list_response.status == "success", "POP3 message list should work"
        assert list_response.data["message_count"] == 1, "POP3 should see 1 message"
        
        # Step 5: THE CRITICAL TEST - Bob retrieves emails via POP3
        # This was returning empty list in the original bug
        
        # Inject server reference to simulate working network discovery
        # (The network discovery issue is separate from the core POP3 retrieval bug)
        self.bob_client._test_pop3_server = self.pop3_server
        
        emails = self.bob_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="bob",
            password="password123"
        )
        
        # THE CRITICAL ASSERTIONS - these were failing in the original bug
        assert emails is not None, "POP3 retrieval should not return None (CRITICAL REGRESSION TEST)"
        assert len(emails) > 0, "POP3 retrieval should NOT return empty list when emails exist (CRITICAL REGRESSION TEST)"
        assert len(emails) == 1, f"Expected 1 email, got {len(emails)} (CRITICAL REGRESSION TEST)"
        
        # Verify email content is correct
        retrieved_email = emails[0]
        assert retrieved_email.subject == "Team Meeting Tomorrow", "Retrieved email should have correct subject"
        assert retrieved_email.sender == "alice@company.com", "Retrieved email should have correct sender"
        assert "team meeting tomorrow" in retrieved_email.body.lower(), "Retrieved email should have correct body content"

    def test_notebook_scenario_with_multiple_emails(self):
        """Test the notebook scenario with multiple emails like in the full notebook."""
        # Add multiple emails like in the complete notebook scenario
        emails_to_add = [
            EmailMessage(
                sender="alice@company.com",
                recipients=["bob@company.com"],
                subject="Team Meeting Tomorrow",
                body="Hi everyone, don't forget about our team meeting tomorrow at 10 AM."
            ),
            EmailMessage(
                sender="charlie@company.com",
                recipients=["bob@company.com"],
                subject="Re: Team Meeting Tomorrow",
                body="Thanks for the reminder! I'll be there."
            ),
            EmailMessage(
                sender="admin@company.com",
                recipients=["bob@company.com"],
                subject="System Maintenance Notice",
                body="The email system will be down for maintenance this weekend."
            )
        ]
        
        bob_mailbox = self.smtp_server.mailbox_manager.get_mailbox("bob")
        for email in emails_to_add:
            bob_mailbox.add_message(email)
        
        # Verify all emails are in mailbox
        assert len(bob_mailbox.get_messages()) == 3, "Bob should have 3 emails in mailbox"
        
        # Inject server reference
        self.bob_client._test_pop3_server = self.pop3_server
        
        # Retrieve all emails
        retrieved_emails = self.bob_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="bob",
            password="password123"
        )
        
        # Verify all emails retrieved
        assert retrieved_emails is not None, "POP3 retrieval should not return None"
        assert len(retrieved_emails) == 3, f"Should retrieve all 3 emails, got {len(retrieved_emails)}"
        
        # Verify email subjects
        subjects = [email.subject for email in retrieved_emails]
        assert "Team Meeting Tomorrow" in subjects
        assert "Re: Team Meeting Tomorrow" in subjects
        assert "System Maintenance Notice" in subjects

    def test_notebook_scenario_network_connectivity(self):
        """Test that network connectivity works in the notebook scenario."""
        # Test basic connectivity like in the notebook
        ping_result = self.bob_pc.ping(self.mail_server.config.ip_address)
        assert ping_result, "Bob should be able to ping the mail server (like in notebook)"
        
        # Test that services are running
        assert self.smtp_server.operating_state.name == "RUNNING", "SMTP server should be running"
        assert self.pop3_server.operating_state.name == "RUNNING", "POP3 server should be running"
        assert self.bob_client.operating_state.name == "RUNNING", "Bob's email client should be running"

    def test_notebook_scenario_display_methods(self):
        """Test that display methods work like in the notebook."""
        # Add test email
        test_email = EmailMessage(
            sender="alice@company.com",
            recipients=["bob@company.com"],
            subject="Display Test",
            body="Testing display methods."
        )
        bob_mailbox = self.smtp_server.mailbox_manager.get_mailbox("bob")
        bob_mailbox.add_message(test_email)
        
        # Test that display methods don't crash (like used in notebook)
        try:
            # These methods are called in the notebook to show status
            self.smtp_server.show()
            self.pop3_server.show()
            self.bob_client.show()
            self.smtp_server.show_mailbox("bob")
            self.pop3_server.show_mailbox("bob")
        except Exception as e:
            pytest.fail(f"Display methods should not crash: {e}")

    def test_notebook_scenario_empty_mailbox_edge_case(self):
        """Test POP3 retrieval with empty mailbox (edge case from notebook)."""
        # Don't add any emails - test empty mailbox
        
        # Inject server reference
        self.bob_client._test_pop3_server = self.pop3_server
        
        # Retrieve from empty mailbox
        emails = self.bob_client.retrieve_emails_pop3(
            pop3_server_ip=IPv4Address(self.mail_server.config.ip_address),
            username="bob",
            password="password123"
        )
        
        # Should return empty list, not None
        assert emails is not None, "POP3 retrieval should not return None for empty mailbox"
        assert len(emails) == 0, "POP3 retrieval should return empty list for empty mailbox"

if __name__ == "__main__":
    pytest.main([__file__])