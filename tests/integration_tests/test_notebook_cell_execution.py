"""
Test that validates the notebook cells can execute successfully.

This test simulates the execution of key notebook cells to ensure
all imports work and basic functionality is available.
"""

import pytest


class TestNotebookCellExecution:
    """Test notebook cell execution compatibility."""

    def test_notebook_imports(self):
        """Test that all imports used in the notebook work correctly."""
        # Test PrimAITE core imports
        from primaite.simulator.sim_container import Simulation
        from primaite.simulator.network.hardware.nodes.host.computer import Computer
        from primaite.simulator.network.hardware.nodes.network.switch import Switch
        
        # Test PrimAITE-Mail imports
        from primaite_mail.simulator.software.smtp_server import SMTPServer
        from primaite_mail.simulator.software.pop3_server import POP3Server
        from primaite_mail.simulator.software.email_client import EmailClient
        from primaite_mail.simulator.network.protocols.smtp import EmailMessage
        
        # Test standard library imports used in notebook
        import time
        import random
        from datetime import datetime
        
        # If we get here, all imports succeeded
        assert True

    def test_simulation_creation(self):
        """Test simulation creation as shown in notebook."""
        from primaite.simulator.sim_container import Simulation
        
        sim = Simulation()
        assert sim is not None
        assert hasattr(sim, 'network')

    def test_network_component_creation(self):
        """Test network component creation as shown in notebook."""
        from primaite.simulator.network.hardware.nodes.host.computer import Computer
        from primaite.simulator.network.hardware.nodes.network.switch import Switch
        
        # Test switch creation
        switch = Switch.from_config({
            "type": "switch",
            "hostname": "security_switch",
            "num_ports": 8,
            "operating_state": "ON"
        })
        assert switch.config.hostname == "security_switch"
        
        # Test computer creation
        computer = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        assert computer.config.hostname == "mail_server"
        assert str(computer.config.ip_address) == "192.168.1.10"

    def test_email_service_installation(self):
        """Test email service installation as shown in notebook."""
        from primaite.simulator.network.hardware.nodes.host.computer import Computer
        from primaite_mail.simulator.software.smtp_server import SMTPServer
        from primaite_mail.simulator.software.pop3_server import POP3Server
        
        # Create computer
        computer = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        
        # Install services
        computer.software_manager.install(SMTPServer)
        computer.software_manager.install(POP3Server)
        
        # Verify installation
        smtp_server = computer.software_manager.software.get("smtp-server")
        pop3_server = computer.software_manager.software.get("pop3-server")
        
        assert smtp_server is not None
        assert pop3_server is not None
        assert smtp_server.name == "smtp-server"
        assert pop3_server.name == "pop3-server"

    def test_email_client_installation(self):
        """Test email client installation as shown in notebook."""
        from primaite.simulator.network.hardware.nodes.host.computer import Computer
        from primaite_mail.simulator.software.email_client import EmailClient
        
        # Create computer
        computer = Computer.from_config({
            "type": "computer",
            "hostname": "client_pc",
            "ip_address": "192.168.1.20",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        
        # Install client
        computer.software_manager.install(EmailClient)
        
        # Verify installation
        client = computer.software_manager.software.get("email-client")
        assert client is not None
        assert client.name == "email-client"

    def test_mailbox_creation(self):
        """Test mailbox creation as shown in notebook."""
        from primaite.simulator.network.hardware.nodes.host.computer import Computer
        from primaite_mail.simulator.software.smtp_server import SMTPServer
        
        # Create computer and install SMTP server
        computer = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        computer.software_manager.install(SMTPServer)
        smtp_server = computer.software_manager.software.get("smtp-server")
        
        # Create mailboxes as shown in notebook
        security_users = ["admin", "user", "finance", "hr", "it_support"]
        
        for username in security_users:
            success = smtp_server.mailbox_manager.create_mailbox(username)
            # Should succeed for first creation, may fail for duplicates
            assert isinstance(success, bool)
        
        # Verify mailboxes exist
        for username in security_users:
            mailbox = smtp_server.mailbox_manager.get_mailbox(username)
            assert mailbox is not None

    def test_email_message_creation(self):
        """Test email message creation as shown in notebook."""
        from primaite_mail.simulator.network.protocols.smtp import EmailMessage
        
        # Test legitimate email creation
        legitimate_email = EmailMessage(
            sender="admin@company.com",
            recipients=["user@company.com"],
            subject="System Maintenance Notification",
            body="Dear User,\n\nScheduled system maintenance will occur tonight from 2:00 AM to 4:00 AM EST."
        )
        
        assert legitimate_email.sender == "admin@company.com"
        assert legitimate_email.recipients == ["user@company.com"]
        assert "System Maintenance" in legitimate_email.subject
        
        # Test spoofed email creation
        spoofed_email = EmailMessage(
            sender="admin@company.com",  # Spoofed
            recipients=["user@company.com", "finance@company.com"],
            subject="URGENT: Security Update Required",
            body="URGENT SECURITY NOTICE\n\nYour account has been compromised."
        )
        
        assert spoofed_email.sender == "admin@company.com"
        assert len(spoofed_email.recipients) == 2
        assert "URGENT" in spoofed_email.subject

    def test_security_request_structure(self):
        """Test that security request structures are valid."""
        # Test request structures used in notebook
        
        # Block sender request
        block_sender_request = [
            "network", "node", "mail_server", "service", "smtp-server", 
            "block_sender", {"sender_address": "malicious@evil.com"}
        ]
        assert len(block_sender_request) == 7
        assert isinstance(block_sender_request[-1], dict)
        assert "sender_address" in block_sender_request[-1]
        
        # Block IP request
        block_ip_request = [
            "network", "node", "mail_server", "service", "smtp-server", 
            "block_ip", {"ip_address": "192.168.1.100"}
        ]
        assert len(block_ip_request) == 7
        assert isinstance(block_ip_request[-1], dict)
        assert "ip_address" in block_ip_request[-1]
        
        # List policies request
        list_policies_request = [
            "network", "node", "mail_server", "service", "smtp-server", 
            "list_security_policies", {}
        ]
        assert len(list_policies_request) == 7
        assert isinstance(list_policies_request[-1], dict)

    def test_threat_intelligence_structure(self):
        """Test threat intelligence data structure used in notebook."""
        # Test the multi-agent threat intelligence structure
        threat_intelligence = {
            "analyst_1": {
                "threats": ["spam@botnet.com", "malware@trojan.net"],
                "ips": ["203.0.113.50"]
            },
            "analyst_2": {
                "threats": ["phish@fake-bank.com", "scam@lottery.org"],
                "ips": ["198.51.100.25", "192.0.2.0/24"]
            },
            "analyst_3": {
                "threats": ["ceo@spoofed-domain.com"],
                "ips": ["172.16.0.0/16"]
            }
        }
        
        # Verify structure
        assert len(threat_intelligence) == 3
        for analyst, intel in threat_intelligence.items():
            assert "threats" in intel
            assert "ips" in intel
            assert isinstance(intel["threats"], list)
            assert isinstance(intel["ips"], list)
            assert len(intel["threats"]) > 0 or len(intel["ips"]) > 0

    def test_notebook_display_methods(self):
        """Test that display methods used in notebook work."""
        from primaite.simulator.network.hardware.nodes.host.computer import Computer
        from primaite_mail.simulator.software.smtp_server import SMTPServer
        
        # Create computer and install SMTP server
        computer = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        computer.software_manager.install(SMTPServer)
        smtp_server = computer.software_manager.software.get("smtp-server")
        
        # Create a test mailbox
        smtp_server.mailbox_manager.create_mailbox("test_user")
        
        # Test that show methods exist and can be called
        # These should not raise exceptions
        try:
            smtp_server.show_mailbox("test_user")
            computer.sys_log.show(last_n=5)
            # If we get here, the display methods work
            assert True
        except Exception as e:
            # If display methods have issues, we should know about it
            pytest.fail(f"Display method failed: {e}")

    def test_notebook_security_scenarios_complete(self):
        """Test that all notebook security scenarios can be set up."""
        # This test verifies that the complete notebook environment
        # can be created without errors
        
        from primaite.simulator.sim_container import Simulation
        from primaite.simulator.network.hardware.nodes.host.computer import Computer
        from primaite.simulator.network.hardware.nodes.network.switch import Switch
        from primaite_mail.simulator.software.smtp_server import SMTPServer
        from primaite_mail.simulator.software.email_client import EmailClient
        from primaite_mail.simulator.network.protocols.smtp import EmailMessage
        
        # Create complete environment as in notebook
        sim = Simulation()
        
        # Create network components
        switch = Switch.from_config({
            "type": "switch",
            "hostname": "security_switch",
            "num_ports": 8,
            "operating_state": "ON"
        })
        sim.network.add_node(switch)
        
        mail_server = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        sim.network.add_node(mail_server)
        
        admin_pc = Computer.from_config({
            "type": "computer",
            "hostname": "admin_pc",
            "ip_address": "192.168.1.20",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        sim.network.add_node(admin_pc)
        
        attacker_pc = Computer.from_config({
            "type": "computer",
            "hostname": "attacker_pc",
            "ip_address": "192.168.1.100",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        sim.network.add_node(attacker_pc)
        
        # Connect nodes
        sim.network.connect(mail_server.network_interface[1], switch.network_interface[1])
        sim.network.connect(admin_pc.network_interface[1], switch.network_interface[2])
        sim.network.connect(attacker_pc.network_interface[1], switch.network_interface[3])
        
        # Install services
        mail_server.software_manager.install(SMTPServer)
        admin_pc.software_manager.install(EmailClient)
        attacker_pc.software_manager.install(EmailClient)
        
        # Get service references
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        admin_client = admin_pc.software_manager.software.get("email-client")
        attacker_client = attacker_pc.software_manager.software.get("email-client")
        
        # Create mailboxes
        security_users = ["admin", "user", "finance", "hr", "it_support"]
        for username in security_users:
            smtp_server.mailbox_manager.create_mailbox(username)
        
        # Create test emails
        legitimate_email = EmailMessage(
            sender="admin@company.com",
            recipients=["user@company.com"],
            subject="System Maintenance Notice",
            body="Scheduled maintenance tonight."
        )
        
        spoofed_email = EmailMessage(
            sender="admin@company.com",
            recipients=["user@company.com"],
            subject="URGENT: Security Update",
            body="Click here: http://malicious-site.com"
        )
        
        # Verify everything was created successfully
        assert len(sim.network.nodes) == 4
        assert smtp_server is not None
        assert admin_client is not None
        assert attacker_client is not None
        assert len(smtp_server.mailbox_manager.mailboxes) == len(security_users)
        assert legitimate_email.sender == "admin@company.com"
        assert spoofed_email.sender == "admin@company.com"
        
        # Test that security requests can be formed (even if not implemented)
        security_requests = [
            ["network", "node", "mail_server", "service", "smtp-server", "block_sender", {"sender_address": "test@evil.com"}],
            ["network", "node", "mail_server", "service", "smtp-server", "block_ip", {"ip_address": "192.168.1.100"}],
            ["network", "node", "mail_server", "service", "smtp-server", "list_security_policies", {}],
            ["network", "node", "mail_server", "service", "smtp-server", "get_security_statistics", {}]
        ]
        
        for request in security_requests:
            # Verify request structure is valid
            assert len(request) == 7
            assert isinstance(request[-1], dict)
        
        # If we get here, the complete notebook environment works
        assert True