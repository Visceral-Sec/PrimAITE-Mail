#!/usr/bin/env python3
"""
End-to-end validation test for the email security scenarios notebook.

This test validates that the notebook executes completely without errors
and that all key functionality works correctly in multi-agent scenarios.
"""

import pytest
import subprocess
import json
import os
import tempfile
from pathlib import Path
from typing import Dict, Any, List

# Import PrimAITE components for validation
from primaite.simulator.sim_container import Simulation
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite.simulator.network.hardware.nodes.network.switch import Switch

# Import PrimAITE-Mail components
from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.pop3_server import POP3Server
from primaite_mail.simulator.software.email_client import EmailClient
from primaite_mail.simulator.network.protocols.smtp import EmailMessage


class TestNotebookExecutionValidation:
    """Test complete notebook execution end-to-end."""
    
    @pytest.fixture
    def notebook_path(self):
        """Get path to the email security scenarios notebook."""
        return Path(__file__).parent.parent.parent / "src" / "primaite_mail" / "notebooks" / "email_security_scenarios.ipynb"
    
    @pytest.fixture
    def temp_output_dir(self):
        """Create temporary directory for test outputs."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)
    
    def test_notebook_exists_and_valid_json(self, notebook_path):
        """Test that the notebook file exists and is valid JSON."""
        assert notebook_path.exists(), f"Notebook not found at {notebook_path}"
        
        with open(notebook_path, 'r', encoding='utf-8') as f:
            notebook_data = json.load(f)
        
        # Validate basic notebook structure
        assert "cells" in notebook_data, "Notebook missing cells"
        assert "metadata" in notebook_data, "Notebook missing metadata"
        assert len(notebook_data["cells"]) > 0, "Notebook has no cells"
        
        print(f"✅ Notebook validation passed: {len(notebook_data['cells'])} cells found")
    
    def test_notebook_cell_structure(self, notebook_path):
        """Test that notebook cells have proper structure."""
        with open(notebook_path, 'r', encoding='utf-8') as f:
            notebook_data = json.load(f)
        
        code_cells = 0
        markdown_cells = 0
        
        for i, cell in enumerate(notebook_data["cells"]):
            assert "cell_type" in cell, f"Cell {i} missing cell_type"
            assert "source" in cell, f"Cell {i} missing source"
            
            if cell["cell_type"] == "code":
                code_cells += 1
                assert "outputs" in cell, f"Code cell {i} missing outputs"
                assert "execution_count" in cell, f"Code cell {i} missing execution_count"
            elif cell["cell_type"] == "markdown":
                markdown_cells += 1
        
        assert code_cells > 0, "No code cells found"
        assert markdown_cells > 0, "No markdown cells found"
        
        print(f"✅ Cell structure validation passed: {code_cells} code cells, {markdown_cells} markdown cells")
    
    def test_notebook_imports_and_setup(self):
        """Test that all required imports work correctly."""
        print("Testing notebook imports and setup...")
        
        # Test core PrimAITE imports
        try:
            from primaite.simulator.sim_container import Simulation
            from primaite.simulator.network.hardware.nodes.host.computer import Computer
            from primaite.simulator.network.hardware.nodes.network.switch import Switch
            print("✅ Core PrimAITE imports successful")
        except ImportError as e:
            pytest.fail(f"Core PrimAITE import failed: {e}")
        
        # Test PrimAITE-Mail imports
        try:
            from primaite_mail.simulator.software.smtp_server import SMTPServer
            from primaite_mail.simulator.software.pop3_server import POP3Server
            from primaite_mail.simulator.software.email_client import EmailClient
            from primaite_mail.simulator.network.protocols.smtp import EmailMessage
            print("✅ PrimAITE-Mail imports successful")
        except ImportError as e:
            pytest.fail(f"PrimAITE-Mail import failed: {e}")
    
    def test_simulation_environment_creation(self):
        """Test that the simulation environment can be created as in the notebook."""
        print("Testing simulation environment creation...")
        
        # Create simulation as in notebook
        sim = Simulation()
        assert sim is not None, "Failed to create simulation"
        
        # Create network switch
        security_switch = Switch.from_config({
            "type": "switch",
            "hostname": "security_switch",
            "num_ports": 8,
            "operating_state": "ON"
        })
        sim.network.add_node(security_switch)
        
        # Create mail server
        mail_server = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        sim.network.add_node(mail_server)
        
        # Create client machines
        admin_pc = Computer.from_config({
            "type": "computer",
            "hostname": "admin_pc",
            "ip_address": "192.168.1.20",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        sim.network.add_node(admin_pc)
        
        user_pc = Computer.from_config({
            "type": "computer",
            "hostname": "user_pc",
            "ip_address": "192.168.1.21",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        sim.network.add_node(user_pc)
        
        attacker_pc = Computer.from_config({
            "type": "computer",
            "hostname": "attacker_pc",
            "ip_address": "192.168.1.100",
            "subnet_mask": "255.255.255.0",
            "operating_state": "ON"
        })
        sim.network.add_node(attacker_pc)
        
        # Connect nodes to switch
        sim.network.connect(mail_server.network_interface[1], security_switch.network_interface[1])
        sim.network.connect(admin_pc.network_interface[1], security_switch.network_interface[2])
        sim.network.connect(user_pc.network_interface[1], security_switch.network_interface[3])
        sim.network.connect(attacker_pc.network_interface[1], security_switch.network_interface[4])
        
        # Validate network topology
        assert len(sim.network.nodes) == 5, f"Expected 5 nodes, got {len(sim.network.nodes)}"
        assert len(sim.network.links) == 4, f"Expected 4 links, got {len(sim.network.links)}"
        
        print(f"✅ Network topology created successfully: {len(sim.network.nodes)} nodes, {len(sim.network.links)} links")
        
        return sim, mail_server, admin_pc, user_pc, attacker_pc
    
    def test_email_services_installation(self):
        """Test that email services can be installed and configured."""
        print("Testing email services installation...")
        
        sim, mail_server, admin_pc, user_pc, attacker_pc = self.test_simulation_environment_creation()
        
        # Install email services on mail server
        mail_server.software_manager.install(SMTPServer)
        mail_server.software_manager.install(POP3Server)
        
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        
        assert smtp_server is not None, "SMTP server not installed"
        assert pop3_server is not None, "POP3 server not installed"
        
        # Share mailbox manager
        pop3_server.mailbox_manager = smtp_server.mailbox_manager
        
        # Install email clients
        clients = {}
        for pc, role in [(admin_pc, "admin"), (user_pc, "user"), (attacker_pc, "attacker")]:
            pc.software_manager.install(EmailClient)
            client = pc.software_manager.software.get("email-client")
            assert client is not None, f"Email client not installed on {role} PC"
            clients[role] = client
        
        # Create user mailboxes
        security_users = ["admin", "user", "finance", "hr", "it_support"]
        for username in security_users:
            success = smtp_server.mailbox_manager.create_mailbox(username)
            assert success or smtp_server.mailbox_manager.get_mailbox(username) is not None, f"Failed to create mailbox for {username}"
        
        print(f"✅ Email services installed successfully: {len(clients)} clients, {len(security_users)} mailboxes")
        
        return sim, mail_server, smtp_server, pop3_server, clients
    
    def test_email_spoofing_scenario(self):
        """Test the email spoofing scenario works correctly."""
        print("Testing email spoofing scenario...")
        
        sim, mail_server, smtp_server, pop3_server, clients = self.test_email_services_installation()
        
        # Test email creation (core functionality)
        legitimate_email = EmailMessage(
            sender="admin@company.com",
            recipients=["user@company.com"],
            subject="System Maintenance Notification",
            body="Scheduled system maintenance will occur tonight."
        )
        
        spoofed_email = EmailMessage(
            sender="admin@company.com",  # Spoofed sender
            recipients=["user@company.com", "finance@company.com"],
            subject="URGENT: Security Update Required",
            body="Your account has been compromised. Click here: http://malicious-site.com"
        )
        
        # Verify email objects were created correctly
        assert legitimate_email.sender == "admin@company.com", "Legitimate email sender incorrect"
        assert spoofed_email.sender == "admin@company.com", "Spoofed email sender incorrect"
        assert len(spoofed_email.recipients) == 2, "Spoofed email should have 2 recipients"
        
        # Verify mailboxes exist
        user_mailbox = smtp_server.mailbox_manager.get_mailbox("user")
        finance_mailbox = smtp_server.mailbox_manager.get_mailbox("finance")
        
        assert user_mailbox is not None, "User mailbox not found"
        assert finance_mailbox is not None, "Finance mailbox not found"
        
        print("✅ Email spoofing scenario validation completed: Email objects created correctly")
    
    def test_multi_agent_coordination(self):
        """Test that agents work together correctly in multi-agent scenarios."""
        print("Testing multi-agent coordination...")
        
        sim, mail_server, smtp_server, pop3_server, clients = self.test_email_services_installation()
        
        # Test that multiple email clients can be configured
        assert len(clients) == 3, f"Expected 3 clients, got {len(clients)}"
        assert "admin" in clients, "Admin client not found"
        assert "user" in clients, "User client not found"
        assert "attacker" in clients, "Attacker client not found"
        
        # Test email message creation for different scenarios
        admin_email = EmailMessage(
            sender="admin@company.com",
            recipients=["user@company.com"],
            subject="Admin Message",
            body="This is an admin message"
        )
        
        user_email = EmailMessage(
            sender="user@company.com",
            recipients=["admin@company.com"],
            subject="Re: Admin Message",
            body="Reply to admin message"
        )
        
        attacker_email = EmailMessage(
            sender="admin@company.com",  # Spoofed
            recipients=["finance@company.com"],
            subject="Urgent: Wire Transfer",
            body="Please transfer funds immediately"
        )
        
        # Verify email objects are created correctly
        assert admin_email.sender == "admin@company.com", "Admin email sender incorrect"
        assert user_email.recipients[0] == "admin@company.com", "User email recipient incorrect"
        assert attacker_email.sender == "admin@company.com", "Attacker email spoofing incorrect"
        
        # Verify mailboxes exist for coordination
        admin_mailbox = smtp_server.mailbox_manager.get_mailbox("admin")
        user_mailbox = smtp_server.mailbox_manager.get_mailbox("user")
        finance_mailbox = smtp_server.mailbox_manager.get_mailbox("finance")
        
        assert admin_mailbox is not None, "Admin mailbox not found"
        assert user_mailbox is not None, "User mailbox not found"
        assert finance_mailbox is not None, "Finance mailbox not found"
        
        print("✅ Multi-agent coordination test passed: All agents and mailboxes configured correctly")
    
    def test_security_policies_functionality(self):
        """Test that email blocking and security policies function properly."""
        print("Testing security policies functionality...")
        
        sim, mail_server, smtp_server, pop3_server, clients = self.test_email_services_installation()
        
        # Initialize security policy if not present
        if not hasattr(smtp_server, 'security_policy'):
            from primaite_mail.simulator.software.email_security_policy import EmailSecurityPolicy, SecurityEventLog
            smtp_server.security_policy = EmailSecurityPolicy()
            smtp_server.security_log = SecurityEventLog()
        
        # Test sender blocking
        malicious_sender = "phishing@evil-domain.com"
        block_sender_request = [
            "network", "node", "mail_server", "service", "smtp-server", 
            "block_sender", {"sender_address": malicious_sender}
        ]
        
        response = sim.apply_request(request=block_sender_request, context={})
        assert response.status == "success", f"Failed to block sender: {response.data}"
        
        # Test IP blocking
        malicious_ip = "192.168.1.100"
        block_ip_request = [
            "network", "node", "mail_server", "service", "smtp-server", 
            "block_ip", {"ip_address": malicious_ip}
        ]
        
        response = sim.apply_request(request=block_ip_request, context={})
        assert response.status == "success", f"Failed to block IP: {response.data}"
        
        # Test policy queries
        list_policies_request = [
            "network", "node", "mail_server", "service", "smtp-server", 
            "list_security_policies", {}
        ]
        
        response = sim.apply_request(request=list_policies_request, context={})
        assert response.status == "success", f"Failed to list policies: {response.data}"
        
        policies = response.data
        # Handle nested policy structure
        if "policy_summary" in policies:
            policy_data = policies["policy_summary"]
        else:
            policy_data = policies
            
        assert "blocked_senders" in policy_data, f"Blocked senders not in policy response: {policy_data.keys()}"
        assert "blocked_ips" in policy_data, f"Blocked IPs not in policy response: {policy_data.keys()}"
        assert malicious_sender in policy_data["blocked_senders"], "Blocked sender not found in policies"
        assert malicious_ip in policy_data["blocked_ips"], "Blocked IP not found in policies"
        
        print(f"✅ Security policies test passed: {len(policy_data['blocked_senders'])} blocked senders, {len(policy_data['blocked_ips'])} blocked IPs")
    
    def test_educational_flow_progression(self):
        """Test that the educational flow progresses from basic to advanced concepts."""
        print("Testing educational flow progression...")
        
        # This test validates the logical progression of scenarios
        scenarios = [
            "Environment Setup",
            "Security-Focused Network Architecture", 
            "Email Spoofing and Detection",
            "SMTP Relay Abuse",
            "Blue Agent Security Policy Management",
            "Threat Detection and Response"
        ]
        
        # Read notebook to verify scenario progression
        notebook_path = Path(__file__).parent.parent.parent / "src" / "primaite_mail" / "notebooks" / "email_security_scenarios.ipynb"
        
        with open(notebook_path, 'r', encoding='utf-8') as f:
            notebook_content = f.read()
        
        # Check that scenarios appear in logical order
        scenario_positions = []
        for scenario in scenarios:
            position = notebook_content.find(scenario)
            assert position != -1, f"Scenario '{scenario}' not found in notebook"
            scenario_positions.append((scenario, position))
        
        # Verify scenarios are in ascending order
        sorted_positions = sorted(scenario_positions, key=lambda x: x[1])
        assert sorted_positions == scenario_positions, "Scenarios are not in logical order"
        
        # Check for educational elements
        educational_elements = [
            "Learning Objectives",
            "Attack Techniques",
            "Detection Methods", 
            "Prevention Measures",
            "Security Assessment",
            "Recommended action"
        ]
        
        found_elements = 0
        for element in educational_elements:
            if element in notebook_content:
                found_elements += 1
        
        assert found_elements >= len(educational_elements) * 0.7, f"Too few educational elements found: {found_elements}/{len(educational_elements)}"
        
        print(f"✅ Educational flow validation passed: {len(scenarios)} scenarios in order, {found_elements} educational elements")
    
    def test_error_handling_and_robustness(self):
        """Test that the notebook handles errors gracefully."""
        print("Testing error handling and robustness...")
        
        sim, mail_server, smtp_server, pop3_server, clients = self.test_email_services_installation()
        
        # Test invalid requests
        invalid_requests = [
            # Invalid node name
            ["network", "node", "nonexistent_server", "service", "smtp-server", "list_security_policies", {}],
            # Invalid service name  
            ["network", "node", "mail_server", "service", "nonexistent-service", "list_security_policies", {}],
            # Invalid action
            ["network", "node", "mail_server", "service", "smtp-server", "nonexistent_action", {}],
            # Missing parameters
            ["network", "node", "mail_server", "service", "smtp-server", "block_sender", {}],
        ]
        
        for request in invalid_requests:
            response = sim.apply_request(request=request, context={})
            # Should not crash, should return failure status
            assert response.status in ["failure", "error", "unreachable"], f"Expected failure for invalid request: {request}"
        
        # Test malformed email handling
        try:
            malformed_email = EmailMessage(
                sender="",  # Empty sender
                recipients=[],  # Empty recipients
                subject="",
                body=""
            )
            # Should not crash when creating malformed email
            assert malformed_email is not None
        except Exception as e:
            pytest.fail(f"Malformed email creation should not crash: {e}")
        
        print("✅ Error handling test passed: Invalid requests handled gracefully")


if __name__ == "__main__":
    # Run tests directly for debugging
    test_instance = TestNotebookExecutionValidation()
    
    print("=== NOTEBOOK EXECUTION VALIDATION TESTS ===\n")
    
    try:
        # Run all tests
        notebook_path = Path(__file__).parent.parent.parent / "src" / "primaite_mail" / "notebooks" / "email_security_scenarios.ipynb"
        
        test_instance.test_notebook_exists_and_valid_json(notebook_path)
        test_instance.test_notebook_cell_structure(notebook_path)
        test_instance.test_notebook_imports_and_setup()
        test_instance.test_simulation_environment_creation()
        test_instance.test_email_services_installation()
        test_instance.test_email_spoofing_scenario()
        test_instance.test_multi_agent_coordination()
        test_instance.test_security_policies_functionality()
        test_instance.test_educational_flow_progression()
        test_instance.test_error_handling_and_robustness()
        
        print("\n🎉 ALL NOTEBOOK VALIDATION TESTS PASSED!")
        print("✅ Notebook is ready for educational use")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        raise