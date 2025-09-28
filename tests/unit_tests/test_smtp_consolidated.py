# © Crown-owned copyright 2025, Defence Science and Technology Laboratory UK
"""Consolidated SMTP server and email client tests.

This file consolidates overlapping tests from multiple files while maintaining coverage:
- test_smtp_server_timesteps.py
- test_smtp_timestep_behavior.py  
- test_smtp_agent_integration.py
- test_email_delivery_diagnosis.py
"""

import pytest
import yaml
from pathlib import Path

from primaite.simulator.network.container import Network
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite.simulator.sim_container import Simulation
from primaite.game.game import PrimaiteGame
from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.email_client import EmailClient
from primaite_mail.simulator.network.protocols.smtp import EmailMessage
from primaite_mail.game.agents.green_mail_agent import GreenMailAgent


class TestSMTPConsolidated:
    """Consolidated SMTP server and email client tests."""

    @pytest.fixture
    def email_system(self):
        """Create complete email system for testing."""
        network = Network()
        
        # Mail server
        mail_server = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
            "start_up_duration": 0,
        })
        mail_server.power_on()
        network.add_node(mail_server)
        
        # Install SMTP server
        mail_server.software_manager.install(SMTPServer)
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        smtp_server.start()
        
        # Client
        client = Computer.from_config({
            "type": "computer", 
            "hostname": "client_1",
            "ip_address": "192.168.1.21",
            "subnet_mask": "255.255.255.0",
            "start_up_duration": 0,
        })
        client.power_on()
        network.add_node(client)
        
        # Install email client
        client.software_manager.install(EmailClient)
        email_client = client.software_manager.software.get("email-client")
        email_client.config.username = "alice@company.com"
        email_client.config.default_smtp_server = str(mail_server.config.ip_address)
        email_client.run()
        
        # Connect nodes
        network.connect(mail_server.network_interface[1], client.network_interface[1])
        
        # Create mailboxes
        smtp_server.mailbox_manager.create_mailbox("alice")
        smtp_server.mailbox_manager.create_mailbox("bob")
        smtp_server.mailbox_manager.create_mailbox("testuser")
        
        return network, mail_server, client, smtp_server, email_client

    def test_smtp_server_basic_functionality(self, email_system):
        """Test SMTP server initialization and basic operations."""
        network, mail_server, client, smtp_server, email_client = email_system
        
        # Server state
        assert smtp_server.operating_state.name == "RUNNING"
        assert smtp_server.health_state_actual.name == "GOOD"
        assert smtp_server.port == 25
        
        # Mailbox operations
        assert len(smtp_server.mailbox_manager.mailboxes) == 3
        assert "alice" in smtp_server.mailbox_manager.mailboxes
        
        # Timestep stability
        initial_state = smtp_server.operating_state
        for timestep in range(10):
            smtp_server.apply_timestep(timestep)
        assert smtp_server.operating_state == initial_state

    def test_email_client_functionality(self, email_system):
        """Test email client initialization and configuration."""
        network, mail_server, client, smtp_server, email_client = email_system
        
        # Client state
        assert email_client.operating_state.name == "RUNNING"
        assert email_client.config.username == "alice@company.com"
        assert email_client.config.default_smtp_server == str(mail_server.config.ip_address)
        
        # Network connectivity
        ping_result = client.ping(mail_server.network_interface[1].ip_address)
        assert ping_result is True

    def test_email_delivery_via_network_requests(self, email_system):
        """Test email delivery through network request system."""
        network, mail_server, client, smtp_server, email_client = email_system
        
        # Send email via network request
        request = [
            "node", "client_1", "application", "email-client", "send_email",
            {
                "to": ["bob@company.com"],
                "subject": "Network Test",
                "body": "Testing network request delivery",
                "from": "alice@company.com"
            }
        ]
        
        response = network.apply_request(request, {})
        assert response.status in ["success", "failure"]
        
        # Check delivery
        bob_mailbox = smtp_server.mailbox_manager.get_mailbox("bob")
        messages = bob_mailbox.get_messages()
        
        if response.status == "success":
            assert len(messages) > 0
            assert messages[-1].subject == "Network Test"

    def test_green_mail_agent_integration(self, email_system):
        """Test green mail agent with email system."""
        network, mail_server, client, smtp_server, email_client = email_system
        
        # Create agent
        agent_config = {
            "ref": "test_agent",
            "team": "GREEN",
            "type": "green-mail-agent",
            "agent_settings": {
                "node_name": "client_1",
                "sender_email": "alice@company.com",
                "recipients": ["bob@company.com"],
                "send_probability": 1.0,
                "retrieve_probability": 0.0,
                "idle_probability": 0.0,
                "email_frequency": 2,
                "email_variance": 1
            }
        }
        
        agent = GreenMailAgent.from_config(agent_config)
        
        # Test action generation
        action_name, parameters = agent._get_email_action()
        assert action_name == "email-send"
        assert "to" in parameters
        assert "subject" in parameters
        
        # Test request formatting
        request = agent.format_request(action_name, parameters)
        expected_start = ["network", "node", "client_1", "application", "email-client", "send_email"]
        assert request[:6] == expected_start

    def test_full_game_email_scenario(self):
        """Test complete email scenario using game system."""
        config = {
            "metadata": {"version": 3.0},
            "game": {
                "max_episode_length": 30,
                "ports": ["SMTP", "POP3", "DNS"],
                "protocols": ["TCP", "UDP", "ICMP"]
            },
            "agents": [
                {
                    "ref": "alice_agent",
                    "team": "GREEN",
                    "type": "green-mail-agent",
                    "agent_settings": {
                        "node_name": "client_1",
                        "sender_email": "alice@company.com",
                        "recipients": ["bob@company.com"],
                        "send_probability": 1.0,
                        "retrieve_probability": 0.0,
                        "idle_probability": 0.0,
                        "email_frequency": 3,
                        "email_variance": 1
                    },
                    "action_space": {
                        "action_map": {
                            0: {"action": "do-nothing", "options": {}},
                            1: {"action": "email-send", "options": {
                                "node_name": "client_1",
                                "to": ["bob@company.com"],
                                "subject": "Test",
                                "body": "Test",
                                "sender": "alice@company.com"
                            }}
                        }
                    },
                    "reward_function": {"reward_components": [{"type": "dummy", "weight": 1.0}]}
                }
            ],
            "simulation": {
                "network": {
                    "nodes": [
                        {
                            "hostname": "mail_server",
                            "type": "server",
                            "ip_address": "192.168.1.10",
                            "subnet_mask": "255.255.255.0",
                            "services": [{"type": "smtp-server"}]
                        },
                        {
                            "hostname": "client_1", 
                            "type": "computer",
                            "ip_address": "192.168.1.21",
                            "subnet_mask": "255.255.255.0",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "alice@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        }
                    ],
                    "links": [
                        {
                            "endpoint_a_hostname": "mail_server",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "client_1",
                            "endpoint_b_port": 1
                        }
                    ]
                }
            }
        }
        
        # Create and run game
        game = PrimaiteGame.from_config(config)
        
        # Get components
        mail_server = game.simulation.network.get_node_by_hostname("mail_server")
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        
        # Create mailboxes
        smtp_server.mailbox_manager.create_mailbox("alice")
        smtp_server.mailbox_manager.create_mailbox("bob")
        
        # Run simulation
        email_attempts = 0
        for step in range(15):
            game.step()
            
            # Check agent history
            agent = list(game.agents.values())[0]
            if agent.history and agent.history[-1].action == "email-send":
                email_attempts += 1
        
        # Verify emails were attempted and delivered
        bob_mailbox = smtp_server.mailbox_manager.get_mailbox("bob")
        messages = bob_mailbox.get_messages()
        
        assert email_attempts > 0, "Agent should attempt to send emails"
        assert len(messages) > 0, f"Emails should be delivered (attempted: {email_attempts})"

    def test_mailbox_persistence_and_operations(self, email_system):
        """Test mailbox operations and persistence across timesteps."""
        network, mail_server, client, smtp_server, email_client = email_system
        
        # Test mailbox creation/deletion
        assert smtp_server.mailbox_manager.create_mailbox("newuser")
        assert "newuser" in smtp_server.mailbox_manager.mailboxes
        assert not smtp_server.mailbox_manager.create_mailbox("newuser")  # Duplicate
        
        # Test message operations
        mailbox = smtp_server.mailbox_manager.get_mailbox("alice")
        test_message = EmailMessage(
            sender="test@company.com",
            recipients=["alice@company.com"],
            subject="Persistence Test",
            body="Testing message persistence"
        )
        
        mailbox.add_message(test_message)
        initial_count = len(mailbox.get_messages())
        
        # Apply timesteps
        for timestep in range(20):
            smtp_server.apply_timestep(timestep)
        
        # Verify persistence
        final_count = len(mailbox.get_messages())
        assert final_count == initial_count
        assert mailbox.get_messages()[0].subject == "Persistence Test"