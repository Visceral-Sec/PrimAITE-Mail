# © Crown-owned copyright 2025, Defence Science and Technology Laboratory UK
"""Integration tests for blue agent security actions with SMTP server."""

import pytest
from primaite.simulator.network.container import Network
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.game.actions.email_actions import (
    EmailBlockSenderAction,
    EmailUnblockSenderAction,
    EmailBlockIpAction,
    EmailUnblockIpAction,
    EmailQuerySecurityPoliciesAction,
    EmailGetSecurityStatisticsAction
)


class TestBlueAgentSecurityActions:
    """Integration tests for blue agent security actions."""

    def setup_method(self):
        """Set up test environment with SMTP server."""
        self.network = Network()
        
        # Create mail server node
        self.mail_server = Computer.from_config({
            "type": "computer",
            "hostname": "mail_server",
            "ip_address": "192.168.1.10",
            "subnet_mask": "255.255.255.0",
            "start_up_duration": 0,
        })
        self.mail_server.power_on()
        self.network.add_node(self.mail_server)
        
        # Install SMTP server
        self.mail_server.software_manager.install(SMTPServer)
        self.smtp_server = self.mail_server.software_manager.software.get("smtp-server")
        
        # Configure initial security policies
        self.smtp_server.config.domain = "test.com"
        self.smtp_server.config.blocked_senders = ["spam@malicious.com"]
        self.smtp_server.config.blocked_ips = ["192.168.100.50"]
        self.smtp_server.config.enable_security_logging = True
        
        # Initialize security policies from configuration
        self.smtp_server._init_security_policies()
        self.smtp_server.start()

    def test_block_sender_action_request_formation(self):
        """Test EmailBlockSenderAction forms correct request for simulation."""
        # Create action configuration
        config = EmailBlockSenderAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            sender_address="attacker@evil.com"
        )
        
        # Form request
        request = EmailBlockSenderAction.form_request(config)
        
        # Verify request format
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "block_sender",
            {
                "sender_address": "attacker@evil.com",
                "agent_name": "blue_agent_1"
            }
        ]
        
        assert request == expected_request
        
        # Test direct network-level request (without "network" prefix)
        network_request = request[1:]  # Remove "network" prefix
        response = self.network.apply_request(network_request)
        
        # Verify response
        assert response.status == "success"
        assert response.data["sender_address"] == "attacker@evil.com"
        
        # Verify sender is actually blocked
        assert self.smtp_server.security_policy.is_sender_blocked("attacker@evil.com")

    def test_unblock_sender_action_request_formation(self):
        """Test EmailUnblockSenderAction forms correct request and works."""
        # First verify the initial blocked sender exists
        assert self.smtp_server.security_policy.is_sender_blocked("spam@malicious.com")
        
        # Create action configuration to unblock
        config = EmailUnblockSenderAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            sender_address="spam@malicious.com"
        )
        
        # Form request
        request = EmailUnblockSenderAction.form_request(config)
        
        # Verify request format
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "unblock_sender",
            {
                "sender_address": "spam@malicious.com",
                "agent_name": "blue_agent_1"
            }
        ]
        
        assert request == expected_request
        
        # Test direct network-level request (without "network" prefix)
        network_request = request[1:]  # Remove "network" prefix
        response = self.network.apply_request(network_request)
        
        # Verify response
        assert response.status == "success"
        assert response.data["sender_address"] == "spam@malicious.com"
        
        # Verify sender is actually unblocked
        assert not self.smtp_server.security_policy.is_sender_blocked("spam@malicious.com")

    def test_query_security_policies_action_request_formation(self):
        """Test EmailQuerySecurityPoliciesAction forms correct request and works."""
        # Create action configuration
        config = EmailQuerySecurityPoliciesAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            include_statistics=True
        )
        
        # Form request
        request = EmailQuerySecurityPoliciesAction.form_request(config)
        
        # Verify request format
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "list_security_policies",
            {
                "agent_name": "blue_agent_1",
                "include_statistics": True
            }
        ]
        
        assert request == expected_request
        
        # Test direct network-level request (without "network" prefix)
        network_request = request[1:]  # Remove "network" prefix
        response = self.network.apply_request(network_request)
        
        # Verify response
        assert response.status == "success"
        assert "policy_summary" in response.data
        assert "policy_details" in response.data
        
        # Verify initial policies are present
        assert "spam@malicious.com" in response.data["policy_summary"]["blocked_senders"]
        assert "192.168.100.50" in response.data["policy_summary"]["blocked_ips"]

    def test_get_security_statistics_action_request_formation(self):
        """Test EmailGetSecurityStatisticsAction forms correct request and works."""
        # Create action configuration
        config = EmailGetSecurityStatisticsAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            event_limit=10,
            time_range_hours=24,
            event_type_filter=""
        )
        
        # Form request
        request = EmailGetSecurityStatisticsAction.form_request(config)
        
        # Verify request format
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "get_security_statistics",
            {
                "agent_name": "blue_agent_1",
                "event_limit": 10,
                "time_range_hours": 24,
                "event_type_filter": ""
            }
        ]
        
        assert request == expected_request
        
        # Test direct network-level request (without "network" prefix)
        network_request = request[1:]  # Remove "network" prefix
        response = self.network.apply_request(network_request)
        
        # Verify response
        assert response.status == "success"
        assert "basic_stats" in response.data
        assert "detailed_stats" in response.data
        assert "recent_events" in response.data
        assert "query_info" in response.data
        
        # Verify query info
        assert response.data["query_info"]["queried_by"] == "blue_agent_1"
        assert response.data["query_info"]["event_limit"] == 10
        assert response.data["query_info"]["time_range_hours"] == 24