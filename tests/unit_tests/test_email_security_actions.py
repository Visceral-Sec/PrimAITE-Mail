# © Crown-owned copyright 2025, Defence Science and Technology Laboratory UK
"""Unit tests for email security actions."""

import pytest
from primaite_mail.game.actions.email_actions import (
    EmailBlockSenderAction,
    EmailUnblockSenderAction,
    EmailBlockIpAction,
    EmailUnblockIpAction,
    EmailQuerySecurityPoliciesAction,
    EmailGetSecurityStatisticsAction
)


class TestEmailSecurityActions:
    """Test email security actions for blue agents."""

    def test_email_block_sender_action_form_request(self):
        """Test EmailBlockSenderAction forms correct request."""
        config = EmailBlockSenderAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            sender_address="malicious@attacker.com"
        )
        
        request = EmailBlockSenderAction.form_request(config)
        
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "block_sender",
            {
                "sender_address": "malicious@attacker.com",
                "agent_name": "blue_agent_1"
            }
        ]
        
        assert request == expected_request

    def test_email_unblock_sender_action_form_request(self):
        """Test EmailUnblockSenderAction forms correct request."""
        config = EmailUnblockSenderAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            sender_address="legitimate@company.com"
        )
        
        request = EmailUnblockSenderAction.form_request(config)
        
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "unblock_sender",
            {
                "sender_address": "legitimate@company.com",
                "agent_name": "blue_agent_1"
            }
        ]
        
        assert request == expected_request

    def test_email_block_ip_action_form_request(self):
        """Test EmailBlockIpAction forms correct request."""
        config = EmailBlockIpAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            ip_address="192.168.1.100"
        )
        
        request = EmailBlockIpAction.form_request(config)
        
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "block_ip",
            {
                "ip_address": "192.168.1.100",
                "agent_name": "blue_agent_1"
            }
        ]
        
        assert request == expected_request

    def test_email_block_ip_action_cidr_form_request(self):
        """Test EmailBlockIpAction forms correct request with CIDR range."""
        config = EmailBlockIpAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            ip_address="192.168.1.0/24"
        )
        
        request = EmailBlockIpAction.form_request(config)
        
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "block_ip",
            {
                "ip_address": "192.168.1.0/24",
                "agent_name": "blue_agent_1"
            }
        ]
        
        assert request == expected_request

    def test_email_unblock_ip_action_form_request(self):
        """Test EmailUnblockIpAction forms correct request."""
        config = EmailUnblockIpAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            ip_address="192.168.1.100"
        )
        
        request = EmailUnblockIpAction.form_request(config)
        
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "unblock_ip",
            {
                "ip_address": "192.168.1.100",
                "agent_name": "blue_agent_1"
            }
        ]
        
        assert request == expected_request

    def test_email_query_security_policies_action_form_request(self):
        """Test EmailQuerySecurityPoliciesAction forms correct request."""
        config = EmailQuerySecurityPoliciesAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            include_statistics=True
        )
        
        request = EmailQuerySecurityPoliciesAction.form_request(config)
        
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

    def test_email_query_security_policies_action_form_request_no_stats(self):
        """Test EmailQuerySecurityPoliciesAction forms correct request without statistics."""
        config = EmailQuerySecurityPoliciesAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            include_statistics=False
        )
        
        request = EmailQuerySecurityPoliciesAction.form_request(config)
        
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "list_security_policies",
            {
                "agent_name": "blue_agent_1",
                "include_statistics": False
            }
        ]
        
        assert request == expected_request

    def test_email_get_security_statistics_action_form_request(self):
        """Test EmailGetSecurityStatisticsAction forms correct request."""
        config = EmailGetSecurityStatisticsAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server",
            event_limit=100,
            time_range_hours=48,
            event_type_filter="blocked_sender"
        )
        
        request = EmailGetSecurityStatisticsAction.form_request(config)
        
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "get_security_statistics",
            {
                "agent_name": "blue_agent_1",
                "event_limit": 100,
                "time_range_hours": 48,
                "event_type_filter": "blocked_sender"
            }
        ]
        
        assert request == expected_request

    def test_email_get_security_statistics_action_form_request_defaults(self):
        """Test EmailGetSecurityStatisticsAction forms correct request with default values."""
        config = EmailGetSecurityStatisticsAction.ConfigSchema(
            node_name="blue_agent_1",
            smtp_server_node="mail_server"
        )
        
        request = EmailGetSecurityStatisticsAction.form_request(config)
        
        expected_request = [
            "network",
            "node",
            "mail_server",
            "service",
            "smtp-server",
            "get_security_statistics",
            {
                "agent_name": "blue_agent_1",
                "event_limit": 50,
                "time_range_hours": 24,
                "event_type_filter": ""
            }
        ]
        
        assert request == expected_request

    def test_action_classes_are_properly_defined(self):
        """Test that all action classes are properly defined and can be instantiated."""
        actions = [
            EmailBlockSenderAction,
            EmailUnblockSenderAction,
            EmailBlockIpAction,
            EmailUnblockIpAction,
            EmailQuerySecurityPoliciesAction,
            EmailGetSecurityStatisticsAction
        ]
        
        # Test that all actions have the required methods
        for action_class in actions:
            assert hasattr(action_class, 'form_request'), f"{action_class.__name__} missing form_request method"
            assert hasattr(action_class, 'ConfigSchema'), f"{action_class.__name__} missing ConfigSchema"
            assert callable(action_class.form_request), f"{action_class.__name__}.form_request is not callable"

    def test_config_schema_types_match_discriminators(self):
        """Test that ConfigSchema type fields match action discriminators."""
        test_cases = [
            (EmailBlockSenderAction, "email-block-sender", {
                "node_name": "test_node",
                "smtp_server_node": "test_server",
                "sender_address": "test@example.com"
            }),
            (EmailUnblockSenderAction, "email-unblock-sender", {
                "node_name": "test_node",
                "smtp_server_node": "test_server",
                "sender_address": "test@example.com"
            }),
            (EmailBlockIpAction, "email-block-ip", {
                "node_name": "test_node",
                "smtp_server_node": "test_server",
                "ip_address": "192.168.1.1"
            }),
            (EmailUnblockIpAction, "email-unblock-ip", {
                "node_name": "test_node",
                "smtp_server_node": "test_server",
                "ip_address": "192.168.1.1"
            }),
            (EmailQuerySecurityPoliciesAction, "email-query-security-policies", {
                "node_name": "test_node",
                "smtp_server_node": "test_server"
            }),
            (EmailGetSecurityStatisticsAction, "email-get-security-statistics", {
                "node_name": "test_node",
                "smtp_server_node": "test_server"
            })
        ]
        
        for action_class, expected_type, required_fields in test_cases:
            config = action_class.ConfigSchema(**required_fields)
            assert config.type == expected_type, f"Config type mismatch for {action_class.__name__}"