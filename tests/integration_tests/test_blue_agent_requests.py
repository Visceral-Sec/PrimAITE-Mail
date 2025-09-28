"""Integration tests for blue agent security policy request handlers."""

import pytest
from primaite.simulator.network.container import Network
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite_mail.simulator.software.smtp_server import SMTPServer


class TestBlueAgentSecurityRequests:
    """Test blue agent security policy management requests."""

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
        self.smtp_server.config.blocked_senders = ["initial@blocked.com"]
        self.smtp_server.config.blocked_ips = ["192.168.1.100"]
        self.smtp_server.config.enable_security_logging = True
        
        # Initialize security policies from configuration
        self.smtp_server._init_security_policies()
        
        self.smtp_server.start()

    def test_block_sender_request_success(self):
        """Test successful sender blocking request."""
        request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": "malicious@attacker.com",
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert response.data["action"] == "block_sender"
        assert response.data["sender_address"] == "malicious@attacker.com"
        assert response.data["agent"] == "blue_agent_1"
        assert response.data["blocked_senders_count"] == 2  # Initial + new
        assert "successfully blocked" in response.data["message"]
        
        # Verify sender is actually blocked
        assert self.smtp_server.security_policy.is_sender_blocked("malicious@attacker.com")

    def test_block_sender_request_invalid_format(self):
        """Test sender blocking with invalid email format."""
        request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": "invalid-email-format",
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "failure"
        assert "Invalid email address format" in response.data["reason"]
        assert response.data["sender_address"] == "invalid-email-format"

    def test_block_sender_request_missing_parameters(self):
        """Test sender blocking with missing parameters."""
        request = ["node", "mail_server", "service", "smtp-server", "block_sender", {}]
        
        response = self.network.apply_request(request)
        
        assert response.status == "failure"
        assert response.data["reason"] == "sender_address parameter required"

    def test_unblock_sender_request_success(self):
        """Test successful sender unblocking request."""
        # First block a sender
        block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": "test@example.com",
            "agent_name": "blue_agent_1"
        }]
        self.network.apply_request(block_request)
        
        # Then unblock it
        unblock_request = ["node", "mail_server", "service", "smtp-server", "unblock_sender", {
            "sender_address": "test@example.com",
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(unblock_request)
        
        assert response.status == "success"
        assert response.data["action"] == "unblock_sender"
        assert response.data["sender_address"] == "test@example.com"
        assert response.data["agent"] == "blue_agent_1"
        assert "successfully unblocked" in response.data["message"]
        
        # Verify sender is no longer blocked
        assert not self.smtp_server.security_policy.is_sender_blocked("test@example.com")

    def test_unblock_sender_request_not_found(self):
        """Test unblocking sender that is not in blocklist."""
        request = ["node", "mail_server", "service", "smtp-server", "unblock_sender", {
            "sender_address": "notblocked@example.com",
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "failure"
        assert "Sender not found in blocklist" in response.data["reason"]
        assert response.data["sender_address"] == "notblocked@example.com"

    def test_block_ip_request_success(self):
        """Test successful IP blocking request."""
        request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": "10.0.0.50",
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert response.data["action"] == "block_ip"
        assert response.data["ip_address"] == "10.0.0.50"
        assert response.data["agent"] == "blue_agent_1"
        assert response.data["blocked_ips_count"] == 2  # Initial + new
        assert "successfully blocked" in response.data["message"]
        
        # Verify IP is actually blocked
        assert self.smtp_server.security_policy.is_ip_blocked("10.0.0.50")

    def test_block_ip_request_cidr_range(self):
        """Test IP blocking with CIDR range."""
        request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": "192.168.2.0/24",
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert response.data["ip_address"] == "192.168.2.0/24"
        
        # Verify CIDR range blocking works
        assert self.smtp_server.security_policy.is_ip_blocked("192.168.2.50")
        assert self.smtp_server.security_policy.is_ip_blocked("192.168.2.1")
        assert not self.smtp_server.security_policy.is_ip_blocked("192.168.3.50")

    def test_block_ip_request_invalid_format(self):
        """Test IP blocking with invalid IP format."""
        request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": "invalid-ip-format",
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "failure"
        assert "Invalid IP format" in response.data["reason"]
        assert response.data["ip_address"] == "invalid-ip-format"

    def test_unblock_ip_request_success(self):
        """Test successful IP unblocking request."""
        # First block an IP
        block_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": "172.16.0.100",
            "agent_name": "blue_agent_1"
        }]
        self.network.apply_request(block_request)
        
        # Then unblock it
        unblock_request = ["node", "mail_server", "service", "smtp-server", "unblock_ip", {
            "ip_address": "172.16.0.100",
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(unblock_request)
        
        assert response.status == "success"
        assert response.data["action"] == "unblock_ip"
        assert response.data["ip_address"] == "172.16.0.100"
        assert response.data["agent"] == "blue_agent_1"
        assert "successfully unblocked" in response.data["message"]
        
        # Verify IP is no longer blocked
        assert not self.smtp_server.security_policy.is_ip_blocked("172.16.0.100")

    def test_unblock_ip_request_not_found(self):
        """Test unblocking IP that is not in blocklist."""
        request = ["node", "mail_server", "service", "smtp-server", "unblock_ip", {
            "ip_address": "10.10.10.10",
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "failure"
        assert "IP not found in blocklist" in response.data["reason"]
        assert response.data["ip_address"] == "10.10.10.10"

    def test_security_event_logging(self):
        """Test that security policy changes are logged."""
        # Block a sender
        request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": "logged@test.com",
            "agent_name": "blue_agent_test"
        }]
        
        self.network.apply_request(request)
        
        # Check that event was logged
        events = self.smtp_server.security_log.get_recent_events(10)
        policy_events = [e for e in events if e.event_type == "policy_change"]
        
        assert len(policy_events) > 0
        latest_event = policy_events[-1]
        assert latest_event.agent == "blue_agent_test"
        assert "block_sender" in latest_event.reason
        assert "logged@test.com" in latest_event.reason

    def test_multiple_agent_coordination(self):
        """Test multiple blue agents managing policies."""
        # Agent 1 blocks a sender
        request1 = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": "agent1@test.com",
            "agent_name": "blue_agent_1"
        }]
        response1 = self.network.apply_request(request1)
        assert response1.status == "success"
        
        # Agent 2 blocks an IP
        request2 = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": "10.0.0.200",
            "agent_name": "blue_agent_2"
        }]
        response2 = self.network.apply_request(request2)
        assert response2.status == "success"
        
        # Verify both policies are active
        assert self.smtp_server.security_policy.is_sender_blocked("agent1@test.com")
        assert self.smtp_server.security_policy.is_ip_blocked("10.0.0.200")
        
        # Check that both agents' actions were logged
        events = self.smtp_server.security_log.get_recent_events(10)
        policy_events = [e for e in events if e.event_type == "policy_change"]
        
        agents = {e.agent for e in policy_events}
        assert "blue_agent_1" in agents
        assert "blue_agent_2" in agents

    def test_case_insensitive_sender_handling(self):
        """Test that sender blocking is case insensitive."""
        # Block sender in lowercase
        request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": "test@example.com",
            "agent_name": "blue_agent_1"
        }]
        response = self.network.apply_request(request)
        assert response.status == "success"
        
        # Verify blocking works for different cases
        assert self.smtp_server.security_policy.is_sender_blocked("test@example.com")
        assert self.smtp_server.security_policy.is_sender_blocked("TEST@EXAMPLE.COM")
        assert self.smtp_server.security_policy.is_sender_blocked("Test@Example.Com")

    def test_request_without_parameters(self):
        """Test request handlers with missing parameter dictionary."""
        request = ["node", "mail_server", "service", "smtp-server", "block_sender"]
        
        response = self.network.apply_request(request)
        
        assert response.status == "failure"
        assert response.data["reason"] == "Parameters required"

    def test_initial_configuration_loading(self):
        """Test that initial security policies are loaded from configuration."""
        # Verify initial blocked sender is loaded
        assert self.smtp_server.security_policy.is_sender_blocked("initial@blocked.com")
        
        # Verify initial blocked IP is loaded
        assert self.smtp_server.security_policy.is_ip_blocked("192.168.1.100")
        
        # Check counts
        assert len(self.smtp_server.security_policy.blocked_senders) == 1
        assert len(self.smtp_server.security_policy.blocked_ips) == 1

    def test_list_security_policies_request_basic(self):
        """Test basic security policies listing request."""
        request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert "policy_summary" in response.data
        assert "policy_details" in response.data
        assert response.data["queried_by"] == "blue_agent_1"
        assert response.data["server_domain"] == "test.com"
        assert response.data["security_logging_enabled"] is True
        
        # Check policy summary
        summary = response.data["policy_summary"]
        assert summary["blocked_senders_count"] == 1
        assert summary["blocked_ips_count"] == 1
        assert "initial@blocked.com" in summary["blocked_senders"]
        assert "192.168.1.100" in summary["blocked_ips"]
        assert summary["default_action"] == "reject"
        assert summary["logging_enabled"] is True
        
        # Check policy details
        details = response.data["policy_details"]
        assert details["blocked_senders"]["count"] == 1
        assert details["blocked_ips"]["count"] == 1
        assert "initial@blocked.com" in details["blocked_senders"]["list"]
        assert "192.168.1.100" in details["blocked_ips"]["list"]

    def test_list_security_policies_request_no_details(self):
        """Test security policies listing without details."""
        request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_agent_1",
            "include_details": False
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert "policy_summary" in response.data
        assert "policy_details" not in response.data  # Should not include details

    def test_list_security_policies_request_empty_params(self):
        """Test security policies listing with empty parameters."""
        request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {}]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert response.data["queried_by"] == "unknown"  # Default value

    def test_list_security_policies_request_no_params(self):
        """Test security policies listing without parameter dictionary."""
        request = ["node", "mail_server", "service", "smtp-server", "list_security_policies"]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert "policy_summary" in response.data

    def test_get_security_statistics_request_basic(self):
        """Test basic security statistics request."""
        # Add some security events first
        self.smtp_server.security_log.log_blocked_email("test1@example.com", "192.168.1.1", "Test block")
        self.smtp_server.security_log.log_blocked_ip("192.168.1.200", "Test IP block")
        self.smtp_server.security_log.log_policy_change("blue_agent_1", "add_rule", "test@example.com")
        
        request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert "basic_stats" in response.data
        assert "detailed_stats" in response.data
        assert "recent_events" in response.data
        assert "query_info" in response.data
        
        # Check basic stats
        basic_stats = response.data["basic_stats"]
        assert basic_stats["total_events"] == 3
        assert basic_stats["blocked_senders"] == 1
        assert basic_stats["blocked_ips"] == 1
        assert basic_stats["policy_changes"] == 1
        
        # Check detailed stats
        detailed_stats = response.data["detailed_stats"]
        assert detailed_stats["unique_blocked_senders"] == 1
        assert detailed_stats["unique_blocked_ips"] == 1
        assert detailed_stats["active_sender_blocks"] == 1  # From initial config
        assert detailed_stats["active_ip_blocks"] == 1      # From initial config
        assert detailed_stats["events_returned"] == 3
        assert detailed_stats["total_events_in_log"] == 3
        
        # Check recent events
        events = response.data["recent_events"]
        assert len(events) == 3
        assert all("timestamp" in event for event in events)
        assert all("event_type" in event for event in events)
        assert all("reason" in event for event in events)
        
        # Check query info
        query_info = response.data["query_info"]
        assert query_info["queried_by"] == "blue_agent_1"
        assert query_info["event_limit"] == 50  # Default
        assert query_info["time_range_hours"] is None
        assert query_info["event_type_filter"] is None

    def test_get_security_statistics_request_with_filters(self):
        """Test security statistics request with filtering options."""
        # Add various events
        self.smtp_server.security_log.log_blocked_email("test1@example.com", "192.168.1.1", "Sender block")
        self.smtp_server.security_log.log_blocked_email("test2@example.com", "192.168.1.2", "Another sender block")
        self.smtp_server.security_log.log_blocked_ip("192.168.1.200", "IP block")
        self.smtp_server.security_log.log_policy_change("blue_agent_1", "add_rule", "test@example.com")
        
        request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_agent_1",
            "event_limit": 2,
            "event_type_filter": "blocked_sender"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        
        # Check that filtering was applied
        events = response.data["recent_events"]
        # Should return only blocked_sender events (2 of them), limited by event_limit=2
        assert len(events) == 2  # Should get exactly 2 blocked_sender events
        assert all(event["event_type"] == "blocked_sender" for event in events)
        
        # Check query info reflects filters
        query_info = response.data["query_info"]
        assert query_info["event_limit"] == 2
        assert query_info["event_type_filter"] == "blocked_sender"

    def test_get_security_statistics_request_empty_log(self):
        """Test security statistics request with empty event log."""
        request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        
        # Check empty stats
        basic_stats = response.data["basic_stats"]
        assert basic_stats["total_events"] == 0
        assert basic_stats["blocked_senders"] == 0
        assert basic_stats["blocked_ips"] == 0
        assert basic_stats["policy_changes"] == 0
        
        # Check empty events
        events = response.data["recent_events"]
        assert len(events) == 0

    def test_get_security_statistics_request_no_params(self):
        """Test security statistics request without parameters."""
        request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics"]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert response.data["query_info"]["queried_by"] == "unknown"

    def test_security_query_workflow(self):
        """Test complete security query workflow with policy changes."""
        # Initial state - check policies
        list_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_agent_1"
        }]
        response = self.network.apply_request(list_request)
        
        initial_sender_count = response.data["policy_summary"]["blocked_senders_count"]
        initial_ip_count = response.data["policy_summary"]["blocked_ips_count"]
        
        # Add new policies
        block_sender_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": "workflow@test.com",
            "agent_name": "blue_agent_1"
        }]
        self.network.apply_request(block_sender_request)
        
        block_ip_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": "10.0.0.99",
            "agent_name": "blue_agent_1"
        }]
        self.network.apply_request(block_ip_request)
        
        # Check updated policies
        response = self.network.apply_request(list_request)
        
        assert response.data["policy_summary"]["blocked_senders_count"] == initial_sender_count + 1
        assert response.data["policy_summary"]["blocked_ips_count"] == initial_ip_count + 1
        assert "workflow@test.com" in response.data["policy_summary"]["blocked_senders"]
        assert "10.0.0.99" in response.data["policy_summary"]["blocked_ips"]
        
        # Check statistics reflect the changes
        stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_agent_1"
        }]
        stats_response = self.network.apply_request(stats_request)
        
        # Should have 2 policy change events
        policy_events = [e for e in stats_response.data["recent_events"] if e["event_type"] == "policy_change"]
        assert len(policy_events) == 2
        
        # Check that both actions are logged
        reasons = [e["reason"] for e in policy_events]
        assert any("block_sender" in reason and "workflow@test.com" in reason for reason in reasons)
        assert any("block_ip" in reason and "10.0.0.99" in reason for reason in reasons)

    def test_statistics_with_time_range_filter(self):
        """Test statistics request with time range filtering."""
        # Add some events
        self.smtp_server.security_log.log_blocked_email("test@example.com", "192.168.1.1", "Test event")
        
        request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_agent_1",
            "time_range_hours": 1.0  # Last hour
        }]
        
        response = self.network.apply_request(request)
        
        assert response.status == "success"
        assert response.data["query_info"]["time_range_hours"] == 1.0
        
        # Events should be included (just added)
        assert len(response.data["recent_events"]) >= 1

    def test_concurrent_policy_queries(self):
        """Test multiple agents querying policies concurrently."""
        # Simulate concurrent queries from different agents
        agents = ["blue_agent_1", "blue_agent_2", "blue_agent_3"]
        
        for agent in agents:
            # Each agent queries policies
            list_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
                "agent_name": agent
            }]
            response = self.network.apply_request(list_request)
            
            assert response.status == "success"
            assert response.data["queried_by"] == agent
            
            # Each agent queries statistics
            stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
                "agent_name": agent
            }]
            stats_response = self.network.apply_request(stats_request)
            
            assert stats_response.status == "success"
            assert stats_response.data["query_info"]["queried_by"] == agent