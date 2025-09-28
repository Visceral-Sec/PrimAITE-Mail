"""End-to-end integration tests for email blocking scenarios.

This module tests the complete SOC analyst workflow:
- Blue agent blocks bad actors
- Red agent emails are rejected
- Policy modifications take immediate effect
- CIDR range blocking works correctly
- Multiple blue agents can coordinate
"""

import pytest
from primaite.simulator.network.container import Network
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite_mail.simulator.software.smtp_server import SMTPServer
# No need for SMTP protocol imports since we're testing security methods directly


class TestEmailBlockingEndToEnd:
    """End-to-end tests for email blocking scenarios."""

    def setup_method(self):
        """Set up test environment with mail server and client nodes."""
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
        
        # Create client nodes for red agents
        self.red_client_1 = Computer.from_config({
            "type": "computer",
            "hostname": "red_client_1",
            "ip_address": "192.168.1.100",
            "subnet_mask": "255.255.255.0",
            "start_up_duration": 0,
        })
        self.red_client_1.power_on()
        self.network.add_node(self.red_client_1)
        
        self.red_client_2 = Computer.from_config({
            "type": "computer",
            "hostname": "red_client_2", 
            "ip_address": "10.0.0.50",
            "subnet_mask": "255.255.255.0",
            "start_up_duration": 0,
        })
        self.red_client_2.power_on()
        self.network.add_node(self.red_client_2)
        
        # Install and configure SMTP server
        self.mail_server.software_manager.install(SMTPServer)
        self.smtp_server = self.mail_server.software_manager.software.get("smtp-server")
        
        # Configure SMTP server
        self.smtp_server.config.domain = "company.com"
        self.smtp_server.config.enable_security_logging = True
        self.smtp_server.config.blocked_senders = []
        self.smtp_server.config.blocked_ips = []
        
        # Initialize security policies
        self.smtp_server._init_security_policies()
        self.smtp_server.start()
        
        # Create test mailboxes using request system
        alice_request = ["node", "mail_server", "service", "smtp-server", "create_mailbox", {"username": "alice"}]
        response = self.network.apply_request(alice_request)
        assert response.status == "success"
        
        bob_request = ["node", "mail_server", "service", "smtp-server", "create_mailbox", {"username": "bob"}]
        response = self.network.apply_request(bob_request)
        assert response.status == "success"

    def test_end_to_end_sender_blocking_workflow(self):
        """Test complete sender blocking workflow: blue blocks → red rejected."""
        # Step 1: Verify sender is not blocked initially
        attacker_sender = "attacker@evil.com"
        assert not self.smtp_server.security_policy.is_sender_blocked(attacker_sender)
        
        # Test that sender would be allowed before blocking
        sender_allowed = self.smtp_server._enforce_sender_blocking(attacker_sender, "192.168.1.100")
        assert sender_allowed is True
        
        # Step 2: Blue agent detects threat and blocks sender
        block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": attacker_sender,
            "agent_name": "blue_soc_analyst"
        }]
        
        response = self.network.apply_request(block_request)
        assert response.status == "success"
        assert "successfully blocked" in response.data["message"]
        
        # Verify sender is blocked
        assert self.smtp_server.security_policy.is_sender_blocked(attacker_sender)
        
        # Step 3: Red agent attempts another email (should be rejected)
        sender_allowed = self.smtp_server._enforce_sender_blocking(attacker_sender, "192.168.1.100")
        assert sender_allowed is False
        
        # Step 4: Verify security event was logged
        events = self.smtp_server.security_log.get_recent_events(10)
        blocked_events = [e for e in events if e.event_type == "blocked_sender"]
        assert len(blocked_events) > 0
        assert blocked_events[-1].sender == attacker_sender
        assert blocked_events[-1].ip_address == "192.168.1.100"
        
        # Step 5: Blue agent unblocks sender (threat resolved)
        unblock_request = ["node", "mail_server", "service", "smtp-server", "unblock_sender", {
            "sender_address": attacker_sender,
            "agent_name": "blue_soc_analyst"
        }]
        
        response = self.network.apply_request(unblock_request)
        assert response.status == "success"
        assert "successfully unblocked" in response.data["message"]
        
        # Step 6: Verify sender can now send emails again
        assert not self.smtp_server.security_policy.is_sender_blocked(attacker_sender)
        
        # Test that sender is allowed again
        sender_allowed = self.smtp_server._enforce_sender_blocking(attacker_sender, "192.168.1.100")
        assert sender_allowed is True

    def test_end_to_end_ip_blocking_workflow(self):
        """Test complete IP blocking workflow: blue blocks → red connection refused."""
        # Step 1: Verify IP is not blocked initially
        blocked_ip = "192.168.1.100"
        assert not self.smtp_server.security_policy.is_ip_blocked(blocked_ip)
        
        # Before blocking, connection should be allowed
        connection_allowed = self.smtp_server._enforce_ip_blocking(blocked_ip)
        assert connection_allowed is True
        
        # Step 2: Blue agent detects malicious IP and blocks it
        block_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": blocked_ip,
            "agent_name": "blue_soc_analyst"
        }]
        
        response = self.network.apply_request(block_request)
        assert response.status == "success"
        assert "successfully blocked" in response.data["message"]
        
        # Verify IP is blocked
        assert self.smtp_server.security_policy.is_ip_blocked(blocked_ip)
        
        # Step 3: Red agent attempts connection (should be refused)
        connection_allowed = self.smtp_server._enforce_ip_blocking(blocked_ip)
        assert connection_allowed is False
        
        # Step 4: Verify security event was logged
        events = self.smtp_server.security_log.get_recent_events(10)
        blocked_events = [e for e in events if e.event_type in ["blocked_ip", "connection_refused"]]
        assert len(blocked_events) > 0
        
        # Step 5: Verify other IPs can still connect
        other_ip = "192.168.1.200"
        connection_allowed = self.smtp_server._enforce_ip_blocking(other_ip)
        assert connection_allowed is True
        
        # Step 6: Blue agent unblocks IP
        unblock_request = ["node", "mail_server", "service", "smtp-server", "unblock_ip", {
            "ip_address": blocked_ip,
            "agent_name": "blue_soc_analyst"
        }]
        
        response = self.network.apply_request(unblock_request)
        assert response.status == "success"
        
        # Step 7: Verify IP can connect again
        assert not self.smtp_server.security_policy.is_ip_blocked(blocked_ip)
        connection_allowed = self.smtp_server._enforce_ip_blocking(blocked_ip)
        assert connection_allowed is True

    def test_policy_modification_immediate_effect(self):
        """Test that policy changes take immediate effect."""
        # Test sender blocking immediate effect
        sender = "immediate@test.com"
        
        # Verify sender is not blocked initially
        assert not self.smtp_server.security_policy.is_sender_blocked(sender)
        
        # Block sender
        block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": sender,
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(block_request)
        assert response.status == "success"
        
        # Verify immediate effect
        assert self.smtp_server.security_policy.is_sender_blocked(sender)
        
        # Test sender rejection immediately
        sender_allowed = self.smtp_server._enforce_sender_blocking(sender, "192.168.1.50")
        assert sender_allowed is False
        
        # Test IP blocking immediate effect
        ip = "10.0.0.99"
        
        # Verify IP is not blocked initially
        assert not self.smtp_server.security_policy.is_ip_blocked(ip)
        
        # Block IP
        block_ip_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": ip,
            "agent_name": "blue_agent_1"
        }]
        
        response = self.network.apply_request(block_ip_request)
        assert response.status == "success"
        
        # Verify immediate effect
        assert self.smtp_server.security_policy.is_ip_blocked(ip)
        connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
        assert connection_allowed is False

    def test_cidr_range_blocking_comprehensive(self):
        """Test CIDR range blocking with various IP addresses."""
        # Test /24 range blocking
        cidr_24 = "192.168.1.0/24"
        
        block_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": cidr_24,
            "agent_name": "blue_network_admin"
        }]
        
        response = self.network.apply_request(block_request)
        assert response.status == "success"
        
        # Test IPs within /24 range (should be blocked)
        blocked_ips_24 = [
            "192.168.1.1",
            "192.168.1.50", 
            "192.168.1.100",
            "192.168.1.200",
            "192.168.1.254"
        ]
        
        for ip in blocked_ips_24:
            assert self.smtp_server.security_policy.is_ip_blocked(ip), f"IP {ip} should be blocked by {cidr_24}"
            connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
            assert connection_allowed is False, f"Connection from {ip} should be refused"
        
        # Test IPs outside /24 range (should not be blocked)
        allowed_ips_24 = [
            "192.168.2.1",
            "192.168.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "203.0.113.1"
        ]
        
        for ip in allowed_ips_24:
            assert not self.smtp_server.security_policy.is_ip_blocked(ip), f"IP {ip} should not be blocked by {cidr_24}"
            connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
            assert connection_allowed is True, f"Connection from {ip} should be allowed"
        
        # Test /16 range blocking
        cidr_16 = "10.0.0.0/16"
        
        block_request_16 = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": cidr_16,
            "agent_name": "blue_network_admin"
        }]
        
        response = self.network.apply_request(block_request_16)
        assert response.status == "success"
        
        # Test IPs within /16 range (should be blocked)
        blocked_ips_16 = [
            "10.0.0.1",
            "10.0.1.1",
            "10.0.50.100",
            "10.0.255.254"
        ]
        
        for ip in blocked_ips_16:
            assert self.smtp_server.security_policy.is_ip_blocked(ip), f"IP {ip} should be blocked by {cidr_16}"
        
        # Test IPs outside /16 range (should not be blocked by /16, but may be blocked by /24)
        outside_16_not_24 = [
            "10.1.0.1",  # Outside /16
            "172.16.0.1",  # Outside /16
            "203.0.113.1"  # Outside /16
        ]
        
        for ip in outside_16_not_24:
            # Should not be blocked by the /16 rule
            # (but might be blocked by other rules, so we test the specific policy)
            blocked_by_16 = ip.startswith("10.0.")
            if not blocked_by_16:
                # If not in 10.0.x.x range, should not be blocked by /16 rule
                # But we need to check if it's blocked by the /24 rule
                blocked_by_24 = ip.startswith("192.168.1.")
                expected_blocked = blocked_by_24
                actual_blocked = self.smtp_server.security_policy.is_ip_blocked(ip)
                assert actual_blocked == expected_blocked, f"IP {ip} blocking status incorrect"

    def test_multiple_blue_agents_coordination(self):
        """Test multiple blue agents managing policies concurrently."""
        # Agent 1 blocks senders
        agent1_requests = [
            ("malicious1@attacker.com", "blue_agent_soc_1"),
            ("phishing@scam.net", "blue_agent_soc_1"),
        ]
        
        for sender, agent in agent1_requests:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": agent
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
            assert self.smtp_server.security_policy.is_sender_blocked(sender)
        
        # Agent 2 blocks IPs
        agent2_requests = [
            ("192.168.1.100", "blue_agent_network_2"),
            ("10.0.0.0/24", "blue_agent_network_2"),
        ]
        
        for ip, agent in agent2_requests:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
                "ip_address": ip,
                "agent_name": agent
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
            
            # For CIDR ranges, test an IP within the range instead of the range itself
            if '/' in ip:
                # Test an IP within the CIDR range
                if ip == "10.0.0.0/24":
                    test_ip = "10.0.0.50"
                else:
                    test_ip = ip.split('/')[0]  # Use network address
                assert self.smtp_server.security_policy.is_ip_blocked(test_ip)
            else:
                assert self.smtp_server.security_policy.is_ip_blocked(ip)
        
        # Agent 3 queries current policies
        query_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_agent_monitor_3"
        }]
        
        response = self.network.apply_request(query_request)
        assert response.status == "success"
        
        # Verify all policies are visible
        policy_summary = response.data["policy_summary"]
        assert policy_summary["blocked_senders_count"] == 2
        assert policy_summary["blocked_ips_count"] == 2
        
        blocked_senders = policy_summary["blocked_senders"]
        assert "malicious1@attacker.com" in blocked_senders
        assert "phishing@scam.net" in blocked_senders
        
        blocked_ips = policy_summary["blocked_ips"]
        assert "192.168.1.100" in blocked_ips
        assert "10.0.0.0/24" in blocked_ips
        
        # Verify all agent actions were logged
        stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_agent_monitor_3"
        }]
        
        stats_response = self.network.apply_request(stats_request)
        assert stats_response.status == "success"
        
        events = stats_response.data["recent_events"]
        policy_events = [e for e in events if e["event_type"] == "policy_change"]
        
        # Should have 4 policy change events (2 sender blocks + 2 IP blocks)
        assert len(policy_events) == 4
        
        # Verify different agents are recorded
        agents = {e["agent"] for e in policy_events}
        assert "blue_agent_soc_1" in agents
        assert "blue_agent_network_2" in agents
        
        # Test coordination: Agent 1 removes a rule, Agent 2 verifies
        unblock_request = ["node", "mail_server", "service", "smtp-server", "unblock_sender", {
            "sender_address": "malicious1@attacker.com",
            "agent_name": "blue_agent_soc_1"
        }]
        
        response = self.network.apply_request(unblock_request)
        assert response.status == "success"
        
        # Agent 2 verifies the change
        verify_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_agent_network_2"
        }]
        
        response = self.network.apply_request(verify_request)
        assert response.status == "success"
        
        # Should now have only 1 blocked sender
        assert response.data["policy_summary"]["blocked_senders_count"] == 1
        assert "malicious1@attacker.com" not in response.data["policy_summary"]["blocked_senders"]
        assert "phishing@scam.net" in response.data["policy_summary"]["blocked_senders"]

    def test_soc_analyst_workflow_realistic_scenario(self):
        """Test realistic SOC analyst workflow: detect, block, monitor, adjust."""
        # Scenario: Multiple attack attempts from different sources
        
        # Step 1: Initial attack wave - multiple senders, same IP
        attack_senders = [
            "ceo@company.com",  # CEO spoofing
            "admin@company.com",  # Admin spoofing
            "noreply@bank.com"  # Bank spoofing
        ]
        
        attacker_ip = "203.0.113.100"
        
        # Simulate attacks (before blocking) - verify senders would be allowed
        for sender in attack_senders:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, attacker_ip)
            assert sender_allowed is True, f"Sender {sender} should be allowed initially"
        
        # Step 2: SOC analyst detects pattern and blocks the IP
        block_ip_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": attacker_ip,
            "agent_name": "soc_analyst_alice"
        }]
        
        response = self.network.apply_request(block_ip_request)
        assert response.status == "success"
        
        # Step 3: Verify all subsequent attempts from that IP are blocked
        for sender in attack_senders:
            connection_allowed = self.smtp_server._enforce_ip_blocking(attacker_ip)
            assert connection_allowed is False
        
        # Step 4: Attacker switches to different IP, same senders
        new_attacker_ip = "203.0.113.200"
        
        # Test one sender from new IP (should work since IP not blocked)
        sender_allowed = self.smtp_server._enforce_sender_blocking(attack_senders[0], new_attacker_ip)
        assert sender_allowed is True
        
        # Step 5: SOC analyst adapts strategy - blocks specific senders
        for sender in attack_senders:
            block_sender_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": "soc_analyst_alice"
            }]
            
            response = self.network.apply_request(block_sender_request)
            assert response.status == "success"
        
        # Step 6: Verify sender blocking works from any IP
        for sender in attack_senders:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, new_attacker_ip)
            assert sender_allowed is False, f"Sender {sender} should be blocked from any IP"
        
        # Step 7: Monitor effectiveness
        stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "soc_analyst_alice"
        }]
        
        stats_response = self.network.apply_request(stats_request)
        assert stats_response.status == "success"
        
        # Should have multiple policy changes and blocked attempts
        basic_stats = stats_response.data["basic_stats"]
        assert basic_stats["policy_changes"] >= 4  # 1 IP block + 3 sender blocks
        assert basic_stats["blocked_senders"] >= 3  # At least 3 blocked sender attempts
        
        # Step 8: Legitimate email from different sender should still work
        legitimate_sender = "legitimate@partner.com"
        legitimate_ip = "198.51.100.50"
        sender_allowed = self.smtp_server._enforce_sender_blocking(legitimate_sender, legitimate_ip)
        assert sender_allowed is True

    def test_red_agent_evasion_attempts(self):
        """Test red agent evasion attempts and blue agent countermeasures."""
        # Initial block
        initial_sender = "attacker@evil.com"
        initial_ip = "192.168.1.100"
        
        # Blue agent blocks initial threat
        block_sender_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": initial_sender,
            "agent_name": "blue_defender"
        }]
        
        response = self.network.apply_request(block_sender_request)
        assert response.status == "success"
        
        # Red agent evasion attempt 1: Different sender, same domain
        evasion_sender_1 = "admin@evil.com"
        
        # Should succeed (different sender)
        sender_allowed = self.smtp_server._enforce_sender_blocking(evasion_sender_1, initial_ip)
        assert sender_allowed is True
        
        # Blue agent countermeasure: Block entire domain (simulated with multiple senders)
        domain_senders = [
            "admin@evil.com",
            "user@evil.com", 
            "noreply@evil.com"
        ]
        
        for sender in domain_senders:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": "blue_defender"
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
        
        # Red agent evasion attempt 2: Different domain, same IP
        evasion_sender_2 = "legitimate@company.org"
        
        # Should succeed (different domain, IP not blocked yet)
        sender_allowed = self.smtp_server._enforce_sender_blocking(evasion_sender_2, initial_ip)
        assert sender_allowed is True
        
        # Blue agent countermeasure: Block the IP range
        block_ip_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": "192.168.1.0/24",
            "agent_name": "blue_defender"
        }]
        
        response = self.network.apply_request(block_ip_request)
        assert response.status == "success"
        
        # Red agent evasion attempt 3: Different IP range
        evasion_ip = "10.0.0.50"
        
        # Should be blocked by sender rules but not IP rules
        for sender in domain_senders:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, evasion_ip)
            assert sender_allowed is False, f"Sender {sender} should be blocked from any IP"
        
        # But new sender from new IP should work
        new_sender = "newattacker@different.com"
        sender_allowed = self.smtp_server._enforce_sender_blocking(new_sender, evasion_ip)
        assert sender_allowed is True
        
        # Verify comprehensive blocking statistics
        stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_defender"
        }]
        
        stats_response = self.network.apply_request(stats_request)
        assert stats_response.status == "success"
        
        # Should show multiple policy changes and blocked attempts
        basic_stats = stats_response.data["basic_stats"]
        assert basic_stats["policy_changes"] >= 5  # Multiple blocks
        assert basic_stats["blocked_senders"] >= 3  # Multiple sender blocks

    def test_policy_effectiveness_measurement(self):
        """Test measuring policy effectiveness through statistics."""
        # Establish baseline
        initial_stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_analyst"
        }]
        
        initial_response = self.network.apply_request(initial_stats_request)
        assert initial_response.status == "success"
        
        initial_events = len(initial_response.data["recent_events"])
        
        # Add policies
        policies_to_add = [
            ("block_sender", {"sender_address": "spam@badactor.com"}),
            ("block_sender", {"sender_address": "phishing@scam.net"}),
            ("block_ip", {"ip_address": "192.168.1.100"}),
            ("block_ip", {"ip_address": "10.0.0.0/24"}),
        ]
        
        for action, params in policies_to_add:
            params["agent_name"] = "blue_analyst"
            request = ["node", "mail_server", "service", "smtp-server", action, params]
            
            response = self.network.apply_request(request)
            assert response.status == "success"
        
        # Simulate blocked attempts
        blocked_attempts = [
            ("spam@badactor.com", "192.168.1.50"),
            ("phishing@scam.net", "192.168.1.60"),
            ("user@company.com", "192.168.1.100"),
            ("user@company.com", "10.0.0.50"),
        ]
        
        for sender, ip in blocked_attempts:
            # Test sender blocking
            if self.smtp_server.security_policy.is_sender_blocked(sender):
                sender_allowed = self.smtp_server._enforce_sender_blocking(sender, ip)
                assert sender_allowed is False
            
            # Test IP blocking
            if self.smtp_server.security_policy.is_ip_blocked(ip):
                connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
                assert connection_allowed is False
        
        # Measure effectiveness
        final_stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_analyst"
        }]
        
        final_response = self.network.apply_request(final_stats_request)
        assert final_response.status == "success"
        
        final_stats = final_response.data["basic_stats"]
        
        # Should show policy changes and blocked attempts
        assert final_stats["policy_changes"] >= 4  # 4 policies added
        assert final_stats["blocked_senders"] >= 2  # At least 2 sender blocks
        assert final_stats["blocked_ips"] >= 2  # At least 2 IP blocks
        
        # Check detailed statistics
        detailed_stats = final_response.data["detailed_stats"]
        assert detailed_stats["active_sender_blocks"] == 2  # 2 senders blocked
        assert detailed_stats["active_ip_blocks"] == 2  # 2 IPs/ranges blocked
        
        # Verify events show the activity
        events = final_response.data["recent_events"]
        assert len(events) > initial_events
        
        # Check event types
        event_types = {e["event_type"] for e in events}
        assert "policy_change" in event_types
        assert "blocked_sender" in event_types or "blocked_ip" in event_types

    def test_comprehensive_blocking_scenario(self):
        """Test comprehensive blocking scenario with mixed threats."""
        # Scenario: Coordinated attack from multiple sources
        
        # Attack vectors
        attack_vectors = [
            # Sender spoofing attacks
            ("ceo@company.com", "203.0.113.10", "CEO spoofing"),
            ("admin@company.com", "203.0.113.11", "Admin spoofing"),
            ("support@bank.com", "203.0.113.12", "Bank spoofing"),
            
            # Botnet attacks (same senders, different IPs)
            ("bot@malware.net", "192.168.1.150", "Botnet node 1"),
            ("bot@malware.net", "192.168.1.151", "Botnet node 2"),
            ("bot@malware.net", "192.168.1.152", "Botnet node 3"),
            
            # Distributed attacks (different senders, same subnet)
            ("user1@compromised.org", "10.0.0.10", "Compromised account 1"),
            ("user2@compromised.org", "10.0.0.11", "Compromised account 2"),
            ("user3@compromised.org", "10.0.0.12", "Compromised account 3"),
        ]
        
        # Phase 1: Initial attacks succeed (verify senders would be allowed)
        for sender, ip, description in attack_vectors:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, ip)
            assert sender_allowed is True, f"Initial attack should succeed: {description}"
        
        # Phase 2: SOC analyst response - targeted blocking
        
        # Block spoofed internal addresses
        internal_spoofs = ["ceo@company.com", "admin@company.com"]
        for sender in internal_spoofs:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": "soc_analyst_1"
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
        
        # Block botnet sender
        block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": "bot@malware.net",
            "agent_name": "soc_analyst_1"
        }]
        
        response = self.network.apply_request(block_request)
        assert response.status == "success"
        
        # Block compromised subnet
        block_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": "10.0.0.0/24",
            "agent_name": "soc_analyst_2"
        }]
        
        response = self.network.apply_request(block_request)
        assert response.status == "success"
        
        # Phase 3: Verify blocking effectiveness
        
        # Test spoofed senders (should be blocked)
        for sender in internal_spoofs:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, "203.0.113.99")
            assert sender_allowed is False, f"Spoofed sender {sender} should be blocked"
        
        # Test botnet sender (should be blocked from any IP)
        sender_allowed = self.smtp_server._enforce_sender_blocking("bot@malware.net", "198.51.100.99")
        assert sender_allowed is False
        
        # Test compromised subnet (should be blocked)
        for ip in ["10.0.0.10", "10.0.0.50", "10.0.0.99"]:
            connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
            assert connection_allowed is False
        
        # Test legitimate traffic still works
        legitimate_sender = "partner@trusted.com"
        legitimate_ip = "198.51.100.50"
        sender_allowed = self.smtp_server._enforce_sender_blocking(legitimate_sender, legitimate_ip)
        assert sender_allowed is True
        
        # Phase 4: Verify comprehensive logging and statistics
        stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "soc_manager"
        }]
        
        stats_response = self.network.apply_request(stats_request)
        assert stats_response.status == "success"
        
        basic_stats = stats_response.data["basic_stats"]
        
        # Should have multiple policy changes
        assert basic_stats["policy_changes"] >= 4
        
        # Should have blocked multiple attempts
        assert basic_stats["blocked_senders"] >= 3
        assert basic_stats["blocked_ips"] >= 3
        
        # Check that multiple analysts are recorded
        events = stats_response.data["recent_events"]
        policy_events = [e for e in events if e["event_type"] == "policy_change"]
        
        agents = {e["agent"] for e in policy_events if e.get("agent")}
        assert "soc_analyst_1" in agents
        assert "soc_analyst_2" in agents
        
        # Verify policy summary shows all active blocks
        list_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "soc_manager"
        }]
        
        list_response = self.network.apply_request(list_request)
        assert list_response.status == "success"
        
        policy_summary = list_response.data["policy_summary"]
        assert policy_summary["blocked_senders_count"] >= 3
        assert policy_summary["blocked_ips_count"] >= 1
        
        # Verify specific blocks are in place
        blocked_senders = policy_summary["blocked_senders"]
        assert "ceo@company.com" in blocked_senders
        assert "admin@company.com" in blocked_senders
        assert "bot@malware.net" in blocked_senders
        
        blocked_ips = policy_summary["blocked_ips"]
        assert "10.0.0.0/24" in blocked_ips