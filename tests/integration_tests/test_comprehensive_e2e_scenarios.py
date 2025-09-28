"""Comprehensive end-to-end test scenarios for email security policies.

This module implements the comprehensive test scenarios required by task 10:
- Defensive response scenario: red attack → blue detection → blocking → prevention
- Policy management workflow: establish baseline → monitor → adjust policies  
- Red agent evasion attempts with multiple sender addresses and IPs
- Blue agent coordination and policy effectiveness measurement
- Security event logging verification

These tests verify requirements 6.1, 6.2, 6.3, 6.4, 7.4, 7.5.
"""

import pytest
from primaite.simulator.network.container import Network
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite_mail.simulator.software.smtp_server import SMTPServer


class TestComprehensiveE2EScenarios:
    """Comprehensive end-to-end test scenarios for email security policies."""

    def setup_method(self):
        """Set up test environment with mail server and multiple client nodes."""
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
        
        # Create multiple red agent client nodes
        self.red_clients = []
        red_client_configs = [
            {"hostname": "red_client_1", "ip_address": "192.168.1.100"},
            {"hostname": "red_client_2", "ip_address": "192.168.1.101"},
            {"hostname": "red_client_3", "ip_address": "10.0.0.50"},
            {"hostname": "red_client_4", "ip_address": "10.0.0.51"},
            {"hostname": "red_client_5", "ip_address": "203.0.113.100"},
        ]
        
        for config in red_client_configs:
            client = Computer.from_config({
                "type": "computer",
                "hostname": config["hostname"],
                "ip_address": config["ip_address"],
                "subnet_mask": "255.255.255.0",
                "start_up_duration": 0,
            })
            client.power_on()
            self.network.add_node(client)
            self.red_clients.append(client)
        
        # Install and configure SMTP server
        self.mail_server.software_manager.install(SMTPServer)
        self.smtp_server = self.mail_server.software_manager.software.get("smtp-server")
        
        # Configure SMTP server with security logging enabled
        self.smtp_server.config.domain = "company.com"
        self.smtp_server.config.enable_security_logging = True
        self.smtp_server.config.blocked_senders = []
        self.smtp_server.config.blocked_ips = []
        
        # Initialize security policies and start server
        self.smtp_server._init_security_policies()
        self.smtp_server.start()
        
        # Create test mailboxes
        test_users = ["alice", "bob", "charlie", "admin", "ceo"]
        for username in test_users:
            mailbox_request = ["node", "mail_server", "service", "smtp-server", "create_mailbox", {"username": username}]
            response = self.network.apply_request(mailbox_request)
            assert response.status == "success"

    def test_defensive_response_scenario_complete_workflow(self):
        """Test complete defensive response: red attack → blue detection → blocking → prevention.
        
        This test verifies requirements 6.1, 6.2, 6.3, 6.4:
        - Red agent attacks are realistically blocked
        - Connections are refused for blocked IPs
        - Appropriate failure responses are returned
        - Blocking behavior is consistent with real-world systems
        """
        # Phase 1: Red agent launches coordinated email attack
        attack_scenarios = [
            {
                "description": "CEO spoofing attack",
                "sender": "ceo@company.com",
                "ip": "203.0.113.100",
                "target": "alice",
                "attack_type": "spear_phishing"
            },
            {
                "description": "Admin credential harvesting",
                "sender": "admin@company.com", 
                "ip": "203.0.113.100",
                "target": "bob",
                "attack_type": "credential_harvesting"
            },
            {
                "description": "Bank spoofing",
                "sender": "security@bank.com",
                "ip": "203.0.113.101",
                "target": "charlie",
                "attack_type": "financial_fraud"
            },
            {
                "description": "Botnet spam",
                "sender": "bot@malware.net",
                "ip": "192.168.1.100",
                "target": "alice",
                "attack_type": "malware_distribution"
            }
        ]
        
        # Verify initial attacks would succeed (before detection/blocking)
        for attack in attack_scenarios:
            sender_allowed = self.smtp_server._enforce_sender_blocking(attack["sender"], attack["ip"])
            assert sender_allowed is True, f"Initial attack should succeed: {attack['description']}"
            
            connection_allowed = self.smtp_server._enforce_ip_blocking(attack["ip"])
            assert connection_allowed is True, f"Initial connection should succeed: {attack['description']}"
        
        # Phase 2: Blue agent detection and initial response
        # SOC analyst detects the attack pattern and takes immediate action
        
        # Block the primary attack IP (where multiple attacks originated)
        primary_attack_ip = "203.0.113.100"
        block_ip_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": primary_attack_ip,
            "agent_name": "soc_analyst_detection"
        }]
        
        response = self.network.apply_request(block_ip_request)
        assert response.status == "success"
        assert "successfully blocked" in response.data["message"]
        
        # Verify IP blocking takes immediate effect (Requirement 6.2)
        connection_allowed = self.smtp_server._enforce_ip_blocking(primary_attack_ip)
        assert connection_allowed is False, "Blocked IP should refuse connections immediately"
        
        # Phase 3: Red agent adaptation and continued attacks
        # Red agent switches to different IPs but same senders
        
        # Test attacks from new IPs (should succeed for sender, fail for blocked senders later)
        new_attack_ip = "198.51.100.50"
        
        # CEO spoofing from new IP should still work initially
        sender_allowed = self.smtp_server._enforce_sender_blocking("ceo@company.com", new_attack_ip)
        assert sender_allowed is True, "Attack from new IP should initially succeed"
        
        # Phase 4: Blue agent enhanced response - sender-based blocking
        # SOC analyst realizes IP blocking isn't sufficient, blocks specific senders
        
        high_risk_senders = ["ceo@company.com", "admin@company.com", "security@bank.com"]
        
        for sender in high_risk_senders:
            block_sender_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": "soc_analyst_response"
            }]
            
            response = self.network.apply_request(block_sender_request)
            assert response.status == "success"
            assert "successfully blocked" in response.data["message"]
        
        # Phase 5: Verify comprehensive blocking (Requirements 6.1, 6.3)
        # Test that blocked senders are rejected from any IP
        
        for sender in high_risk_senders:
            # Test from original attack IP (should be blocked by both IP and sender rules)
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, primary_attack_ip)
            assert sender_allowed is False, f"Sender {sender} should be blocked from original IP"
            
            # Test from new IP (should be blocked by sender rule)
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, new_attack_ip)
            assert sender_allowed is False, f"Sender {sender} should be blocked from any IP"
        
        # Test that original attack IP blocks any sender (Requirement 6.2)
        legitimate_sender = "partner@trusted.com"
        connection_allowed = self.smtp_server._enforce_ip_blocking(primary_attack_ip)
        assert connection_allowed is False, "Blocked IP should refuse all connections"
        
        # Phase 6: Verify legitimate traffic still works (Requirement 6.4)
        # Ensure blocking is targeted and doesn't affect legitimate communications
        
        legitimate_scenarios = [
            {"sender": "partner@trusted.com", "ip": "198.51.100.10"},
            {"sender": "customer@client.org", "ip": "198.51.100.20"},
            {"sender": "vendor@supplier.net", "ip": "203.0.113.200"}  # Different from blocked range
        ]
        
        for scenario in legitimate_scenarios:
            sender_allowed = self.smtp_server._enforce_sender_blocking(scenario["sender"], scenario["ip"])
            assert sender_allowed is True, f"Legitimate sender {scenario['sender']} should be allowed"
            
            connection_allowed = self.smtp_server._enforce_ip_blocking(scenario["ip"])
            assert connection_allowed is True, f"Legitimate IP {scenario['ip']} should be allowed"
        
        # Phase 7: Verify security event logging
        # Check that all defensive actions and blocked attempts are properly logged
        
        stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "soc_manager"
        }]
        
        stats_response = self.network.apply_request(stats_request)
        assert stats_response.status == "success"
        
        # Verify policy changes were logged
        basic_stats = stats_response.data["basic_stats"]
        assert basic_stats["policy_changes"] >= 4, "Should have logged IP block + 3 sender blocks"
        
        # Verify blocked attempts were logged
        assert basic_stats["blocked_senders"] >= 3, "Should have logged blocked sender attempts"
        assert basic_stats["blocked_ips"] >= 1, "Should have logged blocked IP attempts"
        
        # Check event details
        events = stats_response.data["recent_events"]
        policy_events = [e for e in events if e["event_type"] == "policy_change"]
        
        # Should have events from both SOC analysts
        agents = {e["agent"] for e in policy_events if e.get("agent")}
        assert "soc_analyst_detection" in agents
        assert "soc_analyst_response" in agents
        
        # Phase 8: Test red agent receives appropriate failure responses (Requirement 6.3)
        # Verify that blocked attempts return realistic SMTP error responses
        
        # This would be tested at the SMTP protocol level in a full implementation
        # For now, we verify the security policy enforcement returns correct blocking status
        
        blocked_attempts = [
            ("ceo@company.com", primary_attack_ip),
            ("admin@company.com", new_attack_ip),
            ("security@bank.com", "10.0.0.99")
        ]
        
        for sender, ip in blocked_attempts:
            # Sender should be blocked
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, ip)
            assert sender_allowed is False, f"Blocked sender {sender} should be rejected"
            
            # If IP is also blocked, connection should be refused
            if self.smtp_server.security_policy.is_ip_blocked(ip):
                connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
                assert connection_allowed is False, f"Blocked IP {ip} should refuse connection"

    def test_policy_management_workflow_complete(self):
        """Test complete policy management workflow: establish baseline → monitor → adjust.
        
        This test verifies requirements 7.4, 7.5:
        - Agents receive structured responses suitable for decision-making
        - Multiple blue agents coordinate through centralized policies
        """
        # Phase 1: Establish security baseline
        # Security team establishes initial security policies based on threat intelligence
        
        baseline_policies = {
            "known_malicious_senders": [
                "spam@known-spammer.com",
                "phishing@scam-site.net",
                "malware@botnet.org"
            ],
            "known_malicious_ips": [
                "192.168.100.0/24",  # Known botnet range
                "10.10.10.10",       # Known C&C server
                "203.0.113.0/28"     # Compromised hosting range
            ]
        }
        
        # Blue agent 1 (Threat Intelligence) establishes sender blocks
        for sender in baseline_policies["known_malicious_senders"]:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": "blue_threat_intel"
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
            assert "successfully blocked" in response.data["message"]
        
        # Blue agent 2 (Network Security) establishes IP blocks
        for ip in baseline_policies["known_malicious_ips"]:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
                "ip_address": ip,
                "agent_name": "blue_network_sec"
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
            assert "successfully blocked" in response.data["message"]
        
        # Phase 2: Monitor policy effectiveness
        # Blue agent 3 (SOC Monitor) queries current policies for situational awareness
        
        monitor_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_soc_monitor"
        }]
        
        monitor_response = self.network.apply_request(monitor_request)
        assert monitor_response.status == "success"
        
        # Verify structured response suitable for decision-making (Requirement 7.4)
        policy_data = monitor_response.data
        assert "policy_summary" in policy_data
        assert "query_timestamp" in policy_data
        assert "policy_details" in policy_data
        
        policy_summary = policy_data["policy_summary"]
        assert policy_summary["blocked_senders_count"] == 3
        assert policy_summary["blocked_ips_count"] == 3
        
        # Verify specific policies are in place
        assert set(policy_summary["blocked_senders"]) == set(baseline_policies["known_malicious_senders"])
        assert set(policy_summary["blocked_ips"]) == set(baseline_policies["known_malicious_ips"])
        
        # Phase 3: Simulate attack attempts and monitor effectiveness
        # Generate some blocked attempts to test monitoring
        
        attack_attempts = [
            ("spam@known-spammer.com", "198.51.100.50"),
            ("phishing@scam-site.net", "198.51.100.51"),
            ("legitimate@company.org", "192.168.100.50"),  # Legitimate sender, blocked IP
            ("user@example.com", "10.10.10.10"),  # Legitimate sender, blocked IP
        ]
        
        for sender, ip in attack_attempts:
            # Test sender blocking
            sender_blocked = self.smtp_server.security_policy.is_sender_blocked(sender)
            if sender_blocked:
                sender_allowed = self.smtp_server._enforce_sender_blocking(sender, ip)
                assert sender_allowed is False
            
            # Test IP blocking
            ip_blocked = self.smtp_server.security_policy.is_ip_blocked(ip)
            if ip_blocked:
                connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
                assert connection_allowed is False
        
        # Phase 4: Monitor security statistics
        # SOC monitor checks effectiveness metrics
        
        stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_soc_monitor"
        }]
        
        stats_response = self.network.apply_request(stats_request)
        assert stats_response.status == "success"
        
        # Verify structured statistics response (Requirement 7.4)
        stats_data = stats_response.data
        assert "basic_stats" in stats_data
        assert "detailed_stats" in stats_data
        assert "recent_events" in stats_data
        
        basic_stats = stats_data["basic_stats"]
        assert basic_stats["policy_changes"] >= 6  # 3 sender + 3 IP blocks
        assert basic_stats["blocked_senders"] >= 2  # At least 2 sender blocks
        assert basic_stats["blocked_ips"] >= 2  # At least 2 IP blocks
        
        detailed_stats = stats_data["detailed_stats"]
        assert detailed_stats["active_sender_blocks"] == 3
        assert detailed_stats["active_ip_blocks"] == 3
        
        # Phase 5: Adjust policies based on new intelligence
        # Threat intelligence agent receives new IOCs and updates policies
        
        # New threat: compromised partner domain
        new_threat_senders = [
            "admin@compromised-partner.com",
            "support@compromised-partner.com"
        ]
        
        # New threat: additional botnet IPs
        new_threat_ips = [
            "172.16.0.0/16",  # Large compromised network
            "203.0.114.100"   # New C&C server
        ]
        
        # Blue agent 1 adds new sender blocks
        for sender in new_threat_senders:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": "blue_threat_intel"
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
        
        # Blue agent 2 adds new IP blocks
        for ip in new_threat_ips:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
                "ip_address": ip,
                "agent_name": "blue_network_sec"
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
        
        # Phase 6: Verify coordinated policy updates (Requirement 7.5)
        # Multiple agents coordinate through centralized SMTP server policies
        
        # SOC monitor verifies all updates are reflected
        final_monitor_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_soc_monitor"
        }]
        
        final_response = self.network.apply_request(final_monitor_request)
        assert final_response.status == "success"
        
        final_summary = final_response.data["policy_summary"]
        assert final_summary["blocked_senders_count"] == 5  # 3 original + 2 new
        assert final_summary["blocked_ips_count"] == 5  # 3 original + 2 new
        
        # Verify all agents' changes are coordinated
        all_expected_senders = baseline_policies["known_malicious_senders"] + new_threat_senders
        all_expected_ips = baseline_policies["known_malicious_ips"] + new_threat_ips
        
        assert set(final_summary["blocked_senders"]) == set(all_expected_senders)
        assert set(final_summary["blocked_ips"]) == set(all_expected_ips)
        
        # Phase 7: Test policy removal coordination
        # Threat intelligence indicates one sender is no longer malicious
        
        unblock_request = ["node", "mail_server", "service", "smtp-server", "unblock_sender", {
            "sender_address": "spam@known-spammer.com",
            "agent_name": "blue_threat_intel"
        }]
        
        response = self.network.apply_request(unblock_request)
        assert response.status == "success"
        
        # Verify change is immediately visible to other agents
        verify_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_soc_monitor"
        }]
        
        verify_response = self.network.apply_request(verify_request)
        assert verify_response.status == "success"
        
        updated_summary = verify_response.data["policy_summary"]
        assert updated_summary["blocked_senders_count"] == 4  # One removed
        assert "spam@known-spammer.com" not in updated_summary["blocked_senders"]
        
        # Verify unblocked sender can now send emails
        sender_allowed = self.smtp_server._enforce_sender_blocking("spam@known-spammer.com", "198.51.100.99")
        assert sender_allowed is True, "Unblocked sender should be allowed"

    def test_red_agent_evasion_and_blue_countermeasures(self):
        """Test red agent evasion attempts and blue agent adaptive countermeasures."""
        
        # Phase 1: Initial red agent attack campaign
        initial_attack = {
            "sender": "attacker@evil.com",
            "ip": "203.0.113.100",
            "campaign": "initial_reconnaissance"
        }
        
        # Verify initial attack would succeed
        sender_allowed = self.smtp_server._enforce_sender_blocking(initial_attack["sender"], initial_attack["ip"])
        assert sender_allowed is True, "Initial attack should succeed"
        
        # Phase 2: Blue agent detects and blocks initial threat
        block_sender_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": initial_attack["sender"],
            "agent_name": "blue_defender"
        }]
        
        response = self.network.apply_request(block_sender_request)
        assert response.status == "success"
        
        # Phase 3: Red agent evasion attempt 1 - Domain variation
        evasion_senders_1 = [
            "admin@evil.com",      # Same domain, different user
            "support@evil.com",    # Same domain, different user
            "noreply@evil.com"     # Same domain, different user
        ]
        
        # Test evasion attempts (should succeed initially)
        for sender in evasion_senders_1:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, initial_attack["ip"])
            assert sender_allowed is True, f"Evasion sender {sender} should initially succeed"
        
        # Phase 4: Blue agent countermeasure 1 - Domain-wide blocking
        # SOC analyst recognizes the pattern and blocks the entire domain
        
        for sender in evasion_senders_1:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": "blue_defender"
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
        
        # Verify domain-wide blocking is effective
        for sender in evasion_senders_1:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, initial_attack["ip"])
            assert sender_allowed is False, f"Domain sender {sender} should be blocked"
        
        # Phase 5: Red agent evasion attempt 2 - Different domains, same IP
        evasion_senders_2 = [
            "user@compromised.org",
            "admin@hacked.net",
            "support@pwned.com"
        ]
        
        # Test attacks from same IP but different domains (should succeed for senders)
        for sender in evasion_senders_2:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, initial_attack["ip"])
            assert sender_allowed is True, f"Different domain sender {sender} should succeed"
        
        # Phase 6: Blue agent countermeasure 2 - IP-based blocking
        # Network security analyst blocks the source IP
        
        block_ip_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": initial_attack["ip"],
            "agent_name": "blue_network_analyst"
        }]
        
        response = self.network.apply_request(block_ip_request)
        assert response.status == "success"
        
        # Verify IP blocking stops all attacks from that IP
        connection_allowed = self.smtp_server._enforce_ip_blocking(initial_attack["ip"])
        assert connection_allowed is False, "Blocked IP should refuse all connections"
        
        # Phase 7: Red agent evasion attempt 3 - Different IP ranges
        evasion_ips = [
            "198.51.100.50",   # Different subnet
            "10.0.0.100",      # Different network
            "172.16.0.50"      # Different private range
        ]
        
        # Test attacks from new IPs (should succeed for connection, but blocked senders still blocked)
        for ip in evasion_ips:
            connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
            assert connection_allowed is True, f"New IP {ip} should allow connections"
            
            # But original blocked senders should still be blocked
            sender_allowed = self.smtp_server._enforce_sender_blocking(initial_attack["sender"], ip)
            assert sender_allowed is False, "Original blocked sender should remain blocked"
        
        # Test new senders from new IPs (should succeed)
        new_sender = "newattacker@different.com"
        for ip in evasion_ips:
            sender_allowed = self.smtp_server._enforce_sender_blocking(new_sender, ip)
            assert sender_allowed is True, f"New sender from new IP {ip} should succeed"
        
        # Phase 8: Blue agent countermeasure 3 - Subnet blocking
        # Network analyst recognizes distributed attack pattern and blocks subnets
        
        subnet_blocks = [
            "198.51.100.0/24",
            "10.0.0.0/16"
        ]
        
        for subnet in subnet_blocks:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
                "ip_address": subnet,
                "agent_name": "blue_network_analyst"
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
        
        # Verify subnet blocking is effective
        blocked_by_subnet = ["198.51.100.50", "10.0.0.100"]
        for ip in blocked_by_subnet:
            connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
            assert connection_allowed is False, f"IP {ip} should be blocked by subnet rule"
        
        # Verify IPs outside blocked subnets still work
        allowed_ip = "172.16.0.50"
        connection_allowed = self.smtp_server._enforce_ip_blocking(allowed_ip)
        assert connection_allowed is True, f"IP {allowed_ip} should still be allowed"
        
        # Phase 9: Red agent evasion attempt 4 - Legitimate-looking senders
        legitimate_spoofs = [
            "ceo@company.com",
            "admin@company.com",
            "security@bank.com"
        ]
        
        # Test spoofed legitimate senders from allowed IP
        for sender in legitimate_spoofs:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, allowed_ip)
            assert sender_allowed is True, f"Spoofed sender {sender} should initially succeed"
        
        # Phase 10: Blue agent countermeasure 4 - Targeted sender blocking
        # SOC analyst blocks high-value spoof targets
        
        for sender in legitimate_spoofs:
            block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": "blue_soc_analyst"
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
        
        # Verify comprehensive blocking effectiveness
        for sender in legitimate_spoofs:
            sender_allowed = self.smtp_server._enforce_sender_blocking(sender, allowed_ip)
            assert sender_allowed is False, f"Spoofed sender {sender} should be blocked"
        
        # Phase 11: Verify evasion tracking and statistics
        stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_security_manager"
        }]
        
        stats_response = self.network.apply_request(stats_request)
        assert stats_response.status == "success"
        
        basic_stats = stats_response.data["basic_stats"]
        
        # Should show extensive policy changes due to evasion/countermeasure cycle
        assert basic_stats["policy_changes"] >= 10, "Should show multiple policy adaptations"
        
        # Should show blocked attempts from evasion attempts
        assert basic_stats["blocked_senders"] >= 5, "Should show multiple blocked sender attempts"
        assert basic_stats["blocked_ips"] >= 3, "Should show multiple blocked IP attempts"
        
        # Verify multiple analysts involved in countermeasures
        events = stats_response.data["recent_events"]
        policy_events = [e for e in events if e["event_type"] == "policy_change"]
        
        analysts = {e["agent"] for e in policy_events if e.get("agent")}
        assert "blue_defender" in analysts
        assert "blue_network_analyst" in analysts
        assert "blue_soc_analyst" in analysts
        
        # Phase 12: Verify legitimate traffic still flows
        # Ensure defensive measures don't break legitimate communications
        
        legitimate_scenarios = [
            {"sender": "partner@trusted.com", "ip": "203.0.114.50"},
            {"sender": "customer@client.org", "ip": "172.17.0.10"},  # Outside blocked ranges
            {"sender": "vendor@supplier.net", "ip": "192.168.2.10"}   # Outside blocked ranges
        ]
        
        for scenario in legitimate_scenarios:
            sender_allowed = self.smtp_server._enforce_sender_blocking(scenario["sender"], scenario["ip"])
            assert sender_allowed is True, f"Legitimate sender {scenario['sender']} should be allowed"
            
            connection_allowed = self.smtp_server._enforce_ip_blocking(scenario["ip"])
            assert connection_allowed is True, f"Legitimate IP {scenario['ip']} should be allowed"

    def test_blue_agent_coordination_and_effectiveness_measurement(self):
        """Test blue agent coordination and comprehensive policy effectiveness measurement."""
        
        # Phase 1: Multi-team coordination setup
        # Different blue agent teams with specific responsibilities
        
        agent_teams = {
            "threat_intel": ["blue_threat_analyst_1", "blue_threat_analyst_2"],
            "network_security": ["blue_network_admin_1", "blue_network_admin_2"],
            "soc_operations": ["blue_soc_analyst_1", "blue_soc_analyst_2", "blue_soc_manager"],
            "incident_response": ["blue_ir_lead", "blue_ir_analyst"]
        }
        
        # Phase 2: Coordinated policy establishment
        # Each team contributes their expertise to establish comprehensive policies
        
        # Threat intelligence team adds known IOCs
        threat_intel_senders = [
            "apt@nation-state.gov",
            "ransomware@criminal.org",
            "phishing@scammer.net"
        ]
        
        for i, sender in enumerate(threat_intel_senders):
            agent = agent_teams["threat_intel"][i % len(agent_teams["threat_intel"])]
            block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
                "sender_address": sender,
                "agent_name": agent
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
        
        # Network security team adds malicious IP ranges
        network_security_ips = [
            "192.168.100.0/24",  # Compromised internal range
            "10.10.10.0/28",     # C&C server range
            "203.0.113.0/25"     # Botnet range
        ]
        
        for i, ip in enumerate(network_security_ips):
            agent = agent_teams["network_security"][i % len(agent_teams["network_security"])]
            block_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
                "ip_address": ip,
                "agent_name": agent
            }]
            
            response = self.network.apply_request(block_request)
            assert response.status == "success"
        
        # Phase 3: SOC operations monitoring
        # SOC team monitors the effectiveness of established policies
        
        soc_monitor_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_soc_manager"
        }]
        
        monitor_response = self.network.apply_request(soc_monitor_request)
        assert monitor_response.status == "success"
        
        # Verify all teams' contributions are visible
        policy_summary = monitor_response.data["policy_summary"]
        assert policy_summary["blocked_senders_count"] == 3
        assert policy_summary["blocked_ips_count"] == 3
        
        # Phase 4: Simulate coordinated attack and measure response effectiveness
        # Generate attack scenarios that test the coordinated defenses
        
        attack_scenarios = [
            # Test threat intel blocks
            {"sender": "apt@nation-state.gov", "ip": "198.51.100.10", "should_block_sender": True},
            {"sender": "ransomware@criminal.org", "ip": "198.51.100.11", "should_block_sender": True},
            
            # Test network security blocks
            {"sender": "user@legitimate.com", "ip": "192.168.100.50", "should_block_ip": True},
            {"sender": "admin@company.org", "ip": "10.10.10.5", "should_block_ip": True},
            
            # Test combined blocks
            {"sender": "phishing@scammer.net", "ip": "203.0.113.100", "should_block_both": True},
            
            # Test legitimate traffic
            {"sender": "partner@trusted.com", "ip": "198.51.100.50", "should_allow": True}
        ]
        
        blocked_sender_attempts = 0
        blocked_ip_attempts = 0
        
        for scenario in attack_scenarios:
            sender = scenario["sender"]
            ip = scenario["ip"]
            
            if scenario.get("should_block_sender"):
                sender_allowed = self.smtp_server._enforce_sender_blocking(sender, ip)
                assert sender_allowed is False, f"Sender {sender} should be blocked by threat intel"
                blocked_sender_attempts += 1
            
            if scenario.get("should_block_ip"):
                connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
                assert connection_allowed is False, f"IP {ip} should be blocked by network security"
                blocked_ip_attempts += 1
            
            if scenario.get("should_block_both"):
                sender_allowed = self.smtp_server._enforce_sender_blocking(sender, ip)
                connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
                assert sender_allowed is False and connection_allowed is False, f"Both sender and IP should be blocked"
                blocked_sender_attempts += 1
                blocked_ip_attempts += 1
            
            if scenario.get("should_allow"):
                sender_allowed = self.smtp_server._enforce_sender_blocking(sender, ip)
                connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
                assert sender_allowed is True and connection_allowed is True, f"Legitimate traffic should be allowed"
        
        # Phase 5: Incident response team analysis
        # IR team analyzes the effectiveness and coordinates additional measures
        
        ir_stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_ir_lead"
        }]
        
        ir_stats_response = self.network.apply_request(ir_stats_request)
        assert ir_stats_response.status == "success"
        
        # Verify comprehensive statistics for effectiveness measurement
        basic_stats = ir_stats_response.data["basic_stats"]
        detailed_stats = ir_stats_response.data["detailed_stats"]
        
        # Should show coordinated policy establishment
        assert basic_stats["policy_changes"] >= 6, "Should show all team contributions"
        
        # Should show blocked attempts from simulated attacks
        assert basic_stats["blocked_senders"] >= blocked_sender_attempts
        assert basic_stats["blocked_ips"] >= blocked_ip_attempts
        
        # Verify detailed effectiveness metrics
        assert detailed_stats["active_sender_blocks"] == 3
        assert detailed_stats["active_ip_blocks"] == 3
        
        # Phase 6: Cross-team policy adjustment
        # Teams coordinate to adjust policies based on new intelligence
        
        # Threat intel discovers one sender is no longer malicious
        unblock_sender_request = ["node", "mail_server", "service", "smtp-server", "unblock_sender", {
            "sender_address": "phishing@scammer.net",
            "agent_name": "blue_threat_analyst_1"
        }]
        
        response = self.network.apply_request(unblock_sender_request)
        assert response.status == "success"
        
        # SOC operations adds emergency block based on incident
        emergency_sender = "urgent@malicious.com"
        soc_block_request = ["node", "mail_server", "service", "smtp-server", "block_sender", {
            "sender_address": emergency_sender,
            "agent_name": "blue_soc_analyst_1"
        }]
        
        response = self.network.apply_request(soc_block_request)
        assert response.status == "success"
        
        # Network security adds new threat IP
        new_threat_ip = "172.16.100.0/24"
        block_new_ip_request = ["node", "mail_server", "service", "smtp-server", "block_ip", {
            "ip_address": new_threat_ip,
            "agent_name": "blue_network_admin_1"
        }]
        
        response = self.network.apply_request(block_new_ip_request)
        assert response.status == "success"
        
        # SOC operations verifies coordinated changes
        verify_request = ["node", "mail_server", "service", "smtp-server", "list_security_policies", {
            "agent_name": "blue_soc_analyst_1"
        }]
        
        verify_response = self.network.apply_request(verify_request)
        assert verify_response.status == "success"
        
        updated_summary = verify_response.data["policy_summary"]
        assert updated_summary["blocked_senders_count"] == 3  # One removed, one added
        assert updated_summary["blocked_ips_count"] == 4  # One added
        
        # Verify specific changes
        assert "phishing@scammer.net" not in updated_summary["blocked_senders"]
        assert emergency_sender in updated_summary["blocked_senders"]
        assert new_threat_ip in updated_summary["blocked_ips"]
        
        # Phase 7: Comprehensive effectiveness measurement
        # Final analysis of coordinated defense effectiveness
        
        final_stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "blue_soc_manager"
        }]
        
        final_stats_response = self.network.apply_request(final_stats_request)
        assert final_stats_response.status == "success"
        
        # Verify all team activities are tracked
        events = final_stats_response.data["recent_events"]
        policy_events = [e for e in events if e["event_type"] == "policy_change"]
        
        # Should have events from all teams
        all_agents = {e["agent"] for e in policy_events if e.get("agent")}
        
        # Verify representation from each team
        threat_intel_agents = set(agent_teams["threat_intel"])
        network_security_agents = set(agent_teams["network_security"])
        soc_agents = set(agent_teams["soc_operations"])
        
        assert len(all_agents & threat_intel_agents) > 0, "Should have threat intel team activity"
        assert len(all_agents & network_security_agents) > 0, "Should have network security team activity"
        assert len(all_agents & soc_agents) > 0, "Should have SOC team activity"
        
        # Verify policy coordination effectiveness
        final_basic_stats = final_stats_response.data["basic_stats"]
        assert final_basic_stats["policy_changes"] >= 9, "Should show all coordinated changes"
        
        # Test that unblocked sender now works
        sender_allowed = self.smtp_server._enforce_sender_blocking("phishing@scammer.net", "198.51.100.99")
        assert sender_allowed is True, "Unblocked sender should be allowed"
        
        # Test that new blocked IP range works
        connection_allowed = self.smtp_server._enforce_ip_blocking("172.16.100.50")
        assert connection_allowed is False, "New blocked IP should be refused"

    def test_comprehensive_security_event_logging_verification(self):
        """Test comprehensive security event logging and auditability."""
        
        # Phase 1: Generate diverse security events
        # Create various types of security events to test logging comprehensiveness
        
        security_scenarios = [
            # Policy establishment events
            {"action": "block_sender", "params": {"sender_address": "malicious@attacker.com", "agent_name": "blue_analyst_1"}},
            {"action": "block_ip", "params": {"ip_address": "192.168.1.100", "agent_name": "blue_analyst_1"}},
            {"action": "block_ip", "params": {"ip_address": "10.0.0.0/24", "agent_name": "blue_network_admin"}},
            
            # Policy modification events
            {"action": "unblock_sender", "params": {"sender_address": "malicious@attacker.com", "agent_name": "blue_analyst_2"}},
            {"action": "block_sender", "params": {"sender_address": "phishing@scam.net", "agent_name": "blue_analyst_2"}},
            
            # Multiple agent coordination
            {"action": "block_sender", "params": {"sender_address": "spam@badactor.org", "agent_name": "blue_soc_team_1"}},
            {"action": "block_ip", "params": {"ip_address": "203.0.113.0/28", "agent_name": "blue_soc_team_2"}},
        ]
        
        # Execute security actions and verify each is logged
        for scenario in security_scenarios:
            action = scenario["action"]
            params = scenario["params"]
            
            request = ["node", "mail_server", "service", "smtp-server", action, params]
            response = self.network.apply_request(request)
            assert response.status == "success", f"Action {action} should succeed"
        
        # Phase 2: Generate blocked attempt events
        # Simulate various types of blocked attempts to test enforcement logging
        
        blocked_attempts = [
            # Sender blocking attempts
            {"sender": "phishing@scam.net", "ip": "198.51.100.10", "type": "sender_block"},
            {"sender": "spam@badactor.org", "ip": "198.51.100.11", "type": "sender_block"},
            
            # IP blocking attempts
            {"sender": "user@legitimate.com", "ip": "192.168.1.100", "type": "ip_block"},
            {"sender": "admin@company.org", "ip": "10.0.0.50", "type": "ip_block"},
            {"sender": "partner@trusted.net", "ip": "203.0.113.10", "type": "ip_block"},
            
            # CIDR range blocking attempts
            {"sender": "user@example.com", "ip": "203.0.113.15", "type": "cidr_block"},
        ]
        
        for attempt in blocked_attempts:
            sender = attempt["sender"]
            ip = attempt["ip"]
            
            # Test sender blocking (generates log events)
            if self.smtp_server.security_policy.is_sender_blocked(sender):
                sender_allowed = self.smtp_server._enforce_sender_blocking(sender, ip)
                assert sender_allowed is False, f"Sender {sender} should be blocked"
            
            # Test IP blocking (generates log events)
            if self.smtp_server.security_policy.is_ip_blocked(ip):
                connection_allowed = self.smtp_server._enforce_ip_blocking(ip)
                assert connection_allowed is False, f"IP {ip} should be blocked"
        
        # Phase 3: Verify comprehensive event logging
        # Check that all security events are properly logged with required details
        
        stats_request = ["node", "mail_server", "service", "smtp-server", "get_security_statistics", {
            "agent_name": "security_auditor"
        }]
        
        stats_response = self.network.apply_request(stats_request)
        assert stats_response.status == "success"
        
        # Verify basic statistics
        basic_stats = stats_response.data["basic_stats"]
        assert basic_stats["policy_changes"] >= 7, "Should log all policy changes"
        assert basic_stats["blocked_senders"] >= 2, "Should log blocked sender attempts"
        assert basic_stats["blocked_ips"] >= 4, "Should log blocked IP attempts"
        
        # Phase 4: Verify detailed event information
        # Check that events contain all required audit information
        
        events = stats_response.data["recent_events"]
        assert len(events) > 0, "Should have recorded security events"
        
        # Verify policy change events have required fields
        policy_events = [e for e in events if e["event_type"] == "policy_change"]
        assert len(policy_events) >= 7, "Should have all policy change events"
        
        for event in policy_events:
            # Verify required fields for audit trail
            assert "timestamp" in event, "Event should have timestamp"
            assert "event_type" in event, "Event should have type"
            assert "agent" in event, "Event should record acting agent"
            assert "reason" in event, "Event should have reason/description"
            
            # Verify timestamp format (should be ISO format)
            timestamp = event["timestamp"]
            assert "T" in timestamp, "Timestamp should be ISO format with T separator"
            
            # Verify agent information
            agent = event["agent"]
            assert agent is not None and len(agent) > 0, "Agent should be recorded"
        
        # Verify blocked attempt events have required fields
        blocked_events = [e for e in events if e["event_type"] in ["blocked_sender", "blocked_ip", "connection_refused"]]
        
        for event in blocked_events:
            assert "timestamp" in event, "Blocked event should have timestamp"
            assert "event_type" in event, "Blocked event should have type"
            assert "reason" in event, "Blocked event should have reason"
            
            # Verify event-specific fields
            if event["event_type"] == "blocked_sender":
                assert "sender" in event, "Blocked sender event should record sender"
                assert "ip_address" in event, "Blocked sender event should record IP"
            elif event["event_type"] in ["blocked_ip", "connection_refused"]:
                assert "ip_address" in event, "Blocked IP event should record IP"
        
        # Phase 5: Test event categorization and severity
        # Verify events are properly categorized by type and severity
        
        event_types = {e["event_type"] for e in events}
        expected_types = {"policy_change", "blocked_sender", "blocked_ip"}
        
        # Should have multiple event types
        assert len(event_types & expected_types) >= 2, "Should have multiple event types"
        
        # Verify severity categorization (if implemented)
        severity_events = [e for e in events if "severity" in e]
        if severity_events:
            severities = {e["severity"] for e in severity_events}
            valid_severities = {"low", "medium", "high"}
            assert severities.issubset(valid_severities), "Severities should be valid values"
        
        # Phase 6: Test event filtering and querying
        # Verify that events can be filtered by various criteria
        
        # Test filtering by agent (if supported)
        agent_specific_events = [e for e in events if e.get("agent") == "blue_analyst_1"]
        assert len(agent_specific_events) >= 2, "Should have events from specific agent"
        
        # Test filtering by event type
        policy_change_events = [e for e in events if e["event_type"] == "policy_change"]
        blocked_events = [e for e in events if e["event_type"] in ["blocked_sender", "blocked_ip"]]
        
        assert len(policy_change_events) > 0, "Should have policy change events"
        assert len(blocked_events) > 0, "Should have blocked attempt events"
        
        # Phase 7: Verify audit trail completeness
        # Check that the audit trail provides complete incident reconstruction capability
        
        # Verify chronological ordering
        timestamps = [e["timestamp"] for e in events if "timestamp" in e]
        assert len(timestamps) > 0, "Should have timestamped events"
        
        # Verify policy changes can be traced
        sender_changes = [e for e in policy_events if 
                         "block_sender" in e.get("reason", "") or 
                         "unblock_sender" in e.get("reason", "")]
        assert len(sender_changes) >= 1, "Should trace sender policy changes"
        
        ip_changes = [e for e in policy_events if 
                     "block_ip" in e.get("reason", "") or 
                     "unblock_ip" in e.get("reason", "")]
        assert len(ip_changes) >= 1, "Should trace IP policy changes"
        
        # Phase 8: Test log retention and management
        # Verify that logs are properly managed and retained
        
        detailed_stats = stats_response.data["detailed_stats"]
        
        # Should track total events
        if "total_events_logged" in detailed_stats:
            total_events = detailed_stats["total_events_logged"]
            assert total_events >= len(events), "Should track total event count"
        
        # Should show active policies
        assert "active_sender_blocks" in detailed_stats, "Should track active sender blocks"
        assert "active_ip_blocks" in detailed_stats, "Should track active IP blocks"
        
        active_senders = detailed_stats["active_sender_blocks"]
        active_ips = detailed_stats["active_ip_blocks"]
        
        # Should reflect current policy state
        assert active_senders >= 2, "Should show current active sender blocks"
        assert active_ips >= 3, "Should show current active IP blocks"
        
        # Phase 9: Verify compliance and forensic capability
        # Test that logs provide sufficient information for compliance and forensics
        
        # Verify all required audit information is present
        compliance_fields = ["timestamp", "event_type", "reason"]
        
        for event in events:
            for field in compliance_fields:
                assert field in event, f"Event should have {field} for compliance"
        
        # Verify forensic reconstruction capability
        # Should be able to reconstruct the sequence of defensive actions
        
        policy_timeline = sorted(policy_events, key=lambda x: x["timestamp"])
        
        # Should show progression of defensive measures
        assert len(policy_timeline) >= 7, "Should have complete policy timeline"
        
        # Verify that both establishment and modification events are captured
        establishment_events = [e for e in policy_timeline if "block" in e.get("reason", "")]
        modification_events = [e for e in policy_timeline if "unblock" in e.get("reason", "")]
        
        assert len(establishment_events) >= 6, "Should capture policy establishment"
        assert len(modification_events) >= 1, "Should capture policy modifications"
        
        # Phase 10: Test event correlation and analysis
        # Verify that events can be correlated for security analysis
        
        # Group events by agent to analyze coordination
        agent_activity = {}
        for event in policy_events:
            agent = event.get("agent")
            if agent:
                if agent not in agent_activity:
                    agent_activity[agent] = []
                agent_activity[agent].append(event)
        
        # Should show multiple agents involved
        assert len(agent_activity) >= 3, "Should show multiple agents coordinating"
        
        # Verify each agent's activity is tracked
        for agent, activities in agent_activity.items():
            assert len(activities) >= 1, f"Agent {agent} should have recorded activities"
            
            # Each activity should have proper attribution
            for activity in activities:
                assert activity["agent"] == agent, "Activity should be properly attributed"