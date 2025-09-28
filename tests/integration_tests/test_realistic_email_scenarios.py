# © Crown-owned copyright 2025, Defence Science and Technology Laboratory UK
"""Realistic email scenario tests for AI training simulation.

This file provides comprehensive realistic email scenarios that simulate:
1. Normal business day traffic patterns
2. Multi-agent concurrent interactions
3. Department-wide communications
4. Security incident scenarios
5. Network resilience testing

These scenarios are designed to provide realistic training data for AI agents
in cybersecurity contexts.
"""

import pytest
import time
import random
from typing import List, Dict, Any
from primaite.game.game import PrimaiteGame
from primaite.simulator.sim_container import Simulation
from primaite.simulator.network.hardware.nodes.host.computer import Computer
from primaite_mail.simulator.software.smtp_server import SMTPServer
from primaite_mail.simulator.software.pop3_server import POP3Server
from primaite_mail.simulator.software.email_client import EmailClient
from primaite_mail.simulator.network.protocols.smtp import EmailMessage
from primaite_mail.game.agents.green_mail_agent import GreenMailAgent


class TestRealisticEmailScenarios:
    """Test realistic email scenarios for AI training."""

    @pytest.fixture
    def enterprise_network_config(self):
        """Create enterprise network configuration for realistic scenarios."""
        return {
            "metadata": {"version": 3.0},
            "game": {
                "max_episode_length": 100,
                "ports": ["SMTP", "POP3", "DNS"],
                "protocols": ["TCP", "UDP", "ICMP"]
            },
            "simulation": {
                "network": {
                    "nodes": [
                        {
                            "hostname": "mail_server",
                            "type": "server",
                            "ip_address": "192.168.1.10",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "services": [
                                {"type": "smtp-server"},
                                {"type": "pop3-server"}
                            ]
                        },
                        {
                            "hostname": "executive_pc",
                            "type": "computer",
                            "ip_address": "192.168.1.21",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "ceo@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "hr_pc",
                            "type": "computer",
                            "ip_address": "192.168.1.22",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "hr@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "finance_pc",
                            "type": "computer",
                            "ip_address": "192.168.1.23",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "finance@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "it_pc",
                            "type": "computer",
                            "ip_address": "192.168.1.24",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "it@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "staff_pc_1",
                            "type": "computer",
                            "ip_address": "192.168.1.25",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "alice@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "staff_pc_2",
                            "type": "computer",
                            "ip_address": "192.168.1.26",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "bob@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "switch_1",
                            "type": "switch",
                            "num_ports": 8
                        },
                        {
                            "hostname": "router_1",
                            "type": "router",
                            "num_ports": 1,
                            "ports": {
                                1: {
                                    "ip_address": "192.168.1.1",
                                    "subnet_mask": "255.255.255.0"
                                }
                            }
                        }
                    ],
                    "links": [
                        {
                            "endpoint_a_hostname": "mail_server",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 1
                        },
                        {
                            "endpoint_a_hostname": "executive_pc",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 2
                        },
                        {
                            "endpoint_a_hostname": "hr_pc",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 3
                        },
                        {
                            "endpoint_a_hostname": "finance_pc",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 4
                        },
                        {
                            "endpoint_a_hostname": "it_pc",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 5
                        },
                        {
                            "endpoint_a_hostname": "staff_pc_1",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 6
                        },
                        {
                            "endpoint_a_hostname": "staff_pc_2",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 7
                        },
                        {
                            "endpoint_a_hostname": "router_1",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 8
                        }
                    ]
                }
            }
        }

    def test_normal_business_day_email_traffic(self, enterprise_network_config):
        "Simulate realistic business day email traffic patterns."
        # Create game without agents first to set up infrastructure
        game = PrimaiteGame.from_config(enterprise_network_config)
        
        # Get mail server and set up mailboxes
        mail_server = game.simulation.network.get_node_by_hostname("mail_server")
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        pop3_server.mailbox_manager = smtp_server.mailbox_manager
        
        # Create user mailboxes
        users = ["ceo", "hr", "finance", "it", "alice", "bob", "admin"]
        for user in users:
            smtp_server.mailbox_manager.create_mailbox(user)
        
        # Simulate business day email patterns
        email_log = []
        
        # 8 AM: Light activity starts
        morning_emails = [
            {
                "sender": "it@company.com",
                "recipients": ["ceo@company.com", "hr@company.com"],
                "subject": "Daily System Status Report",
                "body": "All systems operational. Overnight backups completed successfully."
            },
            {
                "sender": "hr@company.com",
                "recipients": ["alice@company.com", "bob@company.com"],
                "subject": "Team Meeting Today",
                "body": "Reminder: Team meeting at 10 AM in Conference Room A."
            }
        ]
        
        # 9-10 AM: Morning email burst
        morning_burst_emails = [
            {
                "sender": "ceo@company.com",
                "recipients": ["hr@company.com", "finance@company.com", "it@company.com"],
                "subject": "Q4 Planning Meeting",
                "body": "Please prepare Q4 reports for tomorrow's planning session."
            },
            {
                "sender": "finance@company.com",
                "recipients": ["ceo@company.com"],
                "subject": "Monthly Financial Summary",
                "body": "Attached is the monthly financial summary for your review."
            },
            {
                "sender": "alice@company.com",
                "recipients": ["bob@company.com"],
                "subject": "Project Update",
                "body": "The client presentation is ready for review."
            },
            {
                "sender": "bob@company.com",
                "recipients": ["alice@company.com", "it@company.com"],
                "subject": "Technical Requirements",
                "body": "Please review the technical requirements for the new project."
            }
        ]
        
        # 12-1 PM: Lunch break (reduced activity)
        lunch_emails = [
            {
                "sender": "hr@company.com",
                "recipients": ["alice@company.com", "bob@company.com"],
                "subject": "Lunch & Learn Session",
                "body": "Don't forget about today's lunch & learn session on cybersecurity."
            }
        ]
        
        # 3-5 PM: Afternoon activity
        afternoon_emails = [
            {
                "sender": "it@company.com",
                "recipients": ["ceo@company.com", "hr@company.com", "finance@company.com"],
                "subject": "Security Update Required",
                "body": "Please install the latest security updates on your systems."
            },
            {
                "sender": "finance@company.com",
                "recipients": ["hr@company.com"],
                "subject": "Budget Approval Request",
                "body": "Please review and approve the training budget for next quarter."
            }
        ]
        
        # 5-6 PM: End-of-day summaries
        evening_emails = [
            {
                "sender": "ceo@company.com",
                "recipients": ["hr@company.com", "finance@company.com", "it@company.com", "alice@company.com", "bob@company.com"],
                "subject": "End of Day Summary",
                "body": "Great work today everyone. See you tomorrow for the planning meeting."
            }
        ]
        
        # Send all emails and track delivery
        all_emails = morning_emails + morning_burst_emails + lunch_emails + afternoon_emails + evening_emails
        delivered_count = 0
        failed_count = 0
        
        for email_data in all_emails:
            email = EmailMessage(
                sender=email_data["sender"],
                recipients=email_data["recipients"],
                subject=email_data["subject"],
                body=email_data["body"]
            )
            
            # Deliver to each recipient
            for recipient in email.recipients:
                username = recipient.split("@")[0]
                mailbox = smtp_server.mailbox_manager.get_mailbox(username)
                if mailbox and mailbox.add_message(email):
                    delivered_count += 1
                    email_log.append({
                        "sender": email.sender,
                        "recipient": recipient,
                        "subject": email.subject,
                        "delivered": True
                    })
                else:
                    failed_count += 1
                    email_log.append({
                        "sender": email.sender,
                        "recipient": recipient,
                        "subject": email.subject,
                        "delivered": False
                    })
        
        # Verify realistic traffic patterns
        assert delivered_count > 0, "Should deliver some emails"
        assert len(email_log) > 15, "Should have significant email activity"
        
        # Verify different user types received appropriate emails
        ceo_mailbox = smtp_server.mailbox_manager.get_mailbox("ceo")
        hr_mailbox = smtp_server.mailbox_manager.get_mailbox("hr")
        staff_mailbox = smtp_server.mailbox_manager.get_mailbox("alice")
        
        ceo_messages = ceo_mailbox.get_messages()
        hr_messages = hr_mailbox.get_messages()
        staff_messages = staff_mailbox.get_messages()
        
        assert len(ceo_messages) >= 2, "CEO should receive multiple emails"
        assert len(hr_messages) >= 3, "HR should receive multiple emails"
        assert len(staff_messages) >= 2, "Staff should receive multiple emails"
        
        # Verify email content variety
        all_subjects = [msg.subject for msg in ceo_messages + hr_messages + staff_messages]
        unique_subjects = set(all_subjects)
        assert len(unique_subjects) >= 5, "Should have variety in email subjects"
        
        print(f"📊 Business day simulation: {delivered_count} emails delivered, {failed_count} failed")
        print(f"📧 Email variety: {len(unique_subjects)} unique subjects")

    def test_multi_agent_concurrent_email_scenario(self):
        "Test realistic multi-agent concurrent email interactions."
        config = {
            "metadata": {"version": 3.0},
            "game": {
                "max_episode_length": 50,
                "ports": ["SMTP", "POP3", "DNS"],
                "protocols": ["TCP", "UDP", "ICMP"]
            },
            "agents": [
                {
                    "ref": "executive_agent",
                    "team": "GREEN",
                    "type": "green-mail-agent",
                    "agent_settings": {
                        "node_name": "executive_pc",
                        "sender_email": "ceo@company.com",
                        "recipients": ["hr@company.com", "finance@company.com", "it@company.com"],
                        "send_probability": 0.4,
                        "retrieve_probability": 0.3,
                        "idle_probability": 0.3,
                        "email_frequency": 12,
                        "email_variance": 4,
                        "email_subjects": [
                            "Strategic Planning Update",
                            "Board Meeting Preparation",
                            "Quarterly Review",
                            "Company Direction",
                            "Executive Decision"
                        ],
                        "email_templates": [
                            "Please prepare the quarterly reports for review.",
                            "We need to discuss the strategic direction for next year.",
                            "The board meeting is scheduled for next week.",
                            "Please provide an update on your department's progress.",
                            "Let's schedule a meeting to discuss this further."
                        ]
                    },
                    "action_space": {"action_map": {0: {"action": "do-nothing", "options": {}}}},
                    "reward_function": {"reward_components": [{"type": "dummy", "weight": 1.0}]}
                },
                {
                    "ref": "hr_agent",
                    "team": "GREEN",
                    "type": "green-mail-agent",
                    "agent_settings": {
                        "node_name": "hr_pc",
                        "sender_email": "hr@company.com",
                        "recipients": ["alice@company.com", "bob@company.com", "ceo@company.com"],
                        "send_probability": 0.6,
                        "retrieve_probability": 0.3,
                        "idle_probability": 0.1,
                        "email_frequency": 8,
                        "email_variance": 3,
                        "email_subjects": [
                            "Training Reminder",
                            "Policy Update",
                            "Team Meeting",
                            "Performance Review",
                            "Benefits Information"
                        ],
                        "email_templates": [
                            "Please complete your mandatory training by end of week.",
                            "New company policy has been updated in the handbook.",
                            "Team meeting scheduled for tomorrow at 2 PM.",
                            "Performance review cycle begins next month.",
                            "Benefits enrollment period is now open."
                        ]
                    },
                    "action_space": {"action_map": {0: {"action": "do-nothing", "options": {}}}},
                    "reward_function": {"reward_components": [{"type": "dummy", "weight": 1.0}]}
                },
                {
                    "ref": "it_agent",
                    "team": "GREEN",
                    "type": "green-mail-agent",
                    "agent_settings": {
                        "node_name": "it_pc",
                        "sender_email": "it@company.com",
                        "recipients": ["ceo@company.com", "hr@company.com", "finance@company.com", "alice@company.com", "bob@company.com"],
                        "send_probability": 0.7,
                        "retrieve_probability": 0.2,
                        "idle_probability": 0.1,
                        "email_frequency": 6,
                        "email_variance": 2,
                        "email_subjects": [
                            "System Maintenance",
                            "Security Update",
                            "Backup Status",
                            "Network Issue",
                            "Software Update"
                        ],
                        "email_templates": [
                            "Scheduled maintenance will occur tonight from 11 PM to 1 AM.",
                            "Critical security update available. Please install immediately.",
                            "Daily backup completed successfully.",
                            "Network connectivity issue resolved.",
                            "New software version available for download."
                        ]
                    },
                    "action_space": {"action_map": {0: {"action": "do-nothing", "options": {}}}},
                    "reward_function": {"reward_components": [{"type": "dummy", "weight": 1.0}]}
                },
                {
                    "ref": "staff_agent_1",
                    "team": "GREEN",
                    "type": "green-mail-agent",
                    "agent_settings": {
                        "node_name": "staff_pc_1",
                        "sender_email": "alice@company.com",
                        "recipients": ["bob@company.com", "hr@company.com", "it@company.com"],
                        "send_probability": 0.5,
                        "retrieve_probability": 0.4,
                        "idle_probability": 0.1,
                        "email_frequency": 10,
                        "email_variance": 4,
                        "email_subjects": [
                            "Project Update",
                            "Client Feedback",
                            "Meeting Notes",
                            "Question",
                            "Status Report"
                        ],
                        "email_templates": [
                            "Project is on track for delivery next week.",
                            "Client provided positive feedback on the proposal.",
                            "Meeting notes from today's discussion attached.",
                            "I have a question about the new process.",
                            "Weekly status report for your review."
                        ]
                    },
                    "action_space": {"action_map": {0: {"action": "do-nothing", "options": {}}}},
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
                            "default_gateway": "192.168.1.1",
                            "services": [
                                {"type": "smtp-server"},
                                {"type": "pop3-server"}
                            ]
                        },
                        {
                            "hostname": "executive_pc",
                            "type": "computer",
                            "ip_address": "192.168.1.21",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "ceo@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "hr_pc",
                            "type": "computer",
                            "ip_address": "192.168.1.22",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "hr@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "it_pc",
                            "type": "computer",
                            "ip_address": "192.168.1.24",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "it@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "staff_pc_1",
                            "type": "computer",
                            "ip_address": "192.168.1.25",
                            "subnet_mask": "255.255.255.0",
                            "default_gateway": "192.168.1.1",
                            "applications": [
                                {
                                    "type": "email-client",
                                    "options": {
                                        "username": "alice@company.com",
                                        "default_smtp_server": "192.168.1.10",
                                        "default_pop3_server": "192.168.1.10",
                                        "auto_start": True
                                    }
                                }
                            ]
                        },
                        {
                            "hostname": "switch_1",
                            "type": "switch",
                            "num_ports": 7
                        },
                        {
                            "hostname": "router_1",
                            "type": "router",
                            "num_ports": 1,
                            "ports": {
                                1: {
                                    "ip_address": "192.168.1.1",
                                    "subnet_mask": "255.255.255.0"
                                }
                            }
                        }
                    ],
                    "links": [
                        {
                            "endpoint_a_hostname": "mail_server",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 1
                        },
                        {
                            "endpoint_a_hostname": "executive_pc",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 2
                        },
                        {
                            "endpoint_a_hostname": "hr_pc",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 3
                        },
                        {
                            "endpoint_a_hostname": "it_pc",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 4
                        },
                        {
                            "endpoint_a_hostname": "staff_pc_1",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 5
                        },
                        {
                            "endpoint_a_hostname": "router_1",
                            "endpoint_a_port": 1,
                            "endpoint_b_hostname": "switch_1",
                            "endpoint_b_port": 6
                        }
                    ]
                }
            }
        }
        
        # Create and run game
        game = PrimaiteGame.from_config(config)
        
        # Set up mailbox sharing
        mail_server = game.simulation.network.get_node_by_hostname("mail_server")
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        pop3_server.mailbox_manager = smtp_server.mailbox_manager
        
        # Create mailboxes
        users = ["ceo", "hr", "finance", "it", "alice", "bob"]
        for user in users:
            smtp_server.mailbox_manager.create_mailbox(user)
        
        # Run simulation with agent interactions
        agent_activity = {agent_name: {"sends": 0, "retrieves": 0, "idles": 0} for agent_name in game.agents.keys()}
        
        for step in range(40):
            game.step()
            
            # Track agent activities
            for agent_name, agent in game.agents.items():
                if agent.history and len(agent.history) > 0:
                    last_action = agent.history[-1].action
                    if last_action == "email-send":
                        agent_activity[agent_name]["sends"] += 1
                    elif last_action == "email-retrieve":
                        agent_activity[agent_name]["retrieves"] += 1
                    elif last_action == "do-nothing":
                        agent_activity[agent_name]["idles"] += 1
        
        # Verify multi-agent activity
        total_sends = sum(activity["sends"] for activity in agent_activity.values())
        total_retrieves = sum(activity["retrieves"] for activity in agent_activity.values())
        
        assert total_sends > 0, "Agents should send emails"
        
        # Verify different agent types have different activity patterns
        executive_activity = agent_activity.get("executive_agent", {"sends": 0})
        hr_activity = agent_activity.get("hr_agent", {"sends": 0})
        it_activity = agent_activity.get("it_agent", {"sends": 0})
        
        # IT agent should be most active (highest send probability)
        # HR agent should be more active than executive (higher send probability)
        print(f"📊 Multi-agent activity:")
        for agent_name, activity in agent_activity.items():
            print(f"  {agent_name}: {activity['sends']} sends, {activity['retrieves']} retrieves, {activity['idles']} idles")
        
        # Check mailbox contents
        total_messages = 0
        for user in users:
            mailbox = smtp_server.mailbox_manager.get_mailbox(user)
            if mailbox:
                messages = mailbox.get_messages()
                total_messages += len(messages)
                print(f"📧 {user}: {len(messages)} messages")
        
        assert total_messages > 0, "Some emails should be delivered"
        print(f"📊 Total messages delivered: {total_messages}")

    def test_security_incident_email_scenario(self, enterprise_network_config):
        "Test security incident response email scenario."
        game = PrimaiteGame.from_config(enterprise_network_config)
        
        # Set up mail server
        mail_server = game.simulation.network.get_node_by_hostname("mail_server")
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        pop3_server.mailbox_manager = smtp_server.mailbox_manager
        
        # Create user mailboxes
        users = ["ceo", "hr", "finance", "it", "alice", "bob", "security"]
        for user in users:
            smtp_server.mailbox_manager.create_mailbox(user)
        
        # Simulate security incident timeline
        incident_emails = []
        
        # Phase 1: Initial detection
        incident_emails.extend([
            {
                "sender": "it@company.com",
                "recipients": ["security@company.com", "ceo@company.com"],
                "subject": "URGENT: Suspicious Network Activity Detected",
                "body": "Automated monitoring has detected unusual network traffic patterns. Investigating immediately.",
                "phase": "detection"
            },
            {
                "sender": "security@company.com",
                "recipients": ["it@company.com"],
                "subject": "RE: URGENT: Suspicious Network Activity",
                "body": "Acknowledged. Please isolate affected systems and preserve logs.",
                "phase": "response"
            }
        ])
        
        # Phase 2: Incident escalation
        incident_emails.extend([
            {
                "sender": "security@company.com",
                "recipients": ["ceo@company.com", "hr@company.com", "finance@company.com"],
                "subject": "SECURITY INCIDENT: Potential Data Breach",
                "body": "We have confirmed unauthorized access to our systems. Activating incident response plan.",
                "phase": "escalation"
            },
            {
                "sender": "ceo@company.com",
                "recipients": ["hr@company.com", "finance@company.com", "it@company.com"],
                "subject": "IMMEDIATE ACTION REQUIRED: Security Incident",
                "body": "All hands on deck. Please follow security protocols immediately.",
                "phase": "escalation"
            }
        ])
        
        # Phase 3: Containment communications
        incident_emails.extend([
            {
                "sender": "it@company.com",
                "recipients": ["alice@company.com", "bob@company.com"],
                "subject": "MANDATORY: Change All Passwords Immediately",
                "body": "Due to security incident, all users must change passwords within 1 hour.",
                "phase": "containment"
            },
            {
                "sender": "hr@company.com",
                "recipients": ["alice@company.com", "bob@company.com"],
                "subject": "Security Incident - Work From Home Today",
                "body": "As a precaution, all staff should work from home today. Systems being secured.",
                "phase": "containment"
            }
        ])
        
        # Phase 4: Recovery communications
        incident_emails.extend([
            {
                "sender": "security@company.com",
                "recipients": ["ceo@company.com", "it@company.com"],
                "subject": "Incident Status: Threat Contained",
                "body": "Threat has been contained. No data exfiltration detected. Beginning recovery phase.",
                "phase": "recovery"
            },
            {
                "sender": "ceo@company.com",
                "recipients": ["hr@company.com", "finance@company.com", "alice@company.com", "bob@company.com"],
                "subject": "Security Incident Update: Systems Secure",
                "body": "Our security team has contained the incident. Systems are being restored.",
                "phase": "recovery"
            }
        ])
        
        # Phase 5: Post-incident analysis
        incident_emails.extend([
            {
                "sender": "security@company.com",
                "recipients": ["ceo@company.com", "hr@company.com", "it@company.com"],
                "subject": "Post-Incident Report: Lessons Learned",
                "body": "Detailed analysis of the security incident and recommendations for improvement.",
                "phase": "analysis"
            }
        ])
        
        # Deliver incident emails with realistic timing
        delivered_by_phase = {"detection": 0, "response": 0, "escalation": 0, "containment": 0, "recovery": 0, "analysis": 0}
        
        for email_data in incident_emails:
            email = EmailMessage(
                sender=email_data["sender"],
                recipients=email_data["recipients"],
                subject=email_data["subject"],
                body=email_data["body"]
            )
            
            # Deliver to each recipient
            for recipient in email.recipients:
                username = recipient.split("@")[0]
                mailbox = smtp_server.mailbox_manager.get_mailbox(username)
                if mailbox and mailbox.add_message(email):
                    delivered_by_phase[email_data["phase"]] += 1
        
        # Verify incident response communication patterns
        assert delivered_by_phase["detection"] >= 2, "Should have detection phase communications"
        assert delivered_by_phase["escalation"] >= 4, "Should have escalation communications"
        assert delivered_by_phase["containment"] >= 4, "Should have containment communications"
        assert delivered_by_phase["recovery"] >= 4, "Should have recovery communications"
        
        # Verify key personnel received critical communications
        ceo_mailbox = smtp_server.mailbox_manager.get_mailbox("ceo")
        security_mailbox = smtp_server.mailbox_manager.get_mailbox("security")
        it_mailbox = smtp_server.mailbox_manager.get_mailbox("it")
        
        ceo_messages = ceo_mailbox.get_messages()
        security_messages = security_mailbox.get_messages()
        it_messages = it_mailbox.get_messages()
        
        # CEO should receive multiple incident updates
        assert len(ceo_messages) >= 3, "CEO should receive multiple incident updates"
        
        # Security team should be involved in communications
        assert len(security_messages) >= 1, "Security team should receive incident reports"
        
        # IT should receive and send multiple messages
        assert len(it_messages) >= 2, "IT should be heavily involved in incident response"
        
        # Verify urgency indicators in subjects
        urgent_subjects = [msg.subject for msg in ceo_messages + security_messages + it_messages if "URGENT" in msg.subject or "IMMEDIATE" in msg.subject]
        assert len(urgent_subjects) >= 2, "Should have urgent communications during incident"
        
        print(f"📊 Security incident simulation:")
        for phase, count in delivered_by_phase.items():
            print(f"  {phase}: {count} emails delivered")
        
        total_incident_emails = sum(delivered_by_phase.values())
        print(f"📧 Total incident emails: {total_incident_emails}")

    def test_department_collaboration_scenario(self, enterprise_network_config):
        "Test realistic department collaboration email patterns."
        game = PrimaiteGame.from_config(enterprise_network_config)
        
        # Set up mail server
        mail_server = game.simulation.network.get_node_by_hostname("mail_server")
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        pop3_server.mailbox_manager = smtp_server.mailbox_manager
        
        # Create user mailboxes
        users = ["ceo", "hr", "finance", "it", "alice", "bob", "marketing", "sales"]
        for user in users:
            smtp_server.mailbox_manager.create_mailbox(user)
        
        # Simulate cross-department project collaboration
        collaboration_emails = [
            # Project initiation
            {
                "sender": "ceo@company.com",
                "recipients": ["hr@company.com", "finance@company.com", "marketing@company.com", "it@company.com"],
                "subject": "New Product Launch Project - Team Assembly",
                "body": "We're launching a new product. Each department please assign a team member to this project.",
                "category": "initiation"
            },
            
            # Team formation responses
            {
                "sender": "hr@company.com",
                "recipients": ["ceo@company.com", "alice@company.com"],
                "subject": "RE: New Product Launch - Alice Assigned",
                "body": "Alice will represent HR on the product launch team.",
                "category": "team_formation"
            },
            {
                "sender": "finance@company.com",
                "recipients": ["ceo@company.com", "bob@company.com"],
                "subject": "RE: New Product Launch - Bob Assigned",
                "body": "Bob will handle financial planning for the product launch.",
                "category": "team_formation"
            },
            {
                "sender": "it@company.com",
                "recipients": ["ceo@company.com"],
                "subject": "RE: New Product Launch - Technical Support",
                "body": "IT department ready to provide technical infrastructure support.",
                "category": "team_formation"
            },
            
            # Planning phase
            {
                "sender": "alice@company.com",
                "recipients": ["bob@company.com", "marketing@company.com", "it@company.com"],
                "subject": "Product Launch - Initial Planning Meeting",
                "body": "Let's schedule our first planning meeting for next Tuesday at 2 PM.",
                "category": "planning"
            },
            {
                "sender": "bob@company.com",
                "recipients": ["alice@company.com", "finance@company.com"],
                "subject": "Budget Requirements for Product Launch",
                "body": "Initial budget estimate for the product launch project attached.",
                "category": "planning"
            },
            {
                "sender": "marketing@company.com",
                "recipients": ["alice@company.com", "bob@company.com", "sales@company.com"],
                "subject": "Market Research Results",
                "body": "Market research shows strong demand for our new product concept.",
                "category": "planning"
            },
            
            # Execution phase
            {
                "sender": "it@company.com",
                "recipients": ["alice@company.com", "bob@company.com", "marketing@company.com"],
                "subject": "Technical Infrastructure Ready",
                "body": "All technical systems are in place for the product launch.",
                "category": "execution"
            },
            {
                "sender": "sales@company.com",
                "recipients": ["marketing@company.com", "alice@company.com"],
                "subject": "Sales Team Training Complete",
                "body": "Sales team has completed training on the new product features.",
                "category": "execution"
            },
            
            # Status updates
            {
                "sender": "alice@company.com",
                "recipients": ["ceo@company.com", "hr@company.com"],
                "subject": "Product Launch - Weekly Status Report",
                "body": "Project is on track. All departments are meeting their milestones.",
                "category": "status"
            },
            {
                "sender": "bob@company.com",
                "recipients": ["ceo@company.com", "finance@company.com"],
                "subject": "Product Launch - Budget Status",
                "body": "Project is currently 5% under budget with all major expenses accounted for.",
                "category": "status"
            },
            
            # Final coordination
            {
                "sender": "marketing@company.com",
                "recipients": ["ceo@company.com", "alice@company.com", "bob@company.com", "sales@company.com"],
                "subject": "Product Launch - Go Live Tomorrow!",
                "body": "All systems go! Product launches tomorrow at 9 AM EST.",
                "category": "coordination"
            },
            {
                "sender": "ceo@company.com",
                "recipients": ["hr@company.com", "finance@company.com", "it@company.com", "marketing@company.com", "sales@company.com", "alice@company.com", "bob@company.com"],
                "subject": "Congratulations - Successful Product Launch!",
                "body": "Excellent work everyone! The product launch was a complete success.",
                "category": "celebration"
            }
        ]
        
        # Deliver collaboration emails
        delivered_by_category = {}
        
        for email_data in collaboration_emails:
            email = EmailMessage(
                sender=email_data["sender"],
                recipients=email_data["recipients"],
                subject=email_data["subject"],
                body=email_data["body"]
            )
            
            category = email_data["category"]
            if category not in delivered_by_category:
                delivered_by_category[category] = 0
            
            # Deliver to each recipient
            for recipient in email.recipients:
                username = recipient.split("@")[0]
                mailbox = smtp_server.mailbox_manager.get_mailbox(username)
                if mailbox and mailbox.add_message(email):
                    delivered_by_category[category] += 1
        
        # Verify collaboration patterns
        assert delivered_by_category.get("initiation", 0) >= 4, "Should have project initiation emails"
        assert delivered_by_category.get("team_formation", 0) >= 3, "Should have team formation emails"
        assert delivered_by_category.get("planning", 0) >= 6, "Should have planning phase emails"
        assert delivered_by_category.get("execution", 0) >= 4, "Should have execution phase emails"
        assert delivered_by_category.get("status", 0) >= 2, "Should have status update emails"
        
        # Verify key participants received appropriate emails
        ceo_mailbox = smtp_server.mailbox_manager.get_mailbox("ceo")
        alice_mailbox = smtp_server.mailbox_manager.get_mailbox("alice")
        bob_mailbox = smtp_server.mailbox_manager.get_mailbox("bob")
        
        ceo_messages = ceo_mailbox.get_messages()
        alice_messages = alice_mailbox.get_messages()
        bob_messages = bob_mailbox.get_messages()
        
        # CEO should receive project updates and final celebration
        assert len(ceo_messages) >= 4, "CEO should receive multiple project updates"
        
        # Alice and Bob should be heavily involved as team members
        assert len(alice_messages) >= 5, "Alice should receive many collaboration emails"
        assert len(bob_messages) >= 5, "Bob should receive many collaboration emails"
        
        # Verify cross-department communication
        departments_mentioned = set()
        for msg in alice_messages + bob_messages:
            if "marketing" in msg.sender or "marketing" in str(msg.recipients):
                departments_mentioned.add("marketing")
            if "finance" in msg.sender or "finance" in str(msg.recipients):
                departments_mentioned.add("finance")
            if "it" in msg.sender or "it" in str(msg.recipients):
                departments_mentioned.add("it")
        
        assert len(departments_mentioned) >= 2, "Should have cross-department communication"
        
        print(f"📊 Department collaboration simulation:")
        for category, count in delivered_by_category.items():
            print(f"  {category}: {count} emails delivered")
        
        total_collaboration_emails = sum(delivered_by_category.values())
        print(f"📧 Total collaboration emails: {total_collaboration_emails}")
        print(f"🏢 Departments involved: {departments_mentioned}")

    def test_email_system_performance_under_load(self, enterprise_network_config):
        "Test email system performance under realistic load."
        game = PrimaiteGame.from_config(enterprise_network_config)
        
        # Set up mail server
        mail_server = game.simulation.network.get_node_by_hostname("mail_server")
        smtp_server = mail_server.software_manager.software.get("smtp-server")
        pop3_server = mail_server.software_manager.software.get("pop3-server")
        pop3_server.mailbox_manager = smtp_server.mailbox_manager
        
        # Create many user mailboxes (simulating larger organization)
        users = [f"user{i:03d}" for i in range(50)]  # 50 users
        for user in users:
            smtp_server.mailbox_manager.create_mailbox(user)
        
        # Performance test: Bulk email delivery
        start_time = time.time()
        
        # Simulate company-wide announcement
        company_announcement = EmailMessage(
            sender="ceo@company.com",
            recipients=[f"{user}@company.com" for user in users],
            subject="Important Company Announcement",
            body="This is an important announcement that goes to all employees."
        )
        
        # Deliver to all users
        delivered_count = 0
        for recipient in company_announcement.recipients:
            username = recipient.split("@")[0]
            mailbox = smtp_server.mailbox_manager.get_mailbox(username)
            if mailbox and mailbox.add_message(company_announcement):
                delivered_count += 1
        
        bulk_delivery_time = time.time() - start_time
        
        # Performance test: Multiple concurrent emails
        start_time = time.time()
        
        concurrent_emails = []
        for i in range(20):  # 20 different emails
            email = EmailMessage(
                sender=f"user{i:03d}@company.com",
                recipients=[f"user{(i+1) % 50:03d}@company.com", f"user{(i+2) % 50:03d}@company.com"],
                subject=f"Message {i+1}",
                body=f"This is message number {i+1} for performance testing."
            )
            concurrent_emails.append(email)
        
        # Deliver concurrent emails
        concurrent_delivered = 0
        for email in concurrent_emails:
            for recipient in email.recipients:
                username = recipient.split("@")[0]
                mailbox = smtp_server.mailbox_manager.get_mailbox(username)
                if mailbox and mailbox.add_message(email):
                    concurrent_delivered += 1
        
        concurrent_delivery_time = time.time() - start_time
        
        # Performance test: Mailbox operations
        start_time = time.time()
        
        # Test retrieving messages from multiple mailboxes
        total_messages_retrieved = 0
        for i in range(10):  # Check first 10 mailboxes
            username = f"user{i:03d}"
            mailbox = smtp_server.mailbox_manager.get_mailbox(username)
            if mailbox:
                messages = mailbox.get_messages()
                total_messages_retrieved += len(messages)
        
        retrieval_time = time.time() - start_time
        
        # Verify performance metrics
        assert delivered_count == 50, "Should deliver to all 50 users"
        assert concurrent_delivered >= 30, "Should deliver most concurrent emails"
        assert total_messages_retrieved >= 10, "Should retrieve messages from mailboxes"
        
        # Performance assertions (reasonable thresholds)
        assert bulk_delivery_time < 5.0, f"Bulk delivery too slow: {bulk_delivery_time:.2f}s"
        assert concurrent_delivery_time < 3.0, f"Concurrent delivery too slow: {concurrent_delivery_time:.2f}s"
        assert retrieval_time < 1.0, f"Message retrieval too slow: {retrieval_time:.2f}s"
        
        # Calculate throughput metrics
        bulk_throughput = delivered_count / bulk_delivery_time if bulk_delivery_time > 0 else 0
        concurrent_throughput = concurrent_delivered / concurrent_delivery_time if concurrent_delivery_time > 0 else 0
        
        print(f"📊 Performance test results:")
        print(f"  Bulk delivery: {delivered_count} emails in {bulk_delivery_time:.2f}s ({bulk_throughput:.1f} emails/sec)")
        print(f"  Concurrent delivery: {concurrent_delivered} emails in {concurrent_delivery_time:.2f}s ({concurrent_throughput:.1f} emails/sec)")
        print(f"  Message retrieval: {total_messages_retrieved} messages in {retrieval_time:.2f}s")
        
        # Verify system stability after load
        assert smtp_server.operating_state.name == "RUNNING", "SMTP server should remain running after load"
        assert smtp_server.health_state_actual.name in ["GOOD", "FIXING"], "SMTP server should maintain good health"