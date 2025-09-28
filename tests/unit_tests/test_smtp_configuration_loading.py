"""Integration tests for SMTP server configuration loading."""

import pytest
from unittest.mock import Mock

from primaite_mail.simulator.software.smtp_server import SMTPServer


class TestSMTPConfigurationLoading:
    """Test SMTP server configuration loading and initialization."""
    
    def test_configuration_loading_with_valid_policies(self):
        """Test that valid configuration is loaded correctly."""
        # Create a configuration with security policies
        config_data = {
            "type": "smtp-server",
            "domain": "test.company.com",
            "max_message_size": 5242880,  # 5MB
            "require_auth": True,
            "blocked_senders": [
                "malicious@attacker.com",
                "SPAM@BADACTOR.NET",  # Test case normalization
                "phishing@fake-bank.com"
            ],
            "blocked_ips": [
                "192.168.1.100",
                "10.0.0.0/8",
                "172.16.0.50",
                "203.0.113.100/24"  # Test CIDR normalization
            ],
            "enable_security_logging": True
        }
        
        # Create configuration object
        config = SMTPServer.ConfigSchema(**config_data)
        
        # Verify configuration was processed correctly
        assert config.type == "smtp-server"
        assert config.domain == "test.company.com"
        assert config.max_message_size == 5242880
        assert config.require_auth is True
        assert config.enable_security_logging is True
        
        # Verify blocked senders were normalized
        assert len(config.blocked_senders) == 3
        assert "malicious@attacker.com" in config.blocked_senders
        assert "spam@badactor.net" in config.blocked_senders  # Normalized to lowercase
        assert "phishing@fake-bank.com" in config.blocked_senders
        
        # Verify blocked IPs were processed
        assert len(config.blocked_ips) == 4
        assert "192.168.1.100" in config.blocked_ips
        assert "10.0.0.0/8" in config.blocked_ips
        assert "172.16.0.50" in config.blocked_ips
        assert "203.0.113.0/24" in config.blocked_ips  # Normalized CIDR
    
    def test_configuration_loading_with_empty_policies(self):
        """Test configuration loading with empty security policies."""
        config_data = {
            "type": "smtp-server",
            "domain": "localhost",
            "blocked_senders": [],
            "blocked_ips": [],
            "enable_security_logging": False
        }
        
        config = SMTPServer.ConfigSchema(**config_data)
        
        assert config.blocked_senders == []
        assert config.blocked_ips == []
        assert config.enable_security_logging is False
    
    def test_configuration_loading_with_defaults(self):
        """Test configuration loading with default values."""
        # Minimal configuration - should use defaults
        config_data = {
            "type": "smtp-server"
        }
        
        config = SMTPServer.ConfigSchema(**config_data)
        
        # Check defaults
        assert config.domain == "localhost"
        assert config.max_message_size == 10485760  # 10MB default
        assert config.require_auth is False
        assert config.blocked_senders == []
        assert config.blocked_ips == []
        assert config.enable_security_logging is True
    
    def test_configuration_validation_errors(self):
        """Test that configuration validation catches errors."""
        # Test invalid email addresses
        with pytest.raises(ValueError) as exc_info:
            SMTPServer.ConfigSchema(
                type="smtp-server",
                blocked_senders=["invalid-email-format"]
            )
        assert "Invalid email address format" in str(exc_info.value)
        
        # Test invalid IP addresses
        with pytest.raises(ValueError) as exc_info:
            SMTPServer.ConfigSchema(
                type="smtp-server",
                blocked_ips=["invalid-ip-format"]
            )
        assert "Invalid IP address or CIDR format" in str(exc_info.value)
        
        # Test invalid max_message_size
        with pytest.raises(ValueError) as exc_info:
            SMTPServer.ConfigSchema(
                type="smtp-server",
                max_message_size=-1
            )
        assert "max_message_size must be positive" in str(exc_info.value)
    
    def test_security_policy_initialization_simulation(self):
        """Test simulated security policy initialization from configuration."""
        from primaite_mail.simulator.software.security_policy import EmailSecurityPolicy, SecurityEventLog
        
        # Create configuration
        config_data = {
            "blocked_senders": ["test@malicious.com", "spam@badactor.net"],
            "blocked_ips": ["192.168.1.100", "10.0.0.0/8"],
            "enable_security_logging": True
        }
        
        config = SMTPServer.ConfigSchema(**config_data)
        
        # Simulate the initialization process that happens in SMTPServer.__init__
        security_policy = EmailSecurityPolicy()
        security_log = SecurityEventLog()
        
        # Simulate loading blocked senders
        loaded_senders = 0
        for sender in config.blocked_senders:
            if security_policy.add_blocked_sender(sender):
                loaded_senders += 1
        
        # Simulate loading blocked IPs
        loaded_ips = 0
        for ip in config.blocked_ips:
            if security_policy.add_blocked_ip(ip):
                loaded_ips += 1
        
        # Configure logging
        security_policy.enable_logging = config.enable_security_logging
        
        # Verify initialization results
        assert loaded_senders == 2
        assert loaded_ips == 2
        assert len(security_policy.blocked_senders) == 2
        assert len(security_policy.blocked_ips) == 2
        assert security_policy.enable_logging is True
        
        # Test that policies work
        assert security_policy.is_sender_blocked("test@malicious.com")
        assert security_policy.is_sender_blocked("spam@badactor.net")
        assert security_policy.is_ip_blocked("192.168.1.100")
        assert security_policy.is_ip_blocked("10.0.0.50")  # Should match 10.0.0.0/8
        
        # Test that non-blocked items are not blocked
        assert not security_policy.is_sender_blocked("legitimate@company.com")
        assert not security_policy.is_ip_blocked("172.16.0.1")
    
    def test_configuration_edge_cases(self):
        """Test configuration edge cases and boundary conditions."""
        # Test with maximum reasonable values
        large_sender_list = [f"user{i}@example.com" for i in range(50)]
        large_ip_list = [f"192.168.{i//256}.{i%256}" for i in range(50)]
        
        config = SMTPServer.ConfigSchema(
            blocked_senders=large_sender_list,
            blocked_ips=large_ip_list,
            max_message_size=104857600  # 100MB
        )
        
        assert len(config.blocked_senders) == 50
        assert len(config.blocked_ips) == 50
        assert config.max_message_size == 104857600
        
        # Test with minimum values
        config = SMTPServer.ConfigSchema(
            max_message_size=1  # Minimum positive value
        )
        
        assert config.max_message_size == 1
    
    def test_configuration_with_mixed_case_and_whitespace(self):
        """Test configuration handling of mixed case and whitespace."""
        config_data = {
            "blocked_senders": [
                "  Test@Example.COM  ",  # Whitespace and mixed case
                "ANOTHER@DOMAIN.NET",
                "normal@email.com"
            ],
            "blocked_ips": [
                "  192.168.1.100  ",  # Whitespace
                "10.0.0.0/8"
            ]
        }
        
        config = SMTPServer.ConfigSchema(**config_data)
        
        # Verify normalization
        assert "test@example.com" in config.blocked_senders
        assert "another@domain.net" in config.blocked_senders
        assert "normal@email.com" in config.blocked_senders
        
        # IP addresses should be trimmed
        assert "192.168.1.100" in config.blocked_ips
        assert "10.0.0.0/8" in config.blocked_ips
    
    def test_configuration_yaml_compatibility(self):
        """Test that configuration is compatible with YAML loading patterns."""
        # This simulates how configuration would come from a YAML file
        yaml_like_config = {
            "type": "smtp-server",
            "domain": "mail.company.com",
            "max_message_size": 10485760,
            "require_auth": True,
            "blocked_senders": [
                "attacker@malicious.com",
                "spam@badactor.net"
            ],
            "blocked_ips": [
                "192.168.100.50",
                "10.0.0.0/8"
            ],
            "enable_security_logging": True
        }
        
        # This should work without any issues
        config = SMTPServer.ConfigSchema(**yaml_like_config)
        
        assert config.type == "smtp-server"
        assert config.domain == "mail.company.com"
        assert len(config.blocked_senders) == 2
        assert len(config.blocked_ips) == 2
        assert config.enable_security_logging is True


class TestConfigurationErrorHandling:
    """Test configuration error handling and validation."""
    
    def test_invalid_email_formats_detailed(self):
        """Test detailed validation of various invalid email formats."""
        invalid_emails = [
            ("no-at-symbol", "missing @ symbol"),
            ("@domain.com", "missing local part"),
            ("user@", "missing domain"),
            ("user@domain", "missing TLD"),
            ("user.domain.com", "missing @ symbol"),
            ("user@domain.", "invalid domain ending"),
            ("user@@domain.com", "double @ symbol"),
            ("user@domain@com", "multiple @ symbols")
        ]
        
        for invalid_email, description in invalid_emails:
            with pytest.raises(ValueError, match="Invalid email address format"):
                SMTPServer.ConfigSchema(blocked_senders=[invalid_email])
    
    def test_invalid_ip_formats_detailed(self):
        """Test detailed validation of various invalid IP formats."""
        invalid_ips = [
            ("not-an-ip", "text instead of IP"),
            ("256.256.256.256", "octets too large"),
            ("192.168.1", "incomplete IP"),
            ("192.168.1.1.1", "too many octets"),
            ("192.168.1.1/", "incomplete CIDR"),
            ("192.168.1.1/33", "invalid CIDR prefix"),
            ("192.168.1.1/-1", "negative CIDR prefix")
        ]
        
        for invalid_ip, description in invalid_ips:
            with pytest.raises(ValueError, match="Invalid IP address or CIDR format"):
                SMTPServer.ConfigSchema(blocked_ips=[invalid_ip])
    
    def test_type_validation_errors(self):
        """Test type validation for configuration fields."""
        # Test non-string in blocked_senders
        with pytest.raises(ValueError):
            SMTPServer.ConfigSchema(blocked_senders=[123])
        
        # Test non-string in blocked_ips
        with pytest.raises(ValueError):
            SMTPServer.ConfigSchema(blocked_ips=[456])
        
        # Test non-integer max_message_size
        with pytest.raises(ValueError):
            SMTPServer.ConfigSchema(max_message_size="not-a-number")
        
        # Test non-boolean require_auth
        with pytest.raises(ValueError):
            SMTPServer.ConfigSchema(require_auth="not-a-boolean")
    
    def test_boundary_value_validation(self):
        """Test boundary values for numeric fields."""
        # Test zero max_message_size (should fail)
        with pytest.raises(ValueError, match="max_message_size must be positive"):
            SMTPServer.ConfigSchema(max_message_size=0)
        
        # Test negative max_message_size (should fail)
        with pytest.raises(ValueError, match="max_message_size must be positive"):
            SMTPServer.ConfigSchema(max_message_size=-1)
        
        # Test minimum valid max_message_size (should pass)
        config = SMTPServer.ConfigSchema(max_message_size=1)
        assert config.max_message_size == 1
        
        # Test large max_message_size (should pass)
        config = SMTPServer.ConfigSchema(max_message_size=1073741824)  # 1GB
        assert config.max_message_size == 1073741824