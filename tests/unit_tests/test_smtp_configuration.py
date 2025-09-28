"""Unit tests for SMTP server configuration validation."""

import pytest
from pydantic import ValidationError

from primaite_mail.simulator.software.smtp_server import SMTPServer


class TestSMTPServerConfigurationValidation:
    """Test SMTP server configuration validation."""
    
    def test_valid_configuration_default(self):
        """Test that default configuration is valid."""
        config = SMTPServer.ConfigSchema()
        
        assert config.type == "smtp-server"
        assert config.domain == "localhost"
        assert config.max_message_size == 10485760
        assert config.require_auth is False
        assert config.blocked_senders == []
        assert config.blocked_ips == []
        assert config.enable_security_logging is True
    
    def test_valid_configuration_with_security_policies(self):
        """Test valid configuration with security policies."""
        config_data = {
            "type": "smtp-server",
            "domain": "company.com",
            "max_message_size": 5242880,  # 5MB
            "require_auth": True,
            "blocked_senders": [
                "malicious@attacker.com",
                "spam@badactor.net",
                "phishing@fake-bank.com"
            ],
            "blocked_ips": [
                "192.168.1.100",
                "10.0.0.0/8",
                "172.16.0.50",
                "203.0.113.0/24"
            ],
            "enable_security_logging": True
        }
        
        config = SMTPServer.ConfigSchema(**config_data)
        
        assert config.type == "smtp-server"
        assert config.domain == "company.com"
        assert config.max_message_size == 5242880
        assert config.require_auth is True
        assert len(config.blocked_senders) == 3
        assert len(config.blocked_ips) == 4
        assert config.enable_security_logging is True
        
        # Check that email addresses are normalized to lowercase
        assert "malicious@attacker.com" in config.blocked_senders
        assert "spam@badactor.net" in config.blocked_senders
        assert "phishing@fake-bank.com" in config.blocked_senders
        
        # Check that IP addresses are properly formatted
        assert "192.168.1.100" in config.blocked_ips
        assert "10.0.0.0/8" in config.blocked_ips
        assert "172.16.0.50" in config.blocked_ips
        assert "203.0.113.0/24" in config.blocked_ips


class TestBlockedSendersValidation:
    """Test validation of blocked_senders configuration."""
    
    def test_valid_email_addresses(self):
        """Test valid email address formats."""
        valid_emails = [
            "user@example.com",
            "test.email@domain.org",
            "user+tag@company.co.uk",
            "123@numbers.net",
            "a@b.co"
        ]
        
        config = SMTPServer.ConfigSchema(blocked_senders=valid_emails)
        
        assert len(config.blocked_senders) == len(valid_emails)
        # Check normalization to lowercase
        for email in config.blocked_senders:
            assert email.islower()
    
    def test_email_normalization(self):
        """Test that email addresses are normalized to lowercase."""
        mixed_case_emails = [
            "User@Example.COM",
            "Test.Email@DOMAIN.ORG",
            "CAPS@COMPANY.NET"
        ]
        
        config = SMTPServer.ConfigSchema(blocked_senders=mixed_case_emails)
        
        expected_normalized = [
            "user@example.com",
            "test.email@domain.org",
            "caps@company.net"
        ]
        
        assert config.blocked_senders == expected_normalized
    
    def test_invalid_email_formats(self):
        """Test rejection of invalid email formats."""
        invalid_emails = [
            "not-an-email",
            "@domain.com",
            "user@",
            "user@domain",
            "user.domain.com",
            "user@domain.",
            "user@@domain.com",
            "user@domain@com"
        ]
        
        for invalid_email in invalid_emails:
            with pytest.raises(ValidationError) as exc_info:
                SMTPServer.ConfigSchema(blocked_senders=[invalid_email])
            
            # Check for either our custom message or pydantic's built-in validation
            error_str = str(exc_info.value)
            assert ("Invalid email address format" in error_str or 
                    "Blocked sender cannot be empty" in error_str)
    
    def test_empty_string_email_format(self):
        """Test rejection of empty string email specifically."""
        with pytest.raises(ValidationError) as exc_info:
            SMTPServer.ConfigSchema(blocked_senders=[""])
        
        assert "Blocked sender cannot be empty" in str(exc_info.value)
    
    def test_empty_blocked_senders(self):
        """Test that empty blocked_senders list is valid."""
        config = SMTPServer.ConfigSchema(blocked_senders=[])
        assert config.blocked_senders == []
    
    def test_non_string_sender(self):
        """Test rejection of non-string sender entries."""
        with pytest.raises(ValidationError) as exc_info:
            SMTPServer.ConfigSchema(blocked_senders=[123])
        
        # Pydantic's built-in validation handles this
        assert "Input should be a valid string" in str(exc_info.value)
    
    def test_empty_string_sender(self):
        """Test rejection of empty string senders."""
        with pytest.raises(ValidationError) as exc_info:
            SMTPServer.ConfigSchema(blocked_senders=[""])
        
        assert "Blocked sender cannot be empty" in str(exc_info.value)
    
    def test_whitespace_only_sender(self):
        """Test rejection of whitespace-only senders."""
        with pytest.raises(ValidationError) as exc_info:
            SMTPServer.ConfigSchema(blocked_senders=["   "])
        
        assert "Blocked sender cannot be empty" in str(exc_info.value)


class TestBlockedIPsValidation:
    """Test validation of blocked_ips configuration."""
    
    def test_valid_ip_addresses(self):
        """Test valid IP address formats."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "203.0.113.1",
            "127.0.0.1"
        ]
        
        config = SMTPServer.ConfigSchema(blocked_ips=valid_ips)
        
        assert len(config.blocked_ips) == len(valid_ips)
        assert config.blocked_ips == valid_ips
    
    def test_valid_cidr_ranges(self):
        """Test valid CIDR range formats."""
        valid_cidrs = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/16",
            "203.0.113.0/24",
            "192.168.0.0/16"
        ]
        
        config = SMTPServer.ConfigSchema(blocked_ips=valid_cidrs)
        
        assert len(config.blocked_ips) == len(valid_cidrs)
        # CIDR ranges should be normalized
        for cidr in config.blocked_ips:
            assert "/" in cidr
    
    def test_mixed_ips_and_cidrs(self):
        """Test mixing individual IPs and CIDR ranges."""
        mixed_entries = [
            "192.168.1.100",
            "10.0.0.0/8",
            "172.16.0.50",
            "203.0.113.0/24"
        ]
        
        config = SMTPServer.ConfigSchema(blocked_ips=mixed_entries)
        
        assert len(config.blocked_ips) == 4
        assert "192.168.1.100" in config.blocked_ips
        assert "10.0.0.0/8" in config.blocked_ips
        assert "172.16.0.50" in config.blocked_ips
        assert "203.0.113.0/24" in config.blocked_ips
    
    def test_cidr_normalization(self):
        """Test that CIDR ranges are normalized."""
        # Test with host bits set (should be normalized)
        config = SMTPServer.ConfigSchema(blocked_ips=["192.168.1.100/24"])
        
        # Should normalize to network address
        assert "192.168.1.0/24" in config.blocked_ips
    
    def test_invalid_ip_formats(self):
        """Test rejection of invalid IP formats."""
        invalid_ips = [
            "not-an-ip",
            "256.256.256.256",
            "192.168.1",
            "192.168.1.1.1",
            "192.168.1.1/",
            "192.168.1.1/33",
            "192.168.1.1/-1"
        ]
        
        for invalid_ip in invalid_ips:
            with pytest.raises(ValidationError) as exc_info:
                SMTPServer.ConfigSchema(blocked_ips=[invalid_ip])
            
            # Check for either our custom message or pydantic's built-in validation
            error_str = str(exc_info.value)
            assert ("Invalid IP address or CIDR format" in error_str or 
                    "Blocked IP cannot be empty" in error_str)
    
    def test_empty_string_ip_format(self):
        """Test rejection of empty string IP specifically."""
        with pytest.raises(ValidationError) as exc_info:
            SMTPServer.ConfigSchema(blocked_ips=[""])
        
        assert "Blocked IP cannot be empty" in str(exc_info.value)
    
    def test_empty_blocked_ips(self):
        """Test that empty blocked_ips list is valid."""
        config = SMTPServer.ConfigSchema(blocked_ips=[])
        assert config.blocked_ips == []
    
    def test_non_string_ip(self):
        """Test rejection of non-string IP entries."""
        with pytest.raises(ValidationError) as exc_info:
            SMTPServer.ConfigSchema(blocked_ips=[192168001001])
        
        # Pydantic's built-in validation handles this
        assert "Input should be a valid string" in str(exc_info.value)
    
    def test_empty_string_ip(self):
        """Test rejection of empty string IPs."""
        with pytest.raises(ValidationError) as exc_info:
            SMTPServer.ConfigSchema(blocked_ips=[""])
        
        assert "Blocked IP cannot be empty" in str(exc_info.value)
    
    def test_whitespace_only_ip(self):
        """Test rejection of whitespace-only IPs."""
        with pytest.raises(ValidationError) as exc_info:
            SMTPServer.ConfigSchema(blocked_ips=["   "])
        
        assert "Blocked IP cannot be empty" in str(exc_info.value)


class TestOtherConfigurationValidation:
    """Test validation of other configuration fields."""
    
    def test_valid_max_message_size(self):
        """Test valid max_message_size values."""
        valid_sizes = [1, 1024, 1048576, 10485760, 52428800]
        
        for size in valid_sizes:
            config = SMTPServer.ConfigSchema(max_message_size=size)
            assert config.max_message_size == size
    
    def test_invalid_max_message_size(self):
        """Test rejection of invalid max_message_size values."""
        invalid_sizes = [0, -1, -1000]
        
        for size in invalid_sizes:
            with pytest.raises(ValidationError) as exc_info:
                SMTPServer.ConfigSchema(max_message_size=size)
            
            assert "max_message_size must be positive" in str(exc_info.value)
    
    def test_boolean_fields(self):
        """Test boolean configuration fields."""
        # Test require_auth
        config = SMTPServer.ConfigSchema(require_auth=True)
        assert config.require_auth is True
        
        config = SMTPServer.ConfigSchema(require_auth=False)
        assert config.require_auth is False
        
        # Test enable_security_logging
        config = SMTPServer.ConfigSchema(enable_security_logging=True)
        assert config.enable_security_logging is True
        
        config = SMTPServer.ConfigSchema(enable_security_logging=False)
        assert config.enable_security_logging is False
    
    def test_domain_field(self):
        """Test domain configuration field."""
        valid_domains = ["localhost", "company.com", "mail.example.org", "test.co.uk"]
        
        for domain in valid_domains:
            config = SMTPServer.ConfigSchema(domain=domain)
            assert config.domain == domain


class TestConfigurationIntegrationWithSecurityPolicy:
    """Test configuration integration with security policy components."""
    
    def test_configuration_to_security_policy_mapping(self):
        """Test that configuration values map correctly to security policy."""
        from primaite_mail.simulator.software.security_policy import EmailSecurityPolicy
        
        config_data = {
            "blocked_senders": ["malicious@attacker.com", "spam@badactor.net"],
            "blocked_ips": ["192.168.1.100", "10.0.0.0/8"],
            "enable_security_logging": True
        }
        
        config = SMTPServer.ConfigSchema(**config_data)
        
        # Create security policy and manually load from config (simulating server init)
        security_policy = EmailSecurityPolicy()
        
        # Simulate the loading process
        for sender in config.blocked_senders:
            security_policy.add_blocked_sender(sender)
        
        for ip in config.blocked_ips:
            security_policy.add_blocked_ip(ip)
        
        security_policy.enable_logging = config.enable_security_logging
        
        # Verify the mapping worked
        assert len(security_policy.blocked_senders) == 2
        assert len(security_policy.blocked_ips) == 2
        assert security_policy.enable_logging is True
        
        # Check that the policies work
        assert security_policy.is_sender_blocked("malicious@attacker.com")
        assert security_policy.is_sender_blocked("spam@badactor.net")
        assert security_policy.is_ip_blocked("192.168.1.100")
        assert security_policy.is_ip_blocked("10.0.0.50")  # Should match 10.0.0.0/8
    
    def test_configuration_validation_prevents_invalid_policies(self):
        """Test that configuration validation prevents invalid security policies."""
        # This should fail during ConfigSchema validation
        with pytest.raises(ValidationError):
            SMTPServer.ConfigSchema(
                blocked_senders=["invalid-email"],
                blocked_ips=["invalid-ip"]
            )
    
    def test_empty_configuration_creates_empty_policies(self):
        """Test that empty configuration creates empty security policies."""
        from primaite_mail.simulator.software.security_policy import EmailSecurityPolicy
        
        config_data = {
            "blocked_senders": [],
            "blocked_ips": [],
            "enable_security_logging": False
        }
        
        config = SMTPServer.ConfigSchema(**config_data)
        
        # Create security policy and manually load from config
        security_policy = EmailSecurityPolicy()
        security_policy.enable_logging = config.enable_security_logging
        
        assert len(security_policy.blocked_senders) == 0
        assert len(security_policy.blocked_ips) == 0
        assert security_policy.enable_logging is False
    
    def test_configuration_normalization_effects(self):
        """Test that configuration normalization affects security policies correctly."""
        from primaite_mail.simulator.software.security_policy import EmailSecurityPolicy
        
        config_data = {
            "blocked_senders": ["Test@Example.COM", "CAPS@DOMAIN.NET"],
            "blocked_ips": ["192.168.1.100/24"],  # Will be normalized to network address
            "enable_security_logging": True
        }
        
        config = SMTPServer.ConfigSchema(**config_data)
        
        # Check that emails were normalized to lowercase
        assert "test@example.com" in config.blocked_senders
        assert "caps@domain.net" in config.blocked_senders
        
        # Check that CIDR was normalized
        assert "192.168.1.0/24" in config.blocked_ips
        
        # Create security policy and load normalized values
        security_policy = EmailSecurityPolicy()
        
        for sender in config.blocked_senders:
            security_policy.add_blocked_sender(sender)
        
        for ip in config.blocked_ips:
            security_policy.add_blocked_ip(ip)
        
        # Verify normalized values work correctly
        assert security_policy.is_sender_blocked("test@example.com")
        assert security_policy.is_sender_blocked("Test@Example.COM")  # Case insensitive
        assert security_policy.is_ip_blocked("192.168.1.50")  # In the /24 range


class TestConfigurationEdgeCases:
    """Test edge cases in configuration validation."""
    
    def test_unicode_email_addresses(self):
        """Test handling of unicode characters in email addresses."""
        # Basic ASCII should work
        config = SMTPServer.ConfigSchema(blocked_senders=["test@example.com"])
        assert "test@example.com" in config.blocked_senders
        
        # International domain names (IDN) are complex - for now we stick to ASCII
        # This is acceptable for a training environment
    
    def test_ipv6_addresses_supported(self):
        """Test that IPv6 addresses are supported by the validation."""
        ipv6_addresses = [
            "2001:db8::1",
            "::1",
            "2001:db8::/32"
        ]
        
        # IPv6 should be accepted by the validation
        config = SMTPServer.ConfigSchema(blocked_ips=ipv6_addresses)
        assert len(config.blocked_ips) == 3
        
        # Note: While IPv6 is technically supported by ipaddress module,
        # the actual security policy implementation focuses on IPv4 for simplicity
        # This is acceptable for a training environment
    
    def test_large_configuration_lists(self):
        """Test handling of large configuration lists."""
        # Generate large lists
        large_sender_list = [f"user{i}@example.com" for i in range(100)]
        large_ip_list = [f"192.168.{i//256}.{i%256}" for i in range(100)]
        
        config = SMTPServer.ConfigSchema(
            blocked_senders=large_sender_list,
            blocked_ips=large_ip_list
        )
        
        assert len(config.blocked_senders) == 100
        assert len(config.blocked_ips) == 100
    
    def test_duplicate_entries_handling(self):
        """Test handling of duplicate entries in configuration."""
        # Duplicates should be preserved in the list (sets will handle deduplication later)
        duplicate_senders = ["test@example.com", "test@example.com", "other@example.com"]
        duplicate_ips = ["192.168.1.1", "192.168.1.1", "192.168.1.2"]
        
        config = SMTPServer.ConfigSchema(
            blocked_senders=duplicate_senders,
            blocked_ips=duplicate_ips
        )
        
        # Configuration validation doesn't deduplicate - that's handled by the security policy
        assert len(config.blocked_senders) == 3
        assert len(config.blocked_ips) == 3