# SMTP Server Security Policy Configuration

This document describes how to configure initial security policies for SMTP servers in PrimAITE-Mail.

## Overview

The SMTP server now supports pre-configured security policies that can be loaded from configuration files. This allows scenario designers to set up realistic email security baselines for cybersecurity training scenarios.

## Configuration Fields

### Security Policy Fields

The following fields can be added to SMTP server configuration:

```yaml
services:
  - type: "smtp-server"
    domain: "company.com"
    # Standard SMTP configuration...
    
    # Security policy configuration
    blocked_senders:
      - "malicious@attacker.com"
      - "spam@badactor.net"
    blocked_ips:
      - "192.168.1.100"
      - "10.0.0.0/8"
    enable_security_logging: true
```

### Field Descriptions

- **`blocked_senders`** (list of strings): Initial list of blocked sender email addresses
  - Email addresses are automatically normalized to lowercase
  - Must be valid email format (user@domain.tld)
  - Empty list by default

- **`blocked_ips`** (list of strings): Initial list of blocked IP addresses and CIDR ranges
  - Supports individual IP addresses (e.g., "192.168.1.100")
  - Supports CIDR notation (e.g., "10.0.0.0/8", "192.168.1.0/24")
  - CIDR ranges are automatically normalized to network addresses
  - Empty list by default

- **`enable_security_logging`** (boolean): Enable security event logging
  - Default: `true`
  - When enabled, all security events are logged for monitoring

## Validation

The configuration system validates all security policy entries:

### Email Address Validation
- Must contain exactly one '@' symbol
- Must have non-empty local and domain parts
- Domain must contain at least one dot
- Invalid formats will cause configuration loading to fail

### IP Address Validation
- Individual IPs must be valid IPv4 addresses
- CIDR ranges must have valid network/prefix format
- Invalid formats will cause configuration loading to fail

### Other Validation
- `max_message_size` must be positive
- All list entries must be strings
- Empty strings and whitespace-only entries are rejected

## Example Configuration

```yaml
simulation:
  network:
    nodes:
      mail_server:
        hostname: "mail_server"
        type: "computer"
        ip_address: "192.168.1.10"
        services:
          - type: "smtp-server"
            domain: "company.com"
            max_message_size: 10485760  # 10MB
            require_auth: false
            
            # Security policies
            blocked_senders:
              - "malicious@attacker.com"
              - "SPAM@BADACTOR.NET"      # Will be normalized to lowercase
              - "phishing@fake-bank.com"
            
            blocked_ips:
              - "192.168.100.50"         # Single IP
              - "10.0.0.0/8"             # Entire private network
              - "172.16.0.0/16"          # Another private range
              - "203.0.113.100/24"       # Will be normalized to 203.0.113.0/24
            
            enable_security_logging: true
```

## Behavior

### Server Startup
When the SMTP server starts:
1. Configuration is validated for format and syntax
2. Valid entries are loaded into the security policy
3. Invalid entries cause server startup to fail
4. Loading progress is logged to the system log

### Email Blocking
- Emails from blocked senders are rejected with SMTP error code 550
- Connections from blocked IPs are refused early in the SMTP handshake
- All blocking events are logged if security logging is enabled

### Blue Agent Integration
Blue agents can still modify security policies at runtime using the security actions:
- `email-block-sender` / `email-unblock-sender`
- `email-block-ip` / `email-unblock-ip`
- `email-query-security-policies`
- `email-get-security-statistics`

## Error Handling

### Configuration Errors
If the configuration contains invalid entries:
- The server will fail to start
- Detailed error messages indicate which entries are invalid
- Fix the configuration and restart the server

### Runtime Errors
During operation:
- Invalid requests from blue agents are rejected with error responses
- Security policy operations are logged
- The server continues operating with existing valid policies

## Best Practices

### For Scenario Designers
1. **Start Simple**: Begin with a few blocked senders and IPs
2. **Use Realistic Entries**: Use believable malicious domains and IP ranges
3. **Enable Logging**: Always enable security logging for training scenarios
4. **Test Configuration**: Validate configuration before deploying scenarios

### For Training Scenarios
1. **Baseline Security**: Set up initial blocked lists representing known threats
2. **Progressive Difficulty**: Start with obvious threats, add subtle ones over time
3. **Blue Team Learning**: Let blue agents discover and block new threats
4. **Red Team Challenges**: Use non-blocked addresses for red team activities

## Troubleshooting

### Common Issues

**Server won't start with "Invalid email address format"**
- Check that all blocked_senders entries have valid email format
- Ensure each email has exactly one '@' and a proper domain

**Server won't start with "Invalid IP address or CIDR format"**
- Check that all blocked_ips entries are valid IPv4 addresses or CIDR ranges
- Ensure CIDR prefixes are between 0 and 32

**Policies not working as expected**
- Check server logs for policy loading messages
- Verify that security logging is enabled
- Use blue agent query actions to check current policies

### Debugging
1. Check server startup logs for policy loading messages
2. Use `email-query-security-policies` action to verify loaded policies
3. Use `email-get-security-statistics` action to monitor blocking activity
4. Check security event logs for detailed blocking information

## Integration with Existing Features

This configuration system integrates seamlessly with:
- Existing SMTP server functionality
- Blue agent security actions
- Security event logging
- Email attachment policies
- Mailbox management

The configuration provides a foundation that blue agents can build upon during training scenarios.