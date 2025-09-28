# Email Security Scenarios Notebook - User Guide

This guide provides comprehensive documentation for using the Email Security Scenarios notebook with PrimAITE-Mail. The notebook demonstrates realistic cybersecurity training scenarios involving email-based attacks, defenses, and security analysis.

## Table of Contents

- [Getting Started](#getting-started)
- [Notebook Overview](#notebook-overview)
- [Scenario Explanations](#scenario-explanations)
- [Customization Guide](#customization-guide)
- [Troubleshooting](#troubleshooting)
- [Educational Objectives](#educational-objectives)
- [Best Practices](#best-practices)

## Getting Started

### Prerequisites

1. **Environment Setup**: Ensure PrimAITE environment is activated
   ```bash
   pyenv activate primaite
   ```

2. **Required Dependencies**: The notebook requires PrimAITE-Mail extension
   ```bash
   pip install primaite-mail
   ```

3. **Jupyter Environment**: Launch Jupyter Lab or Notebook
   ```bash
   jupyter lab
   # or
   jupyter notebook
   ```

### First Run

1. Open the notebook: `src/primaite_mail/notebooks/email_security_scenarios.ipynb`
2. Run the first cell to initialize the environment
3. Execute cells sequentially for the complete experience
4. Each scenario builds on the previous setup

## Notebook Overview

The notebook is structured in progressive complexity, moving from basic concepts to advanced security scenarios:

### Learning Progression

| **Section** | **Focus** | **Complexity** | **Duration** |
|:------------|:----------|:---------------|:-------------|
| **Environment Setup** | Infrastructure | Basic | 5 minutes |
| **Network Architecture** | Topology | Intermediate | 10 minutes |
| **Email Spoofing** | Attack Simulation | Intermediate | 15 minutes |
| **SMTP Relay Abuse** | Server Security | Advanced | 15 minutes |
| **Blue Team Response** | Defense Implementation | Advanced | 20 minutes |

### Key Components

- **Multi-Agent Environment**: Simulates realistic organizational roles
- **Security-Focused Network**: Enterprise-like topology with security considerations
- **Attack Scenarios**: Realistic threat actor behaviors
- **Defense Mechanisms**: SOC analyst response procedures
- **Educational Analysis**: Clear explanations of security concepts

## Scenario Explanations

### Scenario 1: Email Spoofing and Detection

**Purpose**: Demonstrate how attackers forge sender addresses and how defenders can detect these attacks.

**Learning Objectives**:
- Understand email spoofing techniques
- Learn to identify forged sender addresses
- Practice forensic analysis of email headers
- Implement detection mechanisms

**Key Concepts**:
- **Sender Address Forgery**: Attackers use legitimate-looking sender addresses
- **Source IP Analysis**: Checking originating IP addresses for inconsistencies
- **Behavioral Analysis**: Identifying unusual sending patterns
- **Security Event Correlation**: Linking multiple indicators of compromise

**Real-World Application**: This scenario mirrors common phishing attacks where criminals impersonate executives, IT departments, or trusted partners to deceive recipients.

### Scenario 2: SMTP Relay Abuse

**Purpose**: Show how misconfigured mail servers can be exploited for spam distribution.

**Learning Objectives**:
- Understand open relay vulnerabilities
- Learn server hardening techniques
- Practice attack prevention
- Implement security monitoring

**Key Concepts**:
- **Open Relay Exploitation**: Using misconfigured servers as spam relays
- **Authentication Requirements**: Requiring user authentication for email sending
- **Rate Limiting**: Controlling message volume per sender
- **Reputation Management**: Preventing server IP blacklisting

**Real-World Application**: Many organizations have suffered reputation damage and blacklisting due to compromised or misconfigured mail servers being used for spam distribution.

### Scenario 3: Blue Team Security Response

**Purpose**: Demonstrate how security analysts respond to email-based threats.

**Learning Objectives**:
- Learn SOC analyst workflows
- Practice threat detection and response
- Understand security policy implementation
- Master incident response procedures

**Key Concepts**:
- **Dynamic Threat Response**: Real-time blocking of malicious sources
- **Policy Management**: Configuring and updating security rules
- **Event Correlation**: Linking related security events
- **Threat Intelligence**: Using external threat data for defense

**Real-World Application**: This mirrors the daily work of Security Operations Center (SOC) analysts who monitor, detect, and respond to email-based threats.

## Customization Guide

### Modifying Network Topology

To change the network structure, modify the network creation section:

```python
# Add additional client machines
new_client = Computer.from_config({
    "type": "computer",
    "hostname": "new_client",
    "ip_address": "192.168.1.50",
    "subnet_mask": "255.255.255.0",
    "operating_state": "ON"
})
sim.network.add_node(new_client)

# Connect to switch
sim.network.connect(new_client.network_interface[1], security_switch.network_interface[5])
```

### Creating Custom Attack Scenarios

Add new attack patterns by creating custom email messages:

```python
# Custom phishing email
custom_phishing = EmailMessage(
    sender="ceo@company.com",  # Spoofed executive
    recipients=["finance@company.com"],
    subject="Urgent Wire Transfer Request",
    body="Please transfer $50,000 to account 123456789 immediately. This is confidential."
)
```

### Adjusting Security Policies

Modify security policies to test different defensive postures:

```python
# Block entire IP ranges
block_network_request = [
    "network", "node", "mail_server", "service", "smtp-server", 
    "block_ip", {"ip_address": "10.0.0.0/8"}  # Block entire private range
]

# Block multiple senders at once
malicious_senders = ["phishing@evil.com", "spam@badactor.net", "scam@fraud.org"]
for sender in malicious_senders:
    block_request = [
        "network", "node", "mail_server", "service", "smtp-server", 
        "block_sender", {"sender_address": sender}
    ]
    response = sim.apply_request(request=block_request, context={})
```

### Adding New User Roles

Create additional user types with different behaviors:

```python
# Create executive assistant role
assistant_pc = Computer.from_config({
    "type": "computer",
    "hostname": "assistant_pc",
    "ip_address": "192.168.1.25",
    "subnet_mask": "255.255.255.0",
    "operating_state": "ON"
})

# Install email client
assistant_pc.software_manager.install(EmailClient)
assistant_client = assistant_pc.software_manager.software.get("email-client")

# Create mailbox
smtp_server.mailbox_manager.create_mailbox("assistant")
```

### Scenario Timing Modifications

Adjust scenario complexity by changing the number of steps or interactions:

```python
# Extend scenario duration
for step in range(100):  # Increase from 50 to 100 steps
    # Scenario logic here
    pass

# Add delays between actions
import time
time.sleep(2)  # 2-second delay between email sends
```

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Failed to send email"
**Symptoms**: Email sending operations return False
**Causes**: 
- SMTP server not properly initialized
- Network connectivity issues
- Client configuration problems

**Solutions**:
```python
# Verify SMTP server is running
smtp_server = mail_server.software_manager.software.get("smtp-server")
print(f"SMTP Server status: {smtp_server.name}")

# Check client configuration
print(f"Client username: {clients['admin'].config.username}")
print(f"SMTP server IP: {clients['admin'].config.default_smtp_server}")

# Verify network connectivity
print(f"Mail server IP: {mail_server.config.ip_address}")
```

#### Issue: "Mailbox not found"
**Symptoms**: Mailbox operations fail with None results
**Causes**: 
- Mailbox not created
- Incorrect username
- Mailbox manager not shared between services

**Solutions**:
```python
# Create missing mailboxes
required_users = ["admin", "user", "finance", "hr"]
for username in required_users:
    success = smtp_server.mailbox_manager.create_mailbox(username)
    print(f"Created {username}: {success}")

# Verify mailbox exists
mailbox = smtp_server.mailbox_manager.get_mailbox("user")
if mailbox:
    print(f"Mailbox found: {len(mailbox.get_messages())} messages")
else:
    print("Mailbox not found - creating now")
    smtp_server.mailbox_manager.create_mailbox("user")
```

#### Issue: "Security policy not working"
**Symptoms**: Blocked emails still being delivered
**Causes**: 
- Security policy not initialized
- Incorrect request format
- Policy not applied to SMTP server

**Solutions**:
```python
# Initialize security policy if missing
if not hasattr(smtp_server, 'security_policy'):
    from primaite_mail.simulator.software.email_security_policy import EmailSecurityPolicy
    smtp_server.security_policy = EmailSecurityPolicy()
    print("Security policy initialized")

# Verify policy is active
policies_request = [
    "network", "node", "mail_server", "service", "smtp-server", 
    "list_security_policies", {}
]
response = sim.apply_request(request=policies_request, context={})
print(f"Current policies: {response.data}")
```

#### Issue: "Request failed with 'unreachable'"
**Symptoms**: Simulation requests return "unreachable" status
**Causes**: 
- Incorrect request path
- Component not installed
- Wrong component type (service vs application)

**Solutions**:
```python
# Verify component exists
print(f"Available services: {list(mail_server.software_manager.services.keys())}")
print(f"Available applications: {list(mail_server.software_manager.applications.keys())}")

# Check correct request format
# For services: ["network", "node", "hostname", "service", "service-name", "action"]
# For applications: ["network", "node", "hostname", "application", "app-name", "action"]

# Test with simple request first
test_request = ["network", "node", "mail_server", "service", "smtp-server", "show"]
response = sim.apply_request(request=test_request, context={})
print(f"Test response: {response.status}")
```

### Performance Issues

#### Slow Notebook Execution
**Solutions**:
- Reduce the number of simulation steps
- Limit the number of email messages created
- Use fewer network nodes
- Disable detailed logging if not needed

```python
# Optimize for speed
PRIMAITE_CONFIG["developer_mode"]["output_sys_logs"] = False
PRIMAITE_CONFIG["developer_mode"]["output_agent_logs"] = False

# Reduce scenario complexity
max_emails = 5  # Instead of 20
simulation_steps = 25  # Instead of 100
```

#### Memory Usage
**Solutions**:
- Clear message history periodically
- Limit mailbox size
- Reset simulation between scenarios

```python
# Clear mailbox history
for username in ["admin", "user", "finance"]:
    mailbox = smtp_server.mailbox_manager.get_mailbox(username)
    if mailbox:
        mailbox.messages.clear()

# Reset simulation
sim = Simulation()  # Create fresh simulation
```

### Environment Issues

#### Import Errors
**Solutions**:
```python
# Verify PrimAITE installation
try:
    from primaite.simulator.sim_container import Simulation
    print("✅ PrimAITE core imported successfully")
except ImportError as e:
    print(f"❌ PrimAITE import failed: {e}")
    print("Run: pip install primaite")

# Verify PrimAITE-Mail installation
try:
    from primaite_mail.simulator.software.smtp_server import SMTPServer
    print("✅ PrimAITE-Mail imported successfully")
except ImportError as e:
    print(f"❌ PrimAITE-Mail import failed: {e}")
    print("Run: pip install primaite-mail")
```

#### Jupyter Kernel Issues
**Solutions**:
```bash
# Restart kernel
# In Jupyter: Kernel -> Restart & Clear Output

# Reinstall kernel
python -m ipykernel install --user --name primaite --display-name "PrimAITE"

# Verify environment
which python
pip list | grep primaite
```

## Educational Objectives

### Primary Learning Goals

1. **Threat Recognition**: Students learn to identify common email-based attack patterns
2. **Attack Simulation**: Safe reproduction of attack scenarios for analysis
3. **Defense Implementation**: Practical deployment of security countermeasures
4. **Forensic Analysis**: Investigation techniques for email security incidents
5. **Security Monitoring**: Implementation of continuous security monitoring
6. **Incident Response**: Development of response procedures for email threats

### Skills Development

#### Technical Skills
- Email system administration
- Security policy configuration
- Network traffic analysis
- Incident response procedures
- Threat intelligence utilization

#### Analytical Skills
- Pattern recognition in attack behaviors
- Risk assessment and prioritization
- Security event correlation
- Impact analysis and reporting
- Decision-making under pressure

#### Communication Skills
- Security incident documentation
- Stakeholder communication
- Technical report writing
- Training and awareness delivery

### Assessment Opportunities

#### Knowledge Checks
- Identify spoofed emails in mixed message sets
- Explain the difference between various attack types
- Describe appropriate response procedures
- Analyze the effectiveness of different security policies

#### Practical Exercises
- Configure security policies for different threat scenarios
- Investigate simulated security incidents
- Develop response procedures for new attack types
- Create custom attack scenarios for training purposes

#### Advanced Projects
- Design comprehensive email security architectures
- Develop automated threat detection systems
- Create training materials for end users
- Conduct security assessments of email systems

## Best Practices

### For Instructors

#### Preparation
- Review all scenarios before class
- Test notebook execution in advance
- Prepare additional examples for discussion
- Have troubleshooting solutions ready

#### Delivery
- Start with basic concepts before advanced scenarios
- Encourage hands-on experimentation
- Use real-world examples to illustrate concepts
- Allow time for questions and discussion

#### Assessment
- Focus on understanding over memorization
- Use practical scenarios for evaluation
- Encourage creative problem-solving
- Provide constructive feedback

### For Students

#### Learning Approach
- Execute each cell carefully and observe results
- Experiment with modifications to understand concepts
- Take notes on key observations and insights
- Ask questions when concepts are unclear

#### Practice Recommendations
- Repeat scenarios with different parameters
- Create your own attack scenarios
- Practice explaining concepts to others
- Apply learning to real-world situations

#### Safety Considerations
- Only use techniques in authorized environments
- Never test attacks against real systems
- Respect ethical boundaries in cybersecurity
- Report actual security incidents appropriately

### For Organizations

#### Training Integration
- Incorporate notebook into security awareness programs
- Use scenarios for tabletop exercises
- Adapt content for specific organizational needs
- Regular updates to reflect current threats

#### Skill Development
- Use for SOC analyst training
- Include in incident response training
- Incorporate into security certification programs
- Regular practice sessions for security teams

## Advanced Usage

### Integration with Other Tools

#### SIEM Integration
```python
# Export security events for SIEM analysis
security_events = []
for event in smtp_server.security_log.events:
    security_events.append({
        'timestamp': event.timestamp,
        'event_type': event.event_type,
        'source_ip': event.source_ip,
        'action': event.action_taken
    })

# Save to JSON for SIEM import
import json
with open('security_events.json', 'w') as f:
    json.dump(security_events, f, indent=2)
```

#### Threat Intelligence Feeds
```python
# Simulate threat intelligence integration
threat_indicators = [
    "malicious-domain.com",
    "phishing-site.net", 
    "192.168.100.0/24"
]

# Apply threat intelligence to security policies
for indicator in threat_indicators:
    if '@' in indicator:
        # Email address
        block_request = ["network", "node", "mail_server", "service", "smtp-server", 
                        "block_sender", {"sender_address": indicator}]
    else:
        # IP or domain
        block_request = ["network", "node", "mail_server", "service", "smtp-server", 
                        "block_ip", {"ip_address": indicator}]
    
    response = sim.apply_request(request=block_request, context={})
```

### Custom Metrics and Reporting

```python
# Calculate security metrics
def calculate_security_metrics():
    policies_request = ["network", "node", "mail_server", "service", "smtp-server", 
                       "list_security_policies", {}]
    response = sim.apply_request(request=policies_request, context={})
    
    if response.status == "success":
        policies = response.data.get("policy_summary", {})
        
        metrics = {
            "blocked_senders": len(policies.get("blocked_senders", [])),
            "blocked_ips": len(policies.get("blocked_ips", [])),
            "total_blocks": len(policies.get("blocked_senders", [])) + len(policies.get("blocked_ips", [])),
            "security_events": len(smtp_server.security_log.events) if hasattr(smtp_server, 'security_log') else 0
        }
        
        return metrics
    
    return {}

# Generate security report
metrics = calculate_security_metrics()
print(f"Security Metrics Report:")
print(f"  Blocked Senders: {metrics.get('blocked_senders', 0)}")
print(f"  Blocked IPs: {metrics.get('blocked_ips', 0)}")
print(f"  Total Security Events: {metrics.get('security_events', 0)}")
```

## Conclusion

This notebook provides a comprehensive foundation for understanding email security threats and defenses. By working through the scenarios, users gain practical experience with:

- Realistic attack simulation
- Security policy implementation
- Incident response procedures
- Forensic analysis techniques
- SOC analyst workflows

The modular design allows for customization to meet specific training needs, while the progressive complexity ensures learners can build skills systematically.

For additional support or advanced customization, consult the PrimAITE-Mail documentation or contact the development team.

---

**Version**: 1.0  
**Last Updated**: September 2025  
**Compatibility**: PrimAITE 4.0+, PrimAITE-Mail 1.0+