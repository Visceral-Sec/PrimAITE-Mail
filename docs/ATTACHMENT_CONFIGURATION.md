# Email Attachment Configuration Guide

© Crown-owned copyright 2025, Defence Science and Technology Laboratory UK

This guide provides comprehensive information on configuring the PrimAITE-Mail email attachment system for various cybersecurity training scenarios.

## Table of Contents

- [Attachment Policy Configuration](#attachment-policy-configuration)
- [Agent Action Configuration](#agent-action-configuration)
- [Security Scenarios](#security-scenarios)
- [Performance Tuning](#performance-tuning)
- [Integration Examples](#integration-examples)

## Attachment Policy Configuration

### Basic Policy Setup

```python
from primaite_mail.simulator.network.protocols.email_attachments import AttachmentPolicy

# Default policy for general use
default_policy = AttachmentPolicy(
    max_attachment_size=25 * 1024 * 1024,  # 25MB per attachment
    max_total_size=50 * 1024 * 1024,       # 50MB total message size
    max_attachments=10,                     # Maximum 10 attachments per email
    allowed_extensions=[".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", 
                       ".jpg", ".png", ".gif", ".zip"],
    blocked_extensions=[".exe", ".bat", ".scr", ".com", ".pif", ".vbs"],
    scan_for_malware=True,
    quarantine_suspicious=True
)

# Apply to SMTP server
smtp_server.attachment_policy = default_policy
```

### Restrictive Security Policy

```python
# High-security environment
restrictive_policy = AttachmentPolicy(
    max_attachment_size=5 * 1024 * 1024,   # 5MB limit
    max_total_size=10 * 1024 * 1024,       # 10MB total
    max_attachments=3,                      # Only 3 attachments
    allowed_extensions=[".txt", ".pdf"],    # Only text and PDF
    blocked_extensions=[".exe", ".bat", ".scr", ".com", ".pif", ".vbs", 
                       ".js", ".jar", ".zip", ".rar"],
    scan_for_malware=True,
    quarantine_suspicious=True
)
```

### Permissive Testing Policy

```python
# For development and testing
permissive_policy = AttachmentPolicy(
    max_attachment_size=100 * 1024 * 1024, # 100MB
    max_total_size=200 * 1024 * 1024,      # 200MB total
    max_attachments=20,                     # Many attachments allowed
    allowed_extensions=[],                  # Empty = allow all
    blocked_extensions=[],                  # No restrictions
    scan_for_malware=False,                 # Disable scanning
    quarantine_suspicious=False             # No quarantine
)
```

### Scenario-Specific Policies

#### Red Team Training Policy
```python
# Allow malware for red team training
red_team_policy = AttachmentPolicy(
    max_attachment_size=50 * 1024 * 1024,
    max_total_size=100 * 1024 * 1024,
    max_attachments=15,
    allowed_extensions=[".exe", ".bat", ".scr", ".pdf", ".doc", ".txt"],
    blocked_extensions=[],                  # Allow dangerous files
    scan_for_malware=True,                  # Detect but don't block
    quarantine_suspicious=False             # Let malware through
)
```

#### Blue Team Training Policy
```python
# Strict policy for blue team defense training
blue_team_policy = AttachmentPolicy(
    max_attachment_size=10 * 1024 * 1024,
    max_total_size=25 * 1024 * 1024,
    max_attachments=5,
    allowed_extensions=[".txt", ".pdf", ".doc", ".docx"],
    blocked_extensions=[".exe", ".bat", ".scr", ".com", ".pif", ".vbs",
                       ".js", ".jar", ".zip", ".rar", ".7z"],
    scan_for_malware=True,
    quarantine_suspicious=True
)
```

## Agent Action Configuration

### Email Send with Attachments Action

```yaml
# In agent configuration YAML
action_space:
  action_map:
    10:
      action: email-send-with-attachments
      options:
        node_name: alice_pc
        to: ["bob@company.com"]
        subject: "Project Documents"
        body: "Please find attached project files."
        sender: "alice@company.com"
        attachment_files: [["documents", "report.pdf"], ["documents", "data.xlsx"]]
```

### Email Extract Attachments Action

```yaml
    11:
      action: email-extract-attachments
      options:
        node_name: bob_pc
        email_index: 0
        destination_folder: "downloads"
        extract_all: true
```

### Email Scan Attachments Action (Blue Team)

```yaml
    12:
      action: email-scan-attachments
      options:
        node_name: blue_pc
        email_index: 0
        scan_type: "security"
```

### Email Quarantine Message Action (Blue Team)

```yaml
    13:
      action: email-quarantine-message
      options:
        node_name: blue_pc
        email_index: 0
        reason: "malicious_attachment"
        smtp_server_node: "mail_server"
```

## Security Scenarios

### Scenario 1: Malware Distribution

```python
# Red team sends malware via email
def setup_malware_scenario():
    # Create malicious file
    from primaite.simulator.file_system.file import File
    from primaite.simulator.file_system.file_type import FileType
    from primaite.simulator.file_system.file_system_item_abc import FileSystemItemHealthStatus
    
    malware = File(
        name="update.exe",
        file_type=FileType.EXECUTABLE,
        size=4096,
        health_status=FileSystemItemHealthStatus.CORRUPTED
    )
    malware.write_text("Malicious payload")
    red_pc.file_system.add_file(malware, "payloads")
    
    # Configure permissive policy to allow malware through
    smtp_server.attachment_policy = AttachmentPolicy(
        max_attachment_size=10 * 1024 * 1024,
        allowed_extensions=[".exe"],
        blocked_extensions=[],
        scan_for_malware=True,      # Detect but don't block
        quarantine_suspicious=False  # Allow through for training
    )
    
    return [("payloads", "update.exe")]
```

### Scenario 2: Document Collaboration

```python
# Green team legitimate document sharing
def setup_collaboration_scenario():
    # Create business documents
    report = File(
        name="quarterly_report.pdf",
        file_type=FileType.PDF,
        size=2048,
        health_status=FileSystemItemHealthStatus.HEALTHY
    )
    report.write_text("Q4 Financial Report")
    alice_pc.file_system.add_file(report, "documents")
    
    # Standard business policy
    smtp_server.attachment_policy = AttachmentPolicy(
        max_attachment_size=25 * 1024 * 1024,
        allowed_extensions=[".pdf", ".doc", ".docx", ".xls", ".xlsx"],
        blocked_extensions=[".exe", ".bat", ".scr"],
        scan_for_malware=True,
        quarantine_suspicious=True
    )
    
    return [("documents", "quarterly_report.pdf")]
```

### Scenario 3: Blue Team Defense

```python
# Blue team scanning and quarantine
def setup_defense_scenario():
    # Configure strict security policy
    smtp_server.attachment_policy = AttachmentPolicy(
        max_attachment_size=5 * 1024 * 1024,   # Small limit
        max_attachments=3,                      # Few attachments
        allowed_extensions=[".txt", ".pdf"],    # Only safe types
        blocked_extensions=[".exe", ".bat", ".scr", ".js", ".zip"],
        scan_for_malware=True,
        quarantine_suspicious=True
    )
    
    # Blue team actions for scanning
    blue_actions = [
        {
            "action": "email-scan-attachments",
            "options": {
                "node_name": "blue_pc",
                "email_index": 0,
                "scan_type": "security"
            }
        },
        {
            "action": "email-quarantine-message", 
            "options": {
                "node_name": "blue_pc",
                "email_index": 0,
                "reason": "suspicious_attachment",
                "smtp_server_node": "mail_server"
            }
        }
    ]
    
    return blue_actions
```

## Performance Tuning

### Memory Management

```python
# For large attachment scenarios
large_file_policy = AttachmentPolicy(
    max_attachment_size=100 * 1024 * 1024,  # 100MB
    max_total_size=500 * 1024 * 1024,       # 500MB total
    max_attachments=5,                       # Limit count
    scan_for_malware=False,                  # Disable scanning for performance
    quarantine_suspicious=False
)

# Monitor memory usage
import psutil
import os

def monitor_memory():
    process = psutil.Process(os.getpid())
    memory_mb = process.memory_info().rss / (1024 * 1024)
    print(f"Memory usage: {memory_mb:.2f} MB")
    return memory_mb

# Use before and after large operations
memory_before = monitor_memory()
# ... perform attachment operations ...
memory_after = monitor_memory()
print(f"Memory increase: {memory_after - memory_before:.2f} MB")
```

### Network Performance

```python
# Optimize for network scenarios
def optimize_network_performance():
    # Reduce attachment sizes for faster transmission
    smtp_server.attachment_policy.max_attachment_size = 1 * 1024 * 1024  # 1MB
    
    # Limit concurrent operations
    max_concurrent_sessions = 5
    if len(smtp_server.active_sessions) >= max_concurrent_sessions:
        print("Too many active sessions, waiting...")
        
    # Monitor network links
    for link in network.links:
        if link.operating_state.name != "OPERATIONAL":
            print(f"Warning: Link {link} not operational")
```

## Integration Examples

### Complete Training Scenario

```python
def create_comprehensive_scenario():
    """Create a complete cybersecurity training scenario with attachments."""
    
    # 1. Setup network and computers
    network = Network()
    
    # Mail server
    mail_server = Computer.from_config({
        "hostname": "mail_server",
        "ip_address": "192.168.1.10"
    })
    mail_server.power_on()
    network.add_node(mail_server)
    
    # Client computers
    clients = {}
    for name, ip, team in [
        ("alice_pc", "192.168.1.20", "green"),
        ("bob_pc", "192.168.1.21", "green"), 
        ("red_pc", "192.168.1.30", "red"),
        ("blue_pc", "192.168.1.40", "blue")
    ]:
        client = Computer.from_config({
            "hostname": name,
            "ip_address": ip
        })
        client.power_on()
        network.add_node(client)
        clients[team] = client
    
    # 2. Install email services
    mail_server.software_manager.install(SMTPServer)
    mail_server.software_manager.install(POP3Server)
    
    smtp_server = mail_server.software_manager.software.get("smtp-server")
    pop3_server = mail_server.software_manager.software.get("pop3-server")
    
    # 3. Configure attachment policy for training
    training_policy = AttachmentPolicy(
        max_attachment_size=10 * 1024 * 1024,
        max_total_size=25 * 1024 * 1024,
        max_attachments=5,
        allowed_extensions=[".txt", ".pdf", ".doc", ".exe"],  # Allow exe for training
        blocked_extensions=[".bat", ".scr"],  # Block some dangerous types
        scan_for_malware=True,
        quarantine_suspicious=True
    )
    
    smtp_server.attachment_policy = training_policy
    smtp_server.start()
    
    pop3_server.mailbox_manager = smtp_server.mailbox_manager
    pop3_server.start()
    
    # 4. Create user mailboxes and email clients
    users = ["alice", "bob", "red_agent", "blue_agent"]
    email_clients = {}
    
    for user in users:
        smtp_server.mailbox_manager.create_mailbox(user)
        
        # Install email client on appropriate computer
        if user == "alice":
            computer = clients["green"]
        elif user == "bob": 
            computer = clients["green"]
        elif user == "red_agent":
            computer = clients["red"]
        else:  # blue_agent
            computer = clients["blue"]
            
        computer.software_manager.install(EmailClient)
        client = computer.software_manager.software.get("email-client")
        client.config.username = f"{user}@company.com"
        client.config.default_smtp_server = str(mail_server.config.ip_address)
        client.config.default_pop3_server = str(mail_server.config.ip_address)
        
        email_clients[user] = client
    
    # 5. Create test files for different scenarios
    create_test_files(clients)
    
    return network, smtp_server, pop3_server, email_clients

def create_test_files(clients):
    """Create various test files for attachment scenarios."""
    
    # Green team legitimate documents
    alice_pc = clients["green"]
    docs_folder = Folder("documents")
    alice_pc.file_system.add_folder(docs_folder)
    
    report = File(
        name="report.pdf",
        file_type=FileType.PDF,
        size=2048,
        health_status=FileSystemItemHealthStatus.HEALTHY
    )
    alice_pc.file_system.add_file(report, "documents")
    
    # Red team malware
    red_pc = clients["red"]
    malware_folder = Folder("malware")
    red_pc.file_system.add_folder(malware_folder)
    
    virus = File(
        name="virus.exe",
        file_type=FileType.EXECUTABLE,
        size=4096,
        health_status=FileSystemItemHealthStatus.CORRUPTED
    )
    red_pc.file_system.add_file(virus, "malware")
```

### Agent Configuration Template

```yaml
# Complete agent configuration with attachment actions
agents:
  alice:
    type: "green_agent"
    node_name: "alice_pc"
    action_space:
      action_map:
        0: {action: "do-nothing", options: {}}
        1: 
          action: "email-send-with-attachments"
          options:
            node_name: "alice_pc"
            to: ["bob@company.com"]
            subject: "Business Documents"
            body: "Please review attached documents."
            sender: "alice@company.com"
            attachment_files: [["documents", "report.pdf"]]
        2:
          action: "email-extract-attachments"
          options:
            node_name: "alice_pc"
            email_index: 0
            destination_folder: "downloads"
            extract_all: true

  red_agent:
    type: "red_agent"
    node_name: "red_pc"
    action_space:
      action_map:
        0: {action: "do-nothing", options: {}}
        1:
          action: "email-send-with-attachments"
          options:
            node_name: "red_pc"
            to: ["alice@company.com", "bob@company.com"]
            subject: "Security Update"
            body: "Please install this security update."
            sender: "admin@company.com"
            attachment_files: [["malware", "virus.exe"]]

  blue_agent:
    type: "blue_agent"
    node_name: "blue_pc"
    action_space:
      action_map:
        0: {action: "do-nothing", options: {}}
        1:
          action: "email-scan-attachments"
          options:
            node_name: "blue_pc"
            email_index: 0
            scan_type: "security"
        2:
          action: "email-quarantine-message"
          options:
            node_name: "blue_pc"
            email_index: 0
            reason: "malicious_attachment"
            smtp_server_node: "mail_server"
```

This configuration guide provides comprehensive examples for setting up the email attachment system for various cybersecurity training scenarios. Adjust the policies and configurations based on your specific training objectives and security requirements.