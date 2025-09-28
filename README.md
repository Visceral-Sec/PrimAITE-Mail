# THIS PLUGIN WAS CREATED USING ARTIFICIAL INTELLIGENCE 

## There is a no guarantee that the `primaite-mail` is stable. Please read DISCLAIMER.md.


# PrimAITE-Mail

`primaite-mail` is a collection of plugins which extends [PrimAITE](https://github.com/Autonomous-Resilient-Cyber-Defence/PrimAITE) by introducing email client and server simulation components.

This extension provides realistic email communication simulation including SMTP, POP3, and IMAP protocols for cybersecurity training scenarios.

## Features

- **SMTP Server**: Simulates email sending and relay functionality with attachment support
- **SMTP Client**: Enables agents to send emails through SMTP servers
- **POP3 Server**: Provides email retrieval via POP3 protocol with attachment handling
- **IMAP Server**: Advanced email access with folder management
- **Email Client**: Unified client supporting multiple protocols and file attachments
- **Mailbox Management**: Persistent email storage and organization
- **Authentication**: User-based email access control
- **File Attachments**: Complete attachment system with policy enforcement
- **Security Features**: Malware detection, quarantine, and policy-based restrictions
- **Agent Actions**: Red/blue/green team scenarios with attachment-based attacks and defenses

## Installation

```bash
pip install primaite-mail
```

## Usage

See the example notebooks in the `notebooks/` directory for detailed usage examples.

## Email Attachment System

PrimAITE-Mail includes a comprehensive email attachment system that enables realistic file transfer scenarios through email:

### Key Features

- **File Attachment Support**: Send and receive files through email with full integration to PrimAITE's file system
- **Policy Enforcement**: Configurable size limits, file type restrictions, and security policies
- **Health Status Preservation**: Maintains file corruption status for malware simulation
- **Security Scanning**: Automatic detection of suspicious attachments and quarantine capabilities
- **Multi-Agent Scenarios**: Support for red team malware distribution and blue team defensive measures

### Attachment Policies

Configure attachment restrictions through `AttachmentPolicy`:

```python
from primaite_mail.simulator.network.protocols.email_attachments import AttachmentPolicy

policy = AttachmentPolicy(
    max_attachment_size=10 * 1024 * 1024,  # 10MB per attachment
    max_total_size=25 * 1024 * 1024,       # 25MB total message size
    max_attachments=5,                      # Maximum 5 attachments per email
    allowed_extensions=[".txt", ".pdf", ".doc", ".docx"],
    blocked_extensions=[".exe", ".bat", ".scr"],
    scan_for_malware=True,
    quarantine_suspicious=True
)
```

### Agent Actions

New agent actions for attachment scenarios:

- `email-send-with-attachments`: Send emails with file attachments
- `email-extract-attachments`: Extract attachments from received emails
- `email-scan-attachments`: Blue team scanning for suspicious attachments
- `email-quarantine-message`: Blue team quarantine of malicious emails

### Example Usage

```python
# Send email with attachments
email_client.send_email_with_attachments(
    email=EmailMessage(
        sender="alice@company.com",
        recipients=["bob@company.com"],
        subject="Documents",
        body="Please find attached documents."
    ),
    attachment_files=[("documents", "report.pdf"), ("documents", "data.xlsx")],
    smtp_server_ip="192.168.1.10"
)

# Extract attachments from received email
extracted_files = email_client.extract_attachments(
    email=received_email,
    destination_folder="downloads"
)
```

## Cybersecurity Training Scenarios

The attachment system enables realistic cybersecurity training scenarios:

### Red Team Scenarios
- **Malware Distribution**: Send corrupted executables disguised as legitimate files
- **Social Engineering**: Use convincing filenames and email content to trick recipients
- **Data Exfiltration**: Extract sensitive documents through email attachments

### Blue Team Scenarios
- **Threat Detection**: Scan emails for suspicious attachments and file types
- **Incident Response**: Quarantine malicious emails and generate security alerts
- **Policy Enforcement**: Configure and maintain attachment security policies

### Green Team Scenarios
- **Business Operations**: Normal document sharing and collaboration workflows
- **Compliance**: Legitimate file transfers within policy boundaries
- **User Training**: Demonstrate proper email security practices

## Troubleshooting

### Common Issues

1. **Attachment Not Found**
   - Verify file exists in specified folder using `file_system.show()`
   - Check folder and filename spelling

2. **Size Limit Exceeded**
   - Check `attachment_policy.max_attachment_size` and `max_total_size`
   - Reduce file size or split into multiple emails

3. **Blocked File Type**
   - Review `attachment_policy.blocked_extensions`
   - Use allowed file types from `attachment_policy.allowed_extensions`

4. **Extraction Fails**
   - Ensure destination folder exists
   - Check file system permissions and available space

5. **Quarantine Issues**
   - Files with `CORRUPTED` health status may be automatically quarantined
   - Check quarantine folder and security logs

### Debugging

Enable developer mode for enhanced debugging:

```python
from primaite import PRIMAITE_CONFIG
PRIMAITE_CONFIG["developer_mode"]["enabled"] = True
PRIMAITE_CONFIG["developer_mode"]["output_sys_logs"] = True
```

Use built-in display methods for system status:
- `smtp_server.show()` - Server status and statistics
- `smtp_server.show_mailbox(username)` - Mailbox contents with attachments
- `email_client.show()` - Client configuration and status
- `node.sys_log.show(last_n=10)` - Recent system logs