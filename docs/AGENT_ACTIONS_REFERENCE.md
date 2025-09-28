# Email Attachment Agent Actions Reference

© Crown-owned copyright 2025, Defence Science and Technology Laboratory UK

This document provides a complete reference for all email attachment-related agent actions in PrimAITE-Mail.

## Table of Contents

- [Overview](#overview)
- [Action Definitions](#action-definitions)
- [Request Handlers](#request-handlers)
- [Usage Examples](#usage-examples)
- [Error Handling](#error-handling)

## Overview

The PrimAITE-Mail attachment system provides four main agent actions for cybersecurity training scenarios:

| Action | Purpose | Team | Description |
|--------|---------|------|-------------|
| `email-send-with-attachments` | Send emails with files | All | Send emails with file attachments |
| `email-extract-attachments` | Extract received files | All | Extract attachments from emails |
| `email-scan-attachments` | Security scanning | Blue | Scan emails for threats |
| `email-quarantine-message` | Threat response | Blue | Quarantine malicious emails |

## Action Definitions

### 1. EmailSendWithAttachmentsAction

**Purpose**: Send emails with file attachments via email client

**Configuration Schema**:
```python
class ConfigSchema(AbstractAction.ConfigSchema):
    type: str = "email-send-with-attachments"
    node_name: str                    # Computer hosting email client
    to: list                         # List of recipient email addresses
    subject: str = ""                # Email subject line
    body: str = ""                   # Email body content
    sender: str = ""                 # Sender email address
    attachment_files: list = []      # List of (folder_name, file_name) tuples
```

**Request Format**:
```python
[
    "network",
    "node", 
    config.node_name,
    "application",
    "email-client",
    "send_email",
    {
        "to": config.to,
        "subject": config.subject,
        "body": config.body,
        "from": config.sender,
        "attachment_files": config.attachment_files
    }
]
```

**Example Configuration**:
```yaml
action: email-send-with-attachments
options:
  node_name: "alice_pc"
  to: ["bob@company.com", "charlie@company.com"]
  subject: "Project Documents"
  body: "Please find attached the project files for review."
  sender: "alice@company.com"
  attachment_files: [["documents", "report.pdf"], ["documents", "budget.xlsx"]]
```

### 2. EmailExtractAttachmentsAction

**Purpose**: Extract attachments from received emails to local file system

**Configuration Schema**:
```python
class ConfigSchema(AbstractAction.ConfigSchema):
    type: str = "email-extract-attachments"
    node_name: str                    # Computer hosting email client
    email_index: int = 0              # Index of email to extract from (0-based)
    destination_folder: str = "downloads"  # Folder to extract files to
    extract_all: bool = True          # Extract all attachments or specific ones
```

**Request Format**:
```python
[
    "network",
    "node",
    config.node_name,
    "application", 
    "email-client",
    "extract_attachments",
    {
        "email_index": config.email_index,
        "destination_folder": config.destination_folder,
        "extract_all": config.extract_all
    }
]
```

**Example Configuration**:
```yaml
action: email-extract-attachments
options:
  node_name: "bob_pc"
  email_index: 0
  destination_folder: "downloads"
  extract_all: true
```

### 3. EmailScanAttachmentsAction

**Purpose**: Blue team security scanning of email attachments

**Configuration Schema**:
```python
class ConfigSchema(AbstractAction.ConfigSchema):
    type: str = "email-scan-attachments"
    node_name: str                    # Computer hosting email client
    email_index: int = 0              # Index of email to scan (0-based)
    scan_type: str = "basic"          # Scan type: basic, detailed, security
```

**Request Format**:
```python
[
    "network",
    "node",
    config.node_name,
    "application",
    "email-client", 
    "list_attachments",
    {
        "email_index": config.email_index,
        "scan_type": config.scan_type
    }
]
```

**Example Configuration**:
```yaml
action: email-scan-attachments
options:
  node_name: "blue_pc"
  email_index: 0
  scan_type: "security"
```

### 4. EmailQuarantineMessageAction

**Purpose**: Blue team quarantine of suspicious emails

**Configuration Schema**:
```python
class ConfigSchema(AbstractAction.ConfigSchema):
    type: str = "email-quarantine-message"
    node_name: str                    # Computer requesting quarantine
    email_index: int = 0              # Index of email to quarantine
    reason: str = "suspicious_attachment"  # Reason for quarantine
    smtp_server_node: str = ""        # Node name where SMTP server runs
```

**Request Format**:
```python
[
    "network",
    "node",
    config.smtp_server_node,
    "service",
    "smtp-server",
    "quarantine_message",
    {
        "email_index": config.email_index,
        "reason": config.reason,
        "requesting_node": config.node_name
    }
]
```

**Example Configuration**:
```yaml
action: email-quarantine-message
options:
  node_name: "blue_pc"
  email_index: 0
  reason: "malicious_attachment"
  smtp_server_node: "mail_server"
```

## Request Handlers

### Email Client Request Handlers

The email client provides several request handlers for attachment operations:

#### send_email (Enhanced)
- **Purpose**: Send email with optional attachments
- **Parameters**: 
  - `to`: List of recipients
  - `subject`: Email subject
  - `body`: Email body
  - `from`: Sender address
  - `attachment_files`: Optional list of (folder, filename) tuples
- **Returns**: Success/failure status

#### extract_attachments
- **Purpose**: Extract attachments from a specific email
- **Parameters**:
  - `email_index`: Index of email in client's received emails
  - `destination_folder`: Target folder for extracted files
  - `extract_all`: Whether to extract all attachments
- **Returns**: List of extracted filenames

#### list_attachments
- **Purpose**: List and analyze attachments in an email
- **Parameters**:
  - `email_index`: Index of email to analyze
  - `scan_type`: Type of analysis (basic, detailed, security)
- **Returns**: Attachment metadata and security analysis

### SMTP Server Request Handlers

#### quarantine_message
- **Purpose**: Move suspicious email to quarantine
- **Parameters**:
  - `username`: Mailbox owner
  - `email_index`: Index of email to quarantine
  - `reason`: Reason for quarantine
  - `requesting_node`: Node requesting quarantine
- **Returns**: Success/failure status

#### get_server_stats (Enhanced)
- **Purpose**: Get server statistics including attachment data
- **Returns**: Server stats with attachment metrics

### Mailbox Request Handlers

#### get_mailbox_messages (Enhanced)
- **Purpose**: Get mailbox messages with attachment metadata
- **Parameters**:
  - `username`: Mailbox owner
  - `include_attachments`: Include attachment details
- **Returns**: Messages with attachment information

#### get_message_attachments
- **Purpose**: Get detailed attachment information for a message
- **Parameters**:
  - `username`: Mailbox owner
  - `message_index`: Index of message
- **Returns**: Detailed attachment metadata

## Usage Examples

### Red Team Malware Distribution

```python
# Red team agent configuration
red_team_actions = {
    "send_malware": {
        "action": "email-send-with-attachments",
        "options": {
            "node_name": "red_pc",
            "to": ["alice@company.com", "bob@company.com"],
            "subject": "Important Security Update",
            "body": "Please install the attached security update immediately.",
            "sender": "it-admin@company.com",  # Spoofed sender
            "attachment_files": [["malware", "security_update.exe"]]
        }
    }
}

# Execute red team action
response = game.step(agent_name="red_agent", action_id=1)
print(f"Malware distribution: {response.status}")
```

### Blue Team Defense Response

```python
# Blue team scanning and response
blue_team_actions = {
    "scan_emails": {
        "action": "email-scan-attachments",
        "options": {
            "node_name": "blue_pc",
            "email_index": 0,
            "scan_type": "security"
        }
    },
    "quarantine_threat": {
        "action": "email-quarantine-message",
        "options": {
            "node_name": "blue_pc",
            "email_index": 0,
            "reason": "malicious_executable_detected",
            "smtp_server_node": "mail_server"
        }
    }
}

# Blue team workflow
# 1. Scan for threats
scan_response = game.step(agent_name="blue_agent", action_id=1)
if scan_response.data.get("threats_detected"):
    # 2. Quarantine malicious email
    quarantine_response = game.step(agent_name="blue_agent", action_id=2)
    print(f"Threat quarantined: {quarantine_response.status}")
```

### Green Team Collaboration

```python
# Green team legitimate document sharing
green_team_actions = {
    "share_documents": {
        "action": "email-send-with-attachments",
        "options": {
            "node_name": "alice_pc",
            "to": ["bob@company.com"],
            "subject": "Q4 Financial Reports",
            "body": "Hi Bob, please review the attached Q4 reports.",
            "sender": "alice@company.com",
            "attachment_files": [
                ["documents", "q4_report.pdf"],
                ["documents", "budget_analysis.xlsx"]
            ]
        }
    },
    "extract_documents": {
        "action": "email-extract-attachments",
        "options": {
            "node_name": "bob_pc",
            "email_index": 0,
            "destination_folder": "work_documents",
            "extract_all": true
        }
    }
}

# Green team workflow
# 1. Alice sends documents
send_response = game.step(agent_name="alice", action_id=1)
# 2. Bob extracts documents
extract_response = game.step(agent_name="bob", action_id=2)
print(f"Documents shared: {extract_response.data.get('extracted_files')}")
```

## Error Handling

### Common Error Responses

#### File Not Found
```python
{
    "status": "failure",
    "data": {
        "reason": "File not found: documents/missing.pdf",
        "error_code": "FILE_NOT_FOUND"
    }
}
```

#### Policy Violation
```python
{
    "status": "failure", 
    "data": {
        "reason": "Attachment violates policy: file size exceeds limit",
        "error_code": "POLICY_VIOLATION",
        "policy_details": {
            "max_size": 10485760,
            "actual_size": 20971520
        }
    }
}
```

#### Blocked File Type
```python
{
    "status": "failure",
    "data": {
        "reason": "File type not allowed: .exe",
        "error_code": "BLOCKED_FILE_TYPE",
        "blocked_extensions": [".exe", ".bat", ".scr"]
    }
}
```

#### Quarantine Success
```python
{
    "status": "success",
    "data": {
        "quarantined": true,
        "reason": "malicious_attachment",
        "quarantine_id": "q_001",
        "timestamp": "2025-01-15T10:30:00Z"
    }
}
```

### Error Handling Best Practices

1. **Check Response Status**: Always check `response.status` before processing data
2. **Handle Specific Errors**: Use `error_code` to handle different error types
3. **Provide User Feedback**: Use `reason` field for user-friendly error messages
4. **Log Security Events**: Log quarantine and policy violations for analysis
5. **Retry Logic**: Implement appropriate retry logic for transient failures

### Example Error Handling

```python
def handle_attachment_response(response):
    """Handle attachment operation response with proper error handling."""
    
    if response.status == "success":
        return response.data
    
    error_code = response.data.get("error_code", "UNKNOWN_ERROR")
    reason = response.data.get("reason", "Unknown error occurred")
    
    if error_code == "FILE_NOT_FOUND":
        print(f"File not found: {reason}")
        # Suggest checking file system
        return None
    
    elif error_code == "POLICY_VIOLATION":
        print(f"Policy violation: {reason}")
        policy_details = response.data.get("policy_details", {})
        print(f"Policy details: {policy_details}")
        return None
    
    elif error_code == "BLOCKED_FILE_TYPE":
        print(f"Blocked file type: {reason}")
        blocked_types = response.data.get("blocked_extensions", [])
        print(f"Blocked extensions: {blocked_types}")
        return None
    
    else:
        print(f"Unexpected error: {reason}")
        return None

# Usage
response = game.step(agent_name="alice", action_id=1)
result = handle_attachment_response(response)
if result:
    print("Operation successful")
else:
    print("Operation failed")
```

This reference provides comprehensive information for implementing and using email attachment agent actions in PrimAITE-Mail cybersecurity training scenarios.