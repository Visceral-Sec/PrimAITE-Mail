"""SMTP Server implementation for email sending and relay."""

from datetime import datetime
from typing import Any, Dict, List, Optional
import ipaddress
import re

from pydantic import Field, field_validator, ValidationError

from primaite import getLogger
from primaite.interface.request import RequestFormat, RequestResponse
from primaite.simulator.core import RequestManager, RequestType
from primaite.simulator.system.services.service import Service
from primaite.utils.validation.ip_protocol import PROTOCOL_LOOKUP
from primaite.utils.validation.port import PORT_LOOKUP

from primaite_mail.simulator.network.protocols.smtp import SMTPCommand, SMTPPacket, SMTPStatusCode, EmailMessage
from primaite_mail.simulator.network.protocols.email_attachments import AttachmentPolicy, DEFAULT_ATTACHMENT_POLICY
from primaite_mail.simulator.network.protocols.attachment_manager import AttachmentManager
from primaite_mail.simulator.software.mailbox import MailboxManager
from primaite_mail.simulator.software.security_policy import EmailSecurityPolicy, SecurityEventLog

_LOGGER = getLogger(__name__)


class SMTPServer(Service, discriminator="smtp-server"):
    """
    SMTP Server service for handling email transmission.
    
    Implements RFC 5321 SMTP protocol for receiving and relaying emails.
    """

    class ConfigSchema(Service.ConfigSchema):
        """ConfigSchema for SMTPServer."""

        type: str = "smtp-server"
        domain: str = "localhost"
        max_message_size: int = 10485760  # 10MB
        require_auth: bool = False
        # Security policy configuration
        blocked_senders: List[str] = Field(default_factory=list, description="Initial list of blocked sender addresses")
        blocked_ips: List[str] = Field(default_factory=list, description="Initial list of blocked IP addresses/CIDR ranges")
        enable_security_logging: bool = Field(default=True, description="Enable security event logging")
        
        @field_validator('blocked_senders')
        @classmethod
        def validate_blocked_senders(cls, v: List[str]) -> List[str]:
            """Validate email addresses in blocked_senders list."""
            if not v:
                return v
            
            # Email regex pattern - basic but effective for validation
            email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            
            validated_senders = []
            for sender in v:
                if not isinstance(sender, str):
                    raise ValueError(f"Blocked sender must be a string, got {type(sender)}: {sender}")
                
                sender_clean = sender.strip().lower()
                if not sender_clean:
                    raise ValueError("Blocked sender cannot be empty")
                
                if not email_pattern.match(sender_clean):
                    raise ValueError(f"Invalid email address format: {sender}")
                
                validated_senders.append(sender_clean)
            
            return validated_senders
        
        @field_validator('blocked_ips')
        @classmethod
        def validate_blocked_ips(cls, v: List[str]) -> List[str]:
            """Validate IP addresses and CIDR ranges in blocked_ips list."""
            if not v:
                return v
            
            validated_ips = []
            for ip_entry in v:
                if not isinstance(ip_entry, str):
                    raise ValueError(f"Blocked IP must be a string, got {type(ip_entry)}: {ip_entry}")
                
                ip_clean = ip_entry.strip()
                if not ip_clean:
                    raise ValueError("Blocked IP cannot be empty")
                
                try:
                    # Validate IP or CIDR format
                    if '/' in ip_clean:
                        # CIDR notation
                        network = ipaddress.ip_network(ip_clean, strict=False)
                        # Normalize the CIDR notation
                        validated_ips.append(str(network))
                    else:
                        # Single IP address
                        ip_addr = ipaddress.ip_address(ip_clean)
                        validated_ips.append(str(ip_addr))
                except ValueError as e:
                    raise ValueError(f"Invalid IP address or CIDR format '{ip_entry}': {str(e)}")
            
            return validated_ips
        
        @field_validator('max_message_size')
        @classmethod
        def validate_max_message_size(cls, v: int) -> int:
            """Validate max_message_size is positive."""
            if v <= 0:
                raise ValueError("max_message_size must be positive")
            return v

    config: ConfigSchema = Field(default_factory=lambda: SMTPServer.ConfigSchema())
    mailbox_manager: MailboxManager = Field(default_factory=MailboxManager)
    attachment_manager: AttachmentManager = Field(default_factory=AttachmentManager)
    attachment_policy: AttachmentPolicy = Field(default_factory=lambda: DEFAULT_ATTACHMENT_POLICY)
    active_sessions: Dict[str, Dict] = Field(default_factory=dict)
    quarantine_folder: str = Field(default="quarantine", description="Folder name for quarantined messages")
    # Security policy components
    security_policy: EmailSecurityPolicy = Field(default_factory=EmailSecurityPolicy)
    security_log: SecurityEventLog = Field(default_factory=SecurityEventLog)

    def __init__(self, **kwargs):
        kwargs["name"] = "smtp-server"
        kwargs["port"] = PORT_LOOKUP["SMTP"]
        kwargs["protocol"] = PROTOCOL_LOOKUP["TCP"]
        super().__init__(**kwargs)
        
        # Initialize security policies from configuration
        self._init_security_policies()
        
        self.start()
    
    def start(self) -> bool:
        """Start the SMTP server service."""
        try:
            # Call parent start method if it exists
            if hasattr(super(), 'start'):
                super().start()
            
            self.sys_log.info(f"{self.name}: SMTP server started on port {self.port}")
            return True
        except Exception as e:
            self.sys_log.error(f"{self.name}: Failed to start SMTP server: {e}")
            return False
    
    def stop(self) -> bool:
        """Stop the SMTP server service."""
        try:
            # Clear active sessions
            self.active_sessions.clear()
            
            # Call parent stop method if it exists
            if hasattr(super(), 'stop'):
                super().stop()
            
            self.sys_log.info(f"{self.name}: SMTP server stopped")
            return True
        except Exception as e:
            self.sys_log.error(f"{self.name}: Failed to stop SMTP server: {e}")
            return False
    
    def restart(self) -> bool:
        """Restart the SMTP server service."""
        self.sys_log.info(f"{self.name}: Restarting SMTP server...")
        if self.stop():
            return self.start()
        return False
    
    def _init_security_policies(self) -> None:
        """Initialize security policies from configuration."""
        # Note: Configuration validation happens in ConfigSchema validators
        # So by the time we get here, all entries should be valid
        
        # Load initial blocked senders from config (already validated)
        loaded_senders = 0
        for sender in self.config.blocked_senders:
            # Since validation already happened, we can trust these are valid
            # But we still use the security policy method for consistency
            if self.security_policy.add_blocked_sender(sender):
                loaded_senders += 1
                self.sys_log.info(f"{self.name}: Added blocked sender from config: {sender}")
            else:
                # This should not happen if validation worked correctly
                self.sys_log.error(f"{self.name}: Failed to add validated sender from config: {sender}")
        
        # Load initial blocked IPs from config (already validated)
        loaded_ips = 0
        for ip in self.config.blocked_ips:
            # Since validation already happened, we can trust these are valid
            if self.security_policy.add_blocked_ip(ip):
                loaded_ips += 1
                self.sys_log.info(f"{self.name}: Added blocked IP from config: {ip}")
            else:
                # This should not happen if validation worked correctly
                self.sys_log.error(f"{self.name}: Failed to add validated IP from config: {ip}")
        
        # Configure logging
        self.security_policy.enable_logging = self.config.enable_security_logging
        
        # Log initialization summary
        total_configured_senders = len(self.config.blocked_senders)
        total_configured_ips = len(self.config.blocked_ips)
        
        self.sys_log.info(f"{self.name}: Security policies initialized")
        self.sys_log.info(f"{self.name}: Loaded {loaded_senders}/{total_configured_senders} blocked senders")
        self.sys_log.info(f"{self.name}: Loaded {loaded_ips}/{total_configured_ips} blocked IPs")
        self.sys_log.info(f"{self.name}: Security logging: {'enabled' if self.config.enable_security_logging else 'disabled'}")
        
        # Log any discrepancies (should not happen with proper validation)
        if loaded_senders != total_configured_senders:
            self.sys_log.warning(f"{self.name}: Sender loading mismatch - check configuration validation")
        if loaded_ips != total_configured_ips:
            self.sys_log.warning(f"{self.name}: IP loading mismatch - check configuration validation")

    def _init_request_manager(self) -> RequestManager:
        """Initialize the request manager with SMTP-specific requests."""
        rm = super()._init_request_manager()
        
        def _create_mailbox_request(request: RequestFormat, context: Dict) -> RequestResponse:
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            username = params.get("username")
            if not username:
                return RequestResponse(status="failure", data={"reason": "Username required"})
            
            success = self.mailbox_manager.create_mailbox(username)
            if success:
                return RequestResponse(status="success", data={"username": username})
            else:
                return RequestResponse(status="failure", data={"reason": f"Failed to create mailbox for {username}"})
        
        def _delete_mailbox_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Delete a user mailbox."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            username = params.get("username")
            if not username:
                return RequestResponse(status="failure", data={"reason": "Username required"})
            
            success = self.mailbox_manager.delete_mailbox(username)
            if success:
                return RequestResponse(status="success", data={"username": username})
            else:
                return RequestResponse(status="failure", data={"reason": f"Failed to delete mailbox for {username}"})
        
        def _list_mailboxes_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """List all mailboxes."""
            mailboxes = {}
            for username, mailbox in self.mailbox_manager.mailboxes.items():
                mailboxes[username] = {
                    "total_messages": len(mailbox.get_messages()),
                    "folders": list(mailbox.folders.keys())
                }
            return RequestResponse(status="success", data={"mailboxes": mailboxes})
        
        def _get_mailbox_messages_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get messages from a specific mailbox with attachment metadata."""
            params = request[-1]
            username = params.get("username")
            folder = params.get("folder", "INBOX")
            
            if not username:
                return RequestResponse(status="failure", data={"reason": "Username required"})
            
            mailbox = self.mailbox_manager.get_mailbox(username)
            if not mailbox:
                return RequestResponse(status="failure", data={"reason": f"Mailbox for {username} not found"})
            
            messages = mailbox.get_messages(folder)
            message_data = []
            for msg in messages:
                # Include attachment information
                attachment_info = []
                if msg.has_attachments:
                    for att in msg.attachments:
                        attachment_info.append({
                            "filename": att.filename,
                            "content_type": att.content_type,
                            "file_size": att.file_size,
                            "health_status": att.health_status
                        })
                
                message_data.append({
                    "message_id": msg.message_id,
                    "sender": msg.sender,
                    "recipients": msg.recipients,
                    "subject": msg.subject,
                    "timestamp": msg.timestamp,
                    "body_length": len(msg.body) if msg.body else 0,
                    "has_attachments": msg.has_attachments,
                    "attachment_count": msg.attachment_count,
                    "attachments": attachment_info,
                    "total_size": msg.calculate_total_size()
                })
            
            return RequestResponse(status="success", data={
                "username": username,
                "folder": folder,
                "message_count": len(messages),
                "messages": message_data
            })
        
        def _send_message_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Send a message directly through the SMTP server with attachment support."""
            params = request[-1]
            
            sender = params.get("sender")
            recipients = params.get("recipients", [])
            subject = params.get("subject", "")
            body = params.get("body", "")
            attachment_files = params.get("attachment_files", [])  # List of (folder_name, file_name) tuples
            
            if not sender:
                return RequestResponse(status="failure", data={"reason": "Sender required"})
            if not recipients:
                return RequestResponse(status="failure", data={"reason": "Recipients required"})
            
            if isinstance(recipients, str):
                recipients = [recipients]
            
            # Create email message
            email = EmailMessage(
                sender=sender,
                recipients=recipients,
                subject=subject,
                body=body
            )
            
            # Add attachments if specified
            attachment_errors = []
            if attachment_files:
                # Need file system access to attach files - this would typically come from the node
                # For now, we'll document that this requires file system context
                self.sys_log.info(f"{self.name}: Attachment files specified but file system access needed")
                # In a real implementation, this would integrate with the node's file system
            
            # Validate message with attachments
            is_valid, error_msg, smtp_error_code = self._validate_message_with_attachments(email)
            if not is_valid:
                return RequestResponse(status="failure", data={
                    "reason": f"Message validation failed: {error_msg}",
                    "smtp_error_code": smtp_error_code.value if smtp_error_code else None
                })
            
            # Scan attachments if needed
            quarantine_reason = None
            if email.has_attachments and self.attachment_policy.scan_for_malware:
                scan_results = self._scan_attachments(email)
                suspicious_files = [f"{filename} ({result})" for filename, result in scan_results.items() if result != "CLEAN"]
                
                if suspicious_files and self.attachment_policy.quarantine_suspicious:
                    quarantine_reason = f"Suspicious attachments detected: {', '.join(suspicious_files)}"
            
            # Quarantine if needed
            if quarantine_reason:
                quarantine_success = self._quarantine_message(email, quarantine_reason)
                return RequestResponse(status="success" if quarantine_success else "failure", data={
                    "quarantined": quarantine_success,
                    "reason": quarantine_reason,
                    "delivered": 0,
                    "failed": len(recipients),
                    "failed_recipients": recipients if not quarantine_success else []
                })
            
            # Deliver to mailboxes
            delivered = 0
            failed_recipients = []
            for recipient in recipients:
                username = recipient.split("@")[0]  # Simple username extraction
                mailbox = self.mailbox_manager.get_mailbox(username)
                if mailbox:
                    success = mailbox.add_message(email)
                    if success:
                        delivered += 1
                    else:
                        failed_recipients.append(recipient)
                else:
                    failed_recipients.append(recipient)
            
            return RequestResponse(status="success" if delivered > 0 else "failure", data={
                "delivered": delivered,
                "failed": len(failed_recipients),
                "failed_recipients": failed_recipients,
                "has_attachments": email.has_attachments,
                "attachment_count": email.attachment_count,
                "total_size": email.calculate_total_size()
            })
        
        def _get_server_stats_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get SMTP server statistics including attachment information."""
            # Calculate attachment statistics
            total_attachments = 0
            total_attachment_size = 0
            messages_with_attachments = 0
            quarantined_messages = 0
            
            for mailbox in self.mailbox_manager.mailboxes.values():
                for message in mailbox.get_messages():
                    if message.has_attachments:
                        messages_with_attachments += 1
                        total_attachments += message.attachment_count
                        for attachment in message.attachments:
                            total_attachment_size += attachment.file_size
            
            # Count quarantined messages
            quarantine_mailbox = self.mailbox_manager.get_mailbox(self.quarantine_folder)
            if quarantine_mailbox:
                quarantined_messages = len(quarantine_mailbox.get_messages())
            
            stats = {
                "operating_state": self.operating_state.name,
                "health_state": self.health_state_actual.name,
                "active_sessions": len(self.active_sessions),
                "total_mailboxes": len(self.mailbox_manager.mailboxes),
                "total_messages": sum(len(mailbox.get_messages()) for mailbox in self.mailbox_manager.mailboxes.values()),
                "port": self.port,
                "protocol": self.protocol,
                "domain": self.config.domain,
                "max_message_size": self.config.max_message_size,
                "require_auth": self.config.require_auth,
                # Attachment statistics
                "attachment_policy": {
                    "max_attachment_size": self.attachment_policy.max_attachment_size,
                    "max_total_size": self.attachment_policy.max_total_size,
                    "max_attachments": self.attachment_policy.max_attachments,
                    "scan_for_malware": self.attachment_policy.scan_for_malware,
                    "quarantine_suspicious": self.attachment_policy.quarantine_suspicious
                },
                "attachment_stats": {
                    "total_attachments": total_attachments,
                    "total_attachment_size": total_attachment_size,
                    "messages_with_attachments": messages_with_attachments,
                    "quarantined_messages": quarantined_messages
                }
            }
            return RequestResponse(status="success", data=stats)

        def _quarantine_message_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Quarantine a suspicious email message."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            email_index = params.get("email_index")
            reason = params.get("reason", "Manual quarantine")
            requesting_node = params.get("requesting_node", "unknown")
            
            if email_index is None:
                return RequestResponse(status="failure", data={"reason": "email_index parameter required"})
            
            try:
                # Find the email to quarantine - this is a simplified approach
                # In a real implementation, we'd need to identify the specific email
                # For now, we'll create a mock quarantine action
                
                self.sys_log.warning(f"{self.name}: SECURITY ALERT - Quarantine request from {requesting_node}")
                self.sys_log.warning(f"{self.name}: Quarantine reason: {reason}")
                self.sys_log.warning(f"{self.name}: Email index: {email_index}")
                
                # Create quarantine mailbox if it doesn't exist
                quarantine_mailbox = self.mailbox_manager.get_mailbox(self.quarantine_folder)
                if not quarantine_mailbox:
                    self.mailbox_manager.create_mailbox(self.quarantine_folder)
                    quarantine_mailbox = self.mailbox_manager.get_mailbox(self.quarantine_folder)
                
                # Generate security alert
                alert_data = {
                    "alert_type": "email_quarantine",
                    "timestamp": self.sys_log.get_current_time() if hasattr(self.sys_log, 'get_current_time') else "unknown",
                    "requesting_node": requesting_node,
                    "reason": reason,
                    "email_index": email_index,
                    "quarantine_folder": self.quarantine_folder
                }
                
                return RequestResponse(status="success", data={
                    "quarantined": True,
                    "reason": reason,
                    "alert": alert_data,
                    "quarantine_folder": self.quarantine_folder
                })
                
            except Exception as e:
                self.sys_log.error(f"{self.name}: Failed to quarantine message: {str(e)}")
                return RequestResponse(status="failure", data={"reason": f"Quarantine failed: {str(e)}"})

        def _block_sender_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Block emails from a specific sender address with comprehensive error handling."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            sender_address = params.get("sender_address")
            agent_name = params.get("agent_name", "unknown")
            
            if not sender_address:
                return RequestResponse(status="failure", data={"reason": "sender_address parameter required"})
            
            # Validate email format before attempting to add
            import re
            email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            if not email_pattern.match(sender_address.strip()):
                return RequestResponse(status="failure", data={
                    "reason": f"Invalid email address format: {sender_address}",
                    "sender_address": sender_address,
                    "agent": agent_name,
                    "error_type": "validation_error"
                })
            
            try:
                # Add sender to blocklist with validation and rate limiting
                success = self.security_policy.add_blocked_sender(sender_address)
                
                if success:
                    # Log policy change
                    if self.security_policy.enable_logging:
                        self.security_log.log_policy_change(
                            agent_name, 
                            "block_sender", 
                            sender_address,
                            severity="low",
                            additional_data={"server": self.name, "action_type": "add_rule"}
                        )
                    
                    self.sys_log.info(f"{self.name}: Sender blocked by {agent_name}: {sender_address}")
                    
                    return RequestResponse(status="success", data={
                        "action": "block_sender",
                        "sender_address": sender_address,
                        "agent": agent_name,
                        "blocked_senders_count": len(self.security_policy.blocked_senders),
                        "message": f"Sender {sender_address} successfully blocked"
                    })
                else:
                    # Sender already exists
                    return RequestResponse(status="success", data={
                        "action": "block_sender",
                        "sender_address": sender_address,
                        "agent": agent_name,
                        "blocked_senders_count": len(self.security_policy.blocked_senders),
                        "message": f"Sender {sender_address} was already blocked",
                        "already_blocked": True
                    })
            
            except ValueError as e:
                # Handle validation errors and rate limiting
                error_msg = str(e)
                self.sys_log.warning(f"{self.name}: Block sender request failed from {agent_name}: {error_msg}")
                
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "sender_address": sender_address,
                    "agent": agent_name,
                    "error_type": "validation_error" if "format" in error_msg.lower() else "rate_limit_error"
                })
            
            except Exception as e:
                # Handle unexpected errors gracefully
                error_msg = f"Unexpected error blocking sender: {str(e)}"
                self.sys_log.error(f"{self.name}: {error_msg}")
                
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "sender_address": sender_address,
                    "agent": agent_name,
                    "error_type": "internal_error"
                })
        
        def _unblock_sender_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Remove sender from blocklist with comprehensive error handling."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            sender_address = params.get("sender_address")
            agent_name = params.get("agent_name", "unknown")
            
            if not sender_address:
                return RequestResponse(status="failure", data={"reason": "sender_address parameter required"})
            
            try:
                # Remove sender from blocklist with rate limiting
                success = self.security_policy.remove_blocked_sender(sender_address)
                
                if success:
                    # Log policy change
                    if self.security_policy.enable_logging:
                        self.security_log.log_policy_change(
                            agent_name, 
                            "unblock_sender", 
                            sender_address,
                            severity="low",
                            additional_data={"server": self.name, "action_type": "remove_rule"}
                        )
                    
                    self.sys_log.info(f"{self.name}: Sender unblocked by {agent_name}: {sender_address}")
                    
                    return RequestResponse(status="success", data={
                        "action": "unblock_sender",
                        "sender_address": sender_address,
                        "agent": agent_name,
                        "blocked_senders_count": len(self.security_policy.blocked_senders),
                        "message": f"Sender {sender_address} successfully unblocked"
                    })
                else:
                    return RequestResponse(status="failure", data={
                        "reason": f"Sender not found in blocklist: {sender_address}",
                        "sender_address": sender_address,
                        "agent": agent_name,
                        "error_type": "not_found"
                    })
            
            except ValueError as e:
                # Handle validation errors and rate limiting
                error_msg = str(e)
                self.sys_log.warning(f"{self.name}: Unblock sender request failed from {agent_name}: {error_msg}")
                
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "sender_address": sender_address,
                    "agent": agent_name,
                    "error_type": "validation_error" if "format" in error_msg.lower() else "rate_limit_error"
                })
            
            except Exception as e:
                # Handle unexpected errors gracefully
                error_msg = f"Unexpected error unblocking sender: {str(e)}"
                self.sys_log.error(f"{self.name}: {error_msg}")
                
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "sender_address": sender_address,
                    "agent": agent_name,
                    "error_type": "internal_error"
                })
        
        def _block_ip_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Block emails from a specific IP address or CIDR range with comprehensive error handling."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            ip_address = params.get("ip_address")
            agent_name = params.get("agent_name", "unknown")
            
            if not ip_address:
                return RequestResponse(status="failure", data={"reason": "ip_address parameter required"})
            
            # Validate IP format before attempting to add
            try:
                import ipaddress
                if '/' in ip_address:
                    # CIDR notation
                    ipaddress.ip_network(ip_address, strict=False)
                else:
                    # Single IP
                    ipaddress.ip_address(ip_address)
            except (ipaddress.AddressValueError, ValueError):
                return RequestResponse(status="failure", data={
                    "reason": f"Invalid IP format: '{ip_address}' does not appear to be an IPv4 or IPv6 address",
                    "ip_address": ip_address,
                    "agent": agent_name,
                    "error_type": "validation_error"
                })
            
            try:
                # Add IP to blocklist with validation and rate limiting
                success = self.security_policy.add_blocked_ip(ip_address)
                
                if success:
                    # Log policy change
                    if self.security_policy.enable_logging:
                        self.security_log.log_policy_change(
                            agent_name, 
                            "block_ip", 
                            ip_address,
                            severity="low",
                            additional_data={"server": self.name, "action_type": "add_rule"}
                        )
                    
                    self.sys_log.info(f"{self.name}: IP blocked by {agent_name}: {ip_address}")
                    
                    return RequestResponse(status="success", data={
                        "action": "block_ip",
                        "ip_address": ip_address,
                        "agent": agent_name,
                        "blocked_ips_count": len(self.security_policy.blocked_ips),
                        "message": f"IP {ip_address} successfully blocked"
                    })
                else:
                    # IP already exists
                    return RequestResponse(status="success", data={
                        "action": "block_ip",
                        "ip_address": ip_address,
                        "agent": agent_name,
                        "blocked_ips_count": len(self.security_policy.blocked_ips),
                        "message": f"IP {ip_address} was already blocked",
                        "already_blocked": True
                    })
            
            except ValueError as e:
                # Handle validation errors and rate limiting
                error_msg = str(e)
                self.sys_log.warning(f"{self.name}: Block IP request failed from {agent_name}: {error_msg}")
                
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "ip_address": ip_address,
                    "agent": agent_name,
                    "error_type": "validation_error" if "format" in error_msg.lower() else "rate_limit_error"
                })
            
            except Exception as e:
                # Handle unexpected errors gracefully
                error_msg = f"Unexpected error blocking IP: {str(e)}"
                self.sys_log.error(f"{self.name}: {error_msg}")
                
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "ip_address": ip_address,
                    "agent": agent_name,
                    "error_type": "internal_error"
                })
        
        def _unblock_ip_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Remove IP from blocklist with comprehensive error handling."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            ip_address = params.get("ip_address")
            agent_name = params.get("agent_name", "unknown")
            
            if not ip_address:
                return RequestResponse(status="failure", data={"reason": "ip_address parameter required"})
            
            try:
                # Remove IP from blocklist with rate limiting
                success = self.security_policy.remove_blocked_ip(ip_address)
                
                if success:
                    # Log policy change
                    if self.security_policy.enable_logging:
                        self.security_log.log_policy_change(
                            agent_name, 
                            "unblock_ip", 
                            ip_address,
                            severity="low",
                            additional_data={"server": self.name, "action_type": "remove_rule"}
                        )
                    
                    self.sys_log.info(f"{self.name}: IP unblocked by {agent_name}: {ip_address}")
                    
                    return RequestResponse(status="success", data={
                        "action": "unblock_ip",
                        "ip_address": ip_address,
                        "agent": agent_name,
                        "blocked_ips_count": len(self.security_policy.blocked_ips),
                        "message": f"IP {ip_address} successfully unblocked"
                    })
                else:
                    return RequestResponse(status="failure", data={
                        "reason": f"IP not found in blocklist: {ip_address}",
                        "ip_address": ip_address,
                        "agent": agent_name,
                        "error_type": "not_found"
                    })
            
            except ValueError as e:
                # Handle validation errors and rate limiting
                error_msg = str(e)
                self.sys_log.warning(f"{self.name}: Unblock IP request failed from {agent_name}: {error_msg}")
                
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "ip_address": ip_address,
                    "agent": agent_name,
                    "error_type": "validation_error" if "format" in error_msg.lower() else "rate_limit_error"
                })
            
            except Exception as e:
                # Handle unexpected errors gracefully
                error_msg = f"Unexpected error unblocking IP: {str(e)}"
                self.sys_log.error(f"{self.name}: {error_msg}")
                
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "ip_address": ip_address,
                    "agent": agent_name,
                    "error_type": "internal_error"
                })

        def _list_security_policies_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get current security policies and blocklists."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                # Allow empty parameters for this query
                params = {}
            else:
                params = request[-1]
            
            agent_name = params.get("agent_name", "unknown")
            include_details = params.get("include_details", True)
            
            # Get policy summary
            policy_summary = self.security_policy.get_policy_summary()
            
            # Add metadata
            policy_data = {
                "policy_summary": policy_summary,
                "server_domain": self.config.domain,
                "security_logging_enabled": self.security_policy.enable_logging,
                "queried_by": agent_name,
                "query_timestamp": datetime.now().isoformat()
            }
            
            # Add detailed information if requested
            if include_details:
                policy_data["policy_details"] = {
                    "blocked_senders": {
                        "count": len(self.security_policy.blocked_senders),
                        "list": sorted(list(self.security_policy.blocked_senders))
                    },
                    "blocked_ips": {
                        "count": len(self.security_policy.blocked_ips),
                        "list": sorted(list(self.security_policy.blocked_ips))
                    },
                    "configuration": {
                        "default_action": self.security_policy.default_action,
                        "max_log_events": self.security_log.max_events,
                        "current_log_size": len(self.security_log.events)
                    }
                }
            
            self.sys_log.info(f"{self.name}: Security policies queried by {agent_name}")
            
            return RequestResponse(status="success", data=policy_data)

        def _get_security_statistics_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get security event statistics and recent activity."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                # Allow empty parameters for this query
                params = {}
            else:
                params = request[-1]
            
            agent_name = params.get("agent_name", "unknown")
            event_limit = params.get("event_limit", 50)
            time_range_hours = params.get("time_range_hours")  # Optional time filtering
            event_type_filter = params.get("event_type_filter")  # Optional event type filtering
            
            # Get basic statistics
            stats = self.security_log.get_statistics()
            
            # Get recent events with optional filtering using the filtered events method
            recent_events = self.security_log.get_filtered_events(
                event_type=event_type_filter,
                time_range_hours=time_range_hours,
                limit=event_limit
            )
            
            # Convert events to dictionaries for JSON serialization
            events_data = []
            for event in recent_events:
                event_dict = {
                    "timestamp": event.timestamp,
                    "event_type": event.event_type,
                    "reason": event.reason,
                    "severity": event.severity
                }
                
                # Add optional fields if present
                if event.sender:
                    event_dict["sender"] = event.sender
                if event.ip_address:
                    event_dict["ip_address"] = event.ip_address
                if event.agent:
                    event_dict["agent"] = event.agent
                
                events_data.append(event_dict)
            
            # Calculate additional statistics
            unique_blocked_senders = set()
            unique_blocked_ips = set()
            
            for event in self.security_log.events:
                if event.event_type == "blocked_sender" and event.sender:
                    unique_blocked_senders.add(event.sender)
                elif event.event_type in ["blocked_ip", "connection_refused"] and event.ip_address:
                    unique_blocked_ips.add(event.ip_address)
            
            # Compile comprehensive statistics
            statistics_data = {
                "basic_stats": stats,
                "detailed_stats": {
                    "unique_blocked_senders": len(unique_blocked_senders),
                    "unique_blocked_ips": len(unique_blocked_ips),
                    "active_sender_blocks": len(self.security_policy.blocked_senders),
                    "active_ip_blocks": len(self.security_policy.blocked_ips),
                    "events_returned": len(events_data),
                    "total_events_in_log": len(self.security_log.events)
                },
                "recent_events": events_data,
                "query_info": {
                    "queried_by": agent_name,
                    "query_timestamp": datetime.now().isoformat(),
                    "event_limit": event_limit,
                    "time_range_hours": time_range_hours,
                    "event_type_filter": event_type_filter
                }
            }
            
            self.sys_log.info(f"{self.name}: Security statistics queried by {agent_name} - returned {len(events_data)} events")
            
            return RequestResponse(status="success", data=statistics_data)

        rm.add_request("create_mailbox", RequestType(func=_create_mailbox_request))
        rm.add_request("delete_mailbox", RequestType(func=_delete_mailbox_request))
        rm.add_request("list_mailboxes", RequestType(func=_list_mailboxes_request))
        rm.add_request("get_mailbox_messages", RequestType(func=_get_mailbox_messages_request))
        rm.add_request("send_message", RequestType(func=_send_message_request))
        rm.add_request("get_server_stats", RequestType(func=_get_server_stats_request))
        rm.add_request("quarantine_message", RequestType(func=_quarantine_message_request))
        # Security policy management request handlers
        rm.add_request("block_sender", RequestType(func=_block_sender_request))
        rm.add_request("unblock_sender", RequestType(func=_unblock_sender_request))
        rm.add_request("block_ip", RequestType(func=_block_ip_request))
        rm.add_request("unblock_ip", RequestType(func=_unblock_ip_request))
        # Security policy query and statistics handlers
        rm.add_request("list_security_policies", RequestType(func=_list_security_policies_request))
        rm.add_request("get_security_statistics", RequestType(func=_get_security_statistics_request))
        
        # Performance monitoring and bulk operations handlers
        def _get_performance_stats_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get performance statistics for security policy operations."""
            try:
                stats = self.security_policy.get_performance_stats()
                rate_limit_status = self.security_policy.get_rate_limit_status()
                
                performance_data = {
                    "policy_performance": stats,
                    "rate_limiting": rate_limit_status,
                    "server_info": {
                        "domain": self.config.domain,
                        "max_message_size": self.config.max_message_size,
                        "security_logging_enabled": self.config.enable_security_logging
                    },
                    "timestamp": datetime.now().isoformat()
                }
                
                return RequestResponse(status="success", data=performance_data)
            
            except Exception as e:
                error_msg = f"Failed to get performance statistics: {str(e)}"
                self.sys_log.error(f"{self.name}: {error_msg}")
                return RequestResponse(status="failure", data={"reason": error_msg})
        
        def _bulk_block_senders_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Block multiple senders in a single operation."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            senders = params.get("senders", [])
            agent_name = params.get("agent_name", "unknown")
            skip_invalid = params.get("skip_invalid", True)
            
            if not isinstance(senders, list) or not senders:
                return RequestResponse(status="failure", data={"reason": "senders parameter must be a non-empty list"})
            
            try:
                result = self.security_policy.bulk_add_blocked_senders(senders, skip_invalid=skip_invalid)
                
                # Log bulk operation
                if self.security_policy.enable_logging and result["added"] > 0:
                    self.security_log.log_policy_change(
                        agent_name,
                        "bulk_block_senders",
                        f"{result['added']} senders",
                        severity="low",
                        additional_data={
                            "server": self.name,
                            "action_type": "bulk_add_rules",
                            "total_attempted": len(senders),
                            "added": result["added"],
                            "skipped_invalid": result["skipped_invalid"],
                            "skipped_existing": result["skipped_existing"]
                        }
                    )
                
                self.sys_log.info(f"{self.name}: Bulk sender blocking by {agent_name}: {result['added']}/{len(senders)} added")
                
                return RequestResponse(status="success", data={
                    "action": "bulk_block_senders",
                    "agent": agent_name,
                    "results": result,
                    "blocked_senders_count": len(self.security_policy.blocked_senders)
                })
            
            except ValueError as e:
                error_msg = str(e)
                self.sys_log.warning(f"{self.name}: Bulk block senders failed from {agent_name}: {error_msg}")
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "agent": agent_name,
                    "error_type": "validation_error" if "format" in error_msg.lower() else "rate_limit_error"
                })
            
            except Exception as e:
                error_msg = f"Unexpected error in bulk sender blocking: {str(e)}"
                self.sys_log.error(f"{self.name}: {error_msg}")
                return RequestResponse(status="failure", data={
                    "reason": error_msg,
                    "agent": agent_name,
                    "error_type": "internal_error"
                })
        
        def _validate_policy_integrity_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Validate the integrity of security policy data."""
            try:
                integrity_report = self.security_policy.validate_policy_integrity()
                
                return RequestResponse(status="success", data={
                    "action": "validate_policy_integrity",
                    "integrity_report": integrity_report,
                    "timestamp": datetime.now().isoformat()
                })
            
            except Exception as e:
                error_msg = f"Failed to validate policy integrity: {str(e)}"
                self.sys_log.error(f"{self.name}: {error_msg}")
                return RequestResponse(status="failure", data={"reason": error_msg})
        
        # Register the new handlers
        rm.add_request("get_performance_stats", RequestType(func=_get_performance_stats_request))
        rm.add_request("bulk_block_senders", RequestType(func=_bulk_block_senders_request))
        rm.add_request("validate_policy_integrity", RequestType(func=_validate_policy_integrity_request))
        
        return rm

    def _check_security_policies(self, sender: str, client_ip: str) -> tuple:
        """
        Check if email should be blocked by security policies.
        
        :param sender: Email sender address
        :param client_ip: Client IP address
        :return: Tuple of (is_allowed, reason_if_blocked)
        """
        # Check sender blocking
        if sender and self.security_policy.is_sender_blocked(sender):
            reason = f"Sender address blocked: {sender}"
            if self.security_policy.enable_logging:
                self.security_log.log_blocked_email(
                    sender, 
                    client_ip, 
                    reason,
                    severity="medium",
                    additional_data={"server": self.name, "check_type": "sender_policy"}
                )
            self.sys_log.warning(f"{self.name}: SECURITY BLOCK - {reason} from IP {client_ip}")
            return False, reason
        
        # Check IP blocking
        if client_ip and self.security_policy.is_ip_blocked(client_ip):
            reason = f"IP address blocked: {client_ip}"
            if self.security_policy.enable_logging:
                self.security_log.log_blocked_ip(
                    client_ip, 
                    reason,
                    severity="medium",
                    additional_data={"server": self.name, "check_type": "ip_policy"}
                )
            self.sys_log.warning(f"{self.name}: SECURITY BLOCK - {reason}")
            return False, reason
        
        return True, ""

    def _enforce_ip_blocking(self, client_ip: str) -> bool:
        """
        Check and enforce IP-based blocking at connection level.
        
        :param client_ip: Client IP address
        :return: True if connection should be allowed, False if blocked
        """
        if not client_ip:
            return True  # Allow if no IP provided
        
        if self.security_policy.is_ip_blocked(client_ip):
            reason = f"Connection refused - IP blocked: {client_ip}"
            if self.security_policy.enable_logging:
                # Use the enhanced connection_refused logging method
                self.security_log.log_connection_refused(
                    client_ip, 
                    reason, 
                    severity="high",
                    additional_data={"connection_type": "smtp", "server": self.name}
                )
            self.sys_log.warning(f"{self.name}: SECURITY BLOCK - {reason}")
            return False
        
        return True

    def _enforce_sender_blocking(self, sender: str, client_ip: str) -> bool:
        """
        Check and enforce sender-based blocking during MAIL FROM.
        
        :param sender: Email sender address
        :param client_ip: Client IP address
        :return: True if sender should be allowed, False if blocked
        """
        if not sender:
            return True  # Allow if no sender provided
        
        if self.security_policy.is_sender_blocked(sender):
            reason = f"Sender blocked: {sender}"
            if self.security_policy.enable_logging:
                self.security_log.log_blocked_email(
                    sender, 
                    client_ip, 
                    reason,
                    severity="medium",
                    additional_data={"server": self.name, "smtp_command": "MAIL_FROM"}
                )
            self.sys_log.warning(f"{self.name}: SECURITY BLOCK - {reason} from IP {client_ip}")
            return False
        
        return True

    def _log_security_rejection(self, rejection_type: str, sender: Optional[str], client_ip: str, smtp_error_code: Optional[SMTPStatusCode]) -> None:
        """
        Log security rejection events with SMTP error code information.
        
        :param rejection_type: Type of rejection ("sender", "ip", "connection")
        :param sender: Email sender address (if applicable)
        :param client_ip: Client IP address
        :param smtp_error_code: SMTP error code used for rejection
        """
        try:
            if rejection_type == "sender" and sender:
                reason = f"Sender blocked: {sender} (SMTP {smtp_error_code.value if smtp_error_code else 'N/A'})"
                if self.security_policy.enable_logging:
                    self.security_log.log_blocked_email(sender, client_ip, reason)
                self.sys_log.warning(f"{self.name}: SECURITY REJECTION - {reason} from IP {client_ip}")
                
            elif rejection_type == "ip":
                reason = f"IP blocked: {client_ip} (Connection refused)"
                if self.security_policy.enable_logging:
                    self.security_log.log_blocked_ip(client_ip, reason)
                self.sys_log.warning(f"{self.name}: SECURITY REJECTION - {reason}")
                
            else:
                # Generic rejection logging
                reason = f"Security policy violation: {rejection_type}"
                self.sys_log.warning(f"{self.name}: SECURITY REJECTION - {reason} from IP {client_ip}")
                
        except Exception as e:
            self.sys_log.error(f"{self.name}: Error logging security rejection: {str(e)}")

    def _process_smtp_command(self, packet: SMTPPacket, session_id: Optional[str] = None, client_ip: str = "unknown") -> SMTPPacket:
        """Process SMTP commands and generate appropriate responses."""
        if not self._can_perform_action():
            self.sys_log.error(f"{self.name}: Cannot process command - service not operational")
            return SMTPPacket(
                status_code=SMTPStatusCode.SERVICE_NOT_AVAILABLE,
                message="Service temporarily unavailable"
            )

        self.sys_log.info(f"{self.name}: Received SMTP {packet.command.name if packet.command else 'UNKNOWN'} from session {session_id}")

        # Initialize session if needed
        if session_id and session_id not in self.active_sessions:
            self.sys_log.debug(f"{self.name}: Initializing new session {session_id}")
            self.active_sessions[session_id] = {
                "state": "connected",
                "sender": None,
                "recipients": [],
                "data": None,
                "client_ip": client_ip
            }

        session = self.active_sessions.get(session_id, {})
        # Update client IP in session
        session["client_ip"] = client_ip

        if packet.command == SMTPCommand.HELO or packet.command == SMTPCommand.EHLO:
            return self._handle_helo(packet, session)
        elif packet.command == SMTPCommand.MAIL:
            return self._handle_mail_from(packet, session, client_ip)
        elif packet.command == SMTPCommand.RCPT:
            return self._handle_rcpt_to(packet, session)
        elif packet.command == SMTPCommand.DATA:
            return self._handle_data(packet, session, client_ip)
        elif packet.command == SMTPCommand.QUIT:
            return self._handle_quit(packet, session_id)
        elif packet.command == SMTPCommand.RSET:
            return self._handle_reset(packet, session)
        elif packet.command == SMTPCommand.NOOP:
            return SMTPPacket(status_code=SMTPStatusCode.OK_COMPLETED, message="OK")
        else:
            return SMTPPacket(
                status_code=SMTPStatusCode.COMMAND_NOT_IMPLEMENTED,
                message="Command not implemented"
            )

    def _handle_helo(self, packet: SMTPPacket, session: Dict) -> SMTPPacket:
        """Handle HELO/EHLO command."""
        self.sys_log.info(f"{self.name}: Processing HELO from {packet.arguments or 'unknown client'}")
        session["state"] = "greeted"
        response = SMTPPacket(
            status_code=SMTPStatusCode.OK_COMPLETED,
            message=f"Hello {packet.arguments or 'client'}, pleased to meet you"
        )
        self.sys_log.debug(f"{self.name}: HELO successful, session state: {session['state']}")
        return response

    def _handle_mail_from(self, packet: SMTPPacket, session: Dict, client_ip: str = "unknown") -> SMTPPacket:
        """Handle MAIL FROM command with security policy enforcement."""
        if session.get("state") != "greeted":
            self.sys_log.warning(f"{self.name}: MAIL FROM received without HELO, current state: {session.get('state')}")
            return SMTPPacket(
                status_code=SMTPStatusCode.BAD_SEQUENCE,
                message="Send HELO/EHLO first"
            )
        
        # Extract sender from arguments (MAIL FROM:<sender@domain>)
        if packet.arguments and "FROM:" in packet.arguments.upper():
            sender = packet.arguments.split(":", 1)[1].strip().strip("<>")
            
            # Check sender blocking policy with proper SMTP error code
            if not self._enforce_sender_blocking(sender, client_ip):
                # Log security rejection with proper SMTP error code
                self._log_security_rejection("sender", sender, client_ip, SMTPStatusCode.MAILBOX_UNAVAILABLE)
                return SMTPPacket(
                    status_code=SMTPStatusCode.MAILBOX_UNAVAILABLE,
                    message="Requested action not taken: mailbox unavailable"
                )
            
            session["sender"] = sender
            session["state"] = "mail"
            self.sys_log.info(f"{self.name}: MAIL FROM accepted for sender: {sender}")
            return SMTPPacket(status_code=SMTPStatusCode.OK_COMPLETED, message="Sender OK")
        
        self.sys_log.error(f"{self.name}: Invalid MAIL FROM syntax: {packet.arguments}")
        return SMTPPacket(status_code=SMTPStatusCode.SYNTAX_ERROR, message="Syntax error in MAIL command")

    def _handle_rcpt_to(self, packet: SMTPPacket, session: Dict) -> SMTPPacket:
        """Handle RCPT TO command."""
        if session.get("state") not in ["mail", "rcpt"]:
            return SMTPPacket(
                status_code=SMTPStatusCode.BAD_SEQUENCE,
                message="Send MAIL FROM first"
            )
        
        # Extract recipient from arguments (RCPT TO:<recipient@domain>)
        if packet.arguments and "TO:" in packet.arguments.upper():
            recipient = packet.arguments.split(":", 1)[1].strip().strip("<>")
            session["recipients"].append(recipient)
            session["state"] = "rcpt"
            return SMTPPacket(status_code=SMTPStatusCode.OK_COMPLETED, message="Recipient OK")
        
        return SMTPPacket(status_code=SMTPStatusCode.SYNTAX_ERROR, message="Syntax error in RCPT command")

    def _handle_data(self, packet: SMTPPacket, session: Dict, client_ip: str = "unknown") -> SMTPPacket:
        """Handle DATA command with attachment validation."""
        if session.get("state") != "rcpt":
            self.sys_log.warning(f"{self.name}: DATA received without RCPT TO, current state: {session.get('state')}")
            return SMTPPacket(
                status_code=SMTPStatusCode.BAD_SEQUENCE,
                message="Send RCPT TO first"
            )
        
        if packet.email_data:
            # Process the email data
            email = packet.email_data
            email.sender = session["sender"]
            email.recipients = session["recipients"]
            
            self.sys_log.info(f"{self.name}: Processing email data - Subject: '{email.subject}', Recipients: {email.recipients}")
            
            # Check security policies for the complete email
            is_allowed, block_reason = self._check_security_policies(email.sender, client_ip)
            if not is_allowed:
                # Log security rejection with proper SMTP error code
                if "sender" in block_reason.lower():
                    self._log_security_rejection("sender", email.sender, client_ip, SMTPStatusCode.MAILBOX_UNAVAILABLE)
                elif "ip" in block_reason.lower():
                    self._log_security_rejection("ip", email.sender, client_ip, SMTPStatusCode.MAILBOX_UNAVAILABLE)
                
                return SMTPPacket(
                    status_code=SMTPStatusCode.MAILBOX_UNAVAILABLE,
                    message="Requested action not taken: mailbox unavailable"
                )
            
            # Validate message with attachments
            is_valid, error_msg, smtp_error_code = self._validate_message_with_attachments(email)
            if not is_valid:
                self.sys_log.error(f"{self.name}: Message validation failed: {error_msg}")
                return SMTPPacket(
                    status_code=smtp_error_code,
                    message=error_msg
                )
            
            # Scan attachments for malware if policy requires it
            should_quarantine = False
            quarantine_reason = None
            
            if email.has_attachments and self.attachment_policy.scan_for_malware:
                scan_results = self._scan_attachments(email)
                
                # Check for suspicious attachments
                suspicious_files = []
                for filename, result in scan_results.items():
                    if result != "CLEAN":
                        suspicious_files.append(f"{filename} ({result})")
                
                if suspicious_files and self.attachment_policy.quarantine_suspicious:
                    should_quarantine = True
                    quarantine_reason = f"Suspicious attachments detected: {', '.join(suspicious_files)}"
            
            # Quarantine message if needed
            if should_quarantine:
                quarantine_success = self._quarantine_message(email, quarantine_reason)
                if quarantine_success:
                    # Reset session and return success (message was "delivered" to quarantine)
                    session["state"] = "greeted"
                    session["recipients"] = []
                    return SMTPPacket(
                        status_code=SMTPStatusCode.OK_COMPLETED,
                        message="Message accepted and processed"
                    )
                else:
                    # Quarantine failed, reject message
                    return SMTPPacket(
                        status_code=SMTPStatusCode.LOCAL_ERROR,
                        message="Message processing failed"
                    )
            
            # Apply attachment headers to email
            if email.has_attachments:
                packet.apply_attachment_headers()
                self.sys_log.debug(f"{self.name}: Applied attachment headers to email")
            
            # Deliver email to recipients' mailboxes
            delivered = 0
            failed_recipients = []
            for recipient in email.recipients:
                username = recipient.split("@")[0]  # Simple username extraction
                mailbox = self.mailbox_manager.get_mailbox(username)
                if mailbox:
                    success = mailbox.add_message(email)
                    if success:
                        delivered += 1
                        self.sys_log.info(f"{self.name}: Email delivered to {recipient}")
                    else:
                        failed_recipients.append(recipient)
                        self.sys_log.error(f"{self.name}: Failed to deliver email to {recipient}")
                else:
                    failed_recipients.append(recipient)
                    self.sys_log.warning(f"{self.name}: Mailbox not found for {recipient}")
            
            if delivered > 0:
                session["state"] = "greeted"  # Reset for next message
                session["recipients"] = []
                self.sys_log.info(f"{self.name}: Email delivery completed - {delivered} successful, {len(failed_recipients)} failed")
                return SMTPPacket(
                    status_code=SMTPStatusCode.OK_COMPLETED,
                    message=f"Message accepted for delivery to {delivered} recipients"
                )
            else:
                self.sys_log.error(f"{self.name}: Email delivery failed for all recipients: {failed_recipients}")
                return SMTPPacket(
                    status_code=SMTPStatusCode.MAILBOX_UNAVAILABLE,
                    message="No valid recipients"
                )
        else:
            # Start data input mode
            session["state"] = "data"
            self.sys_log.debug(f"{self.name}: Entering data input mode")
            return SMTPPacket(
                status_code=SMTPStatusCode.START_MAIL_INPUT,
                message="Start mail input; end with <CRLF>.<CRLF>"
            )

    def _handle_quit(self, packet: SMTPPacket, session_id: Optional[str]) -> SMTPPacket:
        """Handle QUIT command."""
        if session_id and session_id in self.active_sessions:
            del self.active_sessions[session_id]
        return SMTPPacket(
            status_code=SMTPStatusCode.CLOSING,
            message="Service closing transmission channel"
        )

    def _handle_reset(self, packet: SMTPPacket, session: Dict) -> SMTPPacket:
        """Handle RSET command."""
        session["sender"] = None
        session["recipients"] = []
        session["state"] = "greeted"
        return SMTPPacket(status_code=SMTPStatusCode.OK_COMPLETED, message="Reset state")

    def _validate_message_with_attachments(self, email: EmailMessage) -> tuple:
        """
        Validate an email message with attachments against the server's attachment policy.
        
        :param email: The email message to validate.
        :return: Tuple of (is_valid, error_message, smtp_error_code).
        """
        try:
            # Check if email has attachments
            if not email.has_attachments:
                self.sys_log.debug(f"{self.name}: Email has no attachments, validation passed")
                return True, None, None
            
            self.sys_log.info(f"{self.name}: Validating email with {email.attachment_count} attachments")
            
            # Validate message size including attachments
            total_size = email.calculate_total_size()
            if total_size > self.config.max_message_size:
                error_msg = f"Message size ({total_size} bytes) exceeds server limit ({self.config.max_message_size} bytes)"
                self.sys_log.warning(f"{self.name}: {error_msg}")
                return False, error_msg, SMTPStatusCode.EXCEEDED_STORAGE
            
            # Validate attachments against policy
            is_valid, policy_error = self.attachment_manager.validate_message_attachments(
                email.attachments, self.attachment_policy
            )
            
            if not is_valid:
                self.sys_log.warning(f"{self.name}: Attachment policy validation failed: {policy_error}")
                
                # Log policy violation for security monitoring
                for attachment in email.attachments:
                    self.attachment_manager.log_policy_violation(
                        attachment=attachment,
                        policy=self.attachment_policy,
                        violation_reason=policy_error,
                        sender=email.sender,
                        recipients=email.recipients
                    )
                
                # Determine appropriate SMTP error code based on violation type
                if "size" in policy_error.lower():
                    return False, policy_error, SMTPStatusCode.EXCEEDED_STORAGE
                elif "extension" in policy_error.lower() or "malware" in policy_error.lower():
                    return False, policy_error, SMTPStatusCode.TRANSACTION_FAILED
                else:
                    return False, policy_error, SMTPStatusCode.TRANSACTION_FAILED
            
            self.sys_log.info(f"{self.name}: Email attachment validation passed")
            return True, None, None
            
        except Exception as e:
            error_msg = f"Error validating message attachments: {str(e)}"
            self.sys_log.error(f"{self.name}: {error_msg}")
            return False, error_msg, SMTPStatusCode.LOCAL_ERROR

    def _scan_attachments(self, email: EmailMessage) -> Dict[str, str]:
        """
        Scan email attachments for suspicious content and malware.
        
        :param email: The email message to scan.
        :return: Dictionary mapping filename to scan result.
        """
        try:
            if not email.has_attachments:
                self.sys_log.debug(f"{self.name}: No attachments to scan")
                return {}
            
            self.sys_log.info(f"{self.name}: Scanning {email.attachment_count} attachments for malware")
            
            # Use AttachmentManager to scan for malware
            scan_results = self.attachment_manager.scan_for_malware(email.attachments)
            
            # Log scan results
            for filename, result in scan_results.items():
                if result == "CLEAN":
                    self.sys_log.debug(f"{self.name}: Attachment '{filename}' scanned clean")
                else:
                    self.sys_log.warning(f"{self.name}: Suspicious attachment detected: '{filename}' - {result}")
            
            return scan_results
            
        except Exception as e:
            self.sys_log.error(f"{self.name}: Error scanning attachments: {str(e)}")
            # Return error status for all attachments
            return {att.filename: "SCAN_ERROR" for att in email.attachments}

    def _quarantine_message(self, email: EmailMessage, reason: str) -> bool:
        """
        Quarantine a suspicious email message.
        
        :param email: The email message to quarantine.
        :param reason: Reason for quarantine.
        :return: True if quarantine was successful, False otherwise.
        """
        try:
            self.sys_log.warning(f"{self.name}: SECURITY ALERT - Quarantining message from {email.sender}")
            self.sys_log.warning(f"{self.name}: Quarantine reason: {reason}")
            self.sys_log.warning(f"{self.name}: Subject: '{email.subject}'")
            self.sys_log.warning(f"{self.name}: Recipients: {', '.join(email.recipients)}")
            
            # Create quarantine mailbox if it doesn't exist
            quarantine_mailbox = self.mailbox_manager.get_mailbox(self.quarantine_folder)
            if not quarantine_mailbox:
                success = self.mailbox_manager.create_mailbox(self.quarantine_folder)
                if not success:
                    self.sys_log.error(f"{self.name}: Failed to create quarantine mailbox")
                    return False
                quarantine_mailbox = self.mailbox_manager.get_mailbox(self.quarantine_folder)
            
            # Add quarantine metadata to email headers
            if not email.headers:
                email.headers = {}
            
            email.headers["X-Quarantine-Reason"] = reason
            email.headers["X-Quarantine-Timestamp"] = str(self.sys_log.get_current_time())
            email.headers["X-Quarantine-Server"] = self.sys_log.hostname
            email.headers["X-Original-Recipients"] = ", ".join(email.recipients)
            
            # Store in quarantine mailbox
            success = quarantine_mailbox.add_message(email)
            if success:
                self.sys_log.info(f"{self.name}: Message successfully quarantined")
                
                # Log security event for monitoring
                self._log_security_event("MESSAGE_QUARANTINED", {
                    "sender": email.sender,
                    "recipients": email.recipients,
                    "subject": email.subject,
                    "reason": reason,
                    "attachment_count": email.attachment_count,
                    "message_size": email.calculate_total_size()
                })
                
                return True
            else:
                self.sys_log.error(f"{self.name}: Failed to add message to quarantine mailbox")
                return False
                
        except Exception as e:
            self.sys_log.error(f"{self.name}: Error quarantining message: {str(e)}")
            return False

    def _log_security_event(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """
        Log security events for monitoring and alerting.
        
        :param event_type: Type of security event.
        :param event_data: Additional event data.
        """
        try:
            # Create comprehensive security log entry
            security_log = {
                "timestamp": str(self.sys_log.get_current_time()),
                "server": self.sys_log.hostname,
                "service": self.name,
                "event_type": event_type,
                "severity": "HIGH" if "QUARANTINE" in event_type or "MALWARE" in event_type else "MEDIUM",
                **event_data
            }
            
            # Log as security alert
            self.sys_log.warning(f"SECURITY EVENT: {event_type}")
            for key, value in security_log.items():
                self.sys_log.warning(f"  {key}: {value}")
            
            # In a real implementation, this could also:
            # - Send alerts to SIEM systems
            # - Trigger automated incident response
            # - Update threat intelligence feeds
            # - Notify security administrators
            
        except Exception as e:
            self.sys_log.error(f"{self.name}: Error logging security event: {str(e)}")

    def receive(self, payload: Any, session_id: Optional[str] = None, **kwargs) -> bool:
        """Receive and process SMTP packets with security policy enforcement."""
        if not isinstance(payload, SMTPPacket):
            self.sys_log.warning(f"{self.name}: Payload is not an SMTP packet")
            return False

        # Extract client IP from kwargs for security checking
        client_ip = kwargs.get("client_ip", kwargs.get("source_ip", "unknown"))
        
        # Enforce IP-level blocking at connection level
        if not self._enforce_ip_blocking(client_ip):
            # Connection refused - log security event and don't process the packet
            self._log_security_rejection("ip", None, client_ip, None)
            self.sys_log.warning(f"{self.name}: Connection refused from blocked IP: {client_ip}")
            return False

        if not super().receive(payload=payload, session_id=session_id, **kwargs):
            return False

        response = self._process_smtp_command(payload, session_id, client_ip=client_ip)
        
        if response:
            return self.send(payload=response, session_id=session_id)
        
        return True

    def show(self, markdown: bool = False):
        """Display SMTP server status and mailbox information in tabular format."""
        from prettytable import PrettyTable, MARKDOWN
        
        # Server status table
        status_table = PrettyTable(["Property", "Value"])
        if markdown:
            status_table.set_style(MARKDOWN)
        status_table.align = "l"
        hostname = getattr(self.sys_log, 'hostname', 'localhost') if hasattr(self, 'sys_log') else 'localhost'
        status_table.title = f"SMTP Server Status ({hostname})"
        
        status_table.add_row(["Service Name", self.name])
        status_table.add_row(["Operating State", self.operating_state.name])
        status_table.add_row(["Health State", self.health_state_actual.name])
        status_table.add_row(["Port", self.port])
        status_table.add_row(["Protocol", self.protocol])
        status_table.add_row(["Active Sessions", len(self.active_sessions)])
        status_table.add_row(["Total Mailboxes", len(self.mailbox_manager.mailboxes)])
        
        # Add attachment policy information
        status_table.add_row(["Max Attachment Size", f"{self.attachment_policy.max_attachment_size // (1024*1024)} MB"])
        status_table.add_row(["Max Total Size", f"{self.attachment_policy.max_total_size // (1024*1024)} MB"])
        status_table.add_row(["Malware Scanning", "Enabled" if self.attachment_policy.scan_for_malware else "Disabled"])
        status_table.add_row(["Quarantine Suspicious", "Enabled" if self.attachment_policy.quarantine_suspicious else "Disabled"])
        
        # Add security policy status
        status_table.add_row(["Security Logging", "Enabled" if self.security_policy.enable_logging else "Disabled"])
        status_table.add_row(["Blocked Senders", len(self.security_policy.blocked_senders)])
        status_table.add_row(["Blocked IPs", len(self.security_policy.blocked_ips)])
        status_table.add_row(["Security Events", len(self.security_log.events)])
        
        print(status_table)
        
        # Mailbox contents table with attachment information
        if self.mailbox_manager.mailboxes:
            mailbox_table = PrettyTable(["Username", "Total Messages", "INBOX", "Sent", "Drafts", "Trash", "Attachments"])
            if markdown:
                mailbox_table.set_style(MARKDOWN)
            mailbox_table.align = "l"
            hostname = getattr(self.sys_log, 'hostname', 'localhost') if hasattr(self, 'sys_log') else 'localhost'
            mailbox_table.title = f"Mailbox Summary ({hostname})"
            
            for username, mailbox in self.mailbox_manager.mailboxes.items():
                inbox_count = len(mailbox.folders.get("INBOX").messages) if "INBOX" in mailbox.folders else 0
                sent_count = len(mailbox.folders.get("Sent").messages) if "Sent" in mailbox.folders else 0
                drafts_count = len(mailbox.folders.get("Drafts").messages) if "Drafts" in mailbox.folders else 0
                trash_count = len(mailbox.folders.get("Trash").messages) if "Trash" in mailbox.folders else 0
                total_messages = len(mailbox.get_messages())
                
                # Count attachments
                total_attachments = sum(msg.attachment_count for msg in mailbox.get_messages())
                
                mailbox_table.add_row([
                    username,
                    total_messages,
                    inbox_count,
                    sent_count,
                    drafts_count,
                    trash_count,
                    total_attachments
                ])
            
            print(mailbox_table)
        
        # Active sessions table
        if self.active_sessions:
            session_table = PrettyTable(["Session ID", "State", "Sender", "Recipients", "Data"])
            if markdown:
                session_table.set_style(MARKDOWN)
            session_table.align = "l"
            hostname = getattr(self.sys_log, 'hostname', 'localhost') if hasattr(self, 'sys_log') else 'localhost'
            session_table.title = f"Active SMTP Sessions ({hostname})"
            
            for session_id, session_data in self.active_sessions.items():
                recipients_str = ", ".join(session_data.get("recipients", []))
                session_table.add_row([
                    session_id[:8] + "..." if len(session_id) > 8 else session_id,
                    session_data.get("state", "unknown"),
                    session_data.get("sender", "none"),
                    recipients_str[:30] + "..." if len(recipients_str) > 30 else recipients_str,
                    "present" if session_data.get("data") else "none"
                ])
            
            print(session_table)

    def show_mailbox(self, username: str = None, markdown: bool = False):
        """Display mailbox contents for a specific user or all users in tabular format."""
        from prettytable import PrettyTable, MARKDOWN
        
        if username:
            # Show specific user's mailbox
            mailbox = self.mailbox_manager.get_mailbox(username)
            if not mailbox:
                print(f"Mailbox for user '{username}' not found")
                return
            
            messages = mailbox.get_messages()
            if not messages:
                print(f"{username}'s mailbox is empty")
                return
            
            msg_table = PrettyTable(["#", "From", "To", "Subject", "Timestamp", "Attachments", "Size"])
            if markdown:
                msg_table.set_style(MARKDOWN)
            msg_table.align = "l"
            msg_table.title = f"{username}'s Mailbox Contents ({len(messages)} messages)"
            
            for i, msg in enumerate(messages, 1):
                # Format attachment info
                attachment_info = f"{msg.attachment_count}" if msg.has_attachments else "0"
                
                # Format size
                size_bytes = msg.calculate_total_size()
                if size_bytes > 1024 * 1024:
                    size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
                elif size_bytes > 1024:
                    size_str = f"{size_bytes / 1024:.1f} KB"
                else:
                    size_str = f"{size_bytes} B"
                
                msg_table.add_row([
                    i,
                    msg.sender[:25] + "..." if len(msg.sender) > 25 else msg.sender,
                    ", ".join(msg.recipients)[:25] + "..." if len(", ".join(msg.recipients)) > 25 else ", ".join(msg.recipients),
                    msg.subject[:35] + "..." if len(msg.subject) > 35 else msg.subject,
                    msg.timestamp[:19] if msg.timestamp else "N/A",
                    attachment_info,
                    size_str
                ])
            
            print(msg_table)
        else:
            # Show all mailboxes
            if not self.mailbox_manager.mailboxes:
                print("No mailboxes found")
                return
            
            for username, mailbox in self.mailbox_manager.mailboxes.items():
                messages = mailbox.get_messages()
                if messages:
                    print(f"\n{'='*60}")
                    self.show_mailbox(username, markdown)

    def show_message(self, username: str, message_number: int, markdown: bool = False):
        """Display detailed content of a specific message in tabular format."""
        from prettytable import PrettyTable, MARKDOWN
        
        mailbox = self.mailbox_manager.get_mailbox(username)
        if not mailbox:
            print(f"Mailbox for user '{username}' not found")
            return
        
        messages = mailbox.get_messages()
        if message_number < 1 or message_number > len(messages):
            print(f"Message {message_number} not found. Valid range: 1-{len(messages)}")
            return
        
        msg = messages[message_number - 1]
        
        # Message details table
        details_table = PrettyTable(["Field", "Value"])
        if markdown:
            details_table.set_style(MARKDOWN)
        details_table.align = "l"
        details_table.title = f"Message {message_number} Details ({username}'s mailbox)"
        
        details_table.add_row(["Message ID", msg.message_id or "N/A"])
        details_table.add_row(["From", msg.sender])
        details_table.add_row(["To", ", ".join(msg.recipients)])
        details_table.add_row(["Subject", msg.subject])
        details_table.add_row(["Timestamp", msg.timestamp or "N/A"])
        details_table.add_row(["Body Length", f"{len(msg.body)} characters"])
        details_table.add_row(["Has Attachments", "Yes" if msg.has_attachments else "No"])
        details_table.add_row(["Attachment Count", str(msg.attachment_count)])
        details_table.add_row(["Total Size", f"{msg.calculate_total_size()} bytes"])
        
        print(details_table)
        
        # Show attachment details if present
        if msg.has_attachments:
            att_table = PrettyTable(["Filename", "Type", "Size", "Health"])
            if markdown:
                att_table.set_style(MARKDOWN)
            att_table.align = "l"
            att_table.title = f"Attachments ({msg.attachment_count})"
            
            for att in msg.attachments:
                att_table.add_row([
                    att.filename,
                    att.content_type,
                    f"{att.file_size} bytes",
                    att.health_status
                ])
            
            print(att_table)
        
        # Message body table
        body_table = PrettyTable(["Message Body"])
        if markdown:
            body_table.set_style(MARKDOWN)
        body_table.align = "l"
        body_table.title = f"Message {message_number} Content"
        
        # Split body into lines for better display
        body_lines = msg.body.split('\n')
        for line in body_lines:
            # Wrap long lines
            if len(line) > 80:
                while line:
                    body_table.add_row([line[:80]])
                    line = line[80:]
            else:
                body_table.add_row([line])
        
        print(body_table)

    def show_security_policies(self, markdown: bool = False):
        """Display detailed security policy information in tabular format."""
        from prettytable import PrettyTable, MARKDOWN
        
        # Security policy overview table
        policy_table = PrettyTable(["Policy Setting", "Value"])
        if markdown:
            policy_table.set_style(MARKDOWN)
        policy_table.align = "l"
        hostname = getattr(self.sys_log, 'hostname', 'localhost') if hasattr(self, 'sys_log') else 'localhost'
        policy_table.title = f"Security Policy Configuration ({hostname})"
        
        policy_table.add_row(["Security Logging", "Enabled" if self.security_policy.enable_logging else "Disabled"])
        policy_table.add_row(["Default Action", self.security_policy.default_action.title()])
        policy_table.add_row(["Total Blocked Senders", len(self.security_policy.blocked_senders)])
        policy_table.add_row(["Total Blocked IPs", len(self.security_policy.blocked_ips)])
        
        # Get log health status
        log_health = self.security_log.get_log_health_status()
        policy_table.add_row(["Event Log Size", f"{log_health['current_size']}/{log_health['max_size']}"])
        policy_table.add_row(["Log Utilization", f"{log_health['utilization_percent']:.1f}%"])
        policy_table.add_row(["Auto Rotation", "Enabled" if self.security_log.auto_rotate else "Disabled"])
        
        print(policy_table)
        
        # Blocked senders table
        if self.security_policy.blocked_senders:
            sender_table = PrettyTable(["#", "Blocked Sender Address"])
            if markdown:
                sender_table.set_style(MARKDOWN)
            sender_table.align = "l"
            sender_table.title = f"Blocked Senders ({len(self.security_policy.blocked_senders)})"
            
            for i, sender in enumerate(sorted(self.security_policy.blocked_senders), 1):
                sender_table.add_row([i, sender])
            
            print(sender_table)
        else:
            print("\nNo blocked senders configured")
        
        # Blocked IPs table
        if self.security_policy.blocked_ips:
            ip_table = PrettyTable(["#", "Blocked IP/CIDR", "Type"])
            if markdown:
                ip_table.set_style(MARKDOWN)
            ip_table.align = "l"
            ip_table.title = f"Blocked IP Addresses ({len(self.security_policy.blocked_ips)})"
            
            for i, ip in enumerate(sorted(self.security_policy.blocked_ips), 1):
                ip_type = "CIDR Range" if '/' in ip else "Single IP"
                ip_table.add_row([i, ip, ip_type])
            
            print(ip_table)
        else:
            print("\nNo blocked IP addresses configured")
        
        # Security statistics
        stats = self.security_log.get_detailed_statistics()
        stats_table = PrettyTable(["Statistic", "Value"])
        if markdown:
            stats_table.set_style(MARKDOWN)
        stats_table.align = "l"
        hostname = getattr(self.sys_log, 'hostname', 'localhost') if hasattr(self, 'sys_log') else 'localhost'
        stats_table.title = f"Security Statistics ({hostname})"
        
        stats_table.add_row(["Total Security Events", stats["total_events"]])
        stats_table.add_row(["Blocked Emails", stats["blocked_senders"]])
        stats_table.add_row(["Blocked Connections", stats["blocked_ips"] + stats["connection_refused"]])
        stats_table.add_row(["Policy Changes", stats["policy_changes"]])
        stats_table.add_row(["High Severity Events", stats["events_by_severity"]["high"]])
        stats_table.add_row(["Medium Severity Events", stats["events_by_severity"]["medium"]])
        stats_table.add_row(["Low Severity Events", stats["events_by_severity"]["low"]])
        stats_table.add_row(["Unique Senders Affected", stats["unique_senders_count"]])
        stats_table.add_row(["Unique IPs Affected", stats["unique_ips_count"]])
        stats_table.add_row(["Active Agents", stats["agents_active_count"]])
        
        print(stats_table)

    def show_security_events(self, limit: int = 20, event_type: str = None, 
                           severity: str = None, time_range_hours: float = None, 
                           markdown: bool = False):
        """Display recent security events in tabular format."""
        from prettytable import PrettyTable, MARKDOWN
        
        # Get filtered events
        events = self.security_log.get_filtered_events(
            event_type=event_type,
            severity=severity,
            time_range_hours=time_range_hours,
            limit=limit
        )
        
        if not events:
            filter_desc = []
            if event_type:
                filter_desc.append(f"type={event_type}")
            if severity:
                filter_desc.append(f"severity={severity}")
            if time_range_hours:
                filter_desc.append(f"last {time_range_hours}h")
            
            filter_str = f" ({', '.join(filter_desc)})" if filter_desc else ""
            print(f"No security events found{filter_str}")
            return
        
        # Create events table
        events_table = PrettyTable(["Time", "Type", "Severity", "Source", "Agent", "Reason"])
        if markdown:
            events_table.set_style(MARKDOWN)
        events_table.align = "l"
        
        # Build title with filter information
        title_parts = [f"Recent Security Events ({len(events)}"]
        if limit and len(events) == limit:
            title_parts.append(f"showing last {limit}")
        
        filter_parts = []
        if event_type:
            filter_parts.append(f"type: {event_type}")
        if severity:
            filter_parts.append(f"severity: {severity}")
        if time_range_hours:
            filter_parts.append(f"last {time_range_hours}h")
        
        if filter_parts:
            title_parts.append(f"filters: {', '.join(filter_parts)}")
        
        events_table.title = f"{' - '.join(title_parts)})"
        
        # Add events to table (most recent first)
        for event in reversed(events):
            # Format timestamp (show only time if today, otherwise date + time)
            try:
                from datetime import datetime
                event_time = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                time_str = event_time.strftime("%H:%M:%S")
            except (ValueError, AttributeError):
                time_str = event.timestamp[:19] if event.timestamp else "N/A"
            
            # Format event type for display
            event_type_display = event.event_type.replace('_', ' ').title()
            
            # Format severity with color indicators (text-based)
            severity_display = event.severity.upper()
            if event.severity == "high":
                severity_display = f"🔴 {severity_display}"
            elif event.severity == "medium":
                severity_display = f"🟡 {severity_display}"
            else:
                severity_display = f"🟢 {severity_display}"
            
            # Determine source (sender or IP)
            source = event.sender or event.ip_address or "system"
            if len(source) > 25:
                source = source[:22] + "..."
            
            # Format agent
            agent = event.agent or "system"
            if len(agent) > 15:
                agent = agent[:12] + "..."
            
            # Format reason
            reason = event.reason
            if len(reason) > 40:
                reason = reason[:37] + "..."
            
            events_table.add_row([
                time_str,
                event_type_display,
                severity_display,
                source,
                agent,
                reason
            ])
        
        print(events_table)
        
        # Show event type summary if no specific type filter
        if not event_type and len(events) > 5:
            type_counts = {}
            for event in events:
                event_type_key = event.event_type
                type_counts[event_type_key] = type_counts.get(event_type_key, 0) + 1
            
            if len(type_counts) > 1:
                summary_table = PrettyTable(["Event Type", "Count"])
                if markdown:
                    summary_table.set_style(MARKDOWN)
                summary_table.align = "l"
                summary_table.title = "Event Type Summary"
                
                for event_type_key, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                    display_type = event_type_key.replace('_', ' ').title()
                    summary_table.add_row([display_type, count])
                
                print(summary_table)

    def describe_state(self) -> Dict:
        """Describe the current state of the SMTP server."""
        state = super().describe_state()
        state["active_sessions"] = len(self.active_sessions)
        state["total_mailboxes"] = len(self.mailbox_manager.mailboxes)
        return state