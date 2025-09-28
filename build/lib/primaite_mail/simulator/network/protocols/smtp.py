"""SMTP Protocol implementation for email simulation."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from primaite_mail.simulator.network.protocols.email_attachments import EmailAttachment


class SMTPCommand(Enum):
    """SMTP Commands as defined in RFC 5321."""
    
    HELO = "HELO"
    EHLO = "EHLO"
    MAIL = "MAIL"
    RCPT = "RCPT"
    DATA = "DATA"
    RSET = "RSET"
    VRFY = "VRFY"
    EXPN = "EXPN"
    HELP = "HELP"
    NOOP = "NOOP"
    QUIT = "QUIT"


class SMTPStatusCode(Enum):
    """SMTP Status Codes as defined in RFC 5321."""
    
    # 2xx Success
    OK = 220
    CLOSING = 221
    AUTH_SUCCESS = 235
    OK_COMPLETED = 250
    USER_NOT_LOCAL = 251
    CANNOT_VRFY = 252
    
    # 3xx Intermediate
    START_MAIL_INPUT = 354
    
    # 4xx Temporary Failure
    SERVICE_NOT_AVAILABLE = 421
    MAILBOX_BUSY = 450
    LOCAL_ERROR = 451
    INSUFFICIENT_STORAGE = 452
    
    # 5xx Permanent Failure
    SYNTAX_ERROR = 500
    PARAMETER_ERROR = 501
    COMMAND_NOT_IMPLEMENTED = 502
    BAD_SEQUENCE = 503
    PARAMETER_NOT_IMPLEMENTED = 504
    MAILBOX_UNAVAILABLE = 550
    USER_NOT_LOCAL_ERROR = 551
    EXCEEDED_STORAGE = 552
    MAILBOX_NAME_INVALID = 553
    TRANSACTION_FAILED = 554


class EmailMessage(BaseModel):
    """Represents an email message with optional file attachments."""
    
    sender: str
    recipients: List[str]
    subject: str = ""
    body: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    timestamp: Optional[str] = None
    message_id: Optional[str] = None
    
    # Attachment support
    attachments: List[EmailAttachment] = Field(default_factory=list)
    """List of file attachments included with this email."""
    
    @property
    def has_attachments(self) -> bool:
        """Check if this email has any attachments."""
        return len(self.attachments) > 0
    
    @property
    def attachment_count(self) -> int:
        """Get the number of attachments in this email."""
        return len(self.attachments)
    
    def calculate_total_size(self) -> int:
        """
        Calculate the total size of the email including headers, body, and attachments.
        
        :return: Total size in bytes.
        """
        # Calculate base message size (headers, sender, recipients, subject, body)
        base_size = len(self.sender.encode('utf-8'))
        base_size += sum(len(recipient.encode('utf-8')) for recipient in self.recipients)
        base_size += len(self.subject.encode('utf-8'))
        base_size += len(self.body.encode('utf-8'))
        
        # Add headers size
        for key, value in self.headers.items():
            base_size += len(f"{key}: {value}\r\n".encode('utf-8'))
        
        # Add attachment sizes (encoded size, not original file size)
        attachment_size = sum(len(attachment.file_data.encode('utf-8')) for attachment in self.attachments)
        
        return base_size + attachment_size
    
    def get_attachment_by_filename(self, filename: str) -> Optional[EmailAttachment]:
        """
        Get an attachment by filename.
        
        :param filename: The filename to search for.
        :return: The attachment if found, None otherwise.
        """
        for attachment in self.attachments:
            if attachment.filename == filename:
                return attachment
        return None
    
    def add_attachment(self, attachment: EmailAttachment) -> None:
        """
        Add an attachment to this email.
        
        :param attachment: The attachment to add.
        """
        self.attachments.append(attachment)
    
    def remove_attachment(self, filename: str) -> bool:
        """
        Remove an attachment by filename.
        
        :param filename: The filename of the attachment to remove.
        :return: True if attachment was removed, False if not found.
        """
        for i, attachment in enumerate(self.attachments):
            if attachment.filename == filename:
                del self.attachments[i]
                return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize the email message to a dictionary for storage or transmission.
        
        :return: Dictionary representation of the email message.
        """
        return {
            "sender": self.sender,
            "recipients": self.recipients,
            "subject": self.subject,
            "body": self.body,
            "headers": self.headers,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
            "attachments": [attachment.model_dump() for attachment in self.attachments],
            "has_attachments": self.has_attachments,
            "attachment_count": self.attachment_count,
            "total_size": self.calculate_total_size()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmailMessage':
        """
        Deserialize an email message from a dictionary.
        
        :param data: Dictionary representation of the email message.
        :return: EmailMessage instance.
        """
        # Extract attachment data and create EmailAttachment objects
        attachments = []
        if "attachments" in data and data["attachments"]:
            for attachment_data in data["attachments"]:
                attachments.append(EmailAttachment(**attachment_data))
        
        # Create EmailMessage with all fields except computed properties
        return cls(
            sender=data["sender"],
            recipients=data["recipients"],
            subject=data.get("subject", ""),
            body=data.get("body", ""),
            headers=data.get("headers", {}),
            timestamp=data.get("timestamp"),
            message_id=data.get("message_id"),
            attachments=attachments
        )
    
    def to_json(self) -> str:
        """
        Serialize the email message to JSON string.
        
        :return: JSON string representation of the email message.
        """
        import json
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'EmailMessage':
        """
        Deserialize an email message from JSON string.
        
        :param json_str: JSON string representation of the email message.
        :return: EmailMessage instance.
        """
        import json
        data = json.loads(json_str)
        return cls.from_dict(data)


class SMTPPacket(BaseModel):
    """SMTP Protocol packet for network communication with attachment support."""
    
    command: Optional[SMTPCommand] = None
    arguments: Optional[str] = None
    status_code: Optional[SMTPStatusCode] = None
    message: Optional[str] = None
    email_data: Optional[EmailMessage] = None
    session_id: Optional[str] = None
    
    # Enhanced fields for attachment handling
    max_message_size: Optional[int] = Field(default=50 * 1024 * 1024, description="Maximum message size in bytes")
    """Maximum allowed message size for this packet (default: 50MB)."""
    
    chunk_size: Optional[int] = Field(default=1024 * 1024, description="Chunk size for large message processing")
    """Size of chunks for processing large messages (default: 1MB)."""
    
    attachment_metadata: Dict[str, Any] = Field(default_factory=dict, description="Attachment metadata for headers")
    """Metadata about attachments for SMTP header processing."""
    
    def calculate_packet_size(self) -> int:
        """
        Calculate the total size of this SMTP packet.
        
        :return: Total packet size in bytes.
        """
        size = 0
        
        # Add command and arguments size
        if self.command:
            size += len(self.command.value.encode('utf-8'))
        if self.arguments:
            size += len(self.arguments.encode('utf-8'))
        
        # Add status code and message size
        if self.status_code:
            size += len(str(self.status_code.value).encode('utf-8'))
        if self.message:
            size += len(self.message.encode('utf-8'))
        
        # Add email data size (this is the largest component for attachment emails)
        if self.email_data:
            size += self.email_data.calculate_total_size()
        
        # Add session ID size
        if self.session_id:
            size += len(self.session_id.encode('utf-8'))
        
        return size
    
    def is_large_message(self) -> bool:
        """
        Check if this packet contains a large message that may need special handling.
        
        :return: True if the message is considered large.
        """
        if not self.email_data:
            return False
        
        # Consider messages with attachments or large total size as "large"
        return (self.email_data.has_attachments or 
                self.email_data.calculate_total_size() > self.chunk_size)
    
    def get_attachment_headers(self) -> Dict[str, str]:
        """
        Generate SMTP headers with attachment metadata for recipient processing.
        
        :return: Dictionary of attachment-related headers.
        """
        headers = {}
        
        if not self.email_data or not self.email_data.has_attachments:
            return headers
        
        # Add attachment count header
        headers["X-Attachment-Count"] = str(self.email_data.attachment_count)
        
        # Add total attachment size header
        total_attachment_size = sum(
            attachment.file_size for attachment in self.email_data.attachments
        )
        headers["X-Attachment-Total-Size"] = str(total_attachment_size)
        
        # Add attachment filenames header (comma-separated)
        filenames = [attachment.filename for attachment in self.email_data.attachments]
        headers["X-Attachment-Filenames"] = ", ".join(filenames)
        
        # Add attachment content types header (comma-separated)
        content_types = [attachment.content_type for attachment in self.email_data.attachments]
        headers["X-Attachment-Content-Types"] = ", ".join(content_types)
        
        # Add health status information for security scanning
        health_statuses = [attachment.health_status for attachment in self.email_data.attachments]
        if any(status != "GOOD" for status in health_statuses):
            headers["X-Attachment-Health-Warning"] = "Contains potentially corrupted files"
            headers["X-Attachment-Health-Status"] = ", ".join(health_statuses)
        
        return headers
    
    def apply_attachment_headers(self) -> None:
        """
        Apply attachment metadata headers to the email data.
        This modifies the email_data headers in place.
        """
        if not self.email_data:
            return
        
        attachment_headers = self.get_attachment_headers()
        
        # Merge attachment headers with existing email headers
        if not self.email_data.headers:
            self.email_data.headers = {}
        
        self.email_data.headers.update(attachment_headers)
    
    def validate_message_size(self) -> tuple[bool, Optional[str]]:
        """
        Validate that the message size is within acceptable limits.
        
        :return: Tuple of (is_valid, error_message).
        """
        if not self.email_data:
            return True, None
        
        message_size = self.email_data.calculate_total_size()
        
        if message_size > self.max_message_size:
            return False, f"Message size ({message_size} bytes) exceeds maximum allowed ({self.max_message_size} bytes)"
        
        return True, None
    
    def get_processing_chunks(self) -> List[Dict[str, Any]]:
        """
        Split large messages into processing chunks for efficient handling.
        
        :return: List of chunk metadata for processing.
        """
        if not self.is_large_message():
            return [{"chunk_id": 0, "size": self.calculate_packet_size(), "is_final": True}]
        
        chunks = []
        total_size = self.calculate_packet_size()
        chunk_count = (total_size + self.chunk_size - 1) // self.chunk_size  # Ceiling division
        
        for i in range(chunk_count):
            start_byte = i * self.chunk_size
            end_byte = min((i + 1) * self.chunk_size, total_size)
            chunk_size = end_byte - start_byte
            
            chunks.append({
                "chunk_id": i,
                "start_byte": start_byte,
                "end_byte": end_byte,
                "size": chunk_size,
                "is_final": i == chunk_count - 1
            })
        
        return chunks
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize the SMTP packet to a dictionary.
        
        :return: Dictionary representation of the packet.
        """
        return {
            "command": self.command.value if self.command else None,
            "arguments": self.arguments,
            "status_code": self.status_code.value if self.status_code else None,
            "message": self.message,
            "email_data": self.email_data.to_dict() if self.email_data else None,
            "session_id": self.session_id,
            "max_message_size": self.max_message_size,
            "chunk_size": self.chunk_size,
            "attachment_metadata": self.attachment_metadata,
            "packet_size": self.calculate_packet_size(),
            "is_large_message": self.is_large_message(),
            "attachment_headers": self.get_attachment_headers()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SMTPPacket':
        """
        Deserialize an SMTP packet from a dictionary.
        
        :param data: Dictionary representation of the packet.
        :return: SMTPPacket instance.
        """
        # Handle enum conversions
        command = SMTPCommand(data["command"]) if data.get("command") else None
        status_code = SMTPStatusCode(data["status_code"]) if data.get("status_code") else None
        
        # Handle email data
        email_data = None
        if data.get("email_data"):
            email_data = EmailMessage.from_dict(data["email_data"])
        
        return cls(
            command=command,
            arguments=data.get("arguments"),
            status_code=status_code,
            message=data.get("message"),
            email_data=email_data,
            session_id=data.get("session_id"),
            max_message_size=data.get("max_message_size", 50 * 1024 * 1024),
            chunk_size=data.get("chunk_size", 1024 * 1024),
            attachment_metadata=data.get("attachment_metadata", {})
        )