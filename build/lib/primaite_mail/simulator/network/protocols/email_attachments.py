"""Email attachment models and data structures."""

import base64
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from primaite.simulator.file_system.file_system_item_abc import FileSystemItemHealthStatus


class EmailAttachment(BaseModel):
    """Represents a file attachment in an email message."""
    
    filename: str
    """The original filename of the attachment."""
    
    content_type: str
    """MIME type of the attachment (e.g., 'application/pdf', 'image/jpeg')."""
    
    file_size: int
    """Size of the original file in bytes."""
    
    file_data: str
    """Base64 encoded file content."""
    
    file_uuid: str
    """UUID reference to the original file in the file system."""
    
    health_status: str
    """Health status of the original file (GOOD, CORRUPT, etc.)."""
    
    @field_validator('file_data')
    @classmethod
    def validate_base64(cls, v):
        """Validate that file_data is valid base64."""
        try:
            base64.b64decode(v)
            return v
        except Exception:
            raise ValueError("file_data must be valid base64 encoded content")
    
    @field_validator('health_status')
    @classmethod
    def validate_health_status(cls, v):
        """Validate that health_status is a valid FileSystemItemHealthStatus."""
        try:
            FileSystemItemHealthStatus[v]
            return v
        except KeyError:
            raise ValueError(f"health_status must be one of: {[status.name for status in FileSystemItemHealthStatus]}")
    
    def get_decoded_content(self) -> bytes:
        """
        Get the decoded file content as bytes.
        
        :return: The decoded file content.
        """
        return base64.b64decode(self.file_data)
    
    @classmethod
    def from_file_content(cls, filename: str, content_type: str, file_content: bytes, 
                         file_uuid: str, health_status: FileSystemItemHealthStatus) -> 'EmailAttachment':
        """
        Create an EmailAttachment from file content.
        
        :param filename: The filename of the attachment.
        :param content_type: MIME type of the file.
        :param file_content: Raw file content as bytes.
        :param file_uuid: UUID of the original file.
        :param health_status: Health status of the original file.
        :return: EmailAttachment instance.
        """
        encoded_content = base64.b64encode(file_content).decode('utf-8')
        
        return cls(
            filename=filename,
            content_type=content_type,
            file_size=len(file_content),
            file_data=encoded_content,
            file_uuid=file_uuid,
            health_status=health_status.name
        )


class AttachmentPolicy(BaseModel):
    """Defines attachment policies and restrictions for email servers."""
    
    max_attachment_size: int = Field(default=25 * 1024 * 1024, description="Maximum size per attachment in bytes")
    """Maximum size allowed for a single attachment (default: 25MB)."""
    
    max_total_size: int = Field(default=50 * 1024 * 1024, description="Maximum total message size in bytes")
    """Maximum total size for an email including all attachments (default: 50MB)."""
    
    max_attachments: int = Field(default=10, description="Maximum number of attachments per email")
    """Maximum number of attachments allowed per email."""
    
    allowed_extensions: List[str] = Field(default_factory=list, description="List of allowed file extensions")
    """List of allowed file extensions (empty list means all extensions allowed)."""
    
    blocked_extensions: List[str] = Field(default_factory=list, description="List of blocked file extensions")
    """List of blocked file extensions."""
    
    scan_for_malware: bool = Field(default=True, description="Enable malware scanning")
    """Whether to scan attachments for malware (corrupted files)."""
    
    quarantine_suspicious: bool = Field(default=True, description="Quarantine suspicious emails")
    """Whether to quarantine emails with suspicious attachments."""
    
    @field_validator('max_attachment_size', 'max_total_size')
    @classmethod
    def validate_positive_sizes(cls, v):
        """Validate that size limits are positive."""
        if v <= 0:
            raise ValueError("Size limits must be positive")
        return v
    
    @field_validator('max_attachments')
    @classmethod
    def validate_max_attachments(cls, v):
        """Validate that max_attachments is positive."""
        if v <= 0:
            raise ValueError("max_attachments must be positive")
        return v
    
    @field_validator('allowed_extensions', 'blocked_extensions')
    @classmethod
    def validate_extensions(cls, v):
        """Validate and normalize file extensions."""
        normalized = []
        for ext in v:
            # Remove leading dot if present and convert to lowercase
            normalized_ext = ext.lstrip('.').lower()
            normalized.append(normalized_ext)
        return normalized
    
    def is_extension_allowed(self, filename: str) -> bool:
        """
        Check if a file extension is allowed based on policy.
        
        :param filename: The filename to check.
        :return: True if the extension is allowed, False otherwise.
        """
        if '.' not in filename:
            # Files without extensions are allowed if no specific restrictions
            return True
        
        extension = filename.split('.')[-1].lower()
        
        # Check blocked extensions first
        if extension in self.blocked_extensions:
            return False
        
        # If allowed_extensions is empty, all extensions are allowed (except blocked ones)
        if not self.allowed_extensions:
            return True
        
        # Check if extension is in allowed list
        return extension in self.allowed_extensions
    
    def validate_attachment(self, attachment: EmailAttachment) -> tuple[bool, Optional[str]]:
        """
        Validate an attachment against this policy.
        
        :param attachment: The attachment to validate.
        :return: Tuple of (is_valid, error_message).
        """
        # Check file size
        if attachment.file_size > self.max_attachment_size:
            return False, f"Attachment size ({attachment.file_size} bytes) exceeds maximum allowed ({self.max_attachment_size} bytes)"
        
        # Check file extension
        if not self.is_extension_allowed(attachment.filename):
            return False, f"File extension not allowed: {attachment.filename}"
        
        # Check for malware if scanning is enabled
        if self.scan_for_malware and attachment.health_status == FileSystemItemHealthStatus.CORRUPT.name:
            return False, f"Malware detected in attachment: {attachment.filename}"
        
        return True, None
    
    def validate_message_attachments(self, attachments: List[EmailAttachment]) -> tuple[bool, Optional[str]]:
        """
        Validate all attachments in a message against this policy.
        
        :param attachments: List of attachments to validate.
        :return: Tuple of (is_valid, error_message).
        """
        # Check number of attachments
        if len(attachments) > self.max_attachments:
            return False, f"Too many attachments ({len(attachments)}), maximum allowed is {self.max_attachments}"
        
        # Check total size
        total_size = sum(attachment.file_size for attachment in attachments)
        if total_size > self.max_total_size:
            return False, f"Total attachment size ({total_size} bytes) exceeds maximum allowed ({self.max_total_size} bytes)"
        
        # Validate each attachment individually
        for attachment in attachments:
            is_valid, error_msg = self.validate_attachment(attachment)
            if not is_valid:
                return False, error_msg
        
        return True, None


# Default attachment policy for email servers
DEFAULT_ATTACHMENT_POLICY = AttachmentPolicy(
    max_attachment_size=25 * 1024 * 1024,  # 25MB
    max_total_size=50 * 1024 * 1024,       # 50MB
    max_attachments=10,
    allowed_extensions=[],  # Empty means all allowed
    blocked_extensions=['exe', 'bat', 'cmd', 'scr', 'pif', 'com'],  # Common executable types
    scan_for_malware=True,
    quarantine_suspicious=True
)