"""AttachmentManager for handling email file attachments."""

from typing import Optional, Tuple

from primaite import getLogger
from primaite.simulator.core import SimComponent
from primaite.simulator.file_system.file_system import FileSystem
from primaite.simulator.file_system.file import File
from primaite.simulator.file_system.file_system_item_abc import FileSystemItemHealthStatus

from primaite_mail.simulator.network.protocols.email_attachments import EmailAttachment, AttachmentPolicy
from primaite_mail.simulator.network.protocols.mime_utils import get_mime_type_from_file_type

_LOGGER = getLogger(__name__)


class AttachmentManager(SimComponent):
    """Simplified attachment manager for PrimAITE's simulated file system."""
    
    def __init__(self, **kwargs):
        """Initialize the AttachmentManager."""
        super().__init__(**kwargs)
        self.logger = _LOGGER
    
    def describe_state(self) -> dict:
        """
        Describe the current state of the AttachmentManager.
        
        :return: Dictionary describing the current state.
        """
        return {
            "component_type": "AttachmentManager",
            "uuid": self.uuid,
            "name": getattr(self, 'name', 'AttachmentManager')
        }

    
    def attach_file(self, file_system: FileSystem, folder_name: str, file_name: str) -> Optional[EmailAttachment]:
        """
        Read a file from the file system and create an EmailAttachment object.
        
        :param file_system: The file system to read from.
        :param folder_name: The name of the folder containing the file.
        :param file_name: The name of the file to attach.
        :return: EmailAttachment object if successful, None if failed.
        """
        try:
            # Basic validation
            if not file_system:
                self.logger.error("File system is None")
                return None
            
            # Get folder
            folder = file_system.get_folder(folder_name)
            if not folder:
                self.logger.error(f"Folder '{folder_name}' not found")
                return None
            
            # Get file
            file_obj = folder.get_file(file_name)
            if not file_obj or file_obj.deleted:
                self.logger.error(f"File '{file_name}' not found in folder '{folder_name}'")
                return None
            
            # Determine MIME type
            content_type = get_mime_type_from_file_type(file_obj.file_type)
            
            # Generate file content and create attachment
            file_content = self._generate_file_content(file_obj)
            attachment = EmailAttachment.from_file_content(
                filename=file_obj.name,
                content_type=content_type,
                file_content=file_content,
                file_uuid=file_obj.uuid,
                health_status=file_obj.health_status
            )
            
            self.logger.debug(f"Successfully attached file '{folder_name}/{file_name}'")
            return attachment
            
        except Exception as e:
            self.logger.error(f"Error attaching file '{folder_name}/{file_name}': {str(e)}")
            return None
    

    
    def _generate_file_content(self, file_obj: File) -> bytes:
        """
        Generate simulated file content based on file properties.
        
        :param file_obj: The file object to generate content for.
        :return: Simulated file content as bytes.
        """
        # Create content that reflects the file's simulated size
        # For corrupted files, include some "corrupted" markers
        if file_obj.health_status == FileSystemItemHealthStatus.CORRUPT:
            # Create corrupted content with some recognizable patterns
            base_content = f"CORRUPTED_FILE_{file_obj.name}_{file_obj.uuid}"
            corrupted_markers = b"\x00\xFF\xDE\xAD\xBE\xEF"  # Binary corruption markers
        else:
            # Create normal content
            base_content = f"FILE_CONTENT_{file_obj.name}_{file_obj.file_type.name}_{file_obj.uuid}"
            corrupted_markers = b""
        
        # Convert to bytes
        content = base_content.encode('utf-8') + corrupted_markers
        
        # Pad or truncate to match the simulated file size
        target_size = file_obj.size
        if len(content) < target_size:
            # Pad with repeating pattern
            padding_pattern = b"PADDING_DATA_"
            padding_needed = target_size - len(content)
            padding_cycles = (padding_needed // len(padding_pattern)) + 1
            padding = (padding_pattern * padding_cycles)[:padding_needed]
            content += padding
        elif len(content) > target_size:
            # Truncate to target size
            content = content[:target_size]
        
        return content
    
    def extract_attachment(self, attachment: EmailAttachment, file_system: FileSystem, 
                          destination_folder: str) -> Tuple[bool, Optional[str]]:
        """
        Extract an attachment and create a file in the recipient's file system.
        
        :param attachment: The EmailAttachment to extract.
        :param file_system: The file system to create the file in.
        :param destination_folder: The name of the destination folder.
        :return: Tuple of (success, error_message).
        """
        try:
            # Basic validation
            if not attachment:
                return False, "Attachment is None"
            
            if not file_system:
                return False, "File system is None"
            
            # Get folder
            folder = file_system.get_folder(destination_folder)
            if not folder:
                return False, f"Folder '{destination_folder}' not found"
            
            # Handle filename conflicts using simple counter-based naming
            original_filename = attachment.filename
            filename = original_filename
            counter = 1
            
            while filename in folder.files and not folder.files[filename].deleted:
                name_parts = original_filename.rsplit('.', 1)
                if len(name_parts) == 2:
                    filename = f"{name_parts[0]}_{counter}.{name_parts[1]}"
                else:
                    filename = f"{original_filename}_{counter}"
                counter += 1
            
            # Extract attachment directly
            return self._extract_attachment_direct(attachment, file_system, destination_folder, filename)
                
        except Exception as e:
            error_msg = f"Error extracting attachment '{attachment.filename if attachment else 'unknown'}': {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def _extract_attachment_direct(self, attachment: EmailAttachment, file_system: FileSystem,
                                 destination_folder: str, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Extract an attachment directly to the file system using simple content decoding.
        
        :param attachment: The EmailAttachment to extract.
        :param file_system: The file system to create the file in.
        :param destination_folder: The name of the destination folder.
        :param filename: The resolved filename to use.
        :return: Tuple of (success, error_message).
        """
        try:
            # Decode attachment content directly
            file_content = attachment.get_decoded_content()
            
            # Determine file type from filename
            from primaite.simulator.file_system.file_type import get_file_type_from_extension, FileType
            
            if '.' in filename:
                extension = filename.split('.')[-1]
                file_type = get_file_type_from_extension(extension)
            else:
                file_type = FileType.UNKNOWN
            
            # Create the file directly in the file system
            extracted_file = file_system.create_file(
                folder_name=destination_folder,
                file_name=filename,
                file_type=file_type,
                size=len(file_content),
                force=True
            )
            
            if not extracted_file:
                return False, f"Failed to create file '{filename}' in folder '{destination_folder}'"
            
            # Preserve original file properties from attachment metadata
            self._restore_file_properties(extracted_file, attachment)
            
            self.logger.debug(f"Successfully extracted attachment '{attachment.filename}' as '{filename}'")
            return True, None
            
        except Exception as e:
            return False, f"Failed to decode attachment content: {str(e)}"
    
    def _restore_file_properties(self, extracted_file: File, attachment: EmailAttachment) -> None:
        """
        Restore file properties from attachment metadata.
        
        :param extracted_file: The extracted file object.
        :param attachment: The original attachment with metadata.
        """
        try:
            # Restore health status from attachment
            health_status = FileSystemItemHealthStatus[attachment.health_status]
            extracted_file.health_status = health_status
            
            # Set the simulated size to match the original file size from attachment
            extracted_file.sim_size = attachment.file_size
            
        except KeyError:
            # Invalid health status in attachment - default to GOOD
            self.logger.warning(f"Invalid health status '{attachment.health_status}' in attachment, "
                              f"defaulting to GOOD")
            extracted_file.health_status = FileSystemItemHealthStatus.GOOD
    
    def validate_attachment(self, attachment: EmailAttachment, policy: AttachmentPolicy) -> Tuple[bool, Optional[str]]:
        """
        Validate an attachment against the provided policy.
        
        :param attachment: The EmailAttachment to validate.
        :param policy: The AttachmentPolicy to validate against.
        :return: Tuple of (is_valid, error_message).
        """
        try:
            if not attachment:
                return False, "Cannot validate null attachment"
            
            if not policy:
                return False, f"Cannot validate attachment '{attachment.filename}' against null policy"
            
            # Use the policy's built-in validation method
            return policy.validate_attachment(attachment)
            
        except Exception as e:
            error_msg = f"Error validating attachment '{attachment.filename if attachment else 'unknown'}': {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    def validate_message_attachments(self, attachments: list[EmailAttachment], 
                                   policy: AttachmentPolicy) -> Tuple[bool, Optional[str]]:
        """
        Validate all attachments in a message against the provided policy.
        
        :param attachments: List of EmailAttachment objects to validate.
        :param policy: The AttachmentPolicy to validate against.
        :return: Tuple of (is_valid, error_message).
        """
        try:
            # Use the policy's built-in validation method for message attachments
            is_valid, error_message = policy.validate_message_attachments(attachments)
            
            if not is_valid:
                self.logger.warning(f"Message attachment validation failed: {error_message}")
            
            return is_valid, error_message
            
        except Exception as e:
            error_msg = f"Error validating message attachments: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def scan_for_malware(self, attachments: list[EmailAttachment]) -> dict[str, str]:
        """
        Scan attachments for malware (corrupted files) and suspicious content.
        
        :param attachments: List of EmailAttachment objects to scan.
        :return: Dictionary mapping filename to scan result.
        """
        scan_results = {}
        
        if not attachments:
            return {}
        
        for i, attachment in enumerate(attachments):
            try:
                if not attachment:
                    scan_results[f"unknown_attachment_{i}"] = "SCAN_ERROR"
                    self.logger.warning(f"Null attachment encountered during scan at index {i}")
                    continue
                
                filename = attachment.filename or f"unnamed_attachment_{i}"
                
                # Check health status for corruption (malware indicator)
                if attachment.health_status == FileSystemItemHealthStatus.CORRUPT.name:
                    scan_results[filename] = "MALWARE_DETECTED"
                    self.logger.warning(f"Malware detected in attachment '{filename}' (corrupted file)")
                    continue
                
                # Check for suspicious file extensions and MIME types
                suspicious_extensions = ['exe', 'bat', 'cmd', 'scr', 'pif', 'com', 'vbs', 'js', 'jar', 'msi']
                
                # Check for double extensions (common malware technique) - highest priority
                if filename.count('.') > 1:
                    parts = filename.lower().split('.')
                    final_extension = parts[-1]
                    if final_extension in suspicious_extensions and len(parts) >= 3:
                        scan_results[filename] = "SUSPICIOUS_DOUBLE_EXTENSION"
                        continue
                
                # Check if file has executable MIME type
                is_executable_mime = False
                try:
                    from primaite_mail.simulator.network.protocols.mime_utils import is_executable_mime_type
                    is_executable_mime = is_executable_mime_type(attachment.content_type)
                except Exception:
                    pass  # Continue with other checks
                
                # Check for suspicious extensions
                if '.' in filename:
                    extension = filename.split('.')[-1].lower()
                    if extension in suspicious_extensions:
                        # If it has both suspicious extension AND executable MIME type,
                        # classify as SUSPICIOUS_EXECUTABLE (more general category)
                        if is_executable_mime:
                            scan_results[filename] = "SUSPICIOUS_EXECUTABLE"
                            self.logger.warning(f"Suspicious executable attachment detected: '{filename}'")
                        else:
                            # Suspicious extension but non-executable MIME type
                            scan_results[filename] = "SUSPICIOUS_EXTENSION"
                        continue
                
                # Check for executable MIME types without suspicious extensions
                if is_executable_mime:
                    scan_results[filename] = "SUSPICIOUS_EXECUTABLE"
                    self.logger.warning(f"Suspicious executable attachment detected: '{filename}'")
                    continue
                
                # Check for unusually large files (potential zip bombs or data exfiltration)
                if attachment.file_size > 100 * 1024 * 1024:  # 100MB
                    scan_results[filename] = "SUSPICIOUS_SIZE"
                    continue
                
                # File appears clean
                scan_results[filename] = "CLEAN"
                
            except Exception as e:
                filename = getattr(attachment, 'filename', f"attachment_{i}") if attachment else f"unknown_{i}"
                self.logger.warning(f"Error scanning attachment '{filename}': {str(e)}")
                scan_results[filename] = "SCAN_ERROR"
        
        return scan_results
    
    def log_policy_violation(self, attachment: EmailAttachment, policy: AttachmentPolicy, 
                           violation_reason: str, sender: str = None, recipients: list[str] = None) -> None:
        """
        Log attachment policy violations for security monitoring.
        
        :param attachment: The EmailAttachment that violated policy.
        :param policy: The AttachmentPolicy that was violated.
        :param violation_reason: Description of the policy violation.
        :param sender: Email sender (optional).
        :param recipients: Email recipients (optional).
        """
        try:
            if not attachment:
                self.logger.error("Cannot log policy violation for null attachment")
                return
            
            if not policy:
                self.logger.error(f"Cannot log policy violation for attachment '{attachment.filename}' - null policy")
                return
            
            # Log security alert
            self.logger.warning(f"SECURITY ALERT - Attachment Policy Violation")
            self.logger.warning(f"File: {attachment.filename}")
            self.logger.warning(f"Size: {attachment.file_size:,} bytes")
            self.logger.warning(f"Type: {attachment.content_type}")
            self.logger.warning(f"Reason: {violation_reason}")
            
            if sender:
                self.logger.warning(f"Sender: {sender}")
            
            if recipients:
                self.logger.warning(f"Recipients: {', '.join(recipients[:3])}")
            
        except Exception as e:
            self.logger.error(f"Error logging policy violation: {str(e)}")
