"""Email Client implementation supporting SMTP, POP3, and IMAP protocols."""

from ipaddress import IPv4Address
from typing import Any, Dict, List, Optional

from pydantic import Field

from primaite import getLogger
from primaite.interface.request import RequestFormat, RequestResponse
from primaite.simulator.core import RequestManager, RequestType
from primaite.simulator.system.applications.application import Application, ApplicationOperatingState
from primaite.utils.validation.ip_protocol import PROTOCOL_LOOKUP
from primaite.utils.validation.port import PORT_LOOKUP

from primaite_mail.simulator.network.protocols.smtp import SMTPCommand, SMTPPacket, SMTPStatusCode, EmailMessage
from primaite_mail.simulator.network.protocols.pop3 import POP3Command, POP3Packet, POP3Status
from primaite_mail.simulator.network.protocols.imap import IMAPCommand, IMAPPacket, IMAPStatus
from primaite_mail.simulator.network.protocols.attachment_manager import AttachmentManager
from primaite_mail.simulator.network.protocols.email_attachments import AttachmentPolicy

_LOGGER = getLogger(__name__)


class EmailClient(Application, discriminator="email-client"):
    """
    Email Client service supporting multiple protocols.
    
    Provides functionality to send emails via SMTP and retrieve emails via POP3/IMAP.
    """

    class ConfigSchema(Application.ConfigSchema):
        """ConfigSchema for EmailClient."""

        type: str = "email-client"
        default_smtp_server: Optional[str] = None
        default_pop3_server: Optional[str] = None
        default_imap_server: Optional[str] = None
        username: Optional[str] = None
        password: Optional[str] = None
        auto_start: bool = True  # Auto-start by default for email clients

    config: ConfigSchema = Field(default_factory=lambda: EmailClient.ConfigSchema())
    active_connections: Dict[str, Dict] = Field(default_factory=dict)
    attachment_manager: AttachmentManager = Field(default_factory=AttachmentManager)

    def __init__(self, **kwargs):
        kwargs["name"] = "email-client"
        kwargs["port"] = PORT_LOOKUP["SMTP"]  # Default to SMTP port
        kwargs["protocol"] = PROTOCOL_LOOKUP["TCP"]
        super().__init__(**kwargs)
        # Note: Don't call run() here - it will be handled by install() method

    def install(self) -> None:
        """Install the email client and auto-start if configured."""
        super().install()
        super().run()
        
        # Ensure node reference is set for file system access
        if not hasattr(self, 'node') and hasattr(self, 'software_manager'):
            if hasattr(self.software_manager, 'node'):
                self.node = self.software_manager.node
        
        # Auto-start the client if configured to do so
        if getattr(self.config, 'auto_start', True):
            # Set execution control to automatic for auto-starting applications
            self.execution_control_status = "automatic"

    def apply_timestep(self, timestep: int) -> None:
        """Apply timestep and handle auto-starting after installation."""
        super().apply_timestep(timestep)
        
        # Auto-start the client after installation completes
        if (self.execution_control_status == "automatic" and 
            self.operating_state == ApplicationOperatingState.CLOSED):
            # Installation completed and we're set to auto-start
            self.run()
            self.sys_log.info(f"{self.name}: Auto-started after installation")

    def run(self) -> bool:
        """Run the email client application."""
        try:
            # Call parent run method if it exists
            if hasattr(super(), 'run'):
                super().run()
            
            # Set operating state to running
            self.operating_state = ApplicationOperatingState.RUNNING
            
            self.sys_log.info(f"{self.name}: Email client started")
            return True
        except Exception as e:
            self.sys_log.error(f"{self.name}: Failed to start email client: {e}")
            return False
    
    def close(self) -> bool:
        """Close the email client application."""
        try:
            # Close all active connections
            for connection_id in list(self.active_connections.keys()):
                self._close_connection(connection_id)
            
            # Call parent close method if it exists
            if hasattr(super(), 'close'):
                super().close()
            
            # Set operating state to closed
            self.operating_state = ApplicationOperatingState.CLOSED
            
            self.sys_log.info(f"{self.name}: Email client closed")
            return True
        except Exception as e:
            self.sys_log.error(f"{self.name}: Failed to close email client: {e}")
            return False
    
    def execute(self) -> bool:
        """Execute the email client (alias for run)."""
        return self.run()
    
    def _close_connection(self, connection_id: str) -> None:
        """Close a specific connection."""
        if connection_id in self.active_connections:
            connection = self.active_connections[connection_id]
            self.sys_log.info(f"{self.name}: Closing connection {connection_id} to {connection.get('server', 'unknown')}")
            del self.active_connections[connection_id]

    def _init_request_manager(self) -> RequestManager:
        """Initialize the request manager with email client requests."""
        rm = super()._init_request_manager()
        
        def _send_email_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Send an email via SMTP with optional attachments."""
            
            # Handle both formats: request as list with params as last element, or request as just params dict
            if isinstance(request, list) and len(request) >= 1 and isinstance(request[-1], dict):
                params = request[-1]
            elif isinstance(request, list) and len(request) == 1 and isinstance(request[0], dict):
                params = request[0]
            elif isinstance(request, dict):
                params = request
            else:
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            # Extract email parameters - handle both 'to' and 'recipient' for compatibility
            to_addresses = params.get("to", params.get("recipient", []))
            if isinstance(to_addresses, str):
                to_addresses = [to_addresses]
            
            subject = params.get("subject", "")
            body = params.get("body", "")
            
            sender = params.get("from", self._get_config_value("username", "user@localhost"))
            smtp_server = params.get("smtp_server", self._get_config_value("default_smtp_server"))
            
            # Extract attachment parameters - handle both 'attachments' and 'attachment_files' for compatibility
            attachments = params.get("attachments", params.get("attachment_files", []))
            
            if not smtp_server:
                return RequestResponse(status="failure", data={"reason": "No SMTP server specified"})
            
            if not to_addresses:
                return RequestResponse(status="failure", data={"reason": "No recipients specified"})
            
            # Create email message
            email = EmailMessage(
                sender=sender,
                recipients=to_addresses,
                subject=subject,
                body=body
            )
            
            # Send email with or without attachments
            if attachments:
                # Validate attachment format
                attachment_files = []
                for attachment in attachments:
                    if isinstance(attachment, dict) and "folder" in attachment and "filename" in attachment:
                        attachment_files.append((attachment["folder"], attachment["filename"]))
                    elif isinstance(attachment, (list, tuple)) and len(attachment) == 2:
                        attachment_files.append((attachment[0], attachment[1]))
                    else:
                        return RequestResponse(
                            status="failure", 
                            data={"reason": f"Invalid attachment format: {attachment}. Expected dict with 'folder' and 'filename' or tuple (folder, filename)"}
                        )
                
                # Check file system access before attempting to send
                file_system = self._get_file_system()
                if not file_system:
                    self.sys_log.error(f"{self.name}: No file system available for attachment processing")
                    return RequestResponse(
                        status="failure", 
                        data={"reason": "No file system available for attachment processing"}
                    )
                else:
                    self.sys_log.debug(f"{self.name}: File system access confirmed for attachments")
                
                success = self.send_email_with_attachments(email, attachment_files, IPv4Address(smtp_server))
                
                # Return detailed response with attachment info
                if success:
                    return RequestResponse(
                        status="success", 
                        data={
                            "message": "Email sent successfully with attachments",
                            "attachment_count": len(attachment_files),
                            "attachments": [{"folder": f, "filename": n} for f, n in attachment_files]
                        }
                    )
                else:
                    return RequestResponse(status="failure", data={"reason": "Failed to send email with attachments"})
            else:
                success = self.send_email(email, IPv4Address(smtp_server))
                return RequestResponse.from_bool(success)
        
        def _retrieve_emails_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Retrieve emails via POP3 with optional attachment extraction."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            
            pop3_server = params.get("pop3_server", self._get_config_value("default_pop3_server"))
            username = params.get("username", self._get_config_value("username"))
            password = params.get("password", self._get_config_value("password"))
            auto_extract = params.get("auto_extract_attachments", False)
            extraction_folder = params.get("extraction_folder", "downloads")
            
            if not all([pop3_server, username, password]):
                return RequestResponse(
                    status="failure", 
                    data={"reason": "Missing POP3 server, username, or password"}
                )
            
            emails = self.retrieve_emails_pop3(
                IPv4Address(pop3_server), username, password,
                auto_extract_attachments=auto_extract,
                extraction_folder=extraction_folder
            )
            
            if emails is not None:
                # Count emails with attachments
                emails_with_attachments = sum(1 for email in emails if email.has_attachments)
                
                return RequestResponse(
                    status="success",
                    data={
                        "emails": [email.dict() for email in emails],
                        "total_emails": len(emails),
                        "emails_with_attachments": emails_with_attachments,
                        "auto_extract_enabled": auto_extract,
                        "extraction_folder": extraction_folder if auto_extract else None
                    }
                )
            else:
                return RequestResponse(status="failure", data={"reason": "Failed to retrieve emails"})
        
        def _configure_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Configure email client settings."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            
            if "username" in params:
                self._set_config_value("username", params["username"])
            if "smtp_server" in params:
                self._set_config_value("default_smtp_server", params["smtp_server"])
            if "pop3_server" in params:
                self._set_config_value("default_pop3_server", params["pop3_server"])
            if "imap_server" in params:
                self._set_config_value("default_imap_server", params["imap_server"])
            if "password" in params:
                self._set_config_value("password", params["password"])
            
            return RequestResponse(status="success", data={"message": "Email client configured successfully"})
        
        def _show_status_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Show email client status."""
            status_data = {
                "username": self._get_config_value("username"),
                "smtp_server": self._get_config_value("default_smtp_server"),
                "pop3_server": self._get_config_value("default_pop3_server"),
                "imap_server": self._get_config_value("default_imap_server"),
                "active_connections": len(self.active_connections),
                "operating_state": self.operating_state.name
            }
            return RequestResponse(status="success", data=status_data)
        
        def _test_connection_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Test connection to email servers."""
            params = request[-1]
            server_type = params.get("server_type", "smtp")  # smtp, pop3, or imap
            
            if server_type == "smtp":
                server_ip = params.get("server_ip", self._get_config_value("default_smtp_server"))
                if not server_ip:
                    return RequestResponse(status="failure", data={"reason": "No SMTP server configured"})
                
                # Simple test email to verify connection
                test_email = EmailMessage(
                    sender=self._get_config_value("username", "test@localhost"),
                    recipients=["test@localhost"],
                    subject="Connection Test",
                    body="This is a connection test message."
                )
                success = self.send_email(test_email, IPv4Address(server_ip))
                if success:
                    return RequestResponse(status="success", data={"server_type": "smtp", "server_ip": server_ip})
                else:
                    return RequestResponse(status="failure", data={"reason": "SMTP connection test failed"})
            
            elif server_type == "pop3":
                server_ip = params.get("server_ip", self._get_config_value("default_pop3_server"))
                username = params.get("username", self._get_config_value("username"))
                password = params.get("password", self._get_config_value("password"))
                
                if not all([server_ip, username, password]):
                    return RequestResponse(status="failure", data={"reason": "Missing POP3 configuration"})
                
                emails = self.retrieve_emails_pop3(IPv4Address(server_ip), username, password)
                success = emails is not None
                if success:
                    return RequestResponse(status="success", data={"server_type": "pop3", "server_ip": server_ip})
                else:
                    return RequestResponse(status="failure", data={"reason": "POP3 connection test failed"})
            
            return RequestResponse(status="failure", data={"reason": f"Unsupported server type: {server_type}"})

        def _extract_attachments_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Extract attachments from a specific email."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            
            # This would typically require an email identifier or email object
            # For now, we'll require the email data to be passed directly
            email_data = params.get("email")
            destination_folder = params.get("destination_folder", "downloads")
            
            if not email_data:
                return RequestResponse(
                    status="failure", 
                    data={"reason": "Email data required for attachment extraction"}
                )
            
            # Check file system access before attempting extraction
            file_system = self._get_file_system()
            if not file_system:
                return RequestResponse(
                    status="failure", 
                    data={"reason": "No file system available for attachment extraction"}
                )
            
            try:
                # Convert email data to EmailMessage object
                if isinstance(email_data, dict):
                    email = EmailMessage.from_dict(email_data)
                elif isinstance(email_data, EmailMessage):
                    email = email_data
                else:
                    return RequestResponse(
                        status="failure", 
                        data={"reason": "Invalid email data format"}
                    )
                
                # Extract attachments
                result = self.extract_attachments(email, destination_folder)
                
                return RequestResponse(
                    status="success" if result["success"] else "failure",
                    data=result
                )
                
            except Exception as e:
                return RequestResponse(
                    status="failure", 
                    data={"reason": f"Error extracting attachments: {str(e)}"}
                )
        
        def _list_attachments_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """List attachment metadata from a specific email."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            
            email_data = params.get("email")
            
            if not email_data:
                return RequestResponse(
                    status="failure", 
                    data={"reason": "Email data required for listing attachments"}
                )
            
            try:
                # Convert email data to EmailMessage object
                if isinstance(email_data, dict):
                    email = EmailMessage.from_dict(email_data)
                elif isinstance(email_data, EmailMessage):
                    email = email_data
                else:
                    return RequestResponse(
                        status="failure", 
                        data={"reason": "Invalid email data format"}
                    )
                
                # Extract attachment metadata
                attachments_info = []
                for attachment in email.attachments:
                    attachments_info.append({
                        "filename": attachment.filename,
                        "content_type": attachment.content_type,
                        "file_size": attachment.file_size,
                        "health_status": attachment.health_status,
                        "file_uuid": attachment.file_uuid
                    })
                
                return RequestResponse(
                    status="success",
                    data={
                        "has_attachments": email.has_attachments,
                        "attachment_count": email.attachment_count,
                        "total_size": email.calculate_total_size(),
                        "attachments": attachments_info
                    }
                )
                
            except Exception as e:
                return RequestResponse(
                    status="failure", 
                    data={"reason": f"Error listing attachments: {str(e)}"}
                )
        
        def _attachment_status_request(request: RequestFormat, context: Dict) -> RequestResponse:
            """Get attachment extraction progress/status."""
            if len(request) < 1 or not isinstance(request[-1], dict):
                return RequestResponse(status="failure", data={"reason": "Parameters required"})
            
            params = request[-1]
            
            # For now, this provides general attachment handling status
            # In a more complex implementation, this could track ongoing extraction operations
            
            # Get file system info if available
            file_system_info = {}
            file_system = self._get_file_system()
            
            if file_system:
                # Check if downloads folder exists and get its contents
                downloads_folder = params.get("folder", "downloads")
                if downloads_folder in file_system.folders:
                    folder = file_system.folders[downloads_folder]
                    file_count = len([f for f in folder.files.values() if not f.deleted])
                    total_size = sum(f.size for f in folder.files.values() if not f.deleted)
                    
                    file_system_info = {
                        "folder_exists": True,
                        "file_count": file_count,
                        "total_size": total_size,
                        "folder_name": downloads_folder
                    }
                else:
                    file_system_info = {
                        "folder_exists": False,
                        "folder_name": downloads_folder
                    }
            
            return RequestResponse(
                status="success",
                data={
                    "attachment_manager_available": self.attachment_manager is not None,
                    "file_system_available": file_system is not None,
                    "service_operational": self._can_perform_action(),
                    "file_system_info": file_system_info
                }
            )

        rm.add_request("send_email", RequestType(func=_send_email_request))
        rm.add_request("send_email_with_attachments", RequestType(func=_send_email_request))  # Alias for compatibility
        rm.add_request("retrieve_emails", RequestType(func=_retrieve_emails_request))
        rm.add_request("configure", RequestType(func=_configure_request))
        rm.add_request("show_status", RequestType(func=_show_status_request))
        rm.add_request("test_connection", RequestType(func=_test_connection_request))
        rm.add_request("extract_attachments", RequestType(func=_extract_attachments_request))
        rm.add_request("list_attachments", RequestType(func=_list_attachments_request))
        rm.add_request("attachment_status", RequestType(func=_attachment_status_request))
        return rm

    def _get_config_value(self, key: str, default=None):
        """Helper method to get config values from either dict or object."""
        if isinstance(self.config, dict):
            # Handle both short and long key names for backward compatibility
            if key == "default_smtp_server":
                return self.config.get("smtp_server", self.config.get("default_smtp_server", default))
            elif key == "default_pop3_server":
                return self.config.get("pop3_server", self.config.get("default_pop3_server", default))
            elif key == "default_imap_server":
                return self.config.get("imap_server", self.config.get("default_imap_server", default))
            else:
                return self.config.get(key, default)
        else:
            return getattr(self.config, key, default)
    
    def _set_config_value(self, key: str, value):
        """Helper method to set config values on either dict or object."""
        if isinstance(self.config, dict):
            self.config[key] = value
        else:
            setattr(self.config, key, value)

    def configure(self, config_dict: Dict[str, Any]) -> None:
        """
        Configure email client settings.
        
        :param config_dict: Dictionary containing configuration parameters.
        """
        if "username" in config_dict:
            self._set_config_value("username", config_dict["username"])
        if "smtp_server" in config_dict:
            self._set_config_value("default_smtp_server", config_dict["smtp_server"])
        if "pop3_server" in config_dict:
            self._set_config_value("default_pop3_server", config_dict["pop3_server"])
        if "imap_server" in config_dict:
            self._set_config_value("default_imap_server", config_dict["imap_server"])
        if "password" in config_dict:
            self._set_config_value("password", config_dict["password"])

    def send_email_with_attachments(self, email: EmailMessage, attachment_files: List[tuple[str, str]],
                                   smtp_server_ip: IPv4Address, smtp_port: int = 25, 
                                   session_id: Optional[str] = None) -> bool:
        """
        Send an email with file attachments via SMTP protocol.
        
        :param email: The email message to send.
        :param attachment_files: List of (folder_name, file_name) tuples for files to attach.
        :param smtp_server_ip: IP address of the SMTP server.
        :param smtp_port: Port of the SMTP server (default 25).
        :param session_id: Optional session ID for tracking.
        :return: True if email was sent successfully, False otherwise.
        """
        if not self._can_perform_action():
            self.sys_log.error(f"{self.name}: Cannot send email - service not operational")
            return False
        
        # Get the file system from the node - improved file system access
        self.sys_log.info(f"{self.name}: Getting file system for attachment processing")
        file_system = self._get_file_system()
        
        if not file_system:
            self.sys_log.error(f"{self.name}: No file system available for attachment processing")
            return False
        else:
            self.sys_log.info(f"{self.name}: File system found for attachment processing")
        
        # Attach files to the email
        for folder_name, file_name in attachment_files:
            self.sys_log.debug(f"{self.name}: Attaching file '{folder_name}/{file_name}'")
            attachment = self.attachment_manager.attach_file(file_system, folder_name, file_name)
            
            if attachment is None:
                self.sys_log.error(f"{self.name}: Failed to attach file '{folder_name}/{file_name}'")
                return False
            
            email.add_attachment(attachment)
            self.sys_log.info(f"{self.name}: Successfully attached '{file_name}' "
                            f"({attachment.file_size} bytes, {attachment.content_type})")
        
        # Send the email using the existing send_email method
        return self.send_email(email, smtp_server_ip, smtp_port, session_id)

    def send_email(self, email: EmailMessage, smtp_server_ip: IPv4Address, 
                   smtp_port: int = 25, session_id: Optional[str] = None) -> bool:
        """Send an email via SMTP protocol."""
        if not self._can_perform_action():
            self.sys_log.error(f"{self.name}: Cannot send email - service not operational")
            return False
        
        self.sys_log.info(f"{self.name}: Starting email send to {', '.join(email.recipients)} via {smtp_server_ip}:{smtp_port}")
        
        try:
            # HELO command
            self.sys_log.debug(f"{self.name}: Sending HELO command")
            helo_packet = SMTPPacket(command=SMTPCommand.HELO, arguments="client")
            if not self.send(payload=helo_packet, dest_ip_address=smtp_server_ip, 
                           dest_port=smtp_port, session_id=session_id):
                self.sys_log.error(f"{self.name}: Failed to send HELO command")
                return False
            
            # MAIL FROM command
            self.sys_log.debug(f"{self.name}: Sending MAIL FROM command for {email.sender}")
            mail_packet = SMTPPacket(command=SMTPCommand.MAIL, arguments=f"FROM:<{email.sender}>")
            if not self.send(payload=mail_packet, dest_ip_address=smtp_server_ip, 
                           dest_port=smtp_port, session_id=session_id):
                self.sys_log.error(f"{self.name}: Failed to send MAIL FROM command")
                return False
            
            # RCPT TO commands
            for recipient in email.recipients:
                self.sys_log.debug(f"{self.name}: Sending RCPT TO command for {recipient}")
                rcpt_packet = SMTPPacket(command=SMTPCommand.RCPT, arguments=f"TO:<{recipient}>")
                if not self.send(payload=rcpt_packet, dest_ip_address=smtp_server_ip, 
                               dest_port=smtp_port, session_id=session_id):
                    self.sys_log.error(f"{self.name}: Failed to send RCPT TO command for {recipient}")
                    return False
            
            # DATA command with email content
            self.sys_log.debug(f"{self.name}: Sending DATA command with email content")
            data_packet = SMTPPacket(command=SMTPCommand.DATA, email_data=email)
            if not self.send(payload=data_packet, dest_ip_address=smtp_server_ip, 
                           dest_port=smtp_port, session_id=session_id):
                self.sys_log.error(f"{self.name}: Failed to send DATA command")
                return False
            
            # QUIT command
            self.sys_log.debug(f"{self.name}: Sending QUIT command")
            quit_packet = SMTPPacket(command=SMTPCommand.QUIT)
            self.send(payload=quit_packet, dest_ip_address=smtp_server_ip, 
                     dest_port=smtp_port, session_id=session_id)
            
            self.sys_log.info(f"{self.name}: Email sent successfully to {smtp_server_ip}")
            return True
            
        except Exception as e:
            self.sys_log.error(f"{self.name}: Exception during email send: {e}")
            return False

    def _get_file_system(self):
        """
        Get the file system from the node with improved access logic.
        
        :return: FileSystem object if found, None otherwise.
        """
        # Try multiple ways to access the file system
        file_system = None
        
        # Method 1: Through software manager (standard PrimAITE pattern) - prioritize this
        if hasattr(self, 'software_manager') and self.software_manager is not None:
            try:
                if hasattr(self.software_manager, 'node') and hasattr(self.software_manager.node, 'file_system'):
                    file_system = self.software_manager.node.file_system
                    self.sys_log.debug(f"{self.name}: Found file system via software manager")
                    # Also set the file_system attribute for future use
                    self.file_system = file_system
            except Exception as e:
                self.sys_log.debug(f"{self.name}: Could not access file system through software manager: {e}")
        
        # Method 2: Direct file_system attribute (standard for Software class)
        elif hasattr(self, 'file_system') and self.file_system is not None:
            file_system = self.file_system
            self.sys_log.debug(f"{self.name}: Found file system via direct file_system attribute")
        
        # Method 3: Direct node reference
        elif hasattr(self, 'node') and hasattr(self.node, 'file_system'):
            file_system = self.node.file_system
            self.sys_log.debug(f"{self.name}: Found file system via direct node reference")
        
        # Method 4: Private node reference
        elif hasattr(self, '_node') and hasattr(self._node, 'file_system'):
            file_system = self._node.file_system
            self.sys_log.debug(f"{self.name}: Found file system via private node reference")
        
        # Method 5: Check if we have a parent container with file system
        elif hasattr(self, 'parent') and hasattr(self.parent, 'file_system'):
            try:
                file_system = self.parent.file_system
                self.sys_log.debug(f"{self.name}: Found file system via parent")
            except Exception as e:
                self.sys_log.debug(f"{self.name}: Could not access file system through parent: {e}")
        
        if file_system:
            self.sys_log.debug(f"{self.name}: Successfully accessed file system")
        else:
            self.sys_log.warning(f"{self.name}: Could not access file system through any method")
        
        return file_system

    def extract_attachments(self, email: EmailMessage, destination_folder: str = "downloads") -> Dict[str, Any]:
        """
        Extract attachments from an email to the local file system.
        
        :param email: The email message containing attachments.
        :param destination_folder: The folder to extract attachments to (default: "downloads").
        :return: Dictionary with extraction results and metadata.
        """
        if not self._can_perform_action():
            self.sys_log.error(f"{self.name}: Cannot extract attachments - service not operational")
            return {"success": False, "reason": "Service not operational", "extracted_files": []}
        
        # Get the file system using improved access logic
        file_system = self._get_file_system()
        
        if not file_system:
            self.sys_log.error(f"{self.name}: No file system available for attachment extraction")
            return {"success": False, "reason": "No file system available", "extracted_files": []}
        
        # Check if email has attachments
        if not email.has_attachments:
            self.sys_log.info(f"{self.name}: Email has no attachments to extract")
            return {"success": True, "reason": "No attachments in email", "extracted_files": []}
        
        # Ensure destination folder exists
        if destination_folder not in file_system.folders:
            self.sys_log.info(f"{self.name}: Creating destination folder '{destination_folder}'")
            folder = file_system.create_folder(destination_folder)
            if not folder:
                self.sys_log.error(f"{self.name}: Failed to create destination folder '{destination_folder}'")
                return {"success": False, "reason": f"Failed to create folder '{destination_folder}'", "extracted_files": []}
        
        extracted_files = []
        failed_extractions = []
        
        # Extract each attachment
        for attachment in email.attachments:
            self.sys_log.info(f"{self.name}: Extracting attachment '{attachment.filename}' "
                            f"({attachment.file_size} bytes, {attachment.content_type})")
            
            success, error_message = self.attachment_manager.extract_attachment(
                attachment, file_system, destination_folder
            )
            
            if success:
                extracted_files.append({
                    "filename": attachment.filename,
                    "folder": destination_folder,
                    "size": attachment.file_size,
                    "content_type": attachment.content_type,
                    "health_status": attachment.health_status
                })
                self.sys_log.info(f"{self.name}: Successfully extracted '{attachment.filename}' to '{destination_folder}'")
            else:
                failed_extractions.append({
                    "filename": attachment.filename,
                    "error": error_message
                })
                self.sys_log.error(f"{self.name}: Failed to extract '{attachment.filename}': {error_message}")
        
        # Determine overall success
        overall_success = len(failed_extractions) == 0
        
        result = {
            "success": overall_success,
            "extracted_files": extracted_files,
            "failed_extractions": failed_extractions,
            "destination_folder": destination_folder,
            "total_attachments": len(email.attachments),
            "successful_extractions": len(extracted_files)
        }
        
        if not overall_success:
            result["reason"] = f"Failed to extract {len(failed_extractions)} out of {len(email.attachments)} attachments"
        
        return result

    def retrieve_emails_pop3(self, pop3_server_ip: IPv4Address, username: str, password: str,
                            pop3_port: int = 110, session_id: Optional[str] = None, 
                            auto_extract_attachments: bool = False, 
                            extraction_folder: str = "downloads") -> Optional[List[EmailMessage]]:
        """
        Retrieve emails via POP3 protocol with optional automatic attachment extraction.
        
        :param pop3_server_ip: IP address of the POP3 server.
        :param username: Username for authentication.
        :param password: Password for authentication.
        :param pop3_port: Port of the POP3 server (default 110).
        :param session_id: Optional session ID for tracking.
        :param auto_extract_attachments: Whether to automatically extract attachments.
        :param extraction_folder: Folder to extract attachments to (default "downloads").
        :return: List of retrieved emails, or None if failed.
        """
        if not self._can_perform_action():
            return None
        
        self.sys_log.info(f"Retrieving emails from {pop3_server_ip} for user {username}")
        
        # Initialize POP3 session state
        self._pop3_session = {
            "state": "connecting",
            "username": username,
            "password": password,
            "server_ip": pop3_server_ip,
            "server_port": pop3_port,
            "session_id": session_id,
            "retrieved_emails": [],
            "message_count": 0,
            "current_message": 0,
            "auto_extract": auto_extract_attachments,
            "extraction_folder": extraction_folder
        }
        
        try:
            # Start POP3 session with USER command
            user_packet = POP3Packet(command=POP3Command.USER, arguments=username)
            if not self.send(payload=user_packet, dest_ip_address=pop3_server_ip, 
                           dest_port=pop3_port, session_id=session_id):
                self.sys_log.error(f"{self.name}: Failed to send USER command")
                return None
            
            self._pop3_session["state"] = "user_sent"
            self.sys_log.debug(f"{self.name}: Sent USER command for {username}")
            
            # Note: In a real network simulation, we would wait for responses here
            # For now, we'll simulate the complete POP3 transaction
            return self._simulate_pop3_transaction()
            
        except Exception as e:
            self.sys_log.error(f"Failed to retrieve emails: {e}")
            return None
    
    def _simulate_pop3_transaction(self) -> Optional[List[EmailMessage]]:
        """
        Simulate a complete POP3 transaction by using the request system.
        
        This approach uses the POP3 server's request handlers directly,
        which is more reliable than network protocol simulation.
        """
        try:
            session = self._pop3_session
            username = session["username"]
            password = session["password"]
            server_ip = session["server_ip"]
            
            self.sys_log.info(f"{self.name}: Simulating POP3 transaction for {username}")
            
            # Find the POP3 server using a more direct approach
            pop3_server = self._find_pop3_server_direct(server_ip)
            if not pop3_server:
                self.sys_log.error(f"{self.name}: Could not find POP3 server at {server_ip}")
                return None
            
            # Use the POP3 server's request system to authenticate and retrieve emails
            self.sys_log.info(f"{self.name}: Authenticating with POP3 server")
            
            # Authenticate user
            auth_response = pop3_server.apply_request(["authenticate_user", {"username": username, "password": password}], {})
            if auth_response.status != "success":
                self.sys_log.error(f"{self.name}: POP3 authentication failed: {auth_response.data}")
                return None
            
            self.sys_log.info(f"{self.name}: POP3 authentication successful")
            
            # Get message list
            list_response = pop3_server.apply_request(["get_message_list", {"username": username}], {})
            if list_response.status != "success":
                self.sys_log.error(f"{self.name}: Failed to get message list: {list_response.data}")
                return None
            
            message_count = list_response.data.get("message_count", 0)
            self.sys_log.info(f"{self.name}: Found {message_count} messages in mailbox")
            
            if message_count == 0:
                return []
            
            # Retrieve each message
            retrieved_emails = []
            for msg_num in range(1, message_count + 1):
                msg_response = pop3_server.apply_request(["retrieve_message", {"username": username, "message_number": msg_num}], {})
                
                if msg_response.status == "success":
                    # Convert response data to EmailMessage
                    msg_data = msg_response.data
                    email = EmailMessage(
                        sender=msg_data["sender"],
                        recipients=msg_data["recipients"],
                        subject=msg_data["subject"],
                        body=msg_data["body"],
                        timestamp=msg_data.get("timestamp")
                    )
                    # Set message ID if available
                    if "message_id" in msg_data:
                        email.message_id = msg_data["message_id"]
                    
                    retrieved_emails.append(email)
                    self.sys_log.info(f"{self.name}: Retrieved message {msg_num}: '{email.subject}' from {email.sender}")
                else:
                    self.sys_log.warning(f"{self.name}: Failed to retrieve message {msg_num}: {msg_response.data}")
            
            self.sys_log.info(f"{self.name}: Successfully retrieved {len(retrieved_emails)} emails via POP3")
            
            # Handle auto-extraction if enabled
            if session["auto_extract"] and retrieved_emails:
                for email in retrieved_emails:
                    if email.has_attachments:
                        self.sys_log.info(f"{self.name}: Auto-extracting attachments from email '{email.subject}'")
                        extraction_result = self.extract_attachments(email, session["extraction_folder"])
                        if extraction_result["success"]:
                            self.sys_log.info(f"{self.name}: Successfully extracted {extraction_result['successful_extractions']} attachments")
                        else:
                            self.sys_log.warning(f"{self.name}: Attachment extraction failed: {extraction_result.get('reason', 'Unknown error')}")
            
            return retrieved_emails
            
        except Exception as e:
            self.sys_log.error(f"{self.name}: Error in POP3 transaction simulation: {e}")
            return None
        finally:
            # Clean up session state
            if hasattr(self, '_pop3_session'):
                delattr(self, '_pop3_session')
    
    def _find_pop3_server_direct(self, server_ip: IPv4Address):
        """
        Find the POP3 server using a more direct approach.
        
        This method tries to find the server by checking connected nodes directly.
        """
        try:
            # Check if we have a test server reference injected
            if hasattr(self, '_test_pop3_server') and self._test_pop3_server:
                self.sys_log.info(f"{self.name}: Using injected test POP3 server reference")
                return self._test_pop3_server
            
            # Get our node
            if not hasattr(self, 'software_manager') or not hasattr(self.software_manager, 'node'):
                return None
            
            node = self.software_manager.node
            
            # Check all network interfaces for connected nodes
            if hasattr(node, 'network_interface') and node.network_interface:
                for interface in node.network_interface.values():
                    if hasattr(interface, 'link') and interface.link:
                        # Get the other end of the link
                        other_interface = interface.link.endpoint_b if interface.link.endpoint_a == interface else interface.link.endpoint_a
                        
                        if (hasattr(other_interface, 'node') and 
                            hasattr(other_interface.node, 'config') and
                            hasattr(other_interface.node.config, 'ip_address')):
                            
                            other_ip = str(other_interface.node.config.ip_address)
                            
                            if other_ip == str(server_ip):
                                # Found the server node
                                server_node = other_interface.node
                                
                                if (hasattr(server_node, 'software_manager') and 
                                    server_node.software_manager and
                                    hasattr(server_node.software_manager, 'software')):
                                    
                                    pop3_server = server_node.software_manager.software.get("pop3-server")
                                    if pop3_server:
                                        self.sys_log.info(f"{self.name}: Found POP3 server via direct connection")
                                        return pop3_server
            
            return None
            
        except Exception as e:
            self.sys_log.error(f"{self.name}: Error in direct POP3 server search: {e}")
            return None
    
    def _find_pop3_server(self, server_ip: IPv4Address):
        """
        Find the POP3 server by IP address.
        
        This is a direct approach that bypasses network protocol issues.
        """
        try:
            # Try to get the network from the node
            if not hasattr(self, 'software_manager') or not hasattr(self.software_manager, 'node'):
                self.sys_log.error(f"{self.name}: No software manager or node available")
                return None
            
            node = self.software_manager.node
            self.sys_log.debug(f"{self.name}: Searching for POP3 server at {server_ip}")
            
            # Method 1: Check direct network connection via links
            if hasattr(node, 'network_interface') and node.network_interface:
                for interface in node.network_interface.values():
                    if hasattr(interface, 'link') and interface.link:
                        # Get the other end of the link
                        other_interface = interface.link.endpoint_b if interface.link.endpoint_a == interface else interface.link.endpoint_a
                        if (hasattr(other_interface, 'node') and 
                            hasattr(other_interface.node, 'config') and
                            hasattr(other_interface.node.config, 'ip_address')):
                            
                            other_ip = str(other_interface.node.config.ip_address)
                            self.sys_log.debug(f"{self.name}: Found connected node with IP {other_ip}")
                            
                            if other_ip == str(server_ip):
                                # Found the server node
                                server_node = other_interface.node
                                self.sys_log.info(f"{self.name}: Found server node {server_node.config.hostname}")
                                
                                if hasattr(server_node, 'software_manager') and server_node.software_manager:
                                    pop3_server = server_node.software_manager.software.get("pop3-server")
                                    if pop3_server:
                                        self.sys_log.info(f"{self.name}: Found POP3 server service")
                                        return pop3_server
                                    else:
                                        self.sys_log.error(f"{self.name}: No POP3 server service on node")
                                else:
                                    self.sys_log.error(f"{self.name}: Server node has no software manager")
            
            # Method 2: Try to find network and search all nodes
            network = None
            if hasattr(node, 'network') and node.network:
                network = node.network
                self.sys_log.debug(f"{self.name}: Found network with {len(network.nodes)} nodes")
            
            if network:
                for i, network_node in enumerate(network.nodes):
                    try:
                        self.sys_log.debug(f"{self.name}: Examining node {i}: {type(network_node).__name__}")
                        
                        # Check if node has config
                        if not hasattr(network_node, 'config'):
                            self.sys_log.debug(f"{self.name}: Node {i} has no config attribute")
                            continue
                            
                        # Check if config has IP address
                        if not hasattr(network_node.config, 'ip_address'):
                            self.sys_log.debug(f"{self.name}: Node {i} config has no ip_address attribute")
                            continue
                        
                        node_ip = str(network_node.config.ip_address)
                        node_hostname = getattr(network_node.config, 'hostname', 'Unknown')
                        self.sys_log.info(f"{self.name}: Checking network node {node_hostname} with IP {node_ip}")
                        
                        if node_ip == str(server_ip):
                            self.sys_log.info(f"{self.name}: Found matching network node {node_hostname}")
                            
                            # Check software manager
                            if not hasattr(network_node, 'software_manager'):
                                self.sys_log.warning(f"{self.name}: Network node has no software_manager attribute")
                                continue
                                
                            if not network_node.software_manager:
                                self.sys_log.warning(f"{self.name}: Network node software_manager is None")
                                continue
                                
                            if not hasattr(network_node.software_manager, 'software'):
                                self.sys_log.warning(f"{self.name}: Software manager has no software attribute")
                                continue
                            
                            # Try to get POP3 server
                            software_dict = network_node.software_manager.software
                            self.sys_log.info(f"{self.name}: Available software: {list(software_dict.keys())}")
                            
                            pop3_server = software_dict.get("pop3-server")
                            if pop3_server:
                                self.sys_log.info(f"{self.name}: Found POP3 server service on network node")
                                return pop3_server
                            else:
                                self.sys_log.warning(f"{self.name}: No POP3 server service on network node")
                        
                    except Exception as e:
                        self.sys_log.error(f"{self.name}: Error checking network node {i}: {e}")
                        continue
            
            self.sys_log.error(f"{self.name}: Could not find POP3 server at {server_ip} using any method")
            return None
            
        except Exception as e:
            self.sys_log.error(f"{self.name}: Error finding POP3 server: {e}")
            return None

    def receive(self, payload: Any, session_id: Optional[str] = None, **kwargs) -> bool:
        """Receive responses from email servers."""
        if not super().receive(payload=payload, session_id=session_id, **kwargs):
            return False
        
        # Handle SMTP responses
        if isinstance(payload, SMTPPacket):
            self.sys_log.info(f"Received SMTP response: {payload.status_code}")
            return True
        
        # Handle POP3 responses
        elif isinstance(payload, POP3Packet):
            self.sys_log.info(f"Received POP3 response: {payload.status}")
            return self._handle_pop3_response(payload, session_id)
        
        # Handle IMAP responses
        elif isinstance(payload, IMAPPacket):
            self.sys_log.info(f"Received IMAP response: {payload.status}")
            return True
        
        return False
    
    def _handle_pop3_response(self, response: POP3Packet, session_id: Optional[str] = None) -> bool:
        """
        Handle POP3 server responses during email retrieval.
        
        This method processes POP3 responses and updates the session state accordingly.
        """
        if not hasattr(self, '_pop3_session'):
            self.sys_log.warning(f"{self.name}: Received POP3 response but no active session")
            return True
        
        session = self._pop3_session
        
        try:
            if session["state"] == "user_sent":
                if response.status == POP3Status.OK:
                    # USER command accepted, send PASS command
                    pass_packet = POP3Packet(command=POP3Command.PASS, arguments=session["password"])
                    if self.send(payload=pass_packet, dest_ip_address=session["server_ip"], 
                               dest_port=session["server_port"], session_id=session["session_id"]):
                        session["state"] = "pass_sent"
                        self.sys_log.debug(f"{self.name}: Sent PASS command")
                else:
                    self.sys_log.error(f"{self.name}: USER command failed: {response.message}")
                    return False
            
            elif session["state"] == "pass_sent":
                if response.status == POP3Status.OK:
                    # Authentication successful, send LIST command
                    list_packet = POP3Packet(command=POP3Command.LIST)
                    if self.send(payload=list_packet, dest_ip_address=session["server_ip"], 
                               dest_port=session["server_port"], session_id=session["session_id"]):
                        session["state"] = "list_sent"
                        self.sys_log.debug(f"{self.name}: Sent LIST command")
                else:
                    self.sys_log.error(f"{self.name}: Authentication failed: {response.message}")
                    return False
            
            elif session["state"] == "list_sent":
                if response.status == POP3Status.OK:
                    # Parse message list
                    message_lines = response.message.split('\n')
                    if message_lines:
                        first_line = message_lines[0].strip()
                        if first_line.endswith('messages'):
                            # Extract message count
                            parts = first_line.split()
                            if parts:
                                try:
                                    session["message_count"] = int(parts[0])
                                    self.sys_log.info(f"{self.name}: Found {session['message_count']} messages")
                                    
                                    if session["message_count"] > 0:
                                        # Start retrieving messages
                                        session["current_message"] = 1
                                        self._retrieve_next_message()
                                    else:
                                        # No messages, finish
                                        self._finish_pop3_session()
                                except ValueError:
                                    self.sys_log.error(f"{self.name}: Could not parse message count")
                                    return False
                else:
                    self.sys_log.error(f"{self.name}: LIST command failed: {response.message}")
                    return False
            
            elif session["state"] == "retr_sent":
                if response.status == POP3Status.OK and response.email_data:
                    # Message retrieved successfully
                    session["retrieved_emails"].append(response.email_data)
                    self.sys_log.info(f"{self.name}: Retrieved message {session['current_message']}: '{response.email_data.subject}'")
                    
                    # Move to next message or finish
                    session["current_message"] += 1
                    if session["current_message"] <= session["message_count"]:
                        self._retrieve_next_message()
                    else:
                        self._finish_pop3_session()
                else:
                    self.sys_log.warning(f"{self.name}: Failed to retrieve message {session['current_message']}")
                    # Continue with next message
                    session["current_message"] += 1
                    if session["current_message"] <= session["message_count"]:
                        self._retrieve_next_message()
                    else:
                        self._finish_pop3_session()
            
            return True
            
        except Exception as e:
            self.sys_log.error(f"{self.name}: Error handling POP3 response: {e}")
            return False
    
    def _retrieve_next_message(self):
        """Send RETR command for the next message."""
        session = self._pop3_session
        retr_packet = POP3Packet(command=POP3Command.RETR, arguments=str(session["current_message"]))
        if self.send(payload=retr_packet, dest_ip_address=session["server_ip"], 
                   dest_port=session["server_port"], session_id=session["session_id"]):
            session["state"] = "retr_sent"
            self.sys_log.debug(f"{self.name}: Sent RETR command for message {session['current_message']}")
    
    def _finish_pop3_session(self):
        """Finish the POP3 session and send QUIT command."""
        session = self._pop3_session
        quit_packet = POP3Packet(command=POP3Command.QUIT)
        self.send(payload=quit_packet, dest_ip_address=session["server_ip"], 
                 dest_port=session["server_port"], session_id=session["session_id"])
        
        self.sys_log.info(f"{self.name}: POP3 session completed, retrieved {len(session['retrieved_emails'])} emails")
        session["state"] = "completed"

    def show(self, markdown: bool = False):
        """Display email client status and configuration in tabular format."""
        from prettytable import PrettyTable, MARKDOWN
        
        # Client status table
        status_table = PrettyTable(["Property", "Value"])
        if markdown:
            status_table.set_style(MARKDOWN)
        status_table.align = "l"
        status_table.title = f"Email Client Status ({self.sys_log.hostname})"
        
        status_table.add_row(["Service Name", self.name])
        status_table.add_row(["Operating State", self.operating_state.name])
        status_table.add_row(["Health State", self.health_state_actual.name])
        status_table.add_row(["Port", self.port])
        status_table.add_row(["Protocol", self.protocol])
        status_table.add_row(["Active Connections", len(self.active_connections)])
        status_table.add_row(["Username", self.config.username or "Not configured"])
        status_table.add_row(["Attachment Manager", "Available" if self.attachment_manager else "Not available"])
        
        print(status_table)
        
        # Server configuration table
        config_table = PrettyTable(["Server Type", "Address", "Status"])
        if markdown:
            config_table.set_style(MARKDOWN)
        config_table.align = "l"
        config_table.title = f"Server Configuration ({self.sys_log.hostname})"
        
        config_table.add_row([
            "SMTP Server",
            self.config.default_smtp_server or "Not configured",
            "Configured" if self.config.default_smtp_server else "Not configured"
        ])
        config_table.add_row([
            "POP3 Server",
            self.config.default_pop3_server or "Not configured",
            "Configured" if self.config.default_pop3_server else "Not configured"
        ])
        config_table.add_row([
            "IMAP Server",
            self.config.default_imap_server or "Not configured",
            "Configured" if self.config.default_imap_server else "Not configured"
        ])
        
        print(config_table)
        
        # Active connections table
        if self.active_connections:
            conn_table = PrettyTable(["Connection ID", "Type", "Details"])
            if markdown:
                conn_table.set_style(MARKDOWN)
            conn_table.align = "l"
            conn_table.title = f"Active Connections ({self.sys_log.hostname})"
            
            for conn_id, conn_data in self.active_connections.items():
                conn_table.add_row([
                    conn_id[:12] + "..." if len(conn_id) > 12 else conn_id,
                    conn_data.get("type", "unknown"),
                    str(conn_data)[:50] + "..." if len(str(conn_data)) > 50 else str(conn_data)
                ])
            
            print(conn_table)

    def show_mailbox(self, pop3_server_ip: IPv4Address = None, username: str = None, 
                     password: str = None, markdown: bool = False):
        """Display mailbox contents by connecting to POP3 server and retrieving message list."""
        from prettytable import PrettyTable, MARKDOWN
        
        # Use configured values if not provided
        server_ip = pop3_server_ip or (IPv4Address(self.config.default_pop3_server) if self.config.default_pop3_server else None)
        user = username or self.config.username
        pwd = password or self.config.password
        
        if not all([server_ip, user, pwd]):
            print("Error: Missing POP3 server, username, or password configuration")
            return
        
        print(f"Connecting to POP3 server {server_ip} as {user}...")
        
        # In a real implementation, this would connect to POP3 and retrieve the message list
        # For now, we'll show a placeholder table
        msg_table = PrettyTable(["#", "Subject", "From", "Size", "Status"])
        if markdown:
            msg_table.set_style(MARKDOWN)
        msg_table.align = "l"
        msg_table.title = f"Email Client View: {user}'s Mailbox (via POP3)"
        
        # This would be populated by actual POP3 LIST command results
        msg_table.add_row(["1", "Connection attempt", f"POP3 Server {server_ip}", "N/A", "Connecting..."])
        
        print(msg_table)
        print(f"Note: This is a client-side view. Use server.show_mailbox() for actual mailbox contents.")

    def describe_state(self) -> Dict:
        """Describe the current state of the email client."""
        state = super().describe_state()
        state["active_connections"] = len(self.active_connections)
        state["configured_servers"] = {
            "smtp": self.config.default_smtp_server,
            "pop3": self.config.default_pop3_server,
            "imap": self.config.default_imap_server
        }
        state["attachment_manager_available"] = self.attachment_manager is not None
        state["file_system_available"] = hasattr(self, 'node') and hasattr(self.node, 'file_system')
        return state