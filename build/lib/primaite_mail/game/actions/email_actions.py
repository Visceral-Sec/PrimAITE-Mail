# © Crown-owned copyright 2025, Defence Science and Technology Laboratory UK
"""Email-specific actions for agents."""

from primaite.game.agent.actions.abstract import AbstractAction
from primaite.interface.request import RequestFormat

__all__ = (
    "EmailSendAction", 
    "EmailRetrieveAction", 
    "EmailConfigureAction",
    "EmailSendWithAttachmentsAction",
    "EmailExtractAttachmentsAction", 
    "EmailScanAttachmentsAction",
    "EmailQuarantineMessageAction",
    "EmailBlockSenderAction",
    "EmailUnblockSenderAction",
    "EmailBlockIpAction",
    "EmailUnblockIpAction",
    "EmailQuerySecurityPoliciesAction",
    "EmailGetSecurityStatisticsAction"
)


class EmailSendAction(AbstractAction, discriminator="email-send"):
    """Action for sending emails via email client."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailSendAction."""

        type: str = "email-send"
        node_name: str
        to: list
        subject: str = ""
        body: str = ""
        sender: str = ""

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
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
                "from": config.sender
            }
        ]


class EmailRetrieveAction(AbstractAction, discriminator="email-retrieve"):
    """Action for retrieving emails via email client."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailRetrieveAction."""

        type: str = "email-retrieve"
        node_name: str
        username: str = ""
        password: str = ""

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
            "network",
            "node",
            config.node_name,
            "application", 
            "email-client",
            "retrieve_emails",
            {
                "username": config.username,
                "password": config.password
            }
        ]


class EmailConfigureAction(AbstractAction, discriminator="email-configure"):
    """Action for configuring email client settings."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailConfigureAction."""

        type: str = "email-configure"
        node_name: str
        username: str = ""
        smtp_server: str = ""
        pop3_server: str = ""
        password: str = ""

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
            "network",
            "node",
            config.node_name,
            "application",
            "email-client", 
            "configure",
            {
                "username": config.username,
                "smtp_server": config.smtp_server,
                "pop3_server": config.pop3_server,
                "password": config.password
            }
        ]


class EmailSendWithAttachmentsAction(AbstractAction, discriminator="email-send-with-attachments"):
    """Action for sending emails with file attachments via email client."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailSendWithAttachmentsAction."""

        type: str = "email-send-with-attachments"
        node_name: str
        to: list
        subject: str = ""
        body: str = ""
        sender: str = ""
        attachment_files: list = []  # List of tuples (folder_name, file_name)

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
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


class EmailExtractAttachmentsAction(AbstractAction, discriminator="email-extract-attachments"):
    """Action for extracting attachments from received emails."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailExtractAttachmentsAction."""

        type: str = "email-extract-attachments"
        node_name: str
        email_index: int = 0  # Index of email to extract attachments from
        destination_folder: str = "downloads"  # Destination folder for extracted files
        extract_all: bool = True  # Whether to extract all attachments or specific ones

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
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


class EmailScanAttachmentsAction(AbstractAction, discriminator="email-scan-attachments"):
    """Action for blue agents to scan email attachments for security analysis."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailScanAttachmentsAction."""

        type: str = "email-scan-attachments"
        node_name: str
        email_index: int = 0  # Index of email to scan attachments from
        scan_type: str = "basic"  # Type of scan: basic, detailed, security

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
            "network",
            "node",
            config.node_name,
            "application",
            "email-client", 
            "list_attachments",  # Use existing list_attachments handler for scanning
            {
                "email_index": config.email_index,
                "scan_type": config.scan_type
            }
        ]


class EmailQuarantineMessageAction(AbstractAction, discriminator="email-quarantine-message"):
    """Action for blue agents to quarantine suspicious emails."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailQuarantineMessageAction."""

        type: str = "email-quarantine-message"
        node_name: str
        email_index: int = 0  # Index of email to quarantine
        reason: str = "suspicious_attachment"  # Reason for quarantine
        smtp_server_node: str = ""  # Node name where SMTP server is running

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        # This action targets the SMTP server to quarantine the message
        return [
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


class EmailBlockSenderAction(AbstractAction, discriminator="email-block-sender"):
    """Action for blue agents to block emails from specific sender addresses."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailBlockSenderAction."""

        type: str = "email-block-sender"
        node_name: str  # Node where the blue agent is located
        smtp_server_node: str  # Node name where SMTP server is running
        sender_address: str  # Email address to block

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
            "network",
            "node",
            config.smtp_server_node,
            "service",
            "smtp-server",
            "block_sender",
            {
                "sender_address": config.sender_address,
                "agent_name": config.node_name
            }
        ]


class EmailUnblockSenderAction(AbstractAction, discriminator="email-unblock-sender"):
    """Action for blue agents to remove sender blocks."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailUnblockSenderAction."""

        type: str = "email-unblock-sender"
        node_name: str  # Node where the blue agent is located
        smtp_server_node: str  # Node name where SMTP server is running
        sender_address: str  # Email address to unblock

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
            "network",
            "node",
            config.smtp_server_node,
            "service",
            "smtp-server",
            "unblock_sender",
            {
                "sender_address": config.sender_address,
                "agent_name": config.node_name
            }
        ]


class EmailBlockIpAction(AbstractAction, discriminator="email-block-ip"):
    """Action for blue agents to block emails from specific IP addresses or CIDR ranges."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailBlockIpAction."""

        type: str = "email-block-ip"
        node_name: str  # Node where the blue agent is located
        smtp_server_node: str  # Node name where SMTP server is running
        ip_address: str  # IP address or CIDR range to block (e.g., "192.168.1.100" or "192.168.1.0/24")

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
            "network",
            "node",
            config.smtp_server_node,
            "service",
            "smtp-server",
            "block_ip",
            {
                "ip_address": config.ip_address,
                "agent_name": config.node_name
            }
        ]


class EmailUnblockIpAction(AbstractAction, discriminator="email-unblock-ip"):
    """Action for blue agents to remove IP blocks."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailUnblockIpAction."""

        type: str = "email-unblock-ip"
        node_name: str  # Node where the blue agent is located
        smtp_server_node: str  # Node name where SMTP server is running
        ip_address: str  # IP address or CIDR range to unblock

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
            "network",
            "node",
            config.smtp_server_node,
            "service",
            "smtp-server",
            "unblock_ip",
            {
                "ip_address": config.ip_address,
                "agent_name": config.node_name
            }
        ]


class EmailQuerySecurityPoliciesAction(AbstractAction, discriminator="email-query-security-policies"):
    """Action for blue agents to query current email security policies."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailQuerySecurityPoliciesAction."""

        type: str = "email-query-security-policies"
        node_name: str  # Node where the blue agent is located
        smtp_server_node: str  # Node name where SMTP server is running
        include_statistics: bool = True  # Whether to include basic statistics

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
            "network",
            "node",
            config.smtp_server_node,
            "service",
            "smtp-server",
            "list_security_policies",
            {
                "agent_name": config.node_name,
                "include_statistics": config.include_statistics
            }
        ]


class EmailGetSecurityStatisticsAction(AbstractAction, discriminator="email-get-security-statistics"):
    """Action for blue agents to get detailed security statistics and recent activity."""

    class ConfigSchema(AbstractAction.ConfigSchema):
        """Configuration schema for EmailGetSecurityStatisticsAction."""

        type: str = "email-get-security-statistics"
        node_name: str  # Node where the blue agent is located
        smtp_server_node: str  # Node name where SMTP server is running
        event_limit: int = 50  # Maximum number of recent events to return
        time_range_hours: int = 24  # Time range for events in hours (0 = all events)
        event_type_filter: str = ""  # Filter by event type (empty = all types)

    @classmethod
    def form_request(cls, config: ConfigSchema) -> RequestFormat:
        """Return the action formatted as a request which can be ingested by the PrimAITE simulation."""
        return [
            "network",
            "node",
            config.smtp_server_node,
            "service",
            "smtp-server",
            "get_security_statistics",
            {
                "agent_name": config.node_name,
                "event_limit": config.event_limit,
                "time_range_hours": config.time_range_hours,
                "event_type_filter": config.event_type_filter
            }
        ]