"""IMAP Protocol implementation for advanced email access."""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from primaite_mail.simulator.network.protocols.smtp import EmailMessage


class IMAPCommand(Enum):
    """IMAP Commands as defined in RFC 3501."""
    
    CAPABILITY = "CAPABILITY"
    NOOP = "NOOP"
    LOGOUT = "LOGOUT"
    STARTTLS = "STARTTLS"
    AUTHENTICATE = "AUTHENTICATE"
    LOGIN = "LOGIN"
    SELECT = "SELECT"
    EXAMINE = "EXAMINE"
    CREATE = "CREATE"
    DELETE = "DELETE"
    RENAME = "RENAME"
    SUBSCRIBE = "SUBSCRIBE"
    UNSUBSCRIBE = "UNSUBSCRIBE"
    LIST = "LIST"
    LSUB = "LSUB"
    STATUS = "STATUS"
    APPEND = "APPEND"
    CHECK = "CHECK"
    CLOSE = "CLOSE"
    EXPUNGE = "EXPUNGE"
    SEARCH = "SEARCH"
    FETCH = "FETCH"
    STORE = "STORE"
    COPY = "COPY"
    UID = "UID"


class IMAPStatus(Enum):
    """IMAP Response status."""
    
    OK = "OK"
    NO = "NO"
    BAD = "BAD"
    PREAUTH = "PREAUTH"
    BYE = "BYE"


class IMAPFolder(BaseModel):
    """Represents an IMAP folder/mailbox."""
    
    name: str
    messages: List[EmailMessage] = Field(default_factory=list)
    flags: List[str] = Field(default_factory=list)
    exists: int = 0
    recent: int = 0
    unseen: int = 0


class IMAPPacket(BaseModel):
    """IMAP Protocol packet for network communication."""
    
    tag: Optional[str] = None
    command: Optional[IMAPCommand] = None
    arguments: Optional[str] = None
    status: Optional[IMAPStatus] = None
    message: Optional[str] = None
    email_data: Optional[EmailMessage] = None
    folder_data: Optional[IMAPFolder] = None
    folders: Optional[List[IMAPFolder]] = None
    session_id: Optional[str] = None