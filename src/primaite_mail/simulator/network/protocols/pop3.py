"""POP3 Protocol implementation for email retrieval."""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel

from primaite_mail.simulator.network.protocols.smtp import EmailMessage


class POP3Command(Enum):
    """POP3 Commands as defined in RFC 1939."""
    
    USER = "USER"
    PASS = "PASS"
    STAT = "STAT"
    LIST = "LIST"
    RETR = "RETR"
    DELE = "DELE"
    NOOP = "NOOP"
    RSET = "RSET"
    QUIT = "QUIT"
    TOP = "TOP"
    UIDL = "UIDL"


class POP3Status(Enum):
    """POP3 Response status."""
    
    OK = "+OK"
    ERR = "-ERR"


class POP3Packet(BaseModel):
    """POP3 Protocol packet for network communication."""
    
    command: Optional[POP3Command] = None
    arguments: Optional[str] = None
    status: Optional[POP3Status] = None
    message: Optional[str] = None
    email_data: Optional[EmailMessage] = None
    email_list: Optional[List[EmailMessage]] = None
    session_id: Optional[str] = None